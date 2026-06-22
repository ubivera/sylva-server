CREATE SCHEMA IF NOT EXISTS identity;

CREATE TYPE identity.user_lifecycle AS ENUM (
    'pending_invite',
    'active',
    'deactivated',
    'anonymized'
);

CREATE TYPE identity.instance_role AS ENUM (
    'owner',
    'admin',
    'member'
);

CREATE TYPE identity.user_kind AS ENUM (
    'member',
    'guest'
);

CREATE TABLE identity.users (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email         TEXT NOT NULL,
    email_lower   TEXT GENERATED ALWAYS AS (lower(email)) STORED,
    display_name  TEXT NOT NULL,
    lifecycle     identity.user_lifecycle NOT NULL DEFAULT 'pending_invite',
    instance_role identity.instance_role NOT NULL DEFAULT 'member',
    kind          identity.user_kind NOT NULL DEFAULT 'member',
    locale        TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX users_email_lower_uniq ON identity.users (email_lower);
CREATE INDEX users_kind_idx ON identity.users (kind);

CREATE TABLE identity.invitations (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email              TEXT NOT NULL,
    email_lower        TEXT GENERATED ALWAYS AS (lower(email)) STORED,
    token_hash         BYTEA NOT NULL,
    invited_by_user_id UUID NOT NULL REFERENCES identity.users(id) ON DELETE CASCADE,
    instance_role      identity.instance_role NOT NULL DEFAULT 'member',
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at         TIMESTAMPTZ NOT NULL,
    accepted_at        TIMESTAMPTZ NULL,
    accepted_user_id   UUID NULL REFERENCES identity.users(id) ON DELETE SET NULL,
    revoked_at         TIMESTAMPTZ NULL
);

CREATE UNIQUE INDEX invitations_token_hash_uniq ON identity.invitations (token_hash);
CREATE INDEX invitations_email_lower_idx        ON identity.invitations (email_lower);
CREATE INDEX invitations_invited_by_idx         ON identity.invitations (invited_by_user_id);

-- ── Sylva Hub: device-enrollment / E2E key material (see docs/design/hub.md) ──
-- These tables are populated by the Hub's account creation + enrollment flows
-- (Phase 2+). A user with no `user_keys` row simply has no E2E key material yet;
-- nothing here is wired into the existing account-creation paths.

-- Per-user cryptographic material. 1:1 with users; a row exists only once the
-- user's keys have been provisioned (client-side) by `Account.Bootstrap` / invite.
-- The server stores public keys + ciphertext only — never plaintext keys.
CREATE TABLE identity.user_keys (
    user_id                 UUID PRIMARY KEY REFERENCES identity.users(id) ON DELETE CASCADE,
    x25519_public           BYTEA NOT NULL,   -- receives wrapped content keys
    ed25519_public          BYTEA NOT NULL,   -- signature verification
    x25519_private_wrapped  BYTEA NOT NULL,   -- private key wrapped by the master key
    ed25519_private_wrapped BYTEA NOT NULL,   -- private key wrapped by the master key
    -- The ONLY server-side copy of the master key, wrapped by KEK =
    -- Argon2id(password, secret_key) — the 1Password-style two-secret derivation.
    -- Both the password and the Secret Key are always required to unwrap it.
    master_key_wrapped      BYTEA NOT NULL,
    kdf_salt                BYTEA NOT NULL,
    -- Argon2id m/t/p for client re-derivation. Opaque to the server (TEXT, not
    -- JSONB) — the server never interprets it, just stores + returns it.
    kdf_params              TEXT NOT NULL,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- The machine plane (thin in slice 1; the always-on agent + management plane is
-- slice 2 — see docs/design/agent.md). One machine hosts many per-OS-user
-- enrollments. `claimed_by_user_id` is the slice-1 single-claim reference; the
-- many-to-many `machine_claims` table (many users : one machine) + retiring this
-- column land with the client-app claiming feature.
CREATE TABLE identity.machines (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    label                   TEXT NOT NULL,
    platform                TEXT NOT NULL,                              -- ios|android|windows|macos|linux
    claimed_by_user_id      UUID NULL REFERENCES identity.users(id) ON DELETE SET NULL,
    -- The agent's Ed25519 machine identity key (slice 2). NULL for thin slice-1
    -- rows created from device enrollment; set when an agent registers. UNIQUE so
    -- one machine identity maps to one row.
    machine_identity_public BYTEA NULL UNIQUE,
    agent_version           TEXT NULL,                                  -- reported at check-in (non-PII)
    location_enabled        BOOLEAN NOT NULL DEFAULT false,             -- admin policy (slice 2, CP3)
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at            TIMESTAMPTZ NULL
);

-- Machine session tokens (slice 2): issued at RegisterMachine, carried by the
-- agent on CheckIn/Subscribe. Mirrors auth.sessions — only the token hash is
-- stored (the raw token lives only on the device).
CREATE TABLE identity.machine_sessions (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    machine_id  UUID NOT NULL REFERENCES identity.machines(id) ON DELETE CASCADE,
    token_hash  BYTEA NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ NOT NULL,
    revoked_at  TIMESTAMPTZ NULL
);

CREATE UNIQUE INDEX machine_sessions_token_hash_uniq ON identity.machine_sessions (token_hash);
CREATE INDEX machine_sessions_by_machine            ON identity.machine_sessions (machine_id);

-- The device-admin group key (slice 2, CP3): device telemetry is end-to-end
-- sealed to this X25519 public key; admins hold the secret. Wrapping the secret
-- to each admin (a `device_admin_group_members` table) is a client-app concern
-- and lands with that panel. One active row (the latest); `id` is the recipient
-- key id stamped on telemetry. See docs/design/agent.md.
CREATE TABLE identity.device_admin_group (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    group_public BYTEA NOT NULL,                                        -- X25519 (32 bytes)
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- E2E-encrypted device telemetry (slice 2, CP3): the server stores ciphertext
-- ONLY — sealed to the device-admin group key, never readable here. The envelope
-- (kind / recipient_key_id / seq) is plaintext for routing + ordering.
CREATE TABLE identity.machine_telemetry (
    id               BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    machine_id       UUID NOT NULL REFERENCES identity.machines(id) ON DELETE CASCADE,
    kind             TEXT NOT NULL,                                     -- location|inventory|...
    recipient_key_id BYTEA NOT NULL,                                    -- which device-admin group key
    seq              BIGINT NOT NULL,                                   -- per-machine sequence
    ciphertext       BYTEA NOT NULL,                                    -- sealed to the group public key
    signature        BYTEA NOT NULL,                                    -- machine-signed envelope (may be empty in CP3)
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX machine_telemetry_by_machine ON identity.machine_telemetry (machine_id, kind, seq);

-- A user-scoped device enrollment: the user's keys bound to a device (and OS
-- user). The master key lives in that OS user's keychain; only the public key is
-- stored here. `master_key_wrapped` (to this device's key) is the slice-2
-- propagation copy; in slice 1 the key arrives via bootstrap / re-unwrap.
CREATE TABLE identity.devices (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id            UUID NOT NULL REFERENCES identity.users(id) ON DELETE CASCADE,
    machine_id         UUID NULL REFERENCES identity.machines(id) ON DELETE SET NULL,
    device_label       TEXT NOT NULL,
    platform           TEXT NOT NULL,
    device_public_key  BYTEA NOT NULL,                                  -- X25519 device pubkey
    master_key_wrapped BYTEA NULL,                                      -- wrapped to device_public_key (slice 2)
    push_token_enc     BYTEA NULL,                                      -- sealed; slice 2+
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at       TIMESTAMPTZ NULL,
    revoked_at         TIMESTAMPTZ NULL
);

CREATE INDEX devices_by_user    ON identity.devices (user_id);
CREATE INDEX devices_by_machine ON identity.devices (machine_id);
