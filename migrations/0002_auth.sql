CREATE SCHEMA IF NOT EXISTS auth;

CREATE TABLE auth.credentials (
    user_id       UUID PRIMARY KEY REFERENCES identity.users(id) ON DELETE CASCADE,
    password_hash TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE auth.sessions (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES identity.users(id) ON DELETE CASCADE,
    token_hash  BYTEA NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ NOT NULL,
    revoked_at  TIMESTAMPTZ NULL
);

CREATE UNIQUE INDEX sessions_token_hash_uniq ON auth.sessions (token_hash);
CREATE INDEX sessions_user_idx               ON auth.sessions (user_id);
CREATE INDEX sessions_expires_at_idx         ON auth.sessions (expires_at);

CREATE TABLE auth.recovery_codes (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code_hash          BYTEA NOT NULL CHECK (octet_length(code_hash) = 32),
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by_user_id UUID NULL REFERENCES identity.users(id) ON DELETE SET NULL,
    rotated_at         TIMESTAMPTZ NULL,
    rotated_by_user_id UUID NULL REFERENCES identity.users(id) ON DELETE SET NULL
);

CREATE UNIQUE INDEX recovery_codes_one_active
    ON auth.recovery_codes ((TRUE))
    WHERE rotated_at IS NULL;

CREATE TABLE auth.user_recovery_codes (
    user_id      UUID PRIMARY KEY REFERENCES identity.users(id) ON DELETE CASCADE,
    code_hash    BYTEA NOT NULL CHECK (octet_length(code_hash) = 32),
    generated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ NULL
);

-- TOTP (authenticator-app) second factors: many per user, each with a
-- user-chosen label. The secret is AEAD-encrypted (XChaCha20-Poly1305)
-- under the instance secret key, not hashed, because the server must
-- recover it to verify codes. A row with verified_at IS NULL is a
-- half-finished enrollment (not an active factor); 2FA is "on" for a
-- user while at least one verified row exists.
CREATE TABLE auth.totp_credentials (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      UUID NOT NULL REFERENCES identity.users(id) ON DELETE CASCADE,
    label        TEXT NOT NULL,
    secret_enc   BYTEA NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    verified_at  TIMESTAMPTZ NULL,
    last_used_at TIMESTAMPTZ NULL
);

CREATE INDEX totp_credentials_user_idx ON auth.totp_credentials (user_id);

-- WebAuthn passkeys: many per user, each with a user-chosen label. Stores
-- only the PUBLIC credential (serialized webauthn-rs `Passkey`), so no
-- encryption is needed (unlike TOTP secrets).
CREATE TABLE auth.webauthn_credentials (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      UUID NOT NULL REFERENCES identity.users(id) ON DELETE CASCADE,
    label        TEXT NOT NULL,
    credential   JSONB NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ NULL
);

CREATE INDEX webauthn_credentials_user_idx ON auth.webauthn_credentials (user_id);

-- Short-lived WebAuthn ceremony state (registration / authentication),
-- held between the start and finish requests. Rows are consumed on finish
-- and replaced on a new start; `purpose` keeps register vs authenticate
-- separate.
CREATE TABLE auth.webauthn_challenges (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID NOT NULL REFERENCES identity.users(id) ON DELETE CASCADE,
    purpose    TEXT NOT NULL,
    state      JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX webauthn_challenges_user_idx ON auth.webauthn_challenges (user_id);
