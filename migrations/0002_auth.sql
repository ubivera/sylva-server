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
