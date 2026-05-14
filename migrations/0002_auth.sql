CREATE SCHEMA IF NOT EXISTS auth;

CREATE TABLE auth.credentials (
    user_id       UUID PRIMARY KEY REFERENCES identity.users(id) ON DELETE CASCADE,
    password_hash TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
