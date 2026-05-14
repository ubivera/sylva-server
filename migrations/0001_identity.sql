CREATE SCHEMA IF NOT EXISTS identity;

CREATE TYPE identity.user_lifecycle AS ENUM (
    'pending_invite',
    'active',
    'soft_deleted',
    'hard_deleted'
);

CREATE TYPE identity.instance_role AS ENUM (
    'owner',
    'admin',
    'user'
);

CREATE TABLE identity.users (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email         TEXT NOT NULL,
    email_lower   TEXT GENERATED ALWAYS AS (lower(email)) STORED,
    display_name  TEXT NOT NULL,
    lifecycle     identity.user_lifecycle NOT NULL DEFAULT 'pending_invite',
    instance_role identity.instance_role NOT NULL DEFAULT 'user',
    locale        TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX users_email_lower_uniq ON identity.users (email_lower);

CREATE TABLE identity.invitations (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email              TEXT NOT NULL,
    email_lower        TEXT GENERATED ALWAYS AS (lower(email)) STORED,
    token_hash         BYTEA NOT NULL,
    invited_by_user_id UUID NOT NULL REFERENCES identity.users(id) ON DELETE CASCADE,
    instance_role      identity.instance_role NOT NULL DEFAULT 'user',
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at         TIMESTAMPTZ NOT NULL,
    accepted_at        TIMESTAMPTZ NULL,
    accepted_user_id   UUID NULL REFERENCES identity.users(id) ON DELETE SET NULL,
    revoked_at         TIMESTAMPTZ NULL
);

CREATE UNIQUE INDEX invitations_token_hash_uniq ON identity.invitations (token_hash);
CREATE INDEX invitations_email_lower_idx        ON identity.invitations (email_lower);
CREATE INDEX invitations_invited_by_idx         ON identity.invitations (invited_by_user_id);
