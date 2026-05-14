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
