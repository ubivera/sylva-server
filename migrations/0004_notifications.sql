CREATE SCHEMA IF NOT EXISTS notifications;

CREATE TYPE notifications.outbox_kind AS ENUM (
    'invitation',
    'pending_role_change_initiated',
    'pending_role_change_vetoed',
    'pending_role_change_applied',
    'pending_lifecycle_initiated',
    'pending_lifecycle_vetoed',
    'pending_lifecycle_applied'
);

CREATE TYPE notifications.outbox_state AS ENUM (
    'pending',
    'sending',
    'sent',
    'failed',
    'dead',
    'skipped'
);

CREATE TABLE notifications.outbox (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    kind             notifications.outbox_kind NOT NULL,
    recipient_email  TEXT NOT NULL,
    subject          TEXT NOT NULL,
    body_text        TEXT NOT NULL,
    body_html        TEXT NOT NULL,
    payload          JSONB NOT NULL DEFAULT '{}'::jsonb,

    state            notifications.outbox_state NOT NULL DEFAULT 'pending',
    attempts         INTEGER NOT NULL DEFAULT 0,
    last_error       TEXT NULL,
    next_attempt_at  TIMESTAMPTZ NOT NULL DEFAULT now(),

    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    sent_at          TIMESTAMPTZ NULL
);

CREATE INDEX outbox_pending_idx
    ON notifications.outbox (next_attempt_at)
    WHERE state = 'pending';

CREATE INDEX outbox_state_idx     ON notifications.outbox (state);
CREATE INDEX outbox_created_at_idx ON notifications.outbox (created_at);
