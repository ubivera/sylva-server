CREATE SCHEMA IF NOT EXISTS audit;

CREATE TABLE audit.events (
    seqno              BIGSERIAL PRIMARY KEY,
    occurred_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor_user_id      UUID NULL REFERENCES identity.users(id) ON DELETE SET NULL,
    actor_display_name TEXT NULL,
    app_id             TEXT NULL,
    event_type         TEXT NOT NULL,
    event_data         JSONB NOT NULL DEFAULT '{}'::jsonb,
    prev_hash          BYTEA NOT NULL,
    hash               BYTEA NOT NULL,
    redacted_at        TIMESTAMPTZ NULL,
    redaction_event_id BIGINT NULL REFERENCES audit.events(seqno) ON DELETE SET NULL
);

CREATE INDEX events_actor_idx       ON audit.events (actor_user_id);
CREATE INDEX events_type_idx        ON audit.events (event_type);
CREATE INDEX events_occurred_at_idx ON audit.events (occurred_at);
