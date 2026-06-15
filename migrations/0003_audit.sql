CREATE SCHEMA IF NOT EXISTS audit;

CREATE TABLE audit.events (
    seqno              BIGSERIAL PRIMARY KEY,
    occurred_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Immutable actor snapshot, deliberately NOT a foreign key. The hash
    -- chain (compute_hash) covers this column, so it must never be mutated
    -- after a row is written. A `REFERENCES ... ON DELETE SET NULL` would
    -- null it across all of a user's past rows when that user is physically
    -- deleted (self-service account delete), invalidating every one of those
    -- rows' hashes. Like actor_display_name, it is frozen at write time and
    -- retained as part of the tamper-evident security record even after the
    -- account is gone.
    actor_user_id      UUID NULL,
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
