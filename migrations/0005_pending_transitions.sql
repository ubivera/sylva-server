CREATE SCHEMA IF NOT EXISTS pending;

CREATE TYPE pending.transition_kind AS ENUM (
    'role_change',
    'deactivate',
    'soft_delete',
    'hard_delete'
);

CREATE TYPE pending.transition_state AS ENUM (
    'pending',
    'applied',
    'vetoed',
    'cancelled'
);

CREATE TABLE pending.transitions (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    kind                pending.transition_kind NOT NULL,
    initiator_user_id   UUID NOT NULL REFERENCES identity.users(id) ON DELETE SET NULL,
    target_user_id      UUID NOT NULL REFERENCES identity.users(id) ON DELETE SET NULL,
    payload             JSONB NOT NULL,
    state               pending.transition_state NOT NULL DEFAULT 'pending',
    effective_at        TIMESTAMPTZ NOT NULL,
    resolved_at         TIMESTAMPTZ NULL,
    resolved_by_user_id UUID NULL REFERENCES identity.users(id) ON DELETE SET NULL,
    resolution          TEXT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX transitions_due_idx
    ON pending.transitions (effective_at)
    WHERE state = 'pending';

CREATE UNIQUE INDEX transitions_one_pending_per_target
    ON pending.transitions (target_user_id)
    WHERE state = 'pending';

CREATE INDEX transitions_initiator_idx ON pending.transitions (initiator_user_id);
CREATE INDEX transitions_state_idx     ON pending.transitions (state);
