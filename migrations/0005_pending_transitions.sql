CREATE SCHEMA IF NOT EXISTS pending;

CREATE TYPE pending.transition_kind AS ENUM (
    'role_change'
    -- Future kinds (deactivate, soft_delete, hard_delete) added in checkpoint 15b.
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
    -- Kind-specific payload, e.g. {"to_role": "admin"} for role_change.
    payload             JSONB NOT NULL,
    state               pending.transition_state NOT NULL DEFAULT 'pending',
    effective_at        TIMESTAMPTZ NOT NULL,
    resolved_at         TIMESTAMPTZ NULL,
    resolved_by_user_id UUID NULL REFERENCES identity.users(id) ON DELETE SET NULL,
    -- "timer" | "recovery_bypass" | "vetoed" | "cancelled"
    resolution          TEXT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Worker's "what's due" query backed by a partial index.
CREATE INDEX transitions_due_idx
    ON pending.transitions (effective_at)
    WHERE state = 'pending';

-- At most one in-flight action per target. Enforced at the DB level so the
-- handler can't accidentally race two pending rows into existence.
CREATE UNIQUE INDEX transitions_one_pending_per_target
    ON pending.transitions (target_user_id)
    WHERE state = 'pending';

CREATE INDEX transitions_initiator_idx ON pending.transitions (initiator_user_id);
CREATE INDEX transitions_state_idx     ON pending.transitions (state);
