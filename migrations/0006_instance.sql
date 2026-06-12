CREATE SCHEMA IF NOT EXISTS hearth_meta;

-- Singleton row tracking instance lifecycle. It lives in `hearth_meta`
-- (alongside `_sqlx_migrations`) on purpose: when the last user closes their
-- account the app scorches every *data* table (identity / auth / audit /
-- notifications / pending), and this row must SURVIVE that wipe so the
-- closed-page middleware can keep serving "this server has been closed" on
-- every subsequent request. `clean` (DROP DATABASE) is the only thing that
-- clears it — exactly the documented "start over" path.
CREATE TABLE hearth_meta.instance (
    -- Enforces a single row: PRIMARY KEY makes `id` unique and CHECK (id)
    -- forces it TRUE, so a second INSERT (which defaults to TRUE) collides.
    id        BOOLEAN PRIMARY KEY DEFAULT TRUE,
    closed_at TIMESTAMPTZ NULL,
    CONSTRAINT instance_singleton CHECK (id)
);

INSERT INTO hearth_meta.instance (id) VALUES (TRUE);
