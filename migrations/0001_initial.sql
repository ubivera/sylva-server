CREATE SCHEMA IF NOT EXISTS hearth;

CREATE TABLE IF NOT EXISTS hearth._meta (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO hearth._meta (key, value)
VALUES ('schema_bootstrap', '0001_initial')
ON CONFLICT (key) DO NOTHING;
