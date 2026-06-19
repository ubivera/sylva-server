CREATE SCHEMA IF NOT EXISTS sylva_meta;

-- Singleton row tracking instance lifecycle. It lives in `sylva_meta`
-- (alongside `_sqlx_migrations`) on purpose: when the last user closes their
-- account the app scorches every *data* table (identity / auth / audit /
-- notifications / pending), and this row must SURVIVE that wipe so the
-- closed-page middleware can keep serving "this server has been closed" on
-- every subsequent request. `clean` (DROP DATABASE) is the only thing that
-- clears it — exactly the documented "start over" path.
CREATE TABLE sylva_meta.instance (
    -- Enforces a single row: PRIMARY KEY makes `id` unique and CHECK (id)
    -- forces it TRUE, so a second INSERT (which defaults to TRUE) collides.
    id        BOOLEAN PRIMARY KEY DEFAULT TRUE,
    closed_at TIMESTAMPTZ NULL,
    -- Owner-editable configuration overrides. NULL means "fall back to the
    -- env/startup default" (see `server::instance::effective`); a set value
    -- wins at runtime. `smtp_password_enc` is sealed with the instance
    -- `secret_key` (XChaCha20-Poly1305), never stored in the clear.
    instance_name      TEXT NULL,
    notifications_mode  TEXT NULL,
    smtp_host           TEXT NULL,
    smtp_port           INT  NULL,
    smtp_tls            TEXT NULL,
    smtp_username       TEXT NULL,
    smtp_password_enc   BYTEA NULL,
    smtp_from_email     TEXT NULL,
    smtp_from_name      TEXT NULL,
    -- Server identity keypair (Ed25519) — the native-client trust anchor that
    -- Sylva Hub TOFU-pins (see docs/design/hub.md). Generated at first-run
    -- (Phase 2); the private key is sealed with the instance `secret_key`
    -- (XChaCha20-Poly1305), like `smtp_password_enc`. NULL until generated. It
    -- lives on this scorch-surviving singleton so the server keeps its identity
    -- across a close/reopen.
    server_identity_public   BYTEA NULL,
    server_identity_priv_enc BYTEA NULL,
    CONSTRAINT instance_singleton CHECK (id)
);

INSERT INTO sylva_meta.instance (id) VALUES (TRUE);
