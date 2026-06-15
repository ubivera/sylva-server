-- Platform module: generic app content storage.
--
-- Apps store their content here as opaque encrypted blobs keyed by
-- (app_id, resource_type, app_resource_id). The server never reads
-- `content_blob` — it only uses the metadata columns for ownership, ordering,
-- and (later) authz. See `design/platform.md` §Generic Resource Storage.
--
-- CP2 is **owner-scoped**: each resource is owned by its creator, and only the
-- creator can read/update/delete it. The resource-permission (ReBAC/sharing)
-- layer + hierarchy/inheritance land later; `parent_resource_id` is stored now
-- but not yet enforced. `app_id` references `platform.registered_apps(id)` (the
-- FK is added after that table is created below — CP3b).
CREATE SCHEMA IF NOT EXISTS platform;

CREATE TABLE platform.resources (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Owning app — FK to platform.registered_apps(id) added below (that table
    -- is created later in this migration). CreateResource also validates the
    -- app is registered + enabled and that resource_type is one it declared.
    app_id             UUID NOT NULL,
    resource_type      TEXT NOT NULL,
    -- The app's own identifier for this resource (client-generated UUID).
    app_resource_id    UUID NOT NULL,
    -- Hierarchy: self-reference + inheritance enforced in a later checkpoint.
    parent_resource_id UUID NULL,

    -- Server-readable metadata.
    owner_user_id      UUID NOT NULL REFERENCES identity.users(id) ON DELETE CASCADE,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at         TIMESTAMPTZ NULL,                 -- tombstone marker

    -- Encrypted content — opaque to the server.
    content_blob       BYTEA NOT NULL,
    content_signature  BYTEA NOT NULL,                   -- Ed25519 sig by last_modified_by
    last_modified_by   UUID NOT NULL,                    -- snapshot (owner-scoped: == owner)
    schema_version     INTEGER NOT NULL,

    -- An app's own id for a (type) is unique within that app.
    UNIQUE (app_id, resource_type, app_resource_id)
);

CREATE INDEX resources_by_owner ON platform.resources (owner_user_id);
CREATE INDEX resources_by_parent ON platform.resources (parent_resource_id);
-- Covers the List query: (app_id, resource_type) newest-first.
CREATE INDEX resources_app_type_listing
    ON platform.resources (app_id, resource_type, updated_at DESC);
CREATE INDEX resources_tombstones
    ON platform.resources (deleted_at) WHERE deleted_at IS NOT NULL;

-- App registration (CP3). Publishers the Owner trusts (their Ed25519 verifying
-- key); apps are signed with a trusted publisher's key so only trusted apps can
-- register. See `design/platform.md` §App Registration.
CREATE TABLE platform.trusted_publishers (
    publisher  TEXT PRIMARY KEY,                                  -- e.g. "Ubivera, LLC"
    public_key BYTEA NOT NULL,                                    -- Ed25519 verifying key (32 bytes)
    added_by   UUID NULL REFERENCES identity.users(id) ON DELETE SET NULL,
    added_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Apps registered on this instance. `id` (the PK) is what `resources.app_id`
-- references (FK below). `resource_types` is the app's declared set; CreateResource
-- validates resource creates against it. Capabilities / event-type schema +
-- enable-disable / uninstall land later.
CREATE TABLE platform.registered_apps (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    app_identifier  TEXT NOT NULL UNIQUE,                         -- "garden.ubivera.tasks"
    display_name    TEXT NOT NULL,
    publisher       TEXT NOT NULL,                                -- a trusted publisher
    app_public_key  BYTEA NOT NULL,                               -- the app's own Ed25519 key
    schema_version  INTEGER NOT NULL,
    resource_types  TEXT[] NOT NULL DEFAULT '{}',
    status          TEXT NOT NULL DEFAULT 'enabled',              -- 'enabled' | 'disabled'
    registered_by   UUID NULL REFERENCES identity.users(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Tie resources to their owning app now that registered_apps exists (CP3b).
-- ON DELETE CASCADE: uninstalling an app reaps its resources. The
-- (app_id, …) listing index above already covers the referencing column.
ALTER TABLE platform.resources
    ADD CONSTRAINT resources_app_id_fkey
    FOREIGN KEY (app_id) REFERENCES platform.registered_apps(id) ON DELETE CASCADE;
