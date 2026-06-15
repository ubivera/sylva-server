//! Storage layer for generic app resources (`platform.resources`).
//!
//! CP2 is **owner-scoped**: every query is keyed on `owner_user_id`, so a
//! resource owned by someone else simply isn't found. The server stores
//! `content_blob` opaquely — it never decrypts. The resource-permission
//! (sharing/ReBAC) layer is a later checkpoint.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

/// Column list shared by every `SELECT`/`RETURNING` so the row mapping stays
/// in one place.
const COLS: &str = "id, app_id, resource_type, app_resource_id, parent_resource_id, \
     owner_user_id, created_at, updated_at, deleted_at, content_blob, \
     content_signature, last_modified_by, schema_version";

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ResourceRow {
    pub id: Uuid,
    pub app_id: Uuid,
    pub resource_type: String,
    pub app_resource_id: Uuid,
    pub parent_resource_id: Option<Uuid>,
    pub owner_user_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
    pub content_blob: Vec<u8>,
    pub content_signature: Vec<u8>,
    pub last_modified_by: Uuid,
    pub schema_version: i32,
}

/// Fields for creating a resource. `owner_user_id` is the authenticated caller;
/// `last_modified_by` is set equal to it on create (owner-scoped).
pub struct NewResource {
    pub app_id: Uuid,
    pub resource_type: String,
    pub app_resource_id: Uuid,
    pub parent_resource_id: Option<Uuid>,
    pub owner_user_id: Uuid,
    pub content_blob: Vec<u8>,
    pub content_signature: Vec<u8>,
    pub schema_version: i32,
}

#[derive(Clone)]
pub struct ResourceRepository {
    pool: PgPool,
}

impl ResourceRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Insert a new resource. A duplicate `(app_id, resource_type,
    /// app_resource_id)` surfaces as a `23505` unique-violation the caller maps
    /// to `AlreadyExists`.
    pub async fn create(&self, new: &NewResource) -> Result<ResourceRow, sqlx::Error> {
        let sql = format!(
            "INSERT INTO platform.resources
                 (app_id, resource_type, app_resource_id, parent_resource_id,
                  owner_user_id, content_blob, content_signature, last_modified_by,
                  schema_version)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $5, $8)
             RETURNING {COLS}"
        );
        sqlx::query_as::<_, ResourceRow>(&sql)
            .bind(new.app_id)
            .bind(&new.resource_type)
            .bind(new.app_resource_id)
            .bind(new.parent_resource_id)
            .bind(new.owner_user_id)
            .bind(&new.content_blob)
            .bind(&new.content_signature)
            .bind(new.schema_version)
            .fetch_one(&self.pool)
            .await
    }

    /// Owner-scoped read of an active (non-deleted) resource.
    pub async fn get_owned(
        &self,
        id: Uuid,
        owner: Uuid,
    ) -> Result<Option<ResourceRow>, sqlx::Error> {
        let sql = format!(
            "SELECT {COLS} FROM platform.resources
             WHERE id = $1 AND owner_user_id = $2 AND deleted_at IS NULL"
        );
        sqlx::query_as::<_, ResourceRow>(&sql)
            .bind(id)
            .bind(owner)
            .fetch_optional(&self.pool)
            .await
    }

    /// Owner-scoped full-blob replacement. Returns `None` if the row doesn't
    /// exist, isn't owned by `owner`, or is already deleted.
    pub async fn update_owned(
        &self,
        id: Uuid,
        owner: Uuid,
        content_blob: &[u8],
        content_signature: &[u8],
        schema_version: i32,
        parent_resource_id: Option<Uuid>,
    ) -> Result<Option<ResourceRow>, sqlx::Error> {
        let sql = format!(
            "UPDATE platform.resources
             SET content_blob = $3, content_signature = $4, schema_version = $5,
                 parent_resource_id = $6, last_modified_by = $2, updated_at = now()
             WHERE id = $1 AND owner_user_id = $2 AND deleted_at IS NULL
             RETURNING {COLS}"
        );
        sqlx::query_as::<_, ResourceRow>(&sql)
            .bind(id)
            .bind(owner)
            .bind(content_blob)
            .bind(content_signature)
            .bind(schema_version)
            .bind(parent_resource_id)
            .fetch_optional(&self.pool)
            .await
    }

    /// Owner-scoped soft delete (sets `deleted_at`). Returns whether a row was
    /// affected (false = not found / not owned / already deleted).
    pub async fn soft_delete_owned(&self, id: Uuid, owner: Uuid) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            "UPDATE platform.resources SET deleted_at = now(), updated_at = now()
             WHERE id = $1 AND owner_user_id = $2 AND deleted_at IS NULL",
        )
        .bind(id)
        .bind(owner)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Owner-scoped list by `(app_id, resource_type)`, newest first. Returns the
    /// page plus the total matching count (ignoring limit/offset).
    pub async fn list_owned(
        &self,
        app_id: Uuid,
        resource_type: &str,
        owner: Uuid,
        limit: i64,
        offset: i64,
        include_deleted: bool,
    ) -> Result<(Vec<ResourceRow>, i64), sqlx::Error> {
        let list_sql = format!(
            "SELECT {COLS} FROM platform.resources
             WHERE app_id = $1 AND resource_type = $2 AND owner_user_id = $3
               AND ($6 OR deleted_at IS NULL)
             ORDER BY updated_at DESC
             LIMIT $4 OFFSET $5"
        );
        let rows: Vec<ResourceRow> = sqlx::query_as::<_, ResourceRow>(&list_sql)
            .bind(app_id)
            .bind(resource_type)
            .bind(owner)
            .bind(limit)
            .bind(offset)
            .bind(include_deleted)
            .fetch_all(&self.pool)
            .await?;

        let (total,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM platform.resources
             WHERE app_id = $1 AND resource_type = $2 AND owner_user_id = $3
               AND ($4 OR deleted_at IS NULL)",
        )
        .bind(app_id)
        .bind(resource_type)
        .bind(owner)
        .bind(include_deleted)
        .fetch_one(&self.pool)
        .await?;

        Ok((rows, total))
    }
}
