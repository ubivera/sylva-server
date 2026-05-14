use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("database error")]
    Database(#[from] sqlx::Error),
}

pub type Result<T> = std::result::Result<T, IdentityError>;

/// Strongly-typed user identifier. Distinct nominal type prevents accidental
/// mixing with the other UUID-keyed entities the design introduces later
/// (DeviceId, ResourceId, GroupId).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, sqlx::Type, Serialize, Deserialize,
)]
#[sqlx(transparent)]
pub struct UserId(pub Uuid);

impl UserId {
    pub fn new(uuid: Uuid) -> Self {
        Self(uuid)
    }

    pub fn into_inner(self) -> Uuid {
        self.0
    }
}

impl std::fmt::Display for UserId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// Lifecycle state of a user record. Mirrors `identity.user_lifecycle` in SQL.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, sqlx::Type, Serialize, Deserialize,
)]
#[sqlx(type_name = "identity.user_lifecycle", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum UserLifecycle {
    PendingInvite,
    Active,
    SoftDeleted,
    HardDeleted,
}

/// Server-level role. Mirrors `identity.instance_role` in SQL. Owner/Admin
/// semantics are spelled out in `docs/design/authz.md`.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, sqlx::Type, Serialize, Deserialize,
)]
#[sqlx(type_name = "identity.instance_role", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum InstanceRole {
    Owner,
    Admin,
    User,
}

#[derive(Debug, Clone, sqlx::FromRow, Serialize)]
pub struct User {
    pub id: UserId,
    pub email: String,
    pub display_name: String,
    pub lifecycle: UserLifecycle,
    pub instance_role: InstanceRole,
    pub locale: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Read-only accessor over `identity.users`. Insert/update methods arrive
/// with the registration flow.
#[derive(Clone)]
pub struct UserRepository {
    pool: PgPool,
}

impl UserRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn count(&self) -> Result<i64> {
        let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM identity.users")
            .fetch_one(&self.pool)
            .await?;
        Ok(count)
    }

    pub async fn find_by_id(&self, id: UserId) -> Result<Option<User>> {
        let user = sqlx::query_as::<_, User>(
            "SELECT id, email, display_name, lifecycle, instance_role, \
                    locale, created_at, updated_at \
             FROM identity.users \
             WHERE id = $1 AND lifecycle <> 'hard_deleted'",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(user)
    }

    pub async fn find_by_email(&self, email: &str) -> Result<Option<User>> {
        let user = sqlx::query_as::<_, User>(
            "SELECT id, email, display_name, lifecycle, instance_role, \
                    locale, created_at, updated_at \
             FROM identity.users \
             WHERE email_lower = lower($1) AND lifecycle <> 'hard_deleted'",
        )
        .bind(email)
        .fetch_optional(&self.pool)
        .await?;
        Ok(user)
    }

    /// List all non-purged users, oldest first. Intended for admin
    /// surfaces (e.g., `GET /admin/users`). Excludes `hard_deleted`
    /// rows because those have been redacted.
    pub async fn list_all(&self) -> Result<Vec<User>> {
        let users = sqlx::query_as::<_, User>(
            "SELECT id, email, display_name, lifecycle, instance_role, \
                    locale, created_at, updated_at \
             FROM identity.users \
             WHERE lifecycle <> 'hard_deleted' \
             ORDER BY created_at",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(users)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn user_lifecycle_serializes_snake_case() {
        let json = serde_json::to_string(&UserLifecycle::PendingInvite).unwrap();
        assert_eq!(json, "\"pending_invite\"");

        let json = serde_json::to_string(&UserLifecycle::SoftDeleted).unwrap();
        assert_eq!(json, "\"soft_deleted\"");
    }

    #[test]
    fn user_lifecycle_round_trips_via_json() {
        for value in [
            UserLifecycle::PendingInvite,
            UserLifecycle::Active,
            UserLifecycle::SoftDeleted,
            UserLifecycle::HardDeleted,
        ] {
            let json = serde_json::to_string(&value).unwrap();
            let back: UserLifecycle = serde_json::from_str(&json).unwrap();
            assert_eq!(back, value);
        }
    }

    #[test]
    fn instance_role_serializes_snake_case() {
        assert_eq!(serde_json::to_string(&InstanceRole::Owner).unwrap(), "\"owner\"");
        assert_eq!(serde_json::to_string(&InstanceRole::Admin).unwrap(), "\"admin\"");
        assert_eq!(serde_json::to_string(&InstanceRole::User).unwrap(), "\"user\"");
    }

    #[test]
    fn user_id_round_trips_via_json() {
        let id = UserId::new(Uuid::parse_str("11111111-2222-3333-4444-555555555555").unwrap());
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, "\"11111111-2222-3333-4444-555555555555\"");
        let back: UserId = serde_json::from_str(&json).unwrap();
        assert_eq!(back, id);
    }

    #[test]
    fn user_id_displays_as_plain_uuid() {
        let raw = Uuid::parse_str("11111111-2222-3333-4444-555555555555").unwrap();
        let id = UserId::new(raw);
        assert_eq!(id.to_string(), raw.to_string());
        assert_eq!(id.into_inner(), raw);
    }
}
