use chrono::{DateTime, Duration, Utc};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
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
///
/// Semantics:
/// - `PendingInvite` — placeholder for the eventual flow that materializes a
///   user row at invite-create time (today users are only inserted at
///   accept-invite).
/// - `Active` — normal user.
/// - `Deactivated` — recoverable suspension. Sessions revoked, login blocked,
///   credentials preserved. Reactivatable to `Active`.
/// - `SoftDeleted` — terminal. The account is "gone": sessions revoked,
///   credentials deleted, PII redacted in the row. Content the user created
///   that other users have access to remains; orphaned content is dropped
///   when the apps platform lands.
/// - `HardDeleted` — terminal. Full purge: same row-level effect as
///   `SoftDeleted` today, but the future content-cleanup hook drops *all*
///   their content regardless of collaborators.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, sqlx::Type, Serialize, Deserialize,
)]
#[sqlx(type_name = "identity.user_lifecycle", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum UserLifecycle {
    PendingInvite,
    Active,
    Deactivated,
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

    /// Look up a "live" user (Active, Deactivated, or PendingInvite).
    /// Soft-deleted and hard-deleted users are treated as not-found here —
    /// they're invisible to normal application code. Admin lifecycle
    /// handlers that need to operate on already-deleted users use
    /// [`UserRepository::find_any`] instead.
    pub async fn find_by_id(&self, id: UserId) -> Result<Option<User>> {
        let user = sqlx::query_as::<_, User>(
            "SELECT id, email, display_name, lifecycle, instance_role, \
                    locale, created_at, updated_at \
             FROM identity.users \
             WHERE id = $1 \
               AND lifecycle IN ('pending_invite', 'active', 'deactivated')",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(user)
    }

    /// Look up a user by id regardless of lifecycle. Returns soft- and
    /// hard-deleted rows too. Intended for admin lifecycle handlers that
    /// need to inspect the current state before transitioning it; do not
    /// use this for auth/visibility decisions.
    pub async fn find_any(&self, id: UserId) -> Result<Option<User>> {
        let user = sqlx::query_as::<_, User>(
            "SELECT id, email, display_name, lifecycle, instance_role, \
                    locale, created_at, updated_at \
             FROM identity.users \
             WHERE id = $1",
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
             WHERE email_lower = lower($1) \
               AND lifecycle IN ('pending_invite', 'active', 'deactivated')",
        )
        .bind(email)
        .fetch_optional(&self.pool)
        .await?;
        Ok(user)
    }

    /// List manageable users (Active, Deactivated, PendingInvite), oldest
    /// first. Soft- and hard-deleted accounts are hidden — those users are
    /// "gone" from the directory's perspective; audit events that
    /// reference them still display via the snapshot `actor_display_name`.
    pub async fn list_all(&self) -> Result<Vec<User>> {
        let users = sqlx::query_as::<_, User>(
            "SELECT id, email, display_name, lifecycle, instance_role, \
                    locale, created_at, updated_at \
             FROM identity.users \
             WHERE lifecycle IN ('pending_invite', 'active', 'deactivated') \
             ORDER BY created_at",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(users)
    }

    /// Partial profile update within the caller's transaction. Each `Some`
    /// field is written; `None` leaves the existing value alone (treated
    /// as "no change", not "set to NULL"). Returns the post-update row.
    /// `updated_at` is bumped to now.
    pub async fn update_profile(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        id: UserId,
        display_name: Option<&str>,
        locale: Option<&str>,
    ) -> Result<User> {
        let user: User = sqlx::query_as(
            "UPDATE identity.users
             SET display_name = COALESCE($2, display_name),
                 locale       = COALESCE($3, locale),
                 updated_at   = now()
             WHERE id = $1
             RETURNING id, email, display_name, lifecycle, instance_role,
                       locale, created_at, updated_at",
        )
        .bind(id)
        .bind(display_name)
        .bind(locale)
        .fetch_one(&mut **tx)
        .await?;
        Ok(user)
    }

    /// True when at least one manageable user (Active, Deactivated,
    /// PendingInvite) already has `email_lower = lower(email)`. Soft- and
    /// hard-deleted users' redacted emails are not considered "in use" —
    /// the original email is freed for re-invitation.
    pub async fn email_in_use(&self, email: &str) -> Result<bool> {
        let exists: Option<i32> = sqlx::query_scalar(
            "SELECT 1 FROM identity.users \
             WHERE email_lower = lower($1) \
               AND lifecycle IN ('pending_invite', 'active', 'deactivated') \
             LIMIT 1",
        )
        .bind(email)
        .fetch_optional(&self.pool)
        .await?;
        Ok(exists.is_some())
    }

    /// Transition `Active` → `Deactivated`. The caller is responsible for
    /// the authz check and for revoking sessions in the same transaction.
    /// Bumps `updated_at`.
    pub async fn deactivate(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        id: UserId,
    ) -> Result<User> {
        let user: User = sqlx::query_as(
            "UPDATE identity.users
             SET lifecycle = 'deactivated', updated_at = now()
             WHERE id = $1
             RETURNING id, email, display_name, lifecycle, instance_role,
                       locale, created_at, updated_at",
        )
        .bind(id)
        .fetch_one(&mut **tx)
        .await?;
        Ok(user)
    }

    /// Transition `Deactivated` → `Active`. Sessions are not restored
    /// (the user must sign in again); credentials were preserved across
    /// deactivation so the existing password still works.
    pub async fn reactivate(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        id: UserId,
    ) -> Result<User> {
        let user: User = sqlx::query_as(
            "UPDATE identity.users
             SET lifecycle = 'active', updated_at = now()
             WHERE id = $1
             RETURNING id, email, display_name, lifecycle, instance_role,
                       locale, created_at, updated_at",
        )
        .bind(id)
        .fetch_one(&mut **tx)
        .await?;
        Ok(user)
    }

    /// Transition to `SoftDeleted`: terminal "account removed" state.
    /// Redacts PII in the row so the user is no longer identifiable from
    /// `identity.users`. Returns the original email (pre-redaction) so the
    /// audit caller can record what was wiped. The caller is responsible
    /// for revoking sessions, deleting credentials, and running future
    /// content-cleanup hooks (collaborator-aware) in the same transaction.
    pub async fn soft_delete(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        id: UserId,
    ) -> Result<(User, String)> {
        redact_and_terminate(tx, id, UserLifecycle::SoftDeleted).await
    }

    /// Transition to `HardDeleted`: terminal "full purge" state. Same
    /// row-level effect as `soft_delete` today; once apps exist, the
    /// content-cleanup hook drops *all* their data regardless of
    /// collaborators. Returns the original email.
    pub async fn hard_delete(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        id: UserId,
    ) -> Result<(User, String)> {
        redact_and_terminate(tx, id, UserLifecycle::HardDeleted).await
    }
}

/// Shared implementation for the two terminal transitions. Redacts PII
/// (email + display_name + locale) in place and sets the requested
/// terminal lifecycle. Returns the row in its post-update form alongside
/// the *original* email so the caller can record it in the audit event.
async fn redact_and_terminate(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    id: UserId,
    new_lifecycle: UserLifecycle,
) -> Result<(User, String)> {
    let original_email: String =
        sqlx::query_scalar("SELECT email FROM identity.users WHERE id = $1 FOR UPDATE")
            .bind(id)
            .fetch_one(&mut **tx)
            .await?;

    let updated: User = sqlx::query_as(
        "UPDATE identity.users
         SET email = 'deleted+' || id || '@purged.invalid',
             display_name = '[deleted user]',
             locale = NULL,
             lifecycle = $2,
             updated_at = now()
         WHERE id = $1
         RETURNING id, email, display_name, lifecycle, instance_role,
                   locale, created_at, updated_at",
    )
    .bind(id)
    .bind(new_lifecycle)
    .fetch_one(&mut **tx)
    .await?;

    Ok((updated, original_email))
}

/// Strongly-typed invitation identifier.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, sqlx::Type, Serialize, Deserialize,
)]
#[sqlx(transparent)]
pub struct InvitationId(pub Uuid);

impl InvitationId {
    pub fn new(uuid: Uuid) -> Self {
        Self(uuid)
    }
    pub fn into_inner(self) -> Uuid {
        self.0
    }
}

#[derive(Debug, Clone, sqlx::FromRow, Serialize)]
pub struct Invitation {
    pub id: InvitationId,
    pub email: String,
    pub invited_by_user_id: UserId,
    pub instance_role: InstanceRole,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub accepted_at: Option<DateTime<Utc>>,
    pub accepted_user_id: Option<UserId>,
    pub revoked_at: Option<DateTime<Utc>>,
}

/// Default time an invitation stays valid. Design spec calls for 7 days
/// (configurable); we hardcode for now.
pub const DEFAULT_INVITATION_TTL: Duration = Duration::days(7);

/// Generate a 32-byte random invitation token (64-char hex). Mirrors the
/// session-token approach in the auth crate; sha256(token) is what's
/// stored server-side.
pub fn generate_invite_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// SHA-256 of an invitation token - what goes into `token_hash`.
pub fn hash_invite_token(token: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hasher.finalize().into()
}

#[derive(Clone)]
pub struct InvitationRepository {
    pool: PgPool,
}

impl InvitationRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Create a new invitation within the caller's transaction. Returns
    /// `(invitation_row, raw_token)`. The raw token is what to embed in
    /// the acceptance URL; only its SHA-256 hash goes into the DB.
    pub async fn create(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        invited_by: UserId,
        email: &str,
        instance_role: InstanceRole,
        ttl: Duration,
    ) -> Result<(Invitation, String)> {
        let token = generate_invite_token();
        let token_hash = hash_invite_token(&token);
        let expires_at = Utc::now() + ttl;

        let invitation: Invitation = sqlx::query_as(
            "INSERT INTO identity.invitations
                 (email, token_hash, invited_by_user_id, instance_role, expires_at)
             VALUES ($1, $2, $3, $4, $5)
             RETURNING id, email, invited_by_user_id, instance_role,
                       created_at, expires_at, accepted_at, accepted_user_id, revoked_at",
        )
        .bind(email)
        .bind(&token_hash[..])
        .bind(invited_by)
        .bind(instance_role)
        .bind(expires_at)
        .fetch_one(&mut **tx)
        .await?;

        Ok((invitation, token))
    }

    /// Look up an invitation by raw token. Returns `Ok(None)` if no
    /// matching invitation exists, the invitation is revoked, expired,
    /// or already accepted.
    pub async fn find_active(&self, token: &str) -> Result<Option<Invitation>> {
        let token_hash = hash_invite_token(token);
        let invitation: Option<Invitation> = sqlx::query_as(
            "SELECT id, email, invited_by_user_id, instance_role,
                    created_at, expires_at, accepted_at, accepted_user_id, revoked_at
             FROM identity.invitations
             WHERE token_hash = $1
               AND accepted_at IS NULL
               AND revoked_at IS NULL
               AND expires_at > now()",
        )
        .bind(&token_hash[..])
        .fetch_optional(&self.pool)
        .await?;
        Ok(invitation)
    }

    /// True when an active invitation (non-accepted, non-revoked,
    /// non-expired) exists for the given email (case-insensitive).
    pub async fn email_has_active_invite(&self, email: &str) -> Result<bool> {
        let exists: Option<i32> = sqlx::query_scalar(
            "SELECT 1 FROM identity.invitations
             WHERE email_lower = lower($1)
               AND accepted_at IS NULL
               AND revoked_at IS NULL
               AND expires_at > now()
             LIMIT 1",
        )
        .bind(email)
        .fetch_optional(&self.pool)
        .await?;
        Ok(exists.is_some())
    }

    /// Mark an invitation accepted within the caller's transaction. Sets
    /// `accepted_at` to now and links to the newly-created user.
    pub async fn mark_accepted(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        invitation_id: InvitationId,
        accepted_user: UserId,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE identity.invitations
             SET accepted_at = now(), accepted_user_id = $2
             WHERE id = $1",
        )
        .bind(invitation_id)
        .bind(accepted_user)
        .execute(&mut **tx)
        .await?;
        Ok(())
    }

    /// Count pending invitations (non-accepted, non-revoked, non-expired).
    /// Used by `/health`.
    pub async fn count_pending(&self) -> Result<i64> {
        let (count,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM identity.invitations
             WHERE accepted_at IS NULL
               AND revoked_at IS NULL
               AND expires_at > now()",
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(count)
    }

    /// List pending invitations (non-accepted, non-revoked, non-expired),
    /// newest first. Intended for `GET /admin/invites`.
    pub async fn list_pending(&self) -> Result<Vec<Invitation>> {
        let invitations: Vec<Invitation> = sqlx::query_as(
            "SELECT id, email, invited_by_user_id, instance_role,
                    created_at, expires_at, accepted_at, accepted_user_id, revoked_at
             FROM identity.invitations
             WHERE accepted_at IS NULL
               AND revoked_at IS NULL
               AND expires_at > now()
             ORDER BY created_at DESC",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(invitations)
    }

    /// Look up an invitation by id (regardless of status). Returns the
    /// row in any state so callers can produce specific error messages.
    pub async fn find_by_id(&self, id: InvitationId) -> Result<Option<Invitation>> {
        let invitation: Option<Invitation> = sqlx::query_as(
            "SELECT id, email, invited_by_user_id, instance_role,
                    created_at, expires_at, accepted_at, accepted_user_id, revoked_at
             FROM identity.invitations
             WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(invitation)
    }

    /// Mark an invitation revoked within the caller's transaction.
    /// Idempotent — already-revoked invitations stay revoked.
    pub async fn revoke(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        invitation_id: InvitationId,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE identity.invitations
             SET revoked_at = COALESCE(revoked_at, now())
             WHERE id = $1",
        )
        .bind(invitation_id)
        .execute(&mut **tx)
        .await?;
        Ok(())
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
