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

pub mod enrollment;
pub use enrollment::{
    Device, DeviceId, DeviceRepository, Machine, MachineId, MachineRepository, MachineSession,
    MachineSessionRepository, NewDevice, UserAvatarRepository, UserKeyMaterial, UserKeyRepository,
};

pub mod machine_telemetry;
pub use machine_telemetry::{
    DeviceAdminGroup, DeviceAdminGroupRepository, MachineTelemetryRepository, NewTelemetry,
};

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
/// - `Anonymized` — terminal. The account is closed: sessions revoked,
///   credentials deleted, PII redacted in the row. The tombstone row stays so
///   anything attributed to it survives under `[deleted user]`.
///
/// There is deliberately **no** state for a full *Delete* — that physically
/// removes the row (see `UserRepository::hard_remove`), so a deleted account
/// simply no longer exists rather than being marked.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, sqlx::Type, Serialize, Deserialize,
)]
#[sqlx(type_name = "identity.user_lifecycle", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum UserLifecycle {
    PendingInvite,
    Active,
    Deactivated,
    Anonymized,
}

/// Server-level role. Mirrors `identity.instance_role` in SQL. Owner/Admin
/// semantics are spelled out in `docs/design/authz.md`. `Member` is the
/// base role — the rebrand from the older `User` label reflects server's
/// community-oriented framing (see `server-web.md`).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, sqlx::Type, Serialize, Deserialize,
)]
#[sqlx(type_name = "identity.instance_role", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum InstanceRole {
    Owner,
    Admin,
    Member,
}

/// Distinguishes account-holding people (`Member`) from no-login
/// share-link holders (`Guest`). Mirrors `identity.user_kind` in SQL.
/// The Members directory at `/members` filters to `Kind::Member`; the
/// Guests surface is reserved for the apps-platform checkpoint where
/// resource-scoped share links materialize.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, sqlx::Type, Serialize, Deserialize, Default,
)]
#[sqlx(type_name = "identity.user_kind", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum UserKind {
    #[default]
    Member,
    Guest,
}

#[derive(Debug, Clone, sqlx::FromRow, Serialize)]
pub struct User {
    pub id: UserId,
    pub email: String,
    pub display_name: String,
    pub lifecycle: UserLifecycle,
    pub instance_role: InstanceRole,
    pub kind: UserKind,
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

    /// Insert a new user row within the caller's transaction — the
    /// registration / bootstrap flow (`Account.Bootstrap`, and later native
    /// invite acceptance). Credentials (`auth`) and key material
    /// (`identity.user_keys`) are written separately in the same transaction.
    pub async fn create(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        email: &str,
        display_name: &str,
        instance_role: InstanceRole,
        lifecycle: UserLifecycle,
    ) -> Result<User> {
        let user: User = sqlx::query_as(
            "INSERT INTO identity.users (email, display_name, instance_role, lifecycle)
             VALUES ($1, $2, $3, $4)
             RETURNING id, email, display_name, lifecycle, instance_role, kind,
                       locale, created_at, updated_at",
        )
        .bind(email)
        .bind(display_name)
        .bind(instance_role)
        .bind(lifecycle)
        .fetch_one(&mut **tx)
        .await?;
        Ok(user)
    }

    pub async fn count(&self) -> Result<i64> {
        let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM identity.users")
            .fetch_one(&self.pool)
            .await?;
        Ok(count)
    }

    /// Number of active human Owners. Drives the "last owner can't close while
    /// others remain" guard and the empty-instance detection.
    pub async fn count_active_owners(&self) -> Result<i64> {
        let (count,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM identity.users \
             WHERE instance_role = 'owner' AND lifecycle = 'active' AND kind = 'member'",
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(count)
    }

    /// Number of active human users (any role). `0` means the instance has been
    /// emptied — nobody can ever sign in again.
    pub async fn count_active_users(&self) -> Result<i64> {
        let (count,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM identity.users \
             WHERE lifecycle = 'active' AND kind = 'member'",
        )
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
            "SELECT id, email, display_name, lifecycle, instance_role, kind, \
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
            "SELECT id, email, display_name, lifecycle, instance_role, kind, \
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
            "SELECT id, email, display_name, lifecycle, instance_role, kind, \
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

    /// List manageable Members (Active, Deactivated, PendingInvite),
    /// oldest first. Filters to `kind = 'member'` so the Members
    /// directory at `/members` doesn't accidentally surface Guests when
    /// the apps-platform checkpoint introduces them. Soft- and
    /// hard-deleted accounts are hidden — those users are "gone" from
    /// the directory's perspective; audit events that reference them
    /// still display via the snapshot `actor_display_name`.
    pub async fn list_all(&self) -> Result<Vec<User>> {
        let users = sqlx::query_as::<_, User>(
            "SELECT id, email, display_name, lifecycle, instance_role, kind, \
                    locale, created_at, updated_at \
             FROM identity.users \
             WHERE lifecycle IN ('pending_invite', 'active', 'deactivated') \
               AND kind = 'member' \
             ORDER BY created_at",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(users)
    }

    /// Active Owner users, excluding any ids in `exclude_ids`. Used
    /// by the pending-transition fan-out to find the reviewer cohort
    /// (every Owner except the initiator + target) for an
    /// Owner-on-Owner pending action.
    ///
    /// Filters out `Deactivated` and `Anonymized` —
    /// those Owners can't sign in to veto, so emailing them would
    /// just bounce. Also filters `kind = 'member'` so future Guest-
    /// kind Owners (if that ever exists) don't accidentally surface.
    pub async fn list_active_owners_excluding(
        &self,
        exclude_ids: &[UserId],
    ) -> Result<Vec<User>> {
        let users = sqlx::query_as::<_, User>(
            "SELECT id, email, display_name, lifecycle, instance_role, kind, \
                    locale, created_at, updated_at \
             FROM identity.users \
             WHERE instance_role = 'owner' \
               AND lifecycle = 'active' \
               AND kind = 'member' \
               AND NOT (id = ANY($1)) \
             ORDER BY created_at",
        )
        .bind(exclude_ids)
        .fetch_all(&self.pool)
        .await?;
        Ok(users)
    }

    /// Bulk fetch users by id, regardless of lifecycle (mirrors
    /// `find_any` semantics for each id). Returns rows in unspecified
    /// order — the caller is expected to re-index by id. Ids that
    /// don't match any row are silently dropped.
    ///
    /// Used by the `/pending` admin page to hydrate the target +
    /// initiator details for each pending transition in a single
    /// round-trip rather than N+1 lookups. We need `find_any` (not
    /// `find_by_id`) because pending transitions can outlive their
    /// targets if a `delete` has already been applied while the action
    /// was in flight.
    pub async fn list_by_ids(&self, ids: &[UserId]) -> Result<Vec<User>> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let users = sqlx::query_as::<_, User>(
            "SELECT id, email, display_name, lifecycle, instance_role, kind, \
                    locale, created_at, updated_at \
             FROM identity.users \
             WHERE id = ANY($1)",
        )
        .bind(ids)
        .fetch_all(&self.pool)
        .await?;
        Ok(users)
    }

    /// Members in a specific lifecycle state, oldest first. Used by the
    /// Members page's "Anonymized" filter, which surfaces `Anonymized` rows
    /// that [`list_all`] intentionally hides. Always filters to
    /// `kind = 'member'`. (Deleted accounts have no row at all, so there is
    /// no terminal state left to surface here besides `Anonymized`.)
    pub async fn list_with_lifecycle(
        &self,
        lifecycle: UserLifecycle,
    ) -> Result<Vec<User>> {
        let users = sqlx::query_as::<_, User>(
            "SELECT id, email, display_name, lifecycle, instance_role, kind, \
                    locale, created_at, updated_at \
             FROM identity.users \
             WHERE lifecycle = $1 \
               AND kind = 'member' \
             ORDER BY created_at",
        )
        .bind(lifecycle)
        .fetch_all(&self.pool)
        .await?;
        Ok(users)
    }

    /// Set a user's `instance_role` within the caller's transaction.
    /// Bumps `updated_at`. The caller is responsible for the authz check
    /// (only Owner can change roles) and for refusing same-role no-ops
    /// before reaching here.
    pub async fn set_instance_role(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        id: UserId,
        new_role: InstanceRole,
    ) -> Result<User> {
        let user: User = sqlx::query_as(
            "UPDATE identity.users
             SET instance_role = $2, updated_at = now()
             WHERE id = $1
             RETURNING id, email, display_name, lifecycle, instance_role, kind,
                       locale, created_at, updated_at",
        )
        .bind(id)
        .bind(new_role)
        .fetch_one(&mut **tx)
        .await?;
        Ok(user)
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
             RETURNING id, email, display_name, lifecycle, instance_role, kind,
                       locale, created_at, updated_at",
        )
        .bind(id)
        .bind(display_name)
        .bind(locale)
        .fetch_one(&mut **tx)
        .await?;
        Ok(user)
    }

    /// Update a user's email address within the caller's transaction.
    /// Bumps `updated_at`; the generated `email_lower` column re-derives
    /// from the new value automatically. Email uniqueness against other
    /// manageable accounts is enforced by the existing `email_lower`
    /// unique index — the caller surfaces a 23505 (`UniqueViolation`)
    /// SQLSTATE as a "that address is already in use" rejection to the
    /// operator.
    ///
    /// The caller is responsible for the password re-auth check and
    /// for emitting the appropriate audit event (`email_changed`).
    pub async fn update_email(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        id: UserId,
        new_email: &str,
    ) -> Result<User> {
        let user: User = sqlx::query_as(
            "UPDATE identity.users
             SET email = $2, updated_at = now()
             WHERE id = $1
             RETURNING id, email, display_name, lifecycle, instance_role, kind,
                       locale, created_at, updated_at",
        )
        .bind(id)
        .bind(new_email)
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
             RETURNING id, email, display_name, lifecycle, instance_role, kind,
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
             RETURNING id, email, display_name, lifecycle, instance_role, kind,
                       locale, created_at, updated_at",
        )
        .bind(id)
        .fetch_one(&mut **tx)
        .await?;
        Ok(user)
    }

    /// Transition to `Anonymized`: terminal "account closed" state. Redacts
    /// PII in the row so the user is no longer identifiable from
    /// `identity.users`. Returns the original email (pre-redaction) so the
    /// audit caller can record what was wiped. The caller is responsible for
    /// revoking sessions and deleting credentials in the same transaction.
    /// (A full *Delete* uses [`UserRepository::hard_remove`] instead, which
    /// drops the row rather than keeping a redacted tombstone.)
    pub async fn anonymize(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        id: UserId,
    ) -> Result<(User, String)> {
        redact_and_terminate(tx, id).await
    }

    /// Physically remove the user row — the genuine "leave no trace"
    /// delete, as opposed to `anonymize` which redacts PII but keeps a
    /// tombstone row. Every foreign key to `identity.users(id)`
    /// is either `ON DELETE CASCADE` (all of `auth.*`, plus invitations
    /// this user *created*) or `ON DELETE SET NULL` (the audit actor link,
    /// `pending.transitions`, invitations they *accepted*), so this single
    /// `DELETE` takes the account and every credential/session/factor with
    /// it. The append-only `audit.events` log is the one exception: rows
    /// keep their denormalised actor name as an immutable security record
    /// (only the id link nulls). The caller owns the authz check and must
    /// append the audit event *before* this in the same transaction.
    pub async fn hard_remove(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        id: UserId,
    ) -> Result<()> {
        sqlx::query("DELETE FROM identity.users WHERE id = $1")
            .bind(id)
            .execute(&mut **tx)
            .await?;
        Ok(())
    }
}

/// Backs [`UserRepository::anonymize`]. Redacts PII (email + display_name +
/// locale) in place and sets the terminal `Anonymized` lifecycle. Returns the
/// row in its post-update form alongside the *original* email so the caller
/// can record it in the audit event.
async fn redact_and_terminate(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    id: UserId,
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
             lifecycle = 'anonymized',
             updated_at = now()
         WHERE id = $1
         RETURNING id, email, display_name, lifecycle, instance_role, kind,
                   locale, created_at, updated_at",
    )
    .bind(id)
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

/// Default time an invitation stays valid. Design spec calls for this to
/// be configurable; currently hardcoded to 7 days.
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

    /// Rotate the token on a pending invitation and extend its expiry
    /// to `now() + DEFAULT_INVITATION_TTL`. Returns the post-update row
    /// and the new raw token (which is what the operator needs to
    /// share with the invitee — only its SHA-256 is persisted).
    ///
    /// "Pending" here means non-accepted, non-revoked, non-expired —
    /// the same conditions [`list_pending`] filters on. Callers that
    /// need to disambiguate why a reissue refused should use the
    /// returned [`ReissueRejection`] to render a specific error
    /// (rather than treating everything as a generic 404).
    ///
    /// The old token's hash is overwritten in the same UPDATE, so any
    /// previously-shared link stops working as soon as this returns.
    /// That's the whole point: reissue is the operator saying "the
    /// link in flight is no good, here's a fresh one."
    pub async fn reissue(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        invitation_id: InvitationId,
    ) -> Result<std::result::Result<(Invitation, String), ReissueRejection>> {
        let new_token = generate_invite_token();
        let new_hash = hash_invite_token(&new_token);
        let new_expires_at = Utc::now() + DEFAULT_INVITATION_TTL;

        let updated: Option<Invitation> = sqlx::query_as(
            "UPDATE identity.invitations
             SET token_hash = $2, expires_at = $3
             WHERE id = $1
               AND accepted_at IS NULL
               AND revoked_at IS NULL
               AND expires_at > now()
             RETURNING id, email, invited_by_user_id, instance_role,
                       created_at, expires_at, accepted_at, accepted_user_id, revoked_at",
        )
        .bind(invitation_id)
        .bind(&new_hash[..])
        .bind(new_expires_at)
        .fetch_optional(&mut **tx)
        .await?;

        if let Some(row) = updated {
            return Ok(Ok((row, new_token)));
        }

        // Update affected zero rows. Look up the row to figure out why
        // so the caller can produce a specific error code.
        let snapshot: Option<Invitation> = sqlx::query_as(
            "SELECT id, email, invited_by_user_id, instance_role,
                    created_at, expires_at, accepted_at, accepted_user_id, revoked_at
             FROM identity.invitations WHERE id = $1",
        )
        .bind(invitation_id)
        .fetch_optional(&mut **tx)
        .await?;

        let rejection = match snapshot {
            None => ReissueRejection::NotFound,
            Some(row) if row.accepted_at.is_some() => ReissueRejection::AlreadyAccepted,
            Some(row) if row.revoked_at.is_some() => ReissueRejection::AlreadyRevoked,
            Some(_) => ReissueRejection::Expired,
        };
        Ok(Err(rejection))
    }
}

/// Why a reissue refused. Mirrors the JSON error codes the JSON admin
/// API surface uses for these cases so the web layer can map straight
/// across to existing banner copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReissueRejection {
    NotFound,
    AlreadyAccepted,
    AlreadyRevoked,
    Expired,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn user_lifecycle_serializes_snake_case() {
        let json = serde_json::to_string(&UserLifecycle::PendingInvite).unwrap();
        assert_eq!(json, "\"pending_invite\"");

        let json = serde_json::to_string(&UserLifecycle::Anonymized).unwrap();
        assert_eq!(json, "\"anonymized\"");
    }

    #[test]
    fn user_lifecycle_round_trips_via_json() {
        for value in [
            UserLifecycle::PendingInvite,
            UserLifecycle::Active,
            UserLifecycle::Deactivated,
            UserLifecycle::Anonymized,
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
        assert_eq!(
            serde_json::to_string(&InstanceRole::Member).unwrap(),
            "\"member\""
        );
    }

    #[test]
    fn user_kind_serializes_snake_case() {
        assert_eq!(serde_json::to_string(&UserKind::Member).unwrap(), "\"member\"");
        assert_eq!(serde_json::to_string(&UserKind::Guest).unwrap(), "\"guest\"");
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
