//! Self-service account closure — a user acting on their *own* account.
//!
//! Two terminal, irreversible actions surfaced in the Data Control settings
//! tab, deliberately separate from the admin lifecycle actions in
//! [`crate::admin_logic`] (which act on *other* users, require `AdminUser`,
//! and route Owner-on-Owner changes through the 72h pending flow):
//!
//! - [`perform_self_anonymize`] — the "keep the data, remove me from it"
//!   close: redact PII, revoke sessions, delete the password credential, but
//!   keep the (now tombstoned) row so anything attributed to the account
//!   survives under a `[deleted user]`.
//! - [`perform_self_delete`] — the genuine "leave no trace" delete: physically
//!   remove the user row so every credential, session, MFA factor, recovery
//!   code and invitation they created cascades away with it. Only the
//!   append-only audit log keeps a frozen record that the account existed and
//!   closed itself.
//!
//! Both are immediate (no peer review) and gated at the web layer by a
//! *critical* re-auth that ignores the ordinary 5-minute sudo window — so the
//! caller has always just re-proved a factor before reaching here. There is no
//! last-owner guard: closing your own account is always your call.

use auth::SessionRepository;
use identity::{InstanceRole, UserRepository};

use crate::app::AppState;
use crate::auth_routes::AuthenticatedUser;

/// Whether `user` is blocked from closing their own account because they are
/// the **last active Owner while other active users remain** — they must hand
/// ownership to a successor first so the instance isn't orphaned. A solo owner
/// (the only active user) is *not* blocked: that's the empty-instance teardown
/// path. Non-owners are never blocked.
pub async fn last_owner_blocked(
    state: &AppState,
    user: &identity::User,
) -> anyhow::Result<bool> {
    if user.instance_role != InstanceRole::Owner {
        return Ok(false);
    }
    let owners = state.users.count_active_owners().await?;
    let users = state.users.count_active_users().await?;
    Ok(owners == 1 && users > 1)
}

/// Anonymize the caller's own account: redact PII (lifecycle `SoftDeleted`),
/// revoke every session, and delete the password credential, leaving the
/// account permanently inaccessible but keeping the tombstone row. Records
/// `account_self_anonymized` in the audit log.
pub async fn perform_self_anonymize(
    state: &AppState,
    user: &AuthenticatedUser,
) -> anyhow::Result<()> {
    let actor = user.actor();
    let user_id = user.user.id;

    let mut tx = state.db.begin().await?;
    let (_redacted, original_email) = UserRepository::anonymize(&mut tx, user_id).await?;
    let revoked = SessionRepository::revoke_all_for_user(&mut tx, user_id).await?;
    auth::delete_credentials(&mut tx, user_id).await?;
    audit::append(
        &mut tx,
        Some(&actor),
        None,
        "account_self_anonymized",
        serde_json::json!({
            "redacted_from_email": original_email,
            "sessions_revoked": revoked,
        }),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Physically delete the caller's own account. The audit event is appended
/// *before* the row vanishes; because `audit.events.actor_user_id` carries no
/// foreign key (it's a frozen snapshot), the deletion leaves that record — and
/// the whole hash chain — intact. Every `auth.*` row and any invitation this
/// user created cascade away with the user row. Records `account_self_deleted`.
pub async fn perform_self_delete(
    state: &AppState,
    user: &AuthenticatedUser,
) -> anyhow::Result<()> {
    let actor = user.actor();
    let user_id = user.user.id;

    let mut tx = state.db.begin().await?;
    audit::append(
        &mut tx,
        Some(&actor),
        None,
        "account_self_deleted",
        serde_json::json!({}),
    )
    .await?;
    UserRepository::hard_remove(&mut tx, user_id).await?;
    tx.commit().await?;
    Ok(())
}
