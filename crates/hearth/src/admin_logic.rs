use auth::SessionRepository;
use identity::{
    DEFAULT_INVITATION_TTL, InstanceRole, Invitation, InvitationRepository, User, UserId,
    UserLifecycle, UserRepository,
};
use thiserror::Error;
use uuid::Uuid;

use crate::{app::AppState, auth_routes::AdminUser};

/// Outcome of a lifecycle or role change that may either apply
/// immediately or route through the 72-hour pending-transition flow.
pub enum Outcome {
    /// The action ran in a single transaction. `target` carries the
    /// most useful snapshot for the action — **post-action** for
    /// `deactivate` / `reactivate` / `change_role` (so JSON callers see
    /// the new lifecycle/role), **pre-action** for `soft_delete` /
    /// `hard_delete` (the post-action record has redacted PII so the
    /// original `display_name` and `email` would be unusable for banner
    /// messaging).
    Applied { target: User },
    /// The action created a `pending.transitions` row instead of
    /// applying. Caller (web/JSON) renders the row to the user.
    Pending(pending::TransitionRow),
}

#[derive(thiserror::Error, Debug)]
pub enum LifecycleError {
    #[error("user_not_found")]
    NotFound,
    #[error("cannot_target_self")]
    SelfTarget,
    #[error("cannot_target_peer_or_higher")]
    PeerOrHigher,
    /// 409 Conflict. The carried string is the JSON error code
    /// (`already_deactivated`, `already_active`, `not_active`,
    /// `not_deactivated`) so the wrapping shell can pass it through
    /// unchanged.
    #[error("{0}")]
    Conflict(&'static str),
    #[error("invalid_recovery_code")]
    InvalidRecoveryCode,
    #[error("pending_action_exists")]
    PendingActionExists,
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

#[derive(thiserror::Error, Debug)]
pub enum RoleError {
    /// Caller is not an Owner. Only Owners can change roles.
    #[error("forbidden")]
    Forbidden,
    #[error("user_not_found")]
    NotFound,
    #[error("cannot_target_self")]
    SelfTarget,
    #[error("not_active")]
    NotActive,
    #[error("already_in_role")]
    AlreadyInRole,
    #[error("invalid_recovery_code")]
    InvalidRecoveryCode,
    #[error("pending_action_exists")]
    PendingActionExists,
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

/// Result of a bypass-code verification attempt. Lets the caller
/// distinguish "didn't try to bypass" (normal path) from "tried with a
/// bad code" (auth failure) without overloading `Option`.
enum BypassResult {
    NoneSupplied,
    Valid(Uuid),
    Invalid,
}

/// What `maybe_verify_bypass` tells the lifecycle action to do next.
/// Replaces an awkward `Option<Option<Uuid>>` with named arms.
enum LifecycleNext {
    /// Apply the action immediately. `bypass_code_id` is `Some(uuid)` if
    /// the caller used the recovery code path, `None` otherwise (the
    /// common case for non-Owner targets).
    ApplyImmediate { bypass_code_id: Option<Uuid> },
    /// Caller is Owner-on-Owner and did not present a bypass code —
    /// route through the 72-hour pending flow.
    RouteToPending,
}

// ────────────────────────────────────────────────────────────────────────
// Public action entry points
// ────────────────────────────────────────────────────────────────────────

/// Active → Deactivated. Sessions are revoked; credentials kept so the
/// account can be reactivated without a password reset. Owner-on-Owner
/// routes through the 72h pending flow unless `bypass_code` matches the
/// active recovery code.
pub async fn perform_deactivate(
    state: &AppState,
    admin: &AdminUser,
    target_id: Uuid,
    bypass_code: Option<&str>,
) -> Result<Outcome, LifecycleError> {
    let target = resolve_lifecycle_target(state, admin, target_id).await?;

    match target.lifecycle {
        UserLifecycle::Active => {}
        UserLifecycle::Deactivated => return Err(LifecycleError::Conflict("already_deactivated")),
        UserLifecycle::SoftDeleted | UserLifecycle::HardDeleted => {
            return Err(LifecycleError::NotFound);
        }
        UserLifecycle::PendingInvite => return Err(LifecycleError::Conflict("not_active")),
    }

    let bypass_code_id = match maybe_verify_bypass(state, admin, &target, bypass_code).await? {
        LifecycleNext::ApplyImmediate { bypass_code_id } => bypass_code_id,
        LifecycleNext::RouteToPending => {
            let row = enqueue_pending_lifecycle(
                state,
                admin,
                &target,
                notifications::LifecycleAction::Deactivate,
            )
            .await?;
            return Ok(Outcome::Pending(row));
        }
    };

    apply_deactivate(state, admin, target, bypass_code_id).await
}

/// Deactivated → Active. No pending path — reactivation is always
/// immediate (it's the "undo" of deactivate).
pub async fn perform_reactivate(
    state: &AppState,
    admin: &AdminUser,
    target_id: Uuid,
) -> Result<User, LifecycleError> {
    let target = resolve_lifecycle_target(state, admin, target_id).await?;

    match target.lifecycle {
        UserLifecycle::Deactivated => {}
        UserLifecycle::Active => return Err(LifecycleError::Conflict("already_active")),
        UserLifecycle::SoftDeleted | UserLifecycle::HardDeleted => {
            return Err(LifecycleError::NotFound);
        }
        UserLifecycle::PendingInvite => return Err(LifecycleError::Conflict("not_deactivated")),
    }

    let actor = admin.actor();
    let target_user_id = target.id;
    let target_email = target.email.clone();

    let result: anyhow::Result<User> = async {
        let mut tx = state.db.begin().await?;
        let updated = UserRepository::reactivate(&mut tx, target_user_id).await?;
        audit::append(
            &mut tx,
            Some(&actor),
            None,
            "user_reactivated",
            serde_json::json!({
                "target_user_id": target_user_id.0,
                "target_email": target_email,
            }),
        )
        .await?;
        tx.commit().await?;
        Ok(updated)
    }
    .await;

    result.map_err(LifecycleError::Internal)
}

/// Active/Deactivated → SoftDeleted. Revokes sessions, deletes
/// credentials, redacts PII. Owner-on-Owner routes through pending
/// unless `bypass_code` is supplied.
pub async fn perform_soft_delete(
    state: &AppState,
    admin: &AdminUser,
    target_id: Uuid,
    bypass_code: Option<&str>,
) -> Result<Outcome, LifecycleError> {
    let target = resolve_lifecycle_target(state, admin, target_id).await?;

    match target.lifecycle {
        UserLifecycle::Active | UserLifecycle::Deactivated => {}
        UserLifecycle::SoftDeleted | UserLifecycle::HardDeleted => {
            return Err(LifecycleError::NotFound);
        }
        UserLifecycle::PendingInvite => return Err(LifecycleError::Conflict("not_active")),
    }

    let bypass_code_id = match maybe_verify_bypass(state, admin, &target, bypass_code).await? {
        LifecycleNext::ApplyImmediate { bypass_code_id } => bypass_code_id,
        LifecycleNext::RouteToPending => {
            let row = enqueue_pending_lifecycle(
                state,
                admin,
                &target,
                notifications::LifecycleAction::SoftDelete,
            )
            .await?;
            return Ok(Outcome::Pending(row));
        }
    };

    apply_soft_delete(state, admin, target, bypass_code_id).await
}

/// Active/Deactivated/SoftDeleted → HardDeleted. Same row-level effect
/// as soft_delete today; once the apps platform lands, this also drops
/// all the user's content. Owner-on-Owner routes through pending.
pub async fn perform_hard_delete(
    state: &AppState,
    admin: &AdminUser,
    target_id: Uuid,
    bypass_code: Option<&str>,
) -> Result<Outcome, LifecycleError> {
    let target = resolve_lifecycle_target(state, admin, target_id).await?;

    match target.lifecycle {
        UserLifecycle::Active | UserLifecycle::Deactivated | UserLifecycle::SoftDeleted => {}
        UserLifecycle::HardDeleted => return Err(LifecycleError::NotFound),
        UserLifecycle::PendingInvite => return Err(LifecycleError::Conflict("not_active")),
    }

    let bypass_code_id = match maybe_verify_bypass(state, admin, &target, bypass_code).await? {
        LifecycleNext::ApplyImmediate { bypass_code_id } => bypass_code_id,
        LifecycleNext::RouteToPending => {
            let row = enqueue_pending_lifecycle(
                state,
                admin,
                &target,
                notifications::LifecycleAction::HardDelete,
            )
            .await?;
            return Ok(Outcome::Pending(row));
        }
    };

    apply_hard_delete(state, admin, target, bypass_code_id).await
}

/// Owner-only. Change a user's `instance_role`. Owner→Owner transitions
/// route through the pending flow unless `bypass_code` matches the
/// active recovery code.
pub async fn perform_change_role(
    state: &AppState,
    admin: &AdminUser,
    target_id: Uuid,
    to_role: InstanceRole,
    bypass_code: Option<&str>,
) -> Result<Outcome, RoleError> {
    if admin.0.user.instance_role != InstanceRole::Owner {
        return Err(RoleError::Forbidden);
    }

    let target = state
        .users
        .find_any(UserId::new(target_id))
        .await
        .map_err(|e| RoleError::Internal(e.into()))?
        .ok_or(RoleError::NotFound)?;

    if target.id == admin.0.user.id {
        return Err(RoleError::SelfTarget);
    }

    match target.lifecycle {
        UserLifecycle::Active | UserLifecycle::Deactivated => {}
        UserLifecycle::SoftDeleted | UserLifecycle::HardDeleted => return Err(RoleError::NotFound),
        UserLifecycle::PendingInvite => return Err(RoleError::NotActive),
    }

    let from_role = target.instance_role;
    if from_role == to_role {
        return Err(RoleError::AlreadyInRole);
    }

    // Only Owner→? transitions can pend; any non-Owner target is applied
    // immediately because demoting/promoting an Admin or User is purely
    // the current Owner's call.
    let owner_target = from_role == InstanceRole::Owner;
    let bypass_code_id: Option<Uuid> = if owner_target {
        match verify_bypass(state, bypass_code).await? {
            BypassResult::NoneSupplied => {
                let row = enqueue_pending_role_change(state, admin, &target, to_role).await?;
                return Ok(Outcome::Pending(row));
            }
            BypassResult::Valid(id) => Some(id),
            BypassResult::Invalid => return Err(RoleError::InvalidRecoveryCode),
        }
    } else {
        None
    };

    apply_role_change(state, admin, target, from_role, to_role, bypass_code_id).await
}

// ────────────────────────────────────────────────────────────────────────
// Shared pre-checks
// ────────────────────────────────────────────────────────────────────────

async fn resolve_lifecycle_target(
    state: &AppState,
    admin: &AdminUser,
    target_id: Uuid,
) -> Result<User, LifecycleError> {
    let target = state
        .users
        .find_any(UserId::new(target_id))
        .await
        .map_err(|e| LifecycleError::Internal(e.into()))?
        .ok_or(LifecycleError::NotFound)?;

    if target.id == admin.0.user.id {
        return Err(LifecycleError::SelfTarget);
    }

    // Owners can target any other user (including peer Owners — that
    // routes through pending). Admins must strictly outrank their target.
    if admin.0.user.instance_role != InstanceRole::Owner
        && !authz::outranks(admin.0.user.instance_role, target.instance_role)
    {
        return Err(LifecycleError::PeerOrHigher);
    }
    Ok(target)
}

fn is_owner_on_owner(admin: &AdminUser, target: &User) -> bool {
    admin.0.user.instance_role == InstanceRole::Owner
        && target.instance_role == InstanceRole::Owner
}

/// Returns `Ok(Some(code_id))` if the caller supplied a valid bypass
/// code, `Ok(None)` if they supplied no code at all (caller's
/// responsibility to decide whether that's acceptable for this target),
/// or `Err(InvalidRecoveryCode)` if the code didn't match.
///
/// Wrapped in [`maybe_verify_bypass`] for the lifecycle case where the
/// "no code + non-Owner target" path is just `Ok(None)` and shouldn't
/// even talk to the recovery_code repo.
async fn verify_bypass(
    state: &AppState,
    code: Option<&str>,
) -> Result<BypassResult, anyhow::Error> {
    let Some(code) = code else {
        return Ok(BypassResult::NoneSupplied);
    };
    match auth::recovery_code::verify(&state.db, code).await? {
        Some(id) => Ok(BypassResult::Valid(id)),
        None => Ok(BypassResult::Invalid),
    }
}

/// Lifecycle-specific dispatch: decides whether a deactivate / delete /
/// purge applies immediately or routes through pending, and verifies any
/// supplied bypass code against the active recovery code along the way.
/// Skips the recovery_code DB hit entirely when the target isn't an
/// Owner — bypass codes are only meaningful for Owner-on-Owner.
async fn maybe_verify_bypass(
    state: &AppState,
    admin: &AdminUser,
    target: &User,
    code: Option<&str>,
) -> Result<LifecycleNext, LifecycleError> {
    if !is_owner_on_owner(admin, target) {
        return Ok(LifecycleNext::ApplyImmediate { bypass_code_id: None });
    }
    match verify_bypass(state, code)
        .await
        .map_err(LifecycleError::Internal)?
    {
        BypassResult::NoneSupplied => Ok(LifecycleNext::RouteToPending),
        BypassResult::Valid(id) => Ok(LifecycleNext::ApplyImmediate {
            bypass_code_id: Some(id),
        }),
        BypassResult::Invalid => Err(LifecycleError::InvalidRecoveryCode),
    }
}

// ────────────────────────────────────────────────────────────────────────
// Apply paths (immediate, transactional)
// ────────────────────────────────────────────────────────────────────────

async fn apply_deactivate(
    state: &AppState,
    admin: &AdminUser,
    target: User,
    bypass_code_id: Option<Uuid>,
) -> Result<Outcome, LifecycleError> {
    let actor = admin.actor();
    let target_user_id = target.id;
    let target_email = target.email.clone();
    let target_display_name = target.display_name.clone();
    let initiator_display_name = admin.0.user.display_name.clone();

    let result: anyhow::Result<User> = async {
        let mut tx = state.db.begin().await?;
        let updated = UserRepository::deactivate(&mut tx, target_user_id).await?;
        let revoked = SessionRepository::revoke_all_for_user(&mut tx, target_user_id).await?;

        if let Some(code_id) = bypass_code_id {
            audit::append(
                &mut tx,
                Some(&actor),
                None,
                "recovery_code_used",
                serde_json::json!({
                    "code_id": code_id,
                    "used_by": actor.user_id.0,
                    "target_user_id": target_user_id.0,
                    "action": "deactivate",
                }),
            )
            .await?;
        }

        let mut event_data = serde_json::json!({
            "target_user_id": target_user_id.0,
            "target_email": target_email,
            "sessions_revoked": revoked,
        });
        if bypass_code_id.is_some() {
            event_data["via"] = serde_json::Value::String("recovery_bypass".into());
        }
        audit::append(&mut tx, Some(&actor), None, "user_deactivated", event_data).await?;

        if bypass_code_id.is_some() {
            notifications::enqueue(
                &mut tx,
                notifications::Notification::PendingLifecycleApplied {
                    recipient_email: target_email.clone(),
                    target_display_name: target_display_name.clone(),
                    initiator_display_name: initiator_display_name.clone(),
                    action: notifications::LifecycleAction::Deactivate,
                    via_recovery_bypass: true,
                    transition_id: None,
                },
            )
            .await?;
        }

        tx.commit().await?;
        Ok(updated)
    }
    .await;

    let updated = result.map_err(LifecycleError::Internal)?;
    Ok(Outcome::Applied { target: updated })
}

async fn apply_soft_delete(
    state: &AppState,
    admin: &AdminUser,
    target: User,
    bypass_code_id: Option<Uuid>,
) -> Result<Outcome, LifecycleError> {
    let actor = admin.actor();
    let target_user_id = target.id;
    let target_display_name = target.display_name.clone();
    let initiator_display_name = admin.0.user.display_name.clone();

    let result: anyhow::Result<()> = async {
        let mut tx = state.db.begin().await?;
        let (_redacted, original_email) =
            UserRepository::soft_delete(&mut tx, target_user_id).await?;
        let revoked = SessionRepository::revoke_all_for_user(&mut tx, target_user_id).await?;
        auth::delete_credentials(&mut tx, target_user_id).await?;

        if let Some(code_id) = bypass_code_id {
            audit::append(
                &mut tx,
                Some(&actor),
                None,
                "recovery_code_used",
                serde_json::json!({
                    "code_id": code_id,
                    "used_by": actor.user_id.0,
                    "target_user_id": target_user_id.0,
                    "action": "soft_delete",
                }),
            )
            .await?;
        }

        let mut event_data = serde_json::json!({
            "target_user_id": target_user_id.0,
            "redacted_from_email": original_email,
            "sessions_revoked": revoked,
        });
        if bypass_code_id.is_some() {
            event_data["via"] = serde_json::Value::String("recovery_bypass".into());
        }
        audit::append(&mut tx, Some(&actor), None, "user_deleted", event_data).await?;

        if bypass_code_id.is_some() {
            notifications::enqueue(
                &mut tx,
                notifications::Notification::PendingLifecycleApplied {
                    recipient_email: original_email.clone(),
                    target_display_name: target_display_name.clone(),
                    initiator_display_name: initiator_display_name.clone(),
                    action: notifications::LifecycleAction::SoftDelete,
                    via_recovery_bypass: true,
                    transition_id: None,
                },
            )
            .await?;
        }

        tx.commit().await?;
        Ok(())
    }
    .await;

    result.map_err(LifecycleError::Internal)?;
    Ok(Outcome::Applied { target })
}

async fn apply_hard_delete(
    state: &AppState,
    admin: &AdminUser,
    target: User,
    bypass_code_id: Option<Uuid>,
) -> Result<Outcome, LifecycleError> {
    let actor = admin.actor();
    let target_user_id = target.id;
    let target_display_name = target.display_name.clone();
    let initiator_display_name = admin.0.user.display_name.clone();
    let prior_lifecycle = target.lifecycle;

    let result: anyhow::Result<()> = async {
        let mut tx = state.db.begin().await?;
        let (_redacted, original_email) =
            UserRepository::hard_delete(&mut tx, target_user_id).await?;
        let revoked = SessionRepository::revoke_all_for_user(&mut tx, target_user_id).await?;
        auth::delete_credentials(&mut tx, target_user_id).await?;

        if let Some(code_id) = bypass_code_id {
            audit::append(
                &mut tx,
                Some(&actor),
                None,
                "recovery_code_used",
                serde_json::json!({
                    "code_id": code_id,
                    "used_by": actor.user_id.0,
                    "target_user_id": target_user_id.0,
                    "action": "hard_delete",
                }),
            )
            .await?;
        }

        let mut event_data = serde_json::json!({
            "target_user_id": target_user_id.0,
            "redacted_from_email": original_email,
            "prior_lifecycle": prior_lifecycle,
            "sessions_revoked": revoked,
        });
        if bypass_code_id.is_some() {
            event_data["via"] = serde_json::Value::String("recovery_bypass".into());
        }
        audit::append(&mut tx, Some(&actor), None, "user_purged", event_data).await?;

        if bypass_code_id.is_some() {
            notifications::enqueue(
                &mut tx,
                notifications::Notification::PendingLifecycleApplied {
                    recipient_email: original_email.clone(),
                    target_display_name: target_display_name.clone(),
                    initiator_display_name: initiator_display_name.clone(),
                    action: notifications::LifecycleAction::HardDelete,
                    via_recovery_bypass: true,
                    transition_id: None,
                },
            )
            .await?;
        }

        tx.commit().await?;
        Ok(())
    }
    .await;

    result.map_err(LifecycleError::Internal)?;
    Ok(Outcome::Applied { target })
}

async fn apply_role_change(
    state: &AppState,
    admin: &AdminUser,
    target: User,
    from_role: InstanceRole,
    to_role: InstanceRole,
    bypass_code_id: Option<Uuid>,
) -> Result<Outcome, RoleError> {
    let actor = admin.actor();
    let target_user_id = target.id;
    let target_email = target.email.clone();
    let target_display_name = target.display_name.clone();
    let initiator_display_name = admin.0.user.display_name.clone();

    let result: anyhow::Result<User> = async {
        let mut tx = state.db.begin().await?;
        let updated = UserRepository::set_instance_role(&mut tx, target_user_id, to_role).await?;

        if let Some(code_id) = bypass_code_id {
            audit::append(
                &mut tx,
                Some(&actor),
                None,
                "recovery_code_used",
                serde_json::json!({
                    "code_id": code_id,
                    "used_by": actor.user_id.0,
                    "target_user_id": target_user_id.0,
                    "action": "role_change",
                }),
            )
            .await?;
            audit::append(
                &mut tx,
                Some(&actor),
                None,
                "pending_role_change_applied",
                serde_json::json!({
                    "transition_id": serde_json::Value::Null,
                    "via": "recovery_bypass",
                    "initiator_user_id": actor.user_id.0,
                    "target_user_id": target_user_id.0,
                    "from_role": from_role,
                    "applied_role": to_role,
                }),
            )
            .await?;
            notifications::enqueue(
                &mut tx,
                notifications::Notification::PendingRoleChangeApplied {
                    recipient_email: target_email.clone(),
                    target_display_name: target_display_name.clone(),
                    initiator_display_name: initiator_display_name.clone(),
                    applied_role: to_role,
                    via_recovery_bypass: true,
                    transition_id: None,
                },
            )
            .await?;
        } else {
            audit::append(
                &mut tx,
                Some(&actor),
                None,
                "user_role_changed",
                serde_json::json!({
                    "target_user_id": target_user_id.0,
                    "target_email": target_email,
                    "from_role": from_role,
                    "to_role": to_role,
                }),
            )
            .await?;
        }
        tx.commit().await?;
        Ok(updated)
    }
    .await;

    let updated = result.map_err(RoleError::Internal)?;
    Ok(Outcome::Applied { target: updated })
}

// ────────────────────────────────────────────────────────────────────────
// Pending-flow helpers (Owner-on-Owner)
// ────────────────────────────────────────────────────────────────────────

async fn enqueue_pending_lifecycle(
    state: &AppState,
    admin: &AdminUser,
    target: &User,
    action: notifications::LifecycleAction,
) -> Result<pending::TransitionRow, LifecycleError> {
    let initiator = admin.0.user.id;
    let initiator_display_name = admin.0.user.display_name.clone();
    let target_user_id = target.id;
    let target_email = target.email.clone();
    let target_display_name = target.display_name.clone();
    let actor = admin.actor();
    let base = state.public_base_url.clone();

    let event_type = match action {
        notifications::LifecycleAction::Deactivate => "pending_deactivate_initiated",
        notifications::LifecycleAction::SoftDelete => "pending_soft_delete_initiated",
        notifications::LifecycleAction::HardDelete => "pending_hard_delete_initiated",
    };

    let result: anyhow::Result<pending::TransitionRow> = async {
        let mut tx = state.db.begin().await?;
        let (transition_id, effective_at) =
            pending::enqueue_lifecycle(&mut tx, initiator, target_user_id, action).await?;

        audit::append(
            &mut tx,
            Some(&actor),
            None,
            event_type,
            serde_json::json!({
                "transition_id": transition_id,
                "initiator_user_id": initiator.0,
                "target_user_id": target_user_id.0,
                "action": action,
                "effective_at": effective_at,
            }),
        )
        .await?;

        notifications::enqueue(
            &mut tx,
            notifications::Notification::PendingLifecycleInitiated {
                recipient_email: target_email,
                target_display_name,
                initiator_display_name,
                action,
                effective_at,
                veto_url: format!("{base}/admin/pending-transitions/{transition_id}/veto"),
                transition_id,
            },
        )
        .await?;

        let row: pending::TransitionRow = sqlx::query_as(
            "SELECT id, kind, initiator_user_id, target_user_id, payload, state,
                    effective_at, resolved_at, resolved_by_user_id, resolution,
                    created_at
             FROM pending.transitions WHERE id = $1",
        )
        .bind(transition_id)
        .fetch_one(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(row)
    }
    .await;

    match result {
        Ok(row) => Ok(row),
        Err(e) => {
            if let Some(pe) = e.downcast_ref::<pending::PendingError>()
                && matches!(pe, pending::PendingError::PendingActionExists)
            {
                return Err(LifecycleError::PendingActionExists);
            }
            Err(LifecycleError::Internal(e))
        }
    }
}

async fn enqueue_pending_role_change(
    state: &AppState,
    admin: &AdminUser,
    target: &User,
    to_role: InstanceRole,
) -> Result<pending::TransitionRow, RoleError> {
    let initiator = admin.0.user.id;
    let initiator_display_name = admin.0.user.display_name.clone();
    let target_user_id = target.id;
    let target_email = target.email.clone();
    let target_display_name = target.display_name.clone();
    let from_role = target.instance_role;
    let actor = admin.actor();
    let base = state.public_base_url.clone();

    let result: anyhow::Result<pending::TransitionRow> = async {
        let mut tx = state.db.begin().await?;
        let (transition_id, effective_at) =
            pending::enqueue_role_change(&mut tx, initiator, target_user_id, to_role).await?;

        audit::append(
            &mut tx,
            Some(&actor),
            None,
            "pending_role_change_initiated",
            serde_json::json!({
                "transition_id": transition_id,
                "initiator_user_id": initiator.0,
                "target_user_id": target_user_id.0,
                "from_role": from_role,
                "to_role": to_role,
                "effective_at": effective_at,
            }),
        )
        .await?;

        notifications::enqueue(
            &mut tx,
            notifications::Notification::PendingRoleChangeInitiated {
                recipient_email: target_email,
                target_display_name,
                initiator_display_name,
                from_role,
                to_role,
                effective_at,
                veto_url: format!("{base}/admin/pending-transitions/{transition_id}/veto"),
                transition_id,
            },
        )
        .await?;

        let row: pending::TransitionRow = sqlx::query_as(
            "SELECT id, kind, initiator_user_id, target_user_id, payload, state,
                    effective_at, resolved_at, resolved_by_user_id, resolution,
                    created_at
             FROM pending.transitions WHERE id = $1",
        )
        .bind(transition_id)
        .fetch_one(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(row)
    }
    .await;

    match result {
        Ok(row) => Ok(row),
        Err(e) => {
            if let Some(pe) = e.downcast_ref::<pending::PendingError>()
                && matches!(pe, pending::PendingError::PendingActionExists)
            {
                return Err(RoleError::PendingActionExists);
            }
            Err(RoleError::Internal(e))
        }
    }
}

// ────────────────────────────────────────────────────────────────────────
// Invitations
// ────────────────────────────────────────────────────────────────────────

/// What `perform_create_invite` hands back on success. `raw_token` is
/// the one-time acceptance token; the caller is responsible for showing
/// it to the operator exactly once and not persisting it anywhere
/// (URLs, logs, history). The DB only ever stores `sha256(raw_token)`.
pub struct CreateInviteOutcome {
    pub invitation: Invitation,
    pub raw_token: String,
}

#[derive(thiserror::Error, Debug)]
pub enum CreateInviteError {
    #[error("email_required")]
    EmailRequired,
    /// Inviter's role doesn't outrank the target role (e.g. Admin
    /// trying to invite an Owner).
    #[error("cannot_invite_higher_role")]
    CannotInviteHigherRole,
    /// A live (non-deleted) Member already owns this email address.
    #[error("email_already_in_use")]
    EmailAlreadyInUse,
    /// An invitation for this email exists and is still valid (not
    /// expired, accepted, or revoked).
    #[error("active_invite_exists")]
    ActiveInviteExists,
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

/// Create an invitation. Validates the inviter's authority over the
/// target role, refuses duplicates against existing accounts and pending
/// invites, then commits the invitation row + audit event + outbound
/// email enqueue in a single transaction so we never get an invite
/// without a delivery attempt (or vice versa).
pub async fn perform_create_invite(
    state: &AppState,
    admin: &AdminUser,
    email: &str,
    target_role: InstanceRole,
) -> Result<CreateInviteOutcome, CreateInviteError> {
    let trimmed = email.trim();
    if trimmed.is_empty() {
        return Err(CreateInviteError::EmailRequired);
    }
    if !authz::satisfies(admin.0.user.instance_role, target_role) {
        return Err(CreateInviteError::CannotInviteHigherRole);
    }

    if state
        .users
        .email_in_use(trimmed)
        .await
        .map_err(|e| CreateInviteError::Internal(e.into()))?
    {
        return Err(CreateInviteError::EmailAlreadyInUse);
    }
    if state
        .invitations
        .email_has_active_invite(trimmed)
        .await
        .map_err(|e| CreateInviteError::Internal(e.into()))?
    {
        return Err(CreateInviteError::ActiveInviteExists);
    }

    let actor = admin.actor();
    let inviter_id = admin.0.user.id;
    let inviter_display_name = admin.0.user.display_name.clone();
    let base = state.public_base_url.clone();
    let email_owned = trimmed.to_string();

    let result: anyhow::Result<CreateInviteOutcome> = async {
        let mut tx = state.db.begin().await?;
        let (invitation, raw_token) = InvitationRepository::create(
            &mut tx,
            inviter_id,
            &email_owned,
            target_role,
            DEFAULT_INVITATION_TTL,
        )
        .await?;

        audit::append(
            &mut tx,
            Some(&actor),
            None,
            "invite_created",
            serde_json::json!({
                "invitation_id": invitation.id.0,
                "invited_email": invitation.email,
                "instance_role": invitation.instance_role,
            }),
        )
        .await?;

        // Commit the delivery email in the same transaction so we never
        // create an invitation without queuing its email (or vice versa).
        let full_accept_url = format!("{base}/invite/{raw_token}");
        notifications::enqueue(
            &mut tx,
            notifications::Notification::Invitation {
                recipient_email: invitation.email.clone(),
                inviter_display_name: inviter_display_name.clone(),
                accept_url: full_accept_url,
                expires_at: invitation.expires_at,
                instance_role: invitation.instance_role,
                invitation_id: invitation.id.0,
            },
        )
        .await?;

        tx.commit().await?;
        Ok(CreateInviteOutcome { invitation, raw_token })
    }
    .await;

    result.map_err(CreateInviteError::Internal)
}

#[derive(thiserror::Error, Debug)]
pub enum RevokeInviteError {
    /// Invitation didn't exist, or was already revoked. Returned as the
    /// same error for both cases so the response doesn't double as an
    /// existence oracle for prior invite IDs.
    #[error("invite_not_found")]
    NotFound,
    /// The invitee already accepted — revoking would orphan the
    /// resulting `identity.users` row from any cleanup intent.
    #[error("invite_already_accepted")]
    AlreadyAccepted,
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

/// Revoke a pending invitation. No-op if already revoked / never
/// existed (returns `NotFound`); refuses if already accepted (returns
/// `AlreadyAccepted`). Mark + audit commit together so the invite
/// can't move to revoked without an audit trail.
pub async fn perform_revoke_invite(
    state: &AppState,
    admin: &AdminUser,
    invitation_id: identity::InvitationId,
) -> Result<(), RevokeInviteError> {
    let invitation = state
        .invitations
        .find_by_id(invitation_id)
        .await
        .map_err(|e| RevokeInviteError::Internal(e.into()))?
        .ok_or(RevokeInviteError::NotFound)?;

    if invitation.accepted_at.is_some() {
        return Err(RevokeInviteError::AlreadyAccepted);
    }
    if invitation.revoked_at.is_some() {
        return Err(RevokeInviteError::NotFound);
    }

    let actor = admin.actor();
    let result: anyhow::Result<()> = async {
        let mut tx = state.db.begin().await?;
        InvitationRepository::revoke(&mut tx, invitation_id).await?;
        audit::append(
            &mut tx,
            Some(&actor),
            None,
            "invite_revoked",
            serde_json::json!({
                "invitation_id": invitation_id.0,
                "invited_email": invitation.email,
                "instance_role": invitation.instance_role,
            }),
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }
    .await;

    result.map_err(RevokeInviteError::Internal)
}

// ────────────────────────────────────────────────────────────────────────
// Pending-transition resolution (veto / cancel)
// ────────────────────────────────────────────────────────────────────────

/// Which terminal state to drive a pending row into. Veto and Cancel
/// share the same DB shape (sets `state`, `resolved_at`,
/// `resolved_by_user_id`, `resolution`) — the only differences are
/// authz (Owner vs initiator-or-Owner) and the audit / notification
/// event types. `pub(crate)` so the JSON cancel handler in
/// `admin_routes` can still drive the shared `resolve_pending_inner`
/// after applying its own authz check.
#[derive(Debug, Clone, Copy)]
pub(crate) enum ResolveKind {
    Veto,
    Cancel,
}

/// Error returned by [`resolve_pending_inner`]. Shared by both
/// veto and cancel paths.
#[derive(Debug, Error)]
pub enum ResolveError {
    #[error("transition_not_found")]
    NotFound,
    #[error("not_pending")]
    NotPending,
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

/// Error returned by [`perform_veto_pending`]. Adds the `NotOwner` arm
/// since the public veto API enforces Owner-only authz; the JSON
/// cancel handler enforces its own authz and uses [`ResolveError`]
/// directly.
#[derive(Debug, Error)]
pub enum VetoError {
    /// Only Owners can veto pending actions.
    #[error("forbidden")]
    NotOwner,
    #[error("transition_not_found")]
    NotFound,
    #[error("not_pending")]
    NotPending,
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

/// Owner-only public API: veto a pending transition. Wraps
/// [`resolve_pending_inner`] with the Owner authz check, then emits
/// the audit event + notification side effects in one transaction.
///
/// Both the JSON `/admin/pending-transitions/{id}/veto` endpoint and
/// the web `POST /pending/{id}/veto` handler call this so the policy
/// stays in one place.
pub async fn perform_veto_pending(
    state: &AppState,
    admin: &AdminUser,
    transition_id: Uuid,
) -> Result<pending::TransitionRow, VetoError> {
    if admin.0.user.instance_role != InstanceRole::Owner {
        return Err(VetoError::NotOwner);
    }
    match resolve_pending_inner(state, admin, transition_id, ResolveKind::Veto).await {
        Ok(row) => Ok(row),
        Err(ResolveError::NotFound) => Err(VetoError::NotFound),
        Err(ResolveError::NotPending) => Err(VetoError::NotPending),
        Err(ResolveError::Internal(e)) => Err(VetoError::Internal(e)),
    }
}

/// Drive a pending row to its terminal state and emit the side
/// effects. Caller-side authz only — this function assumes the caller
/// has already verified the operator is allowed to perform `kind` on
/// the row in question (the veto API requires Owner; cancel allows
/// Owner OR initiator).
///
/// Always runs in a single transaction so that the row state, audit
/// event, and notification outbox row all commit (or roll back)
/// together. On veto, also enqueues a notification to the initiator;
/// cancel skips that since the initiator is usually the canceller
/// themselves.
pub(crate) async fn resolve_pending_inner(
    state: &AppState,
    admin: &AdminUser,
    transition_id: Uuid,
    kind: ResolveKind,
) -> Result<pending::TransitionRow, ResolveError> {
    let actor = admin.actor();
    let by_user_id = admin.0.user.id;
    let admin_display_name = admin.0.user.display_name.clone();

    let result: anyhow::Result<pending::TransitionRow> = async {
        let mut tx = state.db.begin().await?;
        let row = match kind {
            ResolveKind::Veto => pending::veto(&mut tx, transition_id, by_user_id).await?,
            ResolveKind::Cancel => pending::cancel(&mut tx, transition_id, by_user_id).await?,
        };

        // Look up initiator + target display info for audit + notification.
        let initiator_id = row
            .initiator_user_id
            .ok_or_else(|| anyhow::anyhow!("initiator_user_id is null"))?;
        let target_id = row
            .target_user_id
            .ok_or_else(|| anyhow::anyhow!("target_user_id is null"))?;
        let (initiator_email, initiator_display_name, target_display_name): (
            String,
            String,
            String,
        ) = sqlx::query_as(
            "SELECT
                (SELECT email FROM identity.users WHERE id = $1),
                (SELECT display_name FROM identity.users WHERE id = $1),
                (SELECT display_name FROM identity.users WHERE id = $2)",
        )
        .bind(initiator_id)
        .bind(target_id)
        .fetch_one(&mut *tx)
        .await?;

        // Audit + notification details differ by kind. For role_change we
        // include the to_role; for lifecycle kinds we include the action.
        let is_lifecycle = pending::lifecycle_from_kind(row.kind).is_some();
        let event_type = match (kind, is_lifecycle) {
            (ResolveKind::Veto, false) => "pending_role_change_vetoed",
            (ResolveKind::Cancel, false) => "pending_role_change_cancelled",
            (ResolveKind::Veto, true) => "pending_lifecycle_vetoed",
            (ResolveKind::Cancel, true) => "pending_lifecycle_cancelled",
        };

        let mut event_data = serde_json::json!({
            "transition_id": transition_id,
            "initiator_user_id": initiator_id,
            "target_user_id": target_id,
            "resolved_by": by_user_id.0,
        });
        if let Some(action) = pending::lifecycle_from_kind(row.kind) {
            event_data["action"] = serde_json::to_value(action)?;
        } else {
            let payload = row.role_payload()?;
            event_data["to_role"] = serde_json::to_value(payload.to_role)?;
        }
        audit::append(&mut tx, Some(&actor), None, event_type, event_data).await?;

        // Notify the initiator on veto. (Skip notification for cancel —
        // the initiator is usually the cancel-er themselves.)
        if matches!(kind, ResolveKind::Veto) {
            if let Some(action) = pending::lifecycle_from_kind(row.kind) {
                notifications::enqueue(
                    &mut tx,
                    notifications::Notification::PendingLifecycleVetoed {
                        recipient_email: initiator_email,
                        initiator_display_name,
                        target_display_name,
                        vetoed_by_display_name: admin_display_name.clone(),
                        action,
                        transition_id,
                    },
                )
                .await?;
            } else {
                let payload = row.role_payload()?;
                let from_role: InstanceRole = sqlx::query_scalar(
                    "SELECT instance_role FROM identity.users WHERE id = $1",
                )
                .bind(target_id)
                .fetch_one(&mut *tx)
                .await?;
                notifications::enqueue(
                    &mut tx,
                    notifications::Notification::PendingRoleChangeVetoed {
                        recipient_email: initiator_email,
                        initiator_display_name,
                        target_display_name,
                        vetoed_by_display_name: admin_display_name.clone(),
                        from_role,
                        to_role: payload.to_role,
                        transition_id,
                    },
                )
                .await?;
            }
        }

        tx.commit().await?;
        Ok(row)
    }
    .await;

    match result {
        Ok(row) => Ok(row),
        Err(e) => {
            if let Some(pe) = e.downcast_ref::<pending::PendingError>() {
                match pe {
                    pending::PendingError::NotFound => return Err(ResolveError::NotFound),
                    pending::PendingError::NotPending => return Err(ResolveError::NotPending),
                    _ => {}
                }
            }
            Err(ResolveError::Internal(e))
        }
    }
}
