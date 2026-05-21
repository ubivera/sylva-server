use axum::{
    Form,
    extract::{Path, State},
    response::{IntoResponse, Redirect, Response},
};
use hearth::{
    admin_logic::{self, LifecycleError, Outcome, RoleError},
    app::AppState,
};
use identity::InstanceRole;
use serde::Deserialize;
use uuid::Uuid;

use crate::routes::{
    BrowserAuth, check_csrf_token, error_response, require_admin, url_encode,
};

#[derive(Deserialize)]
pub struct LifecycleActionForm {
    pub csrf_token: String,
}

#[derive(Deserialize)]
pub struct RoleChangeForm {
    pub csrf_token: String,
    pub role: InstanceRole,
}

/// `POST /members/{id}/deactivate` — form handler for the Deactivate kebab
/// action. Owner-on-Owner routes through pending; bypass codes are not
/// exposed in the UI so the form sends none.
pub async fn deactivate_member(
    State(state): State<AppState>,
    BrowserAuth(auth): BrowserAuth,
    Path(target_id): Path<Uuid>,
    Form(form): Form<LifecycleActionForm>,
) -> Response {
    if let Err(resp) = check_csrf_token(&state, auth.session_id, &form.csrf_token) {
        return resp;
    }
    let admin = match require_admin(auth) {
        Ok(a) => a,
        Err(resp) => return resp,
    };
    match admin_logic::perform_deactivate(&state, &admin, target_id, None).await {
        Ok(Outcome::Applied { target }) => {
            redirect_users(&format!(
                "/members?action=deactivated&target={}",
                url_encode(&target.display_name)
            ))
        }
        Ok(Outcome::Pending(_)) => redirect_users("/members?action=pending_deactivate"),
        Err(e) => lifecycle_error_to_redirect(e),
    }
}

/// `POST /members/{id}/reactivate` — form handler. No pending path —
/// reactivation is always immediate.
pub async fn reactivate_member(
    State(state): State<AppState>,
    BrowserAuth(auth): BrowserAuth,
    Path(target_id): Path<Uuid>,
    Form(form): Form<LifecycleActionForm>,
) -> Response {
    if let Err(resp) = check_csrf_token(&state, auth.session_id, &form.csrf_token) {
        return resp;
    }
    let admin = match require_admin(auth) {
        Ok(a) => a,
        Err(resp) => return resp,
    };
    match admin_logic::perform_reactivate(&state, &admin, target_id).await {
        Ok(user) => redirect_users(&format!(
            "/members?action=reactivated&target={}",
            url_encode(&user.display_name)
        )),
        Err(e) => lifecycle_error_to_redirect(e),
    }
}

/// `POST /members/{id}/delete` — soft delete (terminal "account removed").
pub async fn delete_member(
    State(state): State<AppState>,
    BrowserAuth(auth): BrowserAuth,
    Path(target_id): Path<Uuid>,
    Form(form): Form<LifecycleActionForm>,
) -> Response {
    if let Err(resp) = check_csrf_token(&state, auth.session_id, &form.csrf_token) {
        return resp;
    }
    let admin = match require_admin(auth) {
        Ok(a) => a,
        Err(resp) => return resp,
    };
    match admin_logic::perform_soft_delete(&state, &admin, target_id, None).await {
        Ok(Outcome::Applied { target }) => redirect_users(&format!(
            "/members?action=deleted&target={}",
            url_encode(&target.display_name)
        )),
        Ok(Outcome::Pending(_)) => redirect_users("/members?action=pending_delete"),
        Err(e) => lifecycle_error_to_redirect(e),
    }
}

/// `POST /members/{id}/purge` — hard delete (full purge).
pub async fn purge_member(
    State(state): State<AppState>,
    BrowserAuth(auth): BrowserAuth,
    Path(target_id): Path<Uuid>,
    Form(form): Form<LifecycleActionForm>,
) -> Response {
    if let Err(resp) = check_csrf_token(&state, auth.session_id, &form.csrf_token) {
        return resp;
    }
    let admin = match require_admin(auth) {
        Ok(a) => a,
        Err(resp) => return resp,
    };
    match admin_logic::perform_hard_delete(&state, &admin, target_id, None).await {
        Ok(Outcome::Applied { target }) => redirect_users(&format!(
            "/members?action=purged&target={}",
            url_encode(&target.display_name)
        )),
        Ok(Outcome::Pending(_)) => redirect_users("/members?action=pending_purge"),
        Err(e) => lifecycle_error_to_redirect(e),
    }
}

/// `POST /members/{id}/role` — change a user's instance role.
/// Owner-only (admin_logic enforces). Owner-on-Owner routes through
/// pending unless a recovery code is supplied (UI doesn't expose this).
pub async fn change_member_role(
    State(state): State<AppState>,
    BrowserAuth(auth): BrowserAuth,
    Path(target_id): Path<Uuid>,
    Form(form): Form<RoleChangeForm>,
) -> Response {
    if let Err(resp) = check_csrf_token(&state, auth.session_id, &form.csrf_token) {
        return resp;
    }
    let admin = match require_admin(auth) {
        Ok(a) => a,
        Err(resp) => return resp,
    };
    match admin_logic::perform_change_role(&state, &admin, target_id, form.role, None).await {
        Ok(Outcome::Applied { target }) => redirect_users(&format!(
            "/members?action=role_changed&target={}",
            url_encode(&target.display_name)
        )),
        Ok(Outcome::Pending(_)) => redirect_users("/members?action=pending_role_change"),
        Err(e) => role_error_to_redirect(e),
    }
}

// ────────────────────────────────────────────────────────────────────────
// Outcome → response mapping
// ────────────────────────────────────────────────────────────────────────

fn redirect_users(location: &str) -> Response {
    Redirect::to(location).into_response()
}

fn lifecycle_error_to_redirect(e: LifecycleError) -> Response {
    let code = match e {
        LifecycleError::NotFound => "user_not_found",
        LifecycleError::SelfTarget => "cannot_target_self",
        LifecycleError::PeerOrHigher => "cannot_target_peer_or_higher",
        LifecycleError::Conflict(c) => c,
        LifecycleError::InvalidRecoveryCode => "invalid_recovery_code",
        LifecycleError::PendingActionExists => "pending_action_exists",
        LifecycleError::Internal(err) => {
            tracing::error!(?err, "lifecycle action internal error (web)");
            return error_response(
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Internal error",
            );
        }
    };
    redirect_users(&format!("/members?error={code}"))
}

fn role_error_to_redirect(e: RoleError) -> Response {
    let code = match e {
        RoleError::Forbidden => "forbidden",
        RoleError::NotFound => "user_not_found",
        RoleError::SelfTarget => "cannot_target_self",
        RoleError::NotActive => "not_active",
        RoleError::AlreadyInRole => "already_in_role",
        RoleError::InvalidRecoveryCode => "invalid_recovery_code",
        RoleError::PendingActionExists => "pending_action_exists",
        RoleError::Internal(err) => {
            tracing::error!(?err, "role change internal error (web)");
            return error_response(
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Internal error",
            );
        }
    };
    redirect_users(&format!("/members?error={code}"))
}
