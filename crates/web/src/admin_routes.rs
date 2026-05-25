use axum::{
    Form,
    extract::{Path, State},
    http::HeaderMap,
    response::{Html, IntoResponse, Redirect, Response},
};

/// True when the request was made by HTMX (the JS layer auto-sets
/// `HX-Request: true` on every htmx-driven request). Handlers branch
/// on this to return either a fragment or a full page so non-JS
/// fallback still works.
fn is_htmx(headers: &HeaderMap) -> bool {
    headers.contains_key("hx-request")
}
use hearth::{
    admin_logic::{self, CreateInviteError, LifecycleError, Outcome, RevokeInviteError, RoleError},
    app::AppState,
    csrf,
};
use identity::{InstanceRole, InvitationId};
use serde::Deserialize;
use uuid::Uuid;

use crate::{
    routes::{BrowserAuth, check_csrf_token, error_response, require_admin, url_encode},
    views,
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

#[derive(Deserialize)]
pub struct InviteForm {
    pub csrf_token: String,
    pub email: String,
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

// ────────────────────────────────────────────────────────────────────────
// /members/invite — invite a new member
// ────────────────────────────────────────────────────────────────────────

/// `GET /members/invite` — render the invitation form. Admin/Owner only.
/// When called via HTMX (e.g., the "Invite another" button in the
/// success modal), returns just the modal-content partial so the swap
/// can keep the dialog open and only replace its inner body.
pub async fn invite_form(
    State(state): State<AppState>,
    BrowserAuth(auth): BrowserAuth,
    headers: HeaderMap,
) -> Response {
    if !matches!(
        auth.user.instance_role,
        InstanceRole::Admin | InstanceRole::Owner,
    ) {
        return error_response(axum::http::StatusCode::FORBIDDEN, "Admins only.");
    }
    let csrf_token = csrf::compute_token(&state.csrf_secret, auth.session_id);
    let ctx = views::ChromeContext {
        instance_name: &state.instance_name,
        user: &auth.user,
        csrf_token: &csrf_token,
    };
    if is_htmx(&headers) {
        Html(
            views::invite_modal_content_form(&ctx, "", InstanceRole::Member, None)
                .into_string(),
        )
        .into_response()
    } else {
        Html(views::members_invite_form_page(&ctx, "", InstanceRole::Member, None).into_string())
            .into_response()
    }
}

/// `POST /members/invite` — submit the invitation form. On success
/// renders the result page **directly** (no redirect) so the one-time
/// acceptance token never enters the URL bar, browser history, or
/// referer header. On validation/auth failure re-renders the form with
/// an inline banner and the entered email preserved.
pub async fn invite_submit(
    State(state): State<AppState>,
    BrowserAuth(auth): BrowserAuth,
    headers: HeaderMap,
    Form(form): Form<InviteForm>,
) -> Response {
    if let Err(resp) = check_csrf_token(&state, auth.session_id, &form.csrf_token) {
        return resp;
    }
    let admin = match require_admin(auth) {
        Ok(a) => a,
        Err(resp) => return resp,
    };
    let htmx = is_htmx(&headers);

    let csrf_token = csrf::compute_token(&state.csrf_secret, admin.0.session_id);
    let ctx = views::ChromeContext {
        instance_name: &state.instance_name,
        user: &admin.0.user,
        csrf_token: &csrf_token,
    };

    match admin_logic::perform_create_invite(&state, &admin, &form.email, form.role).await {
        Ok(outcome) => {
            let accept_url = format!("{}/invite/{}", state.public_base_url, outcome.raw_token);
            if htmx {
                // HTMX swap: just the inner modal content. The dialog
                // stays open, transitioning visually from the form to
                // the success view in place.
                Html(
                    views::invite_modal_content_success(
                        &ctx,
                        &outcome.invitation.email,
                        outcome.invitation.instance_role,
                        &accept_url,
                        outcome.invitation.expires_at,
                    )
                    .into_string(),
                )
                .into_response()
            } else {
                // No-JS / HTMX-absent fallback: full result page.
                Html(
                    views::members_invite_result_page(
                        &ctx,
                        &outcome.invitation.email,
                        outcome.invitation.instance_role,
                        &accept_url,
                        outcome.invitation.expires_at,
                    )
                    .into_string(),
                )
                .into_response()
            }
        }
        Err(e) => {
            let code = match e {
                CreateInviteError::EmailRequired => "email_required",
                CreateInviteError::CannotInviteHigherRole => "cannot_invite_higher_role",
                CreateInviteError::EmailAlreadyInUse => "email_already_in_use",
                CreateInviteError::ActiveInviteExists => "active_invite_exists",
                CreateInviteError::Internal(err) => {
                    tracing::error!(?err, "create invite internal error (web)");
                    return error_response(
                        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                        "Internal error",
                    );
                }
            };
            if htmx {
                Html(
                    views::invite_modal_content_form(&ctx, &form.email, form.role, Some(code))
                        .into_string(),
                )
                .into_response()
            } else {
                Html(
                    views::members_invite_form_page(&ctx, &form.email, form.role, Some(code))
                        .into_string(),
                )
                .into_response()
            }
        }
    }
}

/// `POST /members/invitations/{id}/revoke` — kebab action on a pending
/// invite row. Calls into `admin_logic::perform_revoke_invite` (the
/// same shared transaction the JSON `/api/admin/invites/{id}/revoke`
/// uses) and redirects back to /members with a banner.
pub async fn revoke_invitation(
    State(state): State<AppState>,
    BrowserAuth(auth): BrowserAuth,
    Path(invitation_id): Path<Uuid>,
    Form(form): Form<LifecycleActionForm>,
) -> Response {
    if let Err(resp) = check_csrf_token(&state, auth.session_id, &form.csrf_token) {
        return resp;
    }
    let admin = match require_admin(auth) {
        Ok(a) => a,
        Err(resp) => return resp,
    };
    let id = InvitationId::new(invitation_id);
    match admin_logic::perform_revoke_invite(&state, &admin, id).await {
        Ok(()) => Redirect::to("/members?action=invite_revoked").into_response(),
        Err(RevokeInviteError::NotFound) => {
            Redirect::to("/members?error=invite_not_found").into_response()
        }
        Err(RevokeInviteError::AlreadyAccepted) => {
            Redirect::to("/members?error=invite_already_accepted").into_response()
        }
        Err(RevokeInviteError::Internal(err)) => {
            tracing::error!(?err, "revoke invite internal error (web)");
            error_response(
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Internal error",
            )
        }
    }
}
