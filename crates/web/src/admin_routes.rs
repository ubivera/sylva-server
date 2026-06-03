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
pub(crate) fn is_htmx(headers: &HeaderMap) -> bool {
    headers.contains_key("hx-request")
}

/// Either a full-page `303 See Other` (non-HTMX) or an empty `200 OK`
/// with `HX-Redirect: <url>` so HTMX does a client-side navigation.
/// Used after every destructive action completes (success path) so
/// the operator lands back on /members with a banner instead of
/// seeing the partial swap into the modal.
pub(crate) fn redirect_or_hx_redirect(url: &str, htmx: bool) -> Response {
    if htmx {
        let mut resp = (axum::http::StatusCode::OK, "").into_response();
        if let Ok(v) = axum::http::HeaderValue::from_str(url) {
            resp.headers_mut().insert("HX-Redirect", v);
        }
        resp
    } else {
        Redirect::to(url).into_response()
    }
}

/// Attach a `hearth-toast` HX-Trigger event to a response so the
/// client-side toast system (see `TOAST_JS`) buffers + renders it
/// across the HX-Redirect navigation that usually accompanies these
/// handlers. Non-HTMX responses pass through unchanged — the modal
/// flow requires JS anyway, so a JS-disabled caller wouldn't be
/// hitting these endpoints in the first place.
///
/// HX-Trigger value is `{"hearth-toast": {kind, title, message}}`;
/// the client parses the JSON and dispatches the event with the
/// payload as `event.detail`.
pub(crate) fn with_toast(mut response: Response, toast: Option<views::Toast>) -> Response {
    let Some(t) = toast else {
        return response;
    };
    let payload = serde_json::json!({ "hearth-toast": t });
    if let Ok(json) = serde_json::to_string(&payload)
        && let Ok(v) = axum::http::HeaderValue::from_str(&json)
    {
        response.headers_mut().insert("HX-Trigger", v);
    }
    response
}

/// Convenience: build a toast for `action_token` (looked up against
/// the catalog in [`views::toast_for_action`]) and attach it to the
/// response. No-ops cleanly when the token isn't recognised.
pub(crate) fn redirect_with_action_toast(
    url: &str,
    htmx: bool,
    action: &str,
    target: Option<&str>,
) -> Response {
    let toast = views::toast_for_action(action, target);
    with_toast(redirect_or_hx_redirect(url, htmx), toast)
}

/// Convenience: build a red error toast from `error_code` (looked up
/// against [`views::toast_for_error`]) and attach it to the redirect.
pub(crate) fn redirect_with_error_toast(url: &str, htmx: bool, error_code: &str) -> Response {
    let toast = Some(views::toast_for_error(error_code));
    with_toast(redirect_or_hx_redirect(url, htmx), toast)
}

/// Reauth gate. Verifies the operator's current password against
/// `auth.credentials`. On `Ok(true)` returns control to the caller.
/// On `Ok(false)`:
///  * HTMX → return the reauth modal content with `invalid_password`
///    banner so the modal stays open and the operator can retry.
///  * non-HTMX → fall back to a redirect to /members with the same
///    error code (banner renders above the table).
///
/// On internal error → 500 page.
pub(crate) async fn require_password(
    state: &AppState,
    admin: &hearth::auth_routes::AdminUser,
    password: &str,
    htmx: bool,
    action_url: &str,
    staged_params: &[(&str, &str)],
) -> Result<(), Response> {
    let ok = match auth::verify_user_password(&state.db, admin.0.user.id, password).await {
        Ok(v) => v,
        Err(err) => {
            tracing::error!(?err, "verifying operator password for reauth");
            return Err(error_response(
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Internal error",
            ));
        }
    };
    if ok {
        return Ok(());
    }
    if htmx {
        let csrf_token = csrf::compute_token(&state.csrf_secret, admin.0.session_id);
        let ctx = views::ChromeContext {
            instance_name: &state.instance_name,
            user: &admin.0.user,
            csrf_token: &csrf_token,
            // Reauth modal partial — sidebar isn't rendered.
            pending_count: None,
        };
        Err(Html(
            views::reauth_modal_content(&ctx, action_url, staged_params, Some("invalid_password"))
                .into_string(),
        )
        .into_response())
    } else {
        // Non-HTMX wrong-password just bounces to clean /members.
        // The HTMX modal flow shows an inline error banner inside
        // the reauth modal; the non-HTMX path can't paint a toast
        // (sessionStorage write requires JS on the originating page),
        // so the operator just sees the directory with no feedback.
        Err(Redirect::to("/members").into_response())
    }
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
    routes::{BrowserAuth, check_csrf_token, error_response, pending_count_for, require_admin},
    views,
};

#[derive(Deserialize)]
pub struct LifecycleActionForm {
    pub csrf_token: String,
    /// Operator's current password — re-verified before the action
    /// applies. The reauth modal collects this; the action dialog
    /// (delete / purge / deactivate) hands its params off to the
    /// reauth modal via JS, and the actual POST that lands here
    /// carries both the original params + the operator password.
    pub password: String,
}

#[derive(Deserialize)]
pub struct RoleChangeForm {
    pub csrf_token: String,
    pub role: InstanceRole,
    /// Same re-auth gate as the lifecycle forms above. See
    /// [`LifecycleActionForm::password`].
    pub password: String,
}

/// Reactivate now requires re-auth too (folded into the same gate as
/// the destructive actions). Kept as its own struct so the handler
/// can use a different success banner verb without sharing the
/// `LifecycleActionForm`'s richer Pending-handling.
#[derive(Deserialize)]
pub struct ReactivateForm {
    pub csrf_token: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct InviteForm {
    pub csrf_token: String,
    pub email: String,
    pub role: InstanceRole,
    /// Operator's current password — re-verified before the invite
    /// row + audit + outbound email commit. Inlined into the invite
    /// modal rather than chained through `dlg-reauth` because invite's
    /// success path renders into the same modal (`#invite-modal-content`),
    /// which is awkward to coordinate across two modals via HTMX.
    pub password: String,
}

/// `POST /members/{id}/deactivate` — form handler for the Deactivate kebab
/// action. Owner-on-Owner routes through pending; bypass codes are not
/// exposed in the UI so the form sends none. Requires re-auth.
pub async fn deactivate_member(
    State(state): State<AppState>,
    BrowserAuth(auth): BrowserAuth,
    headers: HeaderMap,
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
    let htmx = is_htmx(&headers);
    let action_url = format!("/members/{target_id}/deactivate");
    if let Err(resp) =
        require_password(&state, &admin, &form.password, htmx, &action_url, &[]).await
    {
        return resp;
    }
    match admin_logic::perform_deactivate(&state, &admin, target_id, None).await {
        Ok(Outcome::Applied { target }) => redirect_with_action_toast(
            "/members",
            htmx,
            "deactivated",
            Some(&target.display_name),
        ),
        Ok(Outcome::Pending(_)) => {
            redirect_with_action_toast("/members", htmx, "pending_deactivate", None)
        }
        Err(e) => lifecycle_error_to_response(e, htmx),
    }
}

/// `POST /members/{id}/reactivate` — form handler. No pending path —
/// reactivation is always immediate. Requires re-auth (the reactivate
/// confirmation dialog chains into the shared reauth modal like the
/// destructive actions do).
pub async fn reactivate_member(
    State(state): State<AppState>,
    BrowserAuth(auth): BrowserAuth,
    headers: HeaderMap,
    Path(target_id): Path<Uuid>,
    Form(form): Form<ReactivateForm>,
) -> Response {
    if let Err(resp) = check_csrf_token(&state, auth.session_id, &form.csrf_token) {
        return resp;
    }
    let admin = match require_admin(auth) {
        Ok(a) => a,
        Err(resp) => return resp,
    };
    let htmx = is_htmx(&headers);
    let action_url = format!("/members/{target_id}/reactivate");
    if let Err(resp) =
        require_password(&state, &admin, &form.password, htmx, &action_url, &[]).await
    {
        return resp;
    }
    match admin_logic::perform_reactivate(&state, &admin, target_id).await {
        Ok(user) => redirect_with_action_toast(
            "/members",
            htmx,
            "reactivated",
            Some(&user.display_name),
        ),
        Err(e) => lifecycle_error_to_response(e, htmx),
    }
}

/// `POST /members/{id}/delete` — soft delete (terminal "account removed").
/// Requires re-auth.
pub async fn delete_member(
    State(state): State<AppState>,
    BrowserAuth(auth): BrowserAuth,
    headers: HeaderMap,
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
    let htmx = is_htmx(&headers);
    let action_url = format!("/members/{target_id}/delete");
    if let Err(resp) =
        require_password(&state, &admin, &form.password, htmx, &action_url, &[]).await
    {
        return resp;
    }
    match admin_logic::perform_soft_delete(&state, &admin, target_id, None).await {
        Ok(Outcome::Applied { target }) => redirect_with_action_toast(
            "/members",
            htmx,
            "deleted",
            Some(&target.display_name),
        ),
        Ok(Outcome::Pending(_)) => {
            redirect_with_action_toast("/members", htmx, "pending_delete", None)
        }
        Err(e) => lifecycle_error_to_response(e, htmx),
    }
}

/// `POST /members/{id}/purge` — hard delete (full purge).
pub async fn purge_member(
    State(state): State<AppState>,
    BrowserAuth(auth): BrowserAuth,
    headers: HeaderMap,
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
    let htmx = is_htmx(&headers);
    let action_url = format!("/members/{target_id}/purge");
    if let Err(resp) =
        require_password(&state, &admin, &form.password, htmx, &action_url, &[]).await
    {
        return resp;
    }
    match admin_logic::perform_hard_delete(&state, &admin, target_id, None).await {
        Ok(Outcome::Applied { target }) => redirect_with_action_toast(
            "/members",
            htmx,
            "purged",
            Some(&target.display_name),
        ),
        Ok(Outcome::Pending(_)) => {
            redirect_with_action_toast("/members", htmx, "pending_purge", None)
        }
        Err(e) => lifecycle_error_to_response(e, htmx),
    }
}

/// `POST /members/{id}/role` — change a user's instance role.
/// Owner-only (admin_logic enforces). Owner-on-Owner routes through
/// pending unless a recovery code is supplied (UI doesn't expose this).
/// Requires re-auth.
pub async fn change_member_role(
    State(state): State<AppState>,
    BrowserAuth(auth): BrowserAuth,
    headers: HeaderMap,
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
    let htmx = is_htmx(&headers);
    let action_url = format!("/members/{target_id}/role");
    // Stage the role value back into the reauth modal if the password
    // is wrong, so the operator's choice survives the partial swap.
    let role_value = match form.role {
        InstanceRole::Owner => "owner",
        InstanceRole::Admin => "admin",
        InstanceRole::Member => "member",
    };
    let staged: &[(&str, &str)] = &[("role", role_value)];
    if let Err(resp) =
        require_password(&state, &admin, &form.password, htmx, &action_url, staged).await
    {
        return resp;
    }
    match admin_logic::perform_change_role(&state, &admin, target_id, form.role, None).await {
        Ok(Outcome::Applied { target }) => redirect_with_action_toast(
            "/members",
            htmx,
            "role_changed",
            Some(&target.display_name),
        ),
        Ok(Outcome::Pending(_)) => {
            redirect_with_action_toast("/members", htmx, "pending_role_change", None)
        }
        Err(e) => role_error_to_response(e, htmx),
    }
}

// ────────────────────────────────────────────────────────────────────────
// Outcome → response mapping
// ────────────────────────────────────────────────────────────────────────

fn lifecycle_error_to_response(e: LifecycleError, htmx: bool) -> Response {
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
    redirect_with_error_toast("/members", htmx, code)
}

fn role_error_to_response(e: RoleError, htmx: bool) -> Response {
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
    redirect_with_error_toast("/members", htmx, code)
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
    let pending_count = pending_count_for(&state, auth.user.instance_role).await;
    let ctx = views::ChromeContext {
        instance_name: &state.instance_name,
        user: &auth.user,
        csrf_token: &csrf_token,
        pending_count,
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
    let pending_count = pending_count_for(&state, admin.0.user.instance_role).await;
    let ctx = views::ChromeContext {
        instance_name: &state.instance_name,
        user: &admin.0.user,
        csrf_token: &csrf_token,
        pending_count,
    };

    // Re-auth gate — verify password before doing anything.
    //
    // The invite chain works like this: the invite modal's Send button
    // doesn't submit directly; it stages email+role into the shared
    // reauth modal (dlg-reauth) via REAUTH_CHAIN_JS, the reauth modal
    // POSTs here with HX-Target=#reauth-modal-content.
    //
    //  * Wrong password (HTMX) → return reauth-modal content with the
    //    `invalid_password` banner; the default target swap keeps the
    //    reauth modal open and just refreshes its body.
    //  * Right password (HTMX) → continue to the invite logic, then
    //    use `HX-Retarget: #invite-modal-content` to flip the swap
    //    target to the invite modal's body, plus `HX-Trigger` events
    //    to switch which modal is visible (close reauth, reopen
    //    invite) and to flag the invite list for refresh on close.
    match auth::verify_user_password(&state.db, admin.0.user.id, &form.password).await {
        Ok(true) => {}
        Ok(false) => {
            return if htmx {
                Html(
                    views::reauth_modal_content(
                        &ctx,
                        "/members/invite",
                        &[
                            ("email", form.email.as_str()),
                            ("role", role_url_token(form.role)),
                        ],
                        Some("invalid_password"),
                    )
                    .into_string(),
                )
                .into_response()
            } else {
                Html(
                    views::members_invite_form_page(
                        &ctx,
                        &form.email,
                        form.role,
                        Some("invalid_password"),
                    )
                    .into_string(),
                )
                .into_response()
            };
        }
        Err(err) => {
            tracing::error!(?err, "verifying operator password for invite");
            return error_response(
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Internal error",
            );
        }
    }

    match admin_logic::perform_create_invite(&state, &admin, &form.email, form.role).await {
        Ok(outcome) => {
            let accept_url = format!("{}/invite/{}", state.public_base_url, outcome.raw_token);
            if htmx {
                let body = views::invite_modal_content_success(
                    &ctx,
                    &outcome.invitation.email,
                    outcome.invitation.instance_role,
                    &accept_url,
                    outcome.invitation.expires_at,
                )
                .into_string();
                invite_modal_swap_response(body, /* succeeded = */ true)
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
                let body = views::invite_modal_content_form(
                    &ctx,
                    &form.email,
                    form.role,
                    Some(code),
                )
                .into_string();
                invite_modal_swap_response(body, /* succeeded = */ false)
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

/// URL token for an `InstanceRole` — `member` / `admin` / `owner`.
/// Used when staging the form's role value back into the reauth modal
/// after a wrong-password attempt.
fn role_url_token(role: InstanceRole) -> &'static str {
    match role {
        InstanceRole::Owner => "owner",
        InstanceRole::Admin => "admin",
        InstanceRole::Member => "member",
    }
}

/// HTMX response for the invite chain's post-reauth swap. The reauth
/// modal's default `hx-target` is `#reauth-modal-content`; here we
/// retarget to `#invite-modal-content` so the body swap lands in the
/// invite modal, and fire `HX-Trigger` events to:
///   * `switch-to-invite-modal` — JS closes dlg-reauth, opens dlg-invite
///   * `invite-success` (only on success) — JS flags the page so the
///     dlg-invite close handler triggers a window reload, surfacing
///     the new pending invite row in the table.
fn invite_modal_swap_response(body: String, succeeded: bool) -> Response {
    let mut resp = Html(body).into_response();
    let headers = resp.headers_mut();
    // `from_static` returns the HeaderValue directly (panics on invalid
    // input at compile time for &'static str literals).
    headers.insert(
        "HX-Retarget",
        axum::http::HeaderValue::from_static("#invite-modal-content"),
    );
    let trigger_value = if succeeded {
        "switch-to-invite-modal, invite-success"
    } else {
        "switch-to-invite-modal"
    };
    headers.insert(
        "HX-Trigger",
        axum::http::HeaderValue::from_static(trigger_value),
    );
    resp
}

/// `POST /members/invitations/{id}/revoke` — kebab action on a pending
/// invite row. Calls into `admin_logic::perform_revoke_invite` (the
/// same shared transaction the JSON `/api/admin/invites/{id}/revoke`
/// uses) and redirects back to /members with a banner.
///
/// Reuses the destructive-action reauth pattern: the kebab opens a
/// confirmation dialog whose Continue button chains into `dlg-reauth`,
/// the operator types their password, and the actual POST lands here
/// with `password` populated. Without the password the request would
/// fail Form deserialization (LifecycleActionForm makes password
/// required) — the dialog is the only legitimate caller.
pub async fn revoke_invitation(
    State(state): State<AppState>,
    BrowserAuth(auth): BrowserAuth,
    headers: HeaderMap,
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
    let htmx = is_htmx(&headers);
    let action_url = format!("/members/invitations/{invitation_id}/revoke");
    if let Err(resp) =
        require_password(&state, &admin, &form.password, htmx, &action_url, &[]).await
    {
        return resp;
    }
    let id = InvitationId::new(invitation_id);
    match admin_logic::perform_revoke_invite(&state, &admin, id).await {
        Ok(()) => redirect_with_action_toast("/members", htmx, "invite_revoked", None),
        Err(RevokeInviteError::NotFound) => {
            redirect_with_error_toast("/members", htmx, "invite_not_found")
        }
        Err(RevokeInviteError::AlreadyAccepted) => {
            redirect_with_error_toast("/members", htmx, "invite_already_accepted")
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

/// `POST /members/invitations/{id}/reissue` — kebab action on a pending
/// invite row. Rotates the invitation's token (old URL stops working
/// immediately), extends its expiry to now+TTL, and renders the new
/// acceptance URL once.
///
/// Reuses the same cross-modal HTMX swap as `invite_submit`: the
/// reauth chain POSTs here, on success we HX-Retarget to
/// `#invite-modal-content` so the swap lands in the existing invite
/// dialog, and fire `switch-to-invite-modal` + `invite-success`
/// triggers so the JS closes reauth, opens the invite dialog (now
/// showing the reissue success body), and flags the page for a
/// reload when the operator closes it (so the bumped expiry shows on
/// the row). Same `LifecycleActionForm` shape; same `require_password`
/// gate as Revoke.
pub async fn reissue_invitation(
    State(state): State<AppState>,
    BrowserAuth(auth): BrowserAuth,
    headers: HeaderMap,
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
    let htmx = is_htmx(&headers);
    let action_url = format!("/members/invitations/{invitation_id}/reissue");
    if let Err(resp) =
        require_password(&state, &admin, &form.password, htmx, &action_url, &[]).await
    {
        return resp;
    }

    let csrf_token = csrf::compute_token(&state.csrf_secret, admin.0.session_id);
    let pending_count = pending_count_for(&state, admin.0.user.instance_role).await;
    let ctx = views::ChromeContext {
        instance_name: &state.instance_name,
        user: &admin.0.user,
        csrf_token: &csrf_token,
        pending_count,
    };

    let id = InvitationId::new(invitation_id);
    match admin_logic::perform_reissue_invite(&state, &admin, id).await {
        Ok(outcome) => {
            let accept_url =
                format!("{}/invite/{}", state.public_base_url, outcome.raw_token);
            if htmx {
                let body = views::reissue_modal_content_success(
                    &ctx,
                    &outcome.invitation.email,
                    outcome.invitation.instance_role,
                    &accept_url,
                    outcome.invitation.expires_at,
                )
                .into_string();
                // Same swap-into-invite-modal response as create-invite.
                // The `succeeded=true` arg flags the page to reload on
                // dlg-invite close so the bumped expires_at + the new
                // pending row state surface.
                invite_modal_swap_response(body, /* succeeded = */ true)
            } else {
                // No-JS / HTMX-absent fallback: render the URL on a
                // standalone result page so the operator still gets
                // the one-time URL. Mirrors invite_submit's fallback.
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
        Err(admin_logic::ReissueInviteError::NotFound) => {
            redirect_with_error_toast("/members", htmx, "invite_not_found")
        }
        Err(admin_logic::ReissueInviteError::AlreadyAccepted) => {
            redirect_with_error_toast("/members", htmx, "invite_already_accepted")
        }
        Err(admin_logic::ReissueInviteError::AlreadyRevoked) => {
            redirect_with_error_toast("/members", htmx, "invite_not_found")
        }
        Err(admin_logic::ReissueInviteError::Expired) => {
            redirect_with_error_toast("/members", htmx, "invite_expired")
        }
        Err(admin_logic::ReissueInviteError::Internal(err)) => {
            tracing::error!(?err, "reissue invite internal error (web)");
            error_response(
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Internal error",
            )
        }
    }
}
