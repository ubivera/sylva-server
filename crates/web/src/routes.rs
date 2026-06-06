use axum::{
    Form,
    extract::{FromRequestParts, OptionalFromRequestParts, Query, State},
    http::{StatusCode, request::Parts},
    response::{Html, IntoResponse, Redirect, Response},
};
use hearth::{app::AppState, auth_routes::SESSION_COOKIE_NAME, csrf};
use serde::Deserialize;

use crate::views;

/// Browser-side auth wrapper: same lookup as
/// [`hearth::auth_routes::AuthenticatedUser`] but rejects with a redirect
/// to `/login` instead of a JSON 401. Browser users hitting an
/// unauthenticated route get bounced to sign in.
pub struct BrowserAuth(pub hearth::auth_routes::AuthenticatedUser);

impl FromRequestParts<AppState> for BrowserAuth {
    type Rejection = Redirect;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        hearth::auth_routes::AuthenticatedUser::from_request_parts(parts, state)
            .await
            .map(BrowserAuth)
            .map_err(|_| Redirect::to("/login"))
    }
}

/// Optional-extraction variant — required for `Option<BrowserAuth>` to
/// work in handler signatures. Missing/invalid auth produces `Ok(None)`
/// rather than a rejection, so handlers like the root redirect can
/// branch on "are we signed in" without needing the bounce-to-login
/// behaviour.
impl OptionalFromRequestParts<AppState> for BrowserAuth {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Option<Self>, Self::Rejection> {
        match hearth::auth_routes::AuthenticatedUser::from_request_parts(parts, state).await {
            Ok(user) => Ok(Some(BrowserAuth(user))),
            Err(_) => Ok(None),
        }
    }
}

/// `GET /` — bounce to the user's account page (if authed) or login.
pub async fn root_redirect(auth: Option<BrowserAuth>) -> Redirect {
    if auth.is_some() {
        Redirect::to("/me")
    } else {
        Redirect::to("/login")
    }
}

/// `GET /login` — render the login form. If the visitor is already
/// authenticated, bounce them to `/me` instead. The optional
/// `?email=…` query param pre-fills the email input — used by the
/// user-card popover's "quick switch" rows to drop the operator
/// into the login form with the other account already typed.
pub async fn login_page(
    auth: Option<BrowserAuth>,
    Query(prefill): Query<LoginPrefill>,
) -> Response {
    if auth.is_some() {
        Redirect::to("/me").into_response()
    } else {
        Html(views::login_page(None, prefill.email.as_deref()).into_string())
            .into_response()
    }
}

/// Optional `?email=…` query param accepted on `GET /login` so the
/// user-card popover can pre-fill the email input on quick switch.
/// Everything is optional and untrusted — the value is rendered as
/// an `<input value>` attribute by Maud, which HTML-escapes it.
#[derive(Deserialize, Default)]
pub struct LoginPrefill {
    pub email: Option<String>,
}

#[derive(Deserialize)]
pub struct LoginForm {
    pub email: String,
    pub password: String,
}

/// `POST /login` — credential check + session creation. Sets the
/// `hearth_session` cookie on success and redirects to `/me`. On failure
/// re-renders the login form with an error message (status 200 so the
/// browser doesn't replace the page with a custom error UI).
pub async fn login_submit(
    State(state): State<AppState>,
    Form(form): Form<LoginForm>,
) -> Response {
    // Verify credentials via the existing auth helper — same code path
    // the JSON API uses, so behaviour stays consistent.
    let outcome = match auth::verify_credentials(&state.db, &form.email, &form.password).await {
        Ok(o) => o,
        Err(err) => {
            tracing::error!(?err, "verifying credentials");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error");
        }
    };

    let user = match outcome {
        Ok(user) => user,
        Err(_) => {
            // Re-render with the email pre-filled so the operator
            // doesn't have to retype it after a bad password — the
            // password field stays empty and gets focus.
            let prefill = Some(form.email.as_str());
            return Html(
                views::login_page(Some("Invalid email or password."), prefill)
                    .into_string(),
            )
            .into_response();
        }
    };

    // Issue a session — same SessionRepository::create + audit shape as
    // the JSON login handler.
    let actor = audit::Actor {
        user_id: user.id,
        display_name: user.display_name.clone(),
    };
    let result: anyhow::Result<String> = async {
        let mut tx = state.db.begin().await?;
        let (session, token) = auth::SessionRepository::create(
            &mut tx,
            user.id,
            auth::DEFAULT_SESSION_TTL,
        )
        .await?;
        audit::append(
            &mut tx,
            Some(&actor),
            None,
            "signin_success",
            serde_json::json!({
                "email": user.email,
                "session_id": session.id,
                "via": "web",
            }),
        )
        .await?;
        tx.commit().await?;
        Ok(token)
    }
    .await;

    let token = match result {
        Ok(t) => t,
        Err(err) => {
            tracing::error!(?err, "issuing session");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error");
        }
    };

    let mut response = Redirect::to("/me").into_response();
    set_cookie_header(
        &mut response,
        &cookie_value(SESSION_COOKIE_NAME, &token, /* clearing = */ false),
    );
    response
}

// ────────────────────────────────────────────────────────────────────────
// /invite/{token} — public acceptance page
// ────────────────────────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
pub struct AcceptInviteForm {
    pub display_name: String,
    pub password: String,
}

/// `GET /invite/{token}` — render the acceptance form. Public. We look
/// up the invitation first to confirm the token is still active; if not
/// (expired, revoked, accepted, unknown), render a generic
/// "unavailable" page rather than the form. We don't distinguish those
/// four cases to avoid leaking which tokens ever existed.
pub async fn accept_invite_form(
    State(state): State<AppState>,
    axum::extract::Path(token): axum::extract::Path<String>,
) -> Response {
    match state.invitations.find_active(&token).await {
        Ok(Some(invitation)) => Html(
            views::accept_invite_page(
                &token,
                &invitation.email,
                invitation.instance_role,
                "",
                None,
            )
            .into_string(),
        )
        .into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Html(views::accept_invite_invalid_page().into_string()),
        )
            .into_response(),
        Err(err) => {
            tracing::error!(?err, "looking up invitation for accept form");
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        }
    }
}

/// `POST /invite/{token}` — accept the invitation. On success, sets the
/// `hearth_session` cookie and redirects to `/me`. On validation
/// failure (missing display_name / password), re-renders the form with
/// the entered display_name preserved. On invalid token (raced expiry,
/// concurrent acceptance), renders the "unavailable" page.
pub async fn accept_invite_submit(
    State(state): State<AppState>,
    axum::extract::Path(token): axum::extract::Path<String>,
    Form(form): Form<AcceptInviteForm>,
) -> Response {
    use hearth::auth_routes::{AcceptInviteError, perform_accept_invite};

    match perform_accept_invite(&state, &token, &form.display_name, &form.password).await {
        Ok(outcome) => {
            // Render the recovery-code interstitial as the POST
            // response body — no redirect. Lets the code ride one HTTP
            // exchange and never appear in a URL, history entry, or
            // referer. Session cookie is set on the same response so
            // the user is signed in when they click "Continue" (which
            // is a plain GET to /me).
            let body = views::accept_invite_recovery_code_page(&outcome.recovery_code)
                .into_string();
            let mut response = Html(body).into_response();
            set_cookie_header(
                &mut response,
                &cookie_value(
                    SESSION_COOKIE_NAME,
                    &outcome.raw_session_token,
                    /* clearing = */ false,
                ),
            );
            response
        }
        Err(AcceptInviteError::InvalidOrExpiredToken) => (
            StatusCode::NOT_FOUND,
            Html(views::accept_invite_invalid_page().into_string()),
        )
            .into_response(),
        Err(e) => {
            // For display_name_required / password_required we need to
            // re-fetch the invitation so we can show the email + role
            // in the rendered form. Cheap — one indexed lookup.
            let code = match e {
                AcceptInviteError::DisplayNameRequired => "display_name_required",
                AcceptInviteError::PasswordRequired => "password_required",
                AcceptInviteError::InvalidOrExpiredToken => unreachable!(),
                AcceptInviteError::Internal(err) => {
                    tracing::error!(?err, "accept invite internal error (web)");
                    return error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Internal error",
                    );
                }
            };
            match state.invitations.find_active(&token).await {
                Ok(Some(invitation)) => Html(
                    views::accept_invite_page(
                        &token,
                        &invitation.email,
                        invitation.instance_role,
                        form.display_name.trim(),
                        Some(code),
                    )
                    .into_string(),
                )
                .into_response(),
                Ok(None) => (
                    StatusCode::NOT_FOUND,
                    Html(views::accept_invite_invalid_page().into_string()),
                )
                    .into_response(),
                Err(err) => {
                    tracing::error!(?err, "re-fetching invitation for form rerender");
                    error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
                }
            }
        }
    }
}

/// `GET /me` — render the authenticated user's account page.
pub async fn me_page(
    State(state): State<AppState>,
    BrowserAuth(auth): BrowserAuth,
) -> Response {
    let csrf_token = csrf::compute_token(&state.csrf_secret, auth.session_id);
    let pending_count = pending_count_for(&state, auth.user.instance_role).await;
    let ctx = views::ChromeContext {
        instance_name: &state.instance_name,
        user: &auth.user,
        csrf_token: &csrf_token,
        pending_count,
    };
    Html(views::me_page(&ctx).into_string()).into_response()
}

/// `GET /modals/account-settings` — render the account-settings
/// dialog as a standalone fragment. Modals are no longer baked into
/// every page as `<template>` blocks; instead the shell ships an empty
/// `#modal-host` and the client fetches a modal's markup on demand
/// (then removes it from the DOM on close). See `MODAL_HOST_JS`.
pub async fn account_settings_modal(
    State(state): State<AppState>,
    BrowserAuth(auth): BrowserAuth,
) -> Response {
    let csrf_token = csrf::compute_token(&state.csrf_secret, auth.session_id);
    let ctx = views::ChromeContext {
        instance_name: &state.instance_name,
        user: &auth.user,
        csrf_token: &csrf_token,
        pending_count: None,
    };
    Html(views::account_settings_modal(&ctx).into_string()).into_response()
}

/// `GET /modals/reauth` — render the reauth dialog as a standalone
/// fragment. Fetched on demand by `REAUTH_CHAIN_JS` whenever an action
/// chains through the password gate (account-settings email change,
/// the /members destructive actions, /pending veto, invite). The
/// chain repoints the form's action + stages the originating payload
/// after the fragment lands.
pub async fn reauth_modal(
    State(state): State<AppState>,
    BrowserAuth(auth): BrowserAuth,
) -> Response {
    let csrf_token = csrf::compute_token(&state.csrf_secret, auth.session_id);
    let ctx = views::ChromeContext {
        instance_name: &state.instance_name,
        user: &auth.user,
        csrf_token: &csrf_token,
        pending_count: None,
    };
    Html(views::reauth_modal(&ctx).into_string()).into_response()
}

#[derive(Deserialize)]
pub struct MeProfileForm {
    pub csrf_token: String,
    pub display_name: String,
}

#[derive(Deserialize)]
pub struct MeEmailForm {
    pub csrf_token: String,
    pub email: String,
    pub password: String,
}

/// `POST /me/profile` — update the operator's `display_name` and
/// `locale`. No re-auth required (low-risk, low-friction). Returns the
/// profile-section partial with a success/error feedback tile so HTMX
/// swaps it in place inside the account-settings modal.
pub async fn me_profile_submit(
    State(state): State<AppState>,
    BrowserAuth(auth): BrowserAuth,
    Form(form): Form<MeProfileForm>,
) -> Response {
    if let Err(resp) = check_csrf_token(&state, auth.session_id, &form.csrf_token) {
        return resp;
    }

    let display_name = form.display_name.trim().to_string();
    if display_name.is_empty() {
        return render_name_partial(
            &state,
            auth.session_id,
            &auth.user,
            Some(views::SettingsFeedback::Error(
                "Display name can't be blank.".to_string(),
            )),
        );
    }

    let actor = audit::Actor {
        user_id: auth.user.id,
        display_name: auth.user.display_name.clone(),
    };
    let old_display_name = auth.user.display_name.clone();
    let result: anyhow::Result<identity::User> = async {
        let mut tx = state.db.begin().await?;
        // `update_profile` still takes an optional `locale` slot. We
        // pass `None` here because the settings UI no longer surfaces
        // locale as an editable field — operators don't typically
        // think about BCP-47 tags. Leaving the column intact keeps
        // future server-side locale-aware rendering paths open.
        let user = identity::UserRepository::update_profile(
            &mut tx,
            auth.user.id,
            Some(&display_name),
            None,
        )
        .await?;
        audit::append(
            &mut tx,
            Some(&actor),
            None,
            "profile_updated",
            serde_json::json!({
                "old_display_name": old_display_name,
                "new_display_name": user.display_name,
            }),
        )
        .await?;
        tx.commit().await?;
        Ok(user)
    }
    .await;

    match result {
        Ok(updated) => render_name_partial(
            &state,
            auth.session_id,
            &updated,
            Some(views::SettingsFeedback::Success(
                "Profile updated.".to_string(),
            )),
        ),
        Err(err) => {
            tracing::error!(?err, "me_profile_submit");
            render_name_partial(
                &state,
                auth.session_id,
                &auth.user,
                Some(views::SettingsFeedback::Error(
                    "Something went wrong. Try again.".to_string(),
                )),
            )
        }
    }
}

/// `POST /me/email` — update the operator's login email. Driven from
/// the account-settings modal's email form via the reauth chain:
/// the settings form stages the new email value into a hidden input
/// on `dlg-reauth`, the operator enters their current password
/// there, and HTMX submits the combined payload here.
///
/// Outcomes:
///
/// - **Wrong password** (HTMX) → return the reauth modal content
///   (inner partial) with the `invalid_password` banner so the modal
///   stays open and the operator can retry. Same shape as the admin
///   destructive actions.
/// - **Invalid email shape / email in use / success / no-op** → HX-
///   Redirect to `/me` with a hearth-toast describing the outcome.
///   Closes both modals (reauth + settings) on the way out.
pub async fn me_email_submit(
    State(state): State<AppState>,
    BrowserAuth(auth): BrowserAuth,
    headers: axum::http::HeaderMap,
    Form(form): Form<MeEmailForm>,
) -> Response {
    if let Err(resp) = check_csrf_token(&state, auth.session_id, &form.csrf_token) {
        return resp;
    }
    let htmx = headers.contains_key("hx-request");

    let new_email = form.email.trim().to_string();

    // Verify the current password before touching the row. A stolen
    // session cookie would let an attacker pivot the login email and
    // lock the operator out; the password check makes that an
    // additional credential-theft step. Wrong password keeps the
    // reauth modal open with a banner (HTMX) or bounces with an
    // error toast (non-HTMX edge case).
    let password_ok = match auth::verify_user_password(
        &state.db,
        auth.user.id,
        &form.password,
    )
    .await
    {
        Ok(ok) => ok,
        Err(err) => {
            tracing::error!(?err, "verify_user_password for email change");
            return error_response(
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Internal error",
            );
        }
    };
    if !password_ok {
        return reauth_invalid_password_response(
            &state,
            auth.session_id,
            &auth.user,
            "/me/email",
            &[("email", &new_email)],
            htmx,
        );
    }

    // Cheap "looks like an email" check. Browser-side validation in
    // the settings form (type=email + required, with REAUTH_CHAIN_JS
    // calling reportValidity before staging) makes a malformed value
    // an attacker / scripted-client scenario, not a normal one.
    let valid_shape = new_email
        .split_once('@')
        .map(|(l, r)| !l.is_empty() && !r.is_empty() && r.contains('.'))
        .unwrap_or(false);
    if !valid_shape {
        return redirect_to_me_with_error(htmx, "email_required");
    }

    // No-op short-circuit when the email isn't actually changing.
    if new_email == auth.user.email {
        return redirect_to_me_with_action(htmx, "email_unchanged");
    }

    // Pre-check uniqueness for the friendly toast. The DB's
    // `email_lower` unique index is the source of truth — a race
    // between this check and the UPDATE would surface as an Internal
    // error (vanishingly rare on a single-operator instance).
    let users = identity::UserRepository::new(state.db.clone());
    match users.email_in_use(&new_email).await {
        Ok(true) => return redirect_to_me_with_error(htmx, "email_already_in_use"),
        Ok(false) => {}
        Err(err) => {
            tracing::error!(?err, "email_in_use pre-check");
            return error_response(
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Internal error",
            );
        }
    }

    let actor = audit::Actor {
        user_id: auth.user.id,
        display_name: auth.user.display_name.clone(),
    };
    let old_email = auth.user.email.clone();
    let result: anyhow::Result<()> = async {
        let mut tx = state.db.begin().await?;
        let updated = identity::UserRepository::update_email(
            &mut tx,
            auth.user.id,
            &new_email,
        )
        .await?;
        audit::append(
            &mut tx,
            Some(&actor),
            None,
            "email_changed",
            serde_json::json!({
                "old_email": old_email,
                "new_email": updated.email,
            }),
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }
    .await;

    match result {
        Ok(()) => redirect_to_me_with_action(htmx, "email_updated"),
        Err(err) => {
            tracing::error!(?err, "me_email_submit");
            error_response(
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Internal error",
            )
        }
    }
}

/// Build the "wrong password" response for an account-settings reauth
/// flow. Mirrors the admin pattern: HTMX → reauth modal partial with
/// `invalid_password` banner; non-HTMX → redirect to /me with a
/// generic error toast (rare path; the modal flow requires JS).
fn reauth_invalid_password_response(
    state: &AppState,
    session_id: uuid::Uuid,
    user: &identity::User,
    action_url: &str,
    staged_params: &[(&str, &str)],
    htmx: bool,
) -> Response {
    if !htmx {
        return redirect_to_me_with_error(htmx, "invalid_password");
    }
    let csrf_token = csrf::compute_token(&state.csrf_secret, session_id);
    let ctx = views::ChromeContext {
        instance_name: &state.instance_name,
        user,
        csrf_token: &csrf_token,
        pending_count: None,
    };
    Html(
        views::reauth_modal_content(
            &ctx,
            action_url,
            staged_params,
            Some("invalid_password"),
        )
        .into_string(),
    )
    .into_response()
}

/// HX-Redirect (when HTMX) or 303 (non-HTMX) to `/me` with a positive
/// toast for `action`. Mirrors `admin_routes::redirect_with_action_toast`
/// but scoped to this crate so we don't reach across to `admin_routes`
/// from `routes`.
fn redirect_to_me_with_action(htmx: bool, action: &str) -> Response {
    let toast = views::toast_for_action(action, None);
    attach_toast(redirect_to_me(htmx), toast)
}

/// HX-Redirect (when HTMX) or 303 (non-HTMX) to `/me` with a red
/// error toast looked up against the shared `error_banner_message`
/// catalog.
fn redirect_to_me_with_error(htmx: bool, error_code: &str) -> Response {
    let toast = Some(views::toast_for_error(error_code));
    attach_toast(redirect_to_me(htmx), toast)
}

fn redirect_to_me(htmx: bool) -> Response {
    if htmx {
        let mut resp = (axum::http::StatusCode::OK, "").into_response();
        if let Ok(v) = axum::http::HeaderValue::from_str("/me") {
            resp.headers_mut().insert("HX-Redirect", v);
        }
        resp
    } else {
        Redirect::to("/me").into_response()
    }
}

fn attach_toast(mut response: Response, toast: Option<views::Toast>) -> Response {
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

/// Render the display-name form partial for an HTMX response. Pulled
/// out so the success and error paths share one rendering site —
/// fewer divergent call shapes to keep in sync.
fn render_name_partial(
    state: &AppState,
    session_id: uuid::Uuid,
    user: &identity::User,
    feedback: Option<views::SettingsFeedback>,
) -> Response {
    let csrf_token = csrf::compute_token(&state.csrf_secret, session_id);
    let ctx = views::ChromeContext {
        instance_name: &state.instance_name,
        user,
        csrf_token: &csrf_token,
        pending_count: None,
    };
    Html(views::settings_name_form(&ctx, feedback.as_ref()).into_string())
        .into_response()
}

/// Fetches the active pending-transition count, but only for Owner
/// viewers — Admins and Members never see the sidebar entry and
/// shouldn't pay for the query. Returns `None` on non-Owner; logs and
/// swallows any DB error (the sidebar then just renders without a
/// badge rather than failing the entire page render).
pub(crate) async fn pending_count_for(
    state: &hearth::app::AppState,
    role: identity::InstanceRole,
) -> Option<u32> {
    if role != identity::InstanceRole::Owner {
        return None;
    }
    match pending::count_active(&state.db).await {
        Ok(n) => Some(n),
        Err(err) => {
            tracing::warn!(?err, "pending count for sidebar badge");
            None
        }
    }
}

/// Query params on `/members`. `action` / `target` / `error` carry the
/// post-action banner state; `sort` / `dir` drive server-side row
/// ordering; `filter` narrows the directory by role or lifecycle. All
/// optional — missing values get sensible defaults (`SortColumn::Joined`,
/// `SortDirection::Asc`, `MemberFilter::All`, no banner).
#[derive(Deserialize, Default)]
pub struct MembersPageQuery {
    pub action: Option<String>,
    pub target: Option<String>,
    pub error: Option<String>,
    pub sort: Option<String>,
    pub dir: Option<String>,
    pub filter: Option<String>,
    /// 1-based page index. Out-of-range values get clamped to
    /// `1..=total_pages` server-side once row count is known.
    pub page: Option<u32>,
    /// Rows per page. Anything outside [`views::ROWS_PER_PAGE_OPTIONS`]
    /// falls back to the default so the dropdown's options always
    /// round-trip cleanly.
    pub rows: Option<u32>,
}

fn parse_rows_per_page(s: Option<u32>) -> u32 {
    match s {
        Some(n) if views::ROWS_PER_PAGE_OPTIONS.contains(&n) => n,
        _ => views::DEFAULT_ROWS_PER_PAGE,
    }
}

fn parse_sort_column(s: Option<&str>) -> views::SortColumn {
    match s {
        Some("name") => views::SortColumn::Name,
        Some("role") => views::SortColumn::Role,
        Some("status") => views::SortColumn::Status,
        // "joined" — and anything unrecognised — falls back to the default.
        _ => views::SortColumn::Joined,
    }
}

fn parse_sort_direction(s: Option<&str>) -> views::SortDirection {
    match s {
        Some("desc") => views::SortDirection::Desc,
        _ => views::SortDirection::Asc,
    }
}

/// Sort `users` in place per the requested column + direction. Stable
/// secondary key is `created_at` so equally-ranked users have a
/// deterministic order between page loads.
fn sort_users(users: &mut [identity::User], sort: views::SortState) {
    use views::{SortColumn, SortDirection};

    fn role_rank(r: identity::InstanceRole) -> u8 {
        match r {
            identity::InstanceRole::Owner => 0,
            identity::InstanceRole::Admin => 1,
            identity::InstanceRole::Member => 2,
        }
    }
    fn status_rank(l: identity::UserLifecycle) -> u8 {
        // Surface live accounts first, then dormant, then terminal —
        // matches what an operator usually wants to see at a glance.
        match l {
            identity::UserLifecycle::Active => 0,
            identity::UserLifecycle::PendingInvite => 1,
            identity::UserLifecycle::Deactivated => 2,
            identity::UserLifecycle::SoftDeleted => 3,
            identity::UserLifecycle::HardDeleted => 4,
        }
    }

    users.sort_by(|a, b| {
        let primary = match sort.column {
            SortColumn::Name => a
                .display_name
                .to_lowercase()
                .cmp(&b.display_name.to_lowercase()),
            SortColumn::Role => role_rank(a.instance_role).cmp(&role_rank(b.instance_role)),
            SortColumn::Status => status_rank(a.lifecycle).cmp(&status_rank(b.lifecycle)),
            SortColumn::Joined => a.created_at.cmp(&b.created_at),
        };
        let primary = if sort.direction == SortDirection::Desc {
            primary.reverse()
        } else {
            primary
        };
        primary.then_with(|| a.created_at.cmp(&b.created_at))
    });
}

/// `GET /members` — admin-only directory of every non-purged Member.
/// Mirrors the JSON `/api/admin/members` endpoint shape. Regular members
/// (role = `Member`) get a 403 error page; the Members nav link is
/// hidden from them in the chrome too, so this gate is the defense in
/// depth.
pub async fn members_page(
    State(state): State<AppState>,
    BrowserAuth(auth): BrowserAuth,
    Query(query): Query<MembersPageQuery>,
) -> Response {
    if !matches!(
        auth.user.instance_role,
        identity::InstanceRole::Admin | identity::InstanceRole::Owner,
    ) {
        return error_response(StatusCode::FORBIDDEN, "Admins only.");
    }
    let filter = query
        .filter
        .as_deref()
        .map(views::MemberFilter::parse_token)
        .unwrap_or_default();

    // Two parallel data sets per filter:
    //   members        — rows from identity.users (existing accounts)
    //   pending_invites — rows from identity.invitations not yet
    //                     accepted/revoked/expired
    //
    // Pending invitations don't materialise as `identity.users` rows
    // until accepted, so they need a separate fetch. The filter values
    // decide which set(s) contribute: `All` shows both, `Status(Pending)`
    // shows only pending invites (no member rows), every other filter
    // shows members only.
    let fetch_members = !matches!(
        filter,
        views::MemberFilter::Status(identity::UserLifecycle::PendingInvite)
    );
    let fetch_invites = matches!(
        filter,
        views::MemberFilter::All
            | views::MemberFilter::Status(identity::UserLifecycle::PendingInvite)
    );

    let members_result = if fetch_members {
        match filter {
            views::MemberFilter::Status(lc) => state.users.list_with_lifecycle(lc).await,
            _ => state.users.list_all().await,
        }
    } else {
        Ok(Vec::new())
    };

    let pending_invites_result = if fetch_invites {
        state.invitations.list_pending().await
    } else {
        Ok(Vec::new())
    };

    let (mut members, pending_invites) = match (members_result, pending_invites_result) {
        (Ok(m), Ok(i)) => (m, i),
        (Err(err), _) => {
            tracing::error!(?err, "listing members for /members page");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error");
        }
        (_, Err(err)) => {
            tracing::error!(?err, "listing pending invitations for /members page");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error");
        }
    };

    if let views::MemberFilter::Role(role) = filter {
        members.retain(|u| u.instance_role == role);
    }
    let sort = views::SortState {
        column: parse_sort_column(query.sort.as_deref()),
        direction: parse_sort_direction(query.dir.as_deref()),
    };
    sort_users(&mut members, sort);

    // Pull last-activity timestamps in a single round-trip covering
    // only the filtered+sorted rows. The Members table renders "—" for
    // users absent from the map (never signed in, or never seeded a
    // session). Pending-invite rows always render "—" since they have
    // no user_id to look up.
    let member_ids: Vec<identity::UserId> = members.iter().map(|u| u.id).collect();
    let last_activity = match state.sessions.last_activity_by_user(&member_ids).await {
        Ok(map) => map,
        Err(err) => {
            tracing::error!(?err, "fetching last_activity for members");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error");
        }
    };

    // Combine the two row sources into one sequence so pagination
    // operates on the unified view. Members come first (sorted), then
    // pending invitations. The MemberRow enum gives the renderer a
    // single iteration target with per-variant dispatch.
    let combined: Vec<views::MemberRow> = members
        .iter()
        .map(|u| views::MemberRow::Member {
            user: u,
            last_activity: last_activity.get(&u.id).copied(),
        })
        .chain(pending_invites.iter().map(views::MemberRow::PendingInvite))
        .collect();
    let total_rows = combined.len() as u32;
    let rows_per_page = parse_rows_per_page(query.rows);
    let total_pages = total_rows.div_ceil(rows_per_page).max(1);
    let current_page = query.page.unwrap_or(1).clamp(1, total_pages);
    let start = ((current_page - 1) * rows_per_page) as usize;
    let end = (start + rows_per_page as usize).min(combined.len());
    let page_slice = &combined[start..end];

    let pagination = views::PaginationState {
        current_page,
        total_pages,
        rows_per_page,
        total_rows,
    };

    let csrf_token = csrf::compute_token(&state.csrf_secret, auth.session_id);
    let pending_count = pending_count_for(&state, auth.user.instance_role).await;

    // Fetch active pending transitions that target any of the
    // currently-displayed members so member_row can render a
    // "Pending …" pill. One bulk query keyed by the displayed user
    // ids — Owner-on-Owner pendings are rare, so this typically
    // returns zero rows on any given page load.
    let displayed_target_ids: Vec<uuid::Uuid> = page_slice
        .iter()
        .filter_map(|row| match row {
            views::MemberRow::Member { user, .. } => Some(user.id.0),
            views::MemberRow::PendingInvite(_) => None,
        })
        .collect();
    let pending_rows = match pending::active_by_target_ids(&state.db, &displayed_target_ids).await {
        Ok(rows) => rows,
        Err(err) => {
            tracing::warn!(?err, "fetching active pendings for /members row badges");
            Vec::new()
        }
    };
    let pending_by_target: std::collections::HashMap<uuid::Uuid, &pending::TransitionRow> =
        pending_rows
            .iter()
            .filter_map(|r| r.target_user_id.map(|tid| (tid, r)))
            .collect();

    let ctx = views::ChromeContext {
        instance_name: &state.instance_name,
        user: &auth.user,
        csrf_token: &csrf_token,
        pending_count,
    };
    let banner = views::MembersBanner {
        action: query.action.as_deref(),
        target: query.target.as_deref(),
        error: query.error.as_deref(),
    };
    Html(
        views::members_page(
            &ctx,
            page_slice,
            banner,
            sort,
            filter,
            pagination,
            &pending_by_target,
        )
        .into_string(),
    )
    .into_response()
}

#[derive(Deserialize)]
pub struct CsrfForm {
    pub csrf_token: String,
}

/// Verify a presented CSRF token against the caller's session. On
/// mismatch returns a 403 error page so the user sees an actionable
/// "reload and try again" message rather than a silent failure.
///
/// `Result<_, Response>` is the natural shape (callers do `if let Err(r)
/// = ... { return r; }`); allowing `result_large_err` since boxing a
/// Response just to satisfy the lint would only obscure the call site.
#[allow(clippy::result_large_err)]
pub(crate) fn check_csrf_token(
    state: &AppState,
    session_id: uuid::Uuid,
    presented: &str,
) -> Result<(), Response> {
    if csrf::verify_token(presented, &state.csrf_secret, session_id) {
        Ok(())
    } else {
        Err(error_response(
            StatusCode::FORBIDDEN,
            "Invalid form token. Reload the page and try again.",
        ))
    }
}

/// Convenience wrapper for handlers whose form has nothing but
/// `csrf_token`. Action handlers with extra fields call
/// [`check_csrf_token`] directly.
#[allow(clippy::result_large_err)]
fn check_csrf(state: &AppState, session_id: uuid::Uuid, form: &CsrfForm) -> Result<(), Response> {
    check_csrf_token(state, session_id, &form.csrf_token)
}

/// Gate a handler on the caller having an admin-or-higher role. Returns
/// the same `AdminUser` wrapper that the JSON API uses, so downstream
/// `admin_logic` calls accept it directly.
#[allow(clippy::result_large_err)]
pub(crate) fn require_admin(
    auth: hearth::auth_routes::AuthenticatedUser,
) -> Result<hearth::auth_routes::AdminUser, Response> {
    if matches!(
        auth.user.instance_role,
        identity::InstanceRole::Admin | identity::InstanceRole::Owner,
    ) {
        Ok(hearth::auth_routes::AdminUser(auth))
    } else {
        Err(error_response(StatusCode::FORBIDDEN, "Admins only."))
    }
}

/// `POST /logout` — revoke the current session, clear the cookie, and
/// bounce to `/login` by default. An optional `next` form field
/// overrides the destination when it's a same-origin relative path
/// (`/`-prefixed and not `//`-prefixed); anything else falls back to
/// `/login` via [`safe_logout_next`], so the endpoint can't be used as
/// an open redirect. Used by the user-card popover's quick-switch rows
/// to land on `/login?email=…` pre-filled after signing out. CSRF-
/// protected: a missing/bad token returns 403, so a malicious
/// cross-site form can't log the user out.
pub async fn logout_submit(
    State(state): State<AppState>,
    BrowserAuth(auth): BrowserAuth,
    Form(form): Form<LogoutForm>,
) -> Response {
    if let Err(resp) = check_csrf_token(&state, auth.session_id, &form.csrf_token) {
        return resp;
    }

    let actor = auth.actor();
    let session_id = auth.session_id;
    let result: anyhow::Result<()> = async {
        let mut tx = state.db.begin().await?;
        auth::SessionRepository::revoke(&mut tx, session_id).await?;
        audit::append(
            &mut tx,
            Some(&actor),
            None,
            "signout",
            serde_json::json!({ "session_id": session_id, "via": "web" }),
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }
    .await;

    if let Err(err) = result {
        tracing::error!(?err, "logout");
        // Best-effort: still clear the cookie and redirect.
    }

    let target = safe_logout_next(form.next.as_deref());
    let mut response = Redirect::to(target).into_response();
    set_cookie_header(
        &mut response,
        &cookie_value(SESSION_COOKIE_NAME, "", /* clearing = */ true),
    );
    response
}

/// Form posted to `/logout`. Carries the CSRF token plus an
/// optional `next` redirect target — used by the user-card
/// popover's "quick switch" rows to drop the operator on the
/// login form pre-filled with the other email after signing
/// out.
#[derive(Deserialize)]
pub struct LogoutForm {
    pub csrf_token: String,
    pub next: Option<String>,
}

/// Sanitize the optional `next` redirect target so the logout
/// endpoint can't be weaponized as an open redirect. Only
/// same-origin relative paths starting with a single `/` are
/// accepted; `//attacker.example.com` (protocol-relative) is
/// rejected. Anything missing or malformed falls back to
/// `/login`.
fn safe_logout_next(next: Option<&str>) -> &str {
    match next {
        Some(n) if n.starts_with('/') && !n.starts_with("//") => n,
        _ => "/login",
    }
}

/// Attach a `Set-Cookie` header to a response. The cookie strings this
/// crate produces are ASCII by construction, so the parse can't fail in
/// practice — but we still handle the impossible-case gracefully rather
/// than panic, and log if it ever does.
fn set_cookie_header(response: &mut Response, value: &str) {
    match value.parse::<axum::http::HeaderValue>() {
        Ok(v) => {
            response.headers_mut().insert(axum::http::header::SET_COOKIE, v);
        }
        Err(err) => {
            tracing::error!(?err, raw = value, "cookie header parse failed (impossible)");
        }
    }
}

/// Format a `Set-Cookie` header value. When `clearing` is true, sets
/// `Max-Age=0` to instruct the browser to delete the cookie immediately.
///
/// Flags:
/// - `HttpOnly` — JS in the page can't read the value (matches the
///   defense-in-depth posture we want for session credentials).
/// - `SameSite=Lax` — sent on top-level navigations + GET cross-site;
///   blocked on cross-site POST. Good default for an admin UI.
/// - **`Secure` is intentionally omitted** for this checkpoint because
///   we ship plain HTTP in dev. TLS lands near-MVP; that checkpoint
///   should flip `Secure` on conditionally based on the public base URL
///   scheme.
fn cookie_value(name: &str, value: &str, clearing: bool) -> String {
    if clearing {
        format!("{name}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax")
    } else {
        format!("{name}={value}; Path=/; HttpOnly; SameSite=Lax")
    }
}

pub(crate) fn error_response(status: StatusCode, message: &str) -> Response {
    (
        status,
        Html(views::error_page(status.as_u16(), message).into_string()),
    )
        .into_response()
}
