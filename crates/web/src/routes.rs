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
    hearth::rate_limit::ClientIp(client_ip): hearth::rate_limit::ClientIp,
    headers: axum::http::HeaderMap,
    Form(form): Form<LoginForm>,
) -> Response {
    let rl_key = format!("login:{client_ip}");
    if !state.rate_limiter.allowed(&rl_key) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Html(
                views::login_page(
                    Some("Too many attempts. Wait a moment and try again."),
                    None,
                )
                .into_string(),
            ),
        )
            .into_response();
    }

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
            state.rate_limiter.record_failure(&rl_key);
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

    // Password is correct. If the user has any second factor (TOTP or a
    // passkey), don't issue a session yet — hand off to /login/verify
    // with a short-lived, single-purpose cookie instead.
    match hearth::mfa::has_second_factor(&state.db, user.id).await {
        Ok(true) => {
            let mut resp = Redirect::to("/login/verify").into_response();
            set_cookie_header(&mut resp, &mfa_pending_cookie(&state, user.id));
            return resp;
        }
        Ok(false) => {}
        Err(err) => {
            tracing::error!(?err, "login: second-factor check");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error");
        }
    }

    let actor = audit::Actor {
        user_id: user.id,
        display_name: user.display_name.clone(),
    };
    let user_agent = hearth::rate_limit::user_agent(&headers);
    let result: anyhow::Result<String> = async {
        let mut tx = state.db.begin().await?;
        let (session, token) = auth::SessionRepository::create(
            &mut tx,
            user.id,
            auth::DEFAULT_SESSION_TTL,
            user_agent.as_deref(),
            Some(client_ip.as_str()),
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
        &cookie_value(SESSION_COOKIE_NAME, &token, /* clearing = */ false, cookie_secure(&state)),
    );
    response
}

/// `POST /login/passkey/start` — begin a passwordless (discoverable)
/// passkey sign-in. Returns the WebAuthn request options + a challenge id
/// as JSON. Public; lightly rate-limited per IP to bound challenge churn.
pub async fn login_passkey_start(
    State(state): State<AppState>,
    hearth::rate_limit::ClientIp(client_ip): hearth::rate_limit::ClientIp,
) -> Response {
    let rl_key = format!("pklogin:{client_ip}");
    if !state.rate_limiter.allowed(&rl_key) {
        return (StatusCode::TOO_MANY_REQUESTS, "slow down").into_response();
    }
    match hearth::webauthn::start_discoverable(&state).await {
        Ok((challenge_id, options)) => axum::Json(serde_json::json!({
            "challenge_id": challenge_id,
            "options": options,
        }))
        .into_response(),
        Err(err) => {
            tracing::error!(?err, "login_passkey_start");
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        }
    }
}

#[derive(Deserialize)]
pub struct LoginPasskeyFinishForm {
    pub challenge_id: uuid::Uuid,
    pub passkey: String,
}

/// `POST /login/passkey/finish` — complete a passwordless sign-in. The
/// assertion identifies the user (via its user handle); on success we
/// issue a session directly — no password, no second step (a passkey
/// requires user verification, so it's inherently multi-factor). Still
/// gated on the account being **active**, mirroring `verify_credentials`.
pub async fn login_passkey_finish(
    State(state): State<AppState>,
    hearth::rate_limit::ClientIp(client_ip): hearth::rate_limit::ClientIp,
    headers: axum::http::HeaderMap,
    Form(form): Form<LoginPasskeyFinishForm>,
) -> Response {
    let rl_key = format!("login:{client_ip}");
    if !state.rate_limiter.allowed(&rl_key) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Html(
                views::login_page(Some("Too many attempts. Wait a moment and try again."), None)
                    .into_string(),
            ),
        )
            .into_response();
    }

    let user_id = match hearth::webauthn::finish_discoverable(&state, form.challenge_id, &form.passkey)
        .await
    {
        Ok(Some(id)) => id,
        Ok(None) => {
            state.rate_limiter.record_failure(&rl_key);
            return Html(
                views::login_page(
                    Some("Passkey sign-in didn't work. Try again, or sign in with your password."),
                    None,
                )
                .into_string(),
            )
            .into_response();
        }
        Err(err) => {
            tracing::error!(?err, "login_passkey_finish");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error");
        }
    };

    let user = match state.users.find_by_id(user_id).await {
        // Only active accounts may sign in (deactivated / deleted users may
        // still have passkey rows — the password path gates this via the
        // `lifecycle = 'active'` filter, so we must too).
        Ok(Some(u)) if matches!(u.lifecycle, identity::UserLifecycle::Active) => u,
        Ok(_) => {
            state.rate_limiter.record_failure(&rl_key);
            return Html(
                views::login_page(Some("That account can't sign in."), None).into_string(),
            )
            .into_response();
        }
        Err(err) => {
            tracing::error!(?err, "login_passkey_finish: user lookup");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error");
        }
    };

    let user_agent = hearth::rate_limit::user_agent(&headers);
    issue_session_after_mfa(
        &state,
        &user,
        MfaFactor::Passkey,
        user_agent.as_deref(),
        Some(client_ip.as_str()),
    )
    .await
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
    hearth::rate_limit::ClientIp(client_ip): hearth::rate_limit::ClientIp,
    headers: axum::http::HeaderMap,
    axum::extract::Path(token): axum::extract::Path<String>,
    Form(form): Form<AcceptInviteForm>,
) -> Response {
    use hearth::auth_routes::{AcceptInviteError, perform_accept_invite};

    let user_agent = hearth::rate_limit::user_agent(&headers);
    match perform_accept_invite(
        &state,
        &token,
        &form.display_name,
        &form.password,
        user_agent.as_deref(),
        Some(client_ip.as_str()),
    )
    .await
    {
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
                    cookie_secure(&state),
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
    // Recovery-code metadata feeds the Data Control tab's "generated /
    // last used" line. A missing row (e.g. accounts predating CP1, or
    // the provisioned first owner) renders the "no code on file" state;
    // a DB error degrades to the same rather than failing the modal.
    let recovery_meta = auth::user_recovery_code::metadata(&state.db, auth.user.id)
        .await
        .unwrap_or_else(|err| {
            tracing::warn!(?err, "loading recovery-code metadata for settings modal");
            None
        });
    // The user's authenticators drive the Security tab's "Registered
    // Authenticators" list. Degrade to empty on error rather than failing
    // the whole modal.
    let totp_creds = auth::user_totp::list_verified(&state.db, auth.user.id)
        .await
        .unwrap_or_else(|err| {
            tracing::warn!(?err, "loading TOTP credentials for settings modal");
            Vec::new()
        });
    let passkey_creds = hearth::webauthn::list(&state.db, auth.user.id)
        .await
        .unwrap_or_else(|err| {
            tracing::warn!(?err, "loading passkeys for settings modal");
            Vec::new()
        });
    let passkey_available = hearth::webauthn::available(&state);
    // Active sessions drive the Devices tab. Degrade to empty on error.
    let sessions = active_sessions(&state, auth.user.id).await;
    let ctx = views::ChromeContext {
        instance_name: &state.instance_name,
        user: &auth.user,
        csrf_token: &csrf_token,
        pending_count: None,
    };
    Html(
        views::account_settings_modal(
            &ctx,
            recovery_meta.as_ref(),
            &totp_creds,
            &passkey_creds,
            passkey_available,
            &sessions,
            auth.session_id,
            chrono::Utc::now(),
        )
        .into_string(),
    )
    .into_response()
}

/// A user's active (non-revoked, non-expired) sessions, newest first — the
/// rows shown in the Devices panel. Degrades to empty on a DB error.
async fn active_sessions(state: &AppState, user_id: identity::UserId) -> Vec<auth::Session> {
    let now = chrono::Utc::now();
    state
        .sessions
        .list_for_user(user_id)
        .await
        .unwrap_or_else(|err| {
            tracing::warn!(?err, "loading sessions for devices panel");
            Vec::new()
        })
        .into_iter()
        .filter(|s| s.revoked_at.is_none() && s.expires_at > now)
        .collect()
}

/// Re-render the Devices section (`#devices-section`) in a given mode — the
/// response for the section GET, the edit/rename, and both revoke handlers
/// (they target it via `outerHTML`).
async fn sessions_section_response(
    state: &AppState,
    auth: &hearth::auth_routes::AuthenticatedUser,
    mode: views::SectionMode,
) -> Response {
    let sessions = active_sessions(state, auth.user.id).await;
    let csrf_token = csrf::compute_token(&state.csrf_secret, auth.session_id);
    let ctx = views::ChromeContext {
        instance_name: &state.instance_name,
        user: &auth.user,
        csrf_token: &csrf_token,
        pending_count: None,
    };
    Html(
        views::sessions_section(
            &ctx,
            &sessions,
            auth.session_id,
            chrono::Utc::now(),
            mode,
            false,
        )
        .into_string(),
    )
    .into_response()
}

#[derive(Deserialize)]
pub struct SessionActionForm {
    pub csrf_token: String,
}

#[derive(Deserialize)]
pub struct SessionRenameForm {
    pub csrf_token: String,
    pub label: String,
}

/// `GET /me/sessions/section` — refresh the Devices island.
pub async fn me_sessions_section(
    State(state): State<AppState>,
    BrowserAuth(auth): BrowserAuth,
) -> Response {
    sessions_section_response(&state, &auth, views::SectionMode::Normal).await
}

/// `GET /me/sessions/{id}/edit` — swap one device row into its inline
/// rename form.
pub async fn me_session_edit(
    State(state): State<AppState>,
    BrowserAuth(auth): BrowserAuth,
    axum::extract::Path(session_id): axum::extract::Path<uuid::Uuid>,
) -> Response {
    sessions_section_response(&state, &auth, views::SectionMode::Renaming(session_id)).await
}

/// `POST /me/sessions/{id}/rename` — set (or clear) a device's nickname.
/// CSRF-only + owner-scoped. An empty label clears it (reverts to the
/// auto-detected "Browser on OS" name).
pub async fn me_session_rename(
    State(state): State<AppState>,
    BrowserAuth(auth): BrowserAuth,
    axum::extract::Path(session_id): axum::extract::Path<uuid::Uuid>,
    Form(form): Form<SessionRenameForm>,
) -> Response {
    if let Err(resp) = check_csrf_token(&state, auth.session_id, &form.csrf_token) {
        return resp;
    }
    let trimmed = form.label.trim();
    let label: Option<String> = if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.chars().take(60).collect())
    };
    if let Err(err) = state
        .sessions
        .set_label(session_id, auth.user.id, label.as_deref())
        .await
    {
        tracing::error!(?err, "session rename");
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error");
    }
    sessions_section_response(&state, &auth, views::SectionMode::Normal).await
}

/// `POST /me/sessions/{id}/revoke` — sign out one device. CSRF-only (a
/// protective action, not reauth-gated). Only the caller's own sessions can
/// be revoked; an unknown/foreign id is a silent no-op (re-renders the list).
pub async fn me_session_revoke(
    State(state): State<AppState>,
    BrowserAuth(auth): BrowserAuth,
    axum::extract::Path(session_id): axum::extract::Path<uuid::Uuid>,
    Form(form): Form<SessionActionForm>,
) -> Response {
    if let Err(resp) = check_csrf_token(&state, auth.session_id, &form.csrf_token) {
        return resp;
    }
    let owned = matches!(
        state.sessions.find_by_id(session_id).await,
        Ok(Some(s)) if s.user_id == auth.user.id.0
    );
    if owned {
        let actor = audit::Actor {
            user_id: auth.user.id,
            display_name: auth.user.display_name.clone(),
        };
        let result: anyhow::Result<()> = async {
            let mut tx = state.db.begin().await?;
            auth::SessionRepository::revoke(&mut tx, session_id).await?;
            audit::append(
                &mut tx,
                Some(&actor),
                None,
                "session_revoked_by_user",
                serde_json::json!({
                    "session_id": session_id,
                    "was_current": session_id == auth.session_id,
                }),
            )
            .await?;
            tx.commit().await?;
            Ok(())
        }
        .await;
        if let Err(err) = result {
            tracing::error!(?err, "session revoke");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error");
        }
    }
    sessions_section_response(&state, &auth, views::SectionMode::Normal).await
}

/// `POST /me/sessions/revoke-others` — sign out every device except this one.
pub async fn me_sessions_revoke_others(
    State(state): State<AppState>,
    BrowserAuth(auth): BrowserAuth,
    Form(form): Form<SessionActionForm>,
) -> Response {
    if let Err(resp) = check_csrf_token(&state, auth.session_id, &form.csrf_token) {
        return resp;
    }
    let actor = audit::Actor {
        user_id: auth.user.id,
        display_name: auth.user.display_name.clone(),
    };
    let result: anyhow::Result<()> = async {
        let mut tx = state.db.begin().await?;
        let count = auth::SessionRepository::revoke_all_for_user_except(
            &mut tx,
            auth.user.id,
            auth.session_id,
        )
        .await?;
        if count > 0 {
            audit::append(
                &mut tx,
                Some(&actor),
                None,
                "sessions_revoked_by_user",
                serde_json::json!({ "count": count }),
            )
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }
    .await;
    if let Err(err) = result {
        tracing::error!(?err, "sessions revoke-others");
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error");
    }
    sessions_section_response(&state, &auth, views::SectionMode::Normal).await
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
    headers: axum::http::HeaderMap,
) -> Response {
    // Always return the modal shell, but flag whether a fresh sudo grant
    // already covers this user — the chain reads `data-sudo-fresh` to skip
    // the factor step (and still has the shell to host an enrollment QR).
    let fresh = require_fresh_sudo(&state, &headers, auth.user.id);
    let (has_totp, has_passkey) = enrolled_factors(&state, auth.user.id).await;
    let csrf_token = csrf::compute_token(&state.csrf_secret, auth.session_id);
    let ctx = views::ChromeContext {
        instance_name: &state.instance_name,
        user: &auth.user,
        csrf_token: &csrf_token,
        pending_count: None,
    };
    Html(views::reauth_modal(&ctx, has_totp, has_passkey, fresh).into_string()).into_response()
}

#[derive(Deserialize)]
pub struct MeReauthForm {
    pub csrf_token: String,
    pub password: Option<String>,
    pub code: Option<String>,
    pub challenge_id: Option<uuid::Uuid>,
    pub passkey: Option<String>,
}

/// `POST /me/reauth` — step-up reauthentication. Verifies the factors the
/// account's assurance level demands (passkey one-tap; or password, plus
/// the authenticator code when TOTP is enrolled), then mints the
/// `hearth_sudo` grant and fires `reauth-ok` so the chain runs the
/// original action. Rate-limited `reauth:{user_id}`. Never accepts a
/// password alone when a second factor is enrolled (no AAL downgrade).
pub async fn me_reauth_submit(
    State(state): State<AppState>,
    BrowserAuth(auth): BrowserAuth,
    Form(form): Form<MeReauthForm>,
) -> Response {
    if let Err(resp) = check_csrf_token(&state, auth.session_id, &form.csrf_token) {
        return resp;
    }
    let user_id = auth.user.id;
    let rl_key = format!("reauth:{}", user_id.0);
    let (has_totp, has_passkey) = enrolled_factors(&state, user_id).await;

    if !state.rate_limiter.allowed(&rl_key) {
        return reauth_modal_error(
            &state,
            &auth,
            has_totp,
            has_passkey,
            "Too many attempts. Wait a moment and try again.",
        );
    }

    // Passkey path (one-tap, AAL2 by itself).
    if let Some(assertion) = form.passkey.as_deref().filter(|s| !s.is_empty()) {
        let Some(challenge_id) = form.challenge_id else {
            return reauth_modal_error(&state, &auth, has_totp, has_passkey, "Passkey verification failed. Try again.");
        };
        return match hearth::webauthn::finish_authentication(&state, user_id, challenge_id, assertion).await {
            Ok(true) => grant_and_proceed(&state, &auth, "passkey").await,
            Ok(false) => {
                state.rate_limiter.record_failure(&rl_key);
                audit_reauth(&state, &auth, "passkey", false).await;
                reauth_modal_error(&state, &auth, has_totp, has_passkey, "That passkey didn't work. Try again.")
            }
            Err(err) => {
                tracing::error!(?err, "reauth: passkey finish");
                error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            }
        };
    }

    // Password (+ TOTP) path. A passkey-but-no-TOTP account has no
    // password fallback — that would drop below the account's AAL.
    if has_passkey && !has_totp {
        return reauth_modal_error(&state, &auth, has_totp, has_passkey, "Verify with your passkey to continue.");
    }
    let password = form.password.as_deref().unwrap_or("");
    if password.is_empty() {
        return reauth_modal_error(&state, &auth, has_totp, has_passkey, "Enter your password to continue.");
    }
    let password_ok = match auth::verify_user_password(&state.db, user_id, password).await {
        Ok(ok) => ok,
        Err(err) => {
            tracing::error!(?err, "reauth: verify password");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error");
        }
    };
    if !password_ok {
        state.rate_limiter.record_failure(&rl_key);
        audit_reauth(&state, &auth, "password", false).await;
        return reauth_modal_error(&state, &auth, has_totp, has_passkey, "That password is incorrect.");
    }
    if has_totp {
        let code = form.code.as_deref().map(str::trim).unwrap_or("");
        let now = chrono::Utc::now().timestamp();
        match auth::user_totp::verify_and_consume(&state.db, &state.secret_key, user_id, code, now).await {
            Ok(Some(_)) => {}
            Ok(None) => {
                state.rate_limiter.record_failure(&rl_key);
                audit_reauth(&state, &auth, "password+totp", false).await;
                return reauth_modal_error(&state, &auth, has_totp, has_passkey, "That authenticator code didn't match.");
            }
            Err(err) => {
                tracing::error!(?err, "reauth: totp verify");
                return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error");
            }
        }
    }
    let factor = if has_totp { "password+totp" } else { "password" };
    grant_and_proceed(&state, &auth, factor).await
}

/// `POST /me/reauth/passkey/start` — begin a passkey assertion for the
/// logged-in user (step-up). Returns the WebAuthn request options + a
/// challenge id as JSON for the get-ceremony.
pub async fn me_reauth_passkey_start(
    State(state): State<AppState>,
    BrowserAuth(auth): BrowserAuth,
) -> Response {
    match hearth::webauthn::start_authentication(&state, auth.user.id).await {
        Ok(Some((challenge_id, options))) => axum::Json(serde_json::json!({
            "challenge_id": challenge_id,
            "options": options,
        }))
        .into_response(),
        Ok(None) => (StatusCode::BAD_REQUEST, "no passkeys").into_response(),
        Err(err) => {
            tracing::error!(?err, "reauth_passkey_start");
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        }
    }
}

/// Successful step-up: mint the `hearth_sudo` grant + fire `reauth-ok`
/// (204, so htmx swaps nothing) so `REAUTH_CHAIN_JS` runs the original
/// action.
async fn grant_and_proceed(
    state: &AppState,
    auth: &hearth::auth_routes::AuthenticatedUser,
    factor: &str,
) -> Response {
    audit_reauth(state, auth, factor, true).await;
    let mut resp = StatusCode::NO_CONTENT.into_response();
    resp.headers_mut().insert(
        "HX-Trigger",
        axum::http::HeaderValue::from_static("reauth-ok"),
    );
    set_cookie_header(&mut resp, &sudo_grant_cookie(state, auth.user.id));
    resp
}

/// Re-render the reauth modal body with a retry message (HTMX swaps it
/// back into `#reauth-modal-content`).
fn reauth_modal_error(
    state: &AppState,
    auth: &hearth::auth_routes::AuthenticatedUser,
    has_totp: bool,
    has_passkey: bool,
    msg: &str,
) -> Response {
    let csrf_token = csrf::compute_token(&state.csrf_secret, auth.session_id);
    let ctx = views::ChromeContext {
        instance_name: &state.instance_name,
        user: &auth.user,
        csrf_token: &csrf_token,
        pending_count: None,
    };
    Html(views::reauth_modal_content(&ctx, has_totp, has_passkey, Some(msg)).into_string())
        .into_response()
}

/// Best-effort audit of a step-up attempt.
async fn audit_reauth(
    state: &AppState,
    auth: &hearth::auth_routes::AuthenticatedUser,
    factor: &str,
    success: bool,
) {
    let actor = audit::Actor {
        user_id: auth.user.id,
        display_name: auth.user.display_name.clone(),
    };
    let event = if success { "reauth_success" } else { "reauth_failed" };
    let logged: anyhow::Result<()> = async {
        let mut tx = state.db.begin().await?;
        audit::append(
            &mut tx,
            Some(&actor),
            None,
            event,
            serde_json::json!({ "factor": factor }),
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }
    .await;
    if let Err(err) = logged {
        tracing::warn!(?err, "audit reauth");
    }
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
        // `update_profile` takes an optional `locale` slot. We pass
        // `None` here because the settings UI doesn't surface locale as
        // an editable field — operators don't typically think about
        // BCP-47 tags. Leaving the column intact keeps future
        // server-side locale-aware rendering paths open.
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

    // Step-up gate: a fresh sudo grant (minted by POST /me/reauth at the
    // account's assurance level) is required. A stolen session alone
    // can't pivot the login email and lock the operator out.
    if let Err(resp) = require_sudo(&state, &headers, auth.user.id) {
        return resp;
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

#[derive(Deserialize)]
pub struct MePasswordForm {
    pub csrf_token: String,
    /// New password, staged from the Security tab's form. The current
    /// password is no longer collected — the `hearth_sudo` grant is the
    /// reauth.
    pub new_password: String,
}

/// `POST /me/password` — change the operator's password. Driven from
/// the Security tab via the reauth chain: the new password is staged
/// into `dlg-reauth`, the operator confirms their current password
/// there, and HTMX submits both here. Mirrors the JSON
/// `account_routes::change_password` exactly — verify current, hash,
/// replace the verifier, revoke every *other* session, audit
/// `password_changed` — so the two surfaces can't drift.
///
/// Wrong current password (HTMX) re-renders the reauth modal with the
/// `invalid_password` banner and the staged new password preserved.
/// Success HX-Redirects to `/me` with a toast.
pub async fn me_password_submit(
    State(state): State<AppState>,
    BrowserAuth(auth): BrowserAuth,
    headers: axum::http::HeaderMap,
    Form(form): Form<MePasswordForm>,
) -> Response {
    if let Err(resp) = check_csrf_token(&state, auth.session_id, &form.csrf_token) {
        return resp;
    }
    let htmx = headers.contains_key("hx-request");

    // Passwords are never trimmed — leading/trailing whitespace is
    // significant. Empty is the one rejection (matches the JSON API).
    if form.new_password.is_empty() {
        return redirect_to_me_with_error(htmx, "new_password_required");
    }

    // Step-up gate (sudo grant). The new password rides the staged
    // payload; the current-password check is now the reauth grant.
    if let Err(resp) = require_sudo(&state, &headers, auth.user.id) {
        return resp;
    }

    let new_phc = match auth::hash_password(&form.new_password) {
        Ok(h) => h,
        Err(err) => {
            tracing::error!(?err, "hashing new password");
            return error_response(
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Internal error",
            );
        }
    };

    let actor = audit::Actor {
        user_id: auth.user.id,
        display_name: auth.user.display_name.clone(),
    };
    let result: anyhow::Result<()> = async {
        let mut tx = state.db.begin().await?;
        auth::update_password_hash(&mut tx, auth.user.id, &new_phc).await?;
        // Revoke every other session so a stolen token stops working;
        // the caller's own session is kept so they're not logged out by
        // their own action.
        let revoked = auth::SessionRepository::revoke_all_for_user_except(
            &mut tx,
            auth.user.id,
            auth.session_id,
        )
        .await?;
        audit::append(
            &mut tx,
            Some(&actor),
            None,
            "password_changed",
            serde_json::json!({ "other_sessions_revoked": revoked }),
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }
    .await;

    match result {
        // Keep the settings modal open: render a confirmation into the
        // (kept-open) reauth modal rather than navigating away. The
        // current session stays alive; other sessions were revoked above.
        Ok(()) => Html(views::password_changed_success_content().into_string()).into_response(),
        Err(err) => {
            tracing::error!(?err, "me_password_submit");
            error_response(
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Internal error",
            )
        }
    }
}

/// Form for reauth-gated actions that carry no payload of their own (e.g.
/// regenerate recovery code, add authenticator/passkey). Authorization is
/// the `hearth_sudo` grant; only the CSRF token rides along.
#[derive(Deserialize)]
pub struct MeReauthOnlyForm {
    pub csrf_token: String,
}

/// `POST /me/recovery-code/regenerate` — mint a fresh offline recovery
/// code, invalidating the old one. Reauth-gated (the Data Control
/// "Regenerate" button chains through `dlg-reauth` for the current
/// password). On success the new plaintext is shown ONCE, swapped into
/// the reauth modal via [`views::recovery_code_modal_content`] — it
/// rides this single response and is never re-rendered. Only the
/// SHA-256 hash is persisted (`auth::user_recovery_code::rotate`).
pub async fn me_recovery_regenerate(
    State(state): State<AppState>,
    BrowserAuth(auth): BrowserAuth,
    headers: axum::http::HeaderMap,
    Form(form): Form<MeReauthOnlyForm>,
) -> Response {
    if let Err(resp) = check_csrf_token(&state, auth.session_id, &form.csrf_token) {
        return resp;
    }

    if let Err(resp) = require_sudo(&state, &headers, auth.user.id) {
        return resp;
    }

    let new_code = auth::recovery_code::generate_code();
    let actor = audit::Actor {
        user_id: auth.user.id,
        display_name: auth.user.display_name.clone(),
    };
    let result: anyhow::Result<()> = async {
        let mut tx = state.db.begin().await?;
        auth::user_recovery_code::rotate(&mut tx, auth.user.id, &new_code).await?;
        audit::append(
            &mut tx,
            Some(&actor),
            None,
            "recovery_code_rotated",
            serde_json::json!({ "via": "self_service" }),
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }
    .await;

    match result {
        Ok(()) => {
            // Swap the new code into the reauth modal (its form's hx-target
            // is #reauth-modal-content) AND refresh the Data Control "Status"
            // line out-of-band, so it flips from "no code" to "Generated …"
            // without the user reopening the panel.
            let meta = auth::user_recovery_code::metadata(&state.db, auth.user.id)
                .await
                .ok()
                .flatten();
            let body = format!(
                "{}{}",
                views::recovery_code_modal_content(&new_code).into_string(),
                views::recovery_status(meta.as_ref(), true).into_string(),
            );
            Html(body).into_response()
        }
        Err(err) => {
            tracing::error!(?err, "me_recovery_regenerate");
            error_response(
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Internal error",
            )
        }
    }
}

// ────────────────────────────────────────────────────────────────────────
// /me/totp/* — authenticator (TOTP) enrollment, reauth-gated
// ────────────────────────────────────────────────────────────────────────

/// Render a QR code for `data` as an inline SVG string (no raster deps).
/// Empty string on the (practically impossible) too-long-data error.
fn render_qr_svg(data: &str) -> String {
    use qrcode::{QrCode, render::svg};
    match QrCode::new(data.as_bytes()) {
        Ok(code) => code
            .render::<svg::Color<'_>>()
            .min_dimensions(184, 184)
            .quiet_zone(true)
            .dark_color(svg::Color("#101828"))
            .light_color(svg::Color("#ffffff"))
            .build(),
        Err(err) => {
            tracing::error!(?err, "rendering TOTP QR");
            String::new()
        }
    }
}

/// Build the enrollment QR fragment for a freshly-generated (or being-
/// retried) secret + its pending credential id.
fn totp_enroll_response(
    state: &AppState,
    auth: &hearth::auth_routes::AuthenticatedUser,
    secret: &[u8],
    cred_id: uuid::Uuid,
    error: Option<&str>,
) -> Response {
    let secret_b32 = auth::totp::base32_encode(secret);
    let uri = auth::totp::otpauth_uri(&state.instance_name, &auth.user.email, &secret_b32);
    let qr = render_qr_svg(&uri);
    let csrf = csrf::compute_token(&state.csrf_secret, auth.session_id);
    Html(views::totp_enroll_modal_content(&qr, &secret_b32, cred_id, &csrf, error).into_string())
        .into_response()
}

/// Render the authenticators island (`#totp-section`) in a given mode —
/// the response for refresh / edit / rename / delete HTMX swaps.
async fn totp_section_response(
    state: &AppState,
    auth: &hearth::auth_routes::AuthenticatedUser,
    mode: views::SectionMode,
) -> Response {
    let creds = match auth::user_totp::list_verified(&state.db, auth.user.id).await {
        Ok(c) => c,
        Err(err) => {
            tracing::error!(?err, "totp section: list");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error");
        }
    };
    let csrf_token = csrf::compute_token(&state.csrf_secret, auth.session_id);
    let ctx = views::ChromeContext {
        instance_name: &state.instance_name,
        user: &auth.user,
        csrf_token: &csrf_token,
        pending_count: None,
    };
    Html(views::totp_authenticators_section(&ctx, &creds, mode, false).into_string())
        .into_response()
}

/// Trim + clamp a user-supplied authenticator label, defaulting to
/// "Authenticator" when blank.
fn clean_label(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        "Authenticator".to_string()
    } else {
        trimmed.chars().take(60).collect()
    }
}

/// `POST /me/totp/start` — begin enrollment of a new authenticator.
/// Reauth-gated (the "Add Authenticator" button chains through
/// `dlg-reauth`). Generates a secret, stores it encrypted + unverified,
/// and swaps the QR + name + confirm-code fragment into the reauth modal.
pub async fn me_totp_start(
    State(state): State<AppState>,
    BrowserAuth(auth): BrowserAuth,
    headers: axum::http::HeaderMap,
    Form(form): Form<MeReauthOnlyForm>,
) -> Response {
    if let Err(resp) = check_csrf_token(&state, auth.session_id, &form.csrf_token) {
        return resp;
    }

    if let Err(resp) = require_sudo(&state, &headers, auth.user.id) {
        return resp;
    }

    match auth::user_totp::count_verified(&state.db, auth.user.id).await {
        Ok(n) if n >= auth::user_totp::MAX_AUTHENTICATORS => {
            return Html(views::totp_limit_reached_content().into_string()).into_response();
        }
        Ok(_) => {}
        Err(err) => {
            tracing::error!(?err, "totp_start: count");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error");
        }
    }

    let secret = auth::totp::generate_secret();
    let stored: anyhow::Result<uuid::Uuid> = async {
        let mut tx = state.db.begin().await?;
        let id =
            auth::user_totp::start_enrollment(&mut tx, &state.secret_key, auth.user.id, &secret)
                .await?;
        tx.commit().await?;
        Ok(id)
    }
    .await;
    match stored {
        Ok(cred_id) => totp_enroll_response(&state, &auth, &secret, cred_id, None),
        Err(err) => {
            tracing::error!(?err, "totp_start: store secret");
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        }
    }
}

#[derive(Deserialize)]
pub struct MeTotpConfirmForm {
    pub csrf_token: String,
    pub cred_id: uuid::Uuid,
    pub label: String,
    pub code: String,
}

/// `POST /me/totp/confirm` — finish enrollment of the in-progress
/// credential by proving a code. Already reauthenticated at `start`, so
/// no password here. Sets the label + marks verified; on a wrong code,
/// re-renders the QR fragment with an inline error.
pub async fn me_totp_confirm(
    State(state): State<AppState>,
    BrowserAuth(auth): BrowserAuth,
    Form(form): Form<MeTotpConfirmForm>,
) -> Response {
    if let Err(resp) = check_csrf_token(&state, auth.session_id, &form.csrf_token) {
        return resp;
    }

    let secret = match auth::user_totp::load_pending_secret(
        &state.db,
        &state.secret_key,
        auth.user.id,
        form.cred_id,
    )
    .await
    {
        Ok(Some(s)) => s,
        // No matching in-progress enrollment — restart.
        Ok(None) => return redirect_to_me_with_error(true, "totp_setup_expired"),
        Err(err) => {
            tracing::error!(?err, "totp_confirm: load secret");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error");
        }
    };

    let now = chrono::Utc::now().timestamp();
    if !auth::totp::verify_code(&secret, form.code.trim(), now) {
        return totp_enroll_response(
            &state,
            &auth,
            &secret,
            form.cred_id,
            Some("That code didn't match. Try again."),
        );
    }

    let label = clean_label(&form.label);
    let actor = audit::Actor {
        user_id: auth.user.id,
        display_name: auth.user.display_name.clone(),
    };
    let result: anyhow::Result<()> = async {
        let mut tx = state.db.begin().await?;
        auth::user_totp::confirm(&mut tx, auth.user.id, form.cred_id, &label).await?;
        audit::append(
            &mut tx,
            Some(&actor),
            None,
            "totp_enrolled",
            serde_json::json!({ "credential_id": form.cred_id }),
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }
    .await;

    match result {
        Ok(()) => {
            // Success content for the reauth modal, plus an out-of-band
            // refresh of the authenticators list inside the still-open
            // settings modal (it was kept open via data-keep-source-open).
            let creds = auth::user_totp::list_verified(&state.db, auth.user.id)
                .await
                .unwrap_or_default();
            let csrf = csrf::compute_token(&state.csrf_secret, auth.session_id);
            let ctx = views::ChromeContext {
                instance_name: &state.instance_name,
                user: &auth.user,
                csrf_token: &csrf,
                pending_count: None,
            };
            let oob = views::totp_authenticators_section(
                &ctx,
                &creds,
                views::SectionMode::Normal,
                /* oob = */ true,
            );
            Html(format!(
                "{}{}",
                views::totp_enrolled_success_content().into_string(),
                oob.into_string(),
            ))
            .into_response()
        }
        Err(err) => {
            tracing::error!(?err, "totp_confirm: confirm");
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        }
    }
}

/// `GET /me/totp/section` — re-render the authenticators island (used by
/// rename/delete "Cancel").
pub async fn me_totp_section(
    State(state): State<AppState>,
    BrowserAuth(auth): BrowserAuth,
) -> Response {
    totp_section_response(&state, &auth, views::SectionMode::Normal).await
}

/// `GET /me/totp/{id}/edit` — render the island with one row in rename mode.
pub async fn me_totp_edit(
    State(state): State<AppState>,
    BrowserAuth(auth): BrowserAuth,
    axum::extract::Path(cred_id): axum::extract::Path<uuid::Uuid>,
) -> Response {
    totp_section_response(&state, &auth, views::SectionMode::Renaming(cred_id)).await
}

#[derive(Deserialize)]
pub struct MeTotpRenameForm {
    pub csrf_token: String,
    pub label: String,
}

/// `POST /me/totp/{id}/rename` — rename an authenticator (no reauth; a
/// label change isn't security-sensitive). Returns the refreshed island.
pub async fn me_totp_rename(
    State(state): State<AppState>,
    BrowserAuth(auth): BrowserAuth,
    axum::extract::Path(cred_id): axum::extract::Path<uuid::Uuid>,
    Form(form): Form<MeTotpRenameForm>,
) -> Response {
    if let Err(resp) = check_csrf_token(&state, auth.session_id, &form.csrf_token) {
        return resp;
    }
    let label = clean_label(&form.label);
    let result: anyhow::Result<()> = async {
        let mut tx = state.db.begin().await?;
        auth::user_totp::rename(&mut tx, auth.user.id, cred_id, &label).await?;
        tx.commit().await?;
        Ok(())
    }
    .await;
    if let Err(err) = result {
        tracing::error!(?err, "totp_rename");
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error");
    }
    totp_section_response(&state, &auth, views::SectionMode::Normal).await
}

/// `GET /me/totp/{id}/confirm-delete` — render the island with one row in
/// delete-confirm mode.
pub async fn me_totp_confirm_delete(
    State(state): State<AppState>,
    BrowserAuth(auth): BrowserAuth,
    axum::extract::Path(cred_id): axum::extract::Path<uuid::Uuid>,
) -> Response {
    totp_section_response(&state, &auth, views::SectionMode::ConfirmDelete(cred_id)).await
}

#[derive(Deserialize)]
pub struct MeTotpDeleteForm {
    pub csrf_token: String,
}

/// `POST /me/totp/{id}/delete` — remove one authenticator. Returns the
/// refreshed island.
pub async fn me_totp_delete(
    State(state): State<AppState>,
    BrowserAuth(auth): BrowserAuth,
    headers: axum::http::HeaderMap,
    axum::extract::Path(cred_id): axum::extract::Path<uuid::Uuid>,
    Form(form): Form<MeTotpDeleteForm>,
) -> Response {
    if let Err(resp) = check_csrf_token(&state, auth.session_id, &form.csrf_token) {
        return resp;
    }
    // Removing a second factor is reauth-gated: it weakens the account, and
    // dropping a passkey can lower the bar for every other sudo-gated action.
    if let Err(resp) = require_sudo(&state, &headers, auth.user.id) {
        return resp;
    }
    let actor = audit::Actor {
        user_id: auth.user.id,
        display_name: auth.user.display_name.clone(),
    };
    let result: anyhow::Result<bool> = async {
        let mut tx = state.db.begin().await?;
        let removed = auth::user_totp::delete(&mut tx, auth.user.id, cred_id).await?;
        if removed {
            audit::append(
                &mut tx,
                Some(&actor),
                None,
                "totp_removed",
                serde_json::json!({ "credential_id": cred_id }),
            )
            .await?;
        }
        tx.commit().await?;
        Ok(removed)
    }
    .await;
    if let Err(err) = result {
        tracing::error!(?err, "totp_delete");
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error");
    }
    totp_removed_response(&state, &auth).await
}

/// Reauth-modal confirmation ("Authenticator removed") plus an out-of-band
/// refresh of `#totp-section`, returned by the reauth-gated delete handler:
/// the chain swaps the confirmation into the open reauth modal while the
/// OOB section updates the list behind it.
async fn totp_removed_response(
    state: &AppState,
    auth: &hearth::auth_routes::AuthenticatedUser,
) -> Response {
    let creds = match auth::user_totp::list_verified(&state.db, auth.user.id).await {
        Ok(c) => c,
        Err(err) => {
            tracing::error!(?err, "totp removed: list");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error");
        }
    };
    let csrf_token = csrf::compute_token(&state.csrf_secret, auth.session_id);
    let ctx = views::ChromeContext {
        instance_name: &state.instance_name,
        user: &auth.user,
        csrf_token: &csrf_token,
        pending_count: None,
    };
    let message = if creds.is_empty() {
        "That was your last authenticator app."
    } else {
        "The authenticator has been removed."
    };
    let body = format!(
        "{}{}",
        views::factor_removed_content("Authenticator removed", message).into_string(),
        views::totp_authenticators_section(&ctx, &creds, views::SectionMode::Normal, true)
            .into_string(),
    );
    Html(body).into_response()
}

// ────────────────────────────────────────────────────────────────────────
// /me/passkey/* — WebAuthn passkey enrollment + management
// ────────────────────────────────────────────────────────────────────────

/// Render the passkeys island (`#passkey-section`) in a given mode.
async fn passkey_section_response(
    state: &AppState,
    auth: &hearth::auth_routes::AuthenticatedUser,
    mode: views::SectionMode,
) -> Response {
    let creds = match hearth::webauthn::list(&state.db, auth.user.id).await {
        Ok(c) => c,
        Err(err) => {
            tracing::error!(?err, "passkey section: list");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error");
        }
    };
    let available = hearth::webauthn::available(state);
    let csrf_token = csrf::compute_token(&state.csrf_secret, auth.session_id);
    let ctx = views::ChromeContext {
        instance_name: &state.instance_name,
        user: &auth.user,
        csrf_token: &csrf_token,
        pending_count: None,
    };
    Html(
        views::passkey_credentials_section(&ctx, &creds, mode, available, false).into_string(),
    )
    .into_response()
}

/// `POST /me/passkey/start` — begin passkey enrollment. Reauth-gated +
/// keep-source-open (like the authenticator add). Starts the WebAuthn
/// registration ceremony and swaps the create-credential fragment into
/// the reauth modal.
pub async fn me_passkey_start(
    State(state): State<AppState>,
    BrowserAuth(auth): BrowserAuth,
    headers: axum::http::HeaderMap,
    Form(form): Form<MeReauthOnlyForm>,
) -> Response {
    if let Err(resp) = check_csrf_token(&state, auth.session_id, &form.csrf_token) {
        return resp;
    }

    if let Err(resp) = require_sudo(&state, &headers, auth.user.id) {
        return resp;
    }

    match hearth::webauthn::count(&state.db, auth.user.id).await {
        Ok(n) if n >= hearth::webauthn::MAX_PASSKEYS => {
            return Html(views::passkey_limit_reached_content().into_string()).into_response();
        }
        Ok(_) => {}
        Err(err) => {
            tracing::error!(?err, "passkey_start: count");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error");
        }
    }

    match hearth::webauthn::start_registration(&state, &auth.user).await {
        Ok((challenge_id, options)) => {
            let options_json = serde_json::to_string(&options).unwrap_or_else(|_| "{}".to_string());
            let csrf = csrf::compute_token(&state.csrf_secret, auth.session_id);
            Html(
                views::passkey_enroll_modal_content(&options_json, challenge_id, &csrf)
                    .into_string(),
            )
            .into_response()
        }
        Err(err) => {
            tracing::error!(?err, "passkey_start: begin registration");
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        }
    }
}

#[derive(Deserialize)]
pub struct MePasskeyFinishForm {
    pub csrf_token: String,
    pub challenge_id: uuid::Uuid,
    pub label: String,
    pub credential: String,
}

/// `POST /me/passkey/finish` — complete enrollment with the browser's
/// credential. Success swaps a confirmation into the reauth modal + an
/// out-of-band refresh of the passkeys list (settings stayed open).
pub async fn me_passkey_finish(
    State(state): State<AppState>,
    BrowserAuth(auth): BrowserAuth,
    Form(form): Form<MePasskeyFinishForm>,
) -> Response {
    if let Err(resp) = check_csrf_token(&state, auth.session_id, &form.csrf_token) {
        return resp;
    }
    let label = clean_label(&form.label);
    match hearth::webauthn::finish_registration(
        &state,
        &auth.user,
        form.challenge_id,
        &label,
        &form.credential,
    )
    .await
    {
        Ok(()) => {
            let actor = audit::Actor {
                user_id: auth.user.id,
                display_name: auth.user.display_name.clone(),
            };
            let logged: anyhow::Result<()> = async {
                let mut tx = state.db.begin().await?;
                audit::append(
                    &mut tx,
                    Some(&actor),
                    None,
                    "passkey_registered",
                    serde_json::json!({}),
                )
                .await?;
                tx.commit().await?;
                Ok(())
            }
            .await;
            if let Err(err) = logged {
                tracing::error!(?err, "passkey_finish: audit");
            }

            let creds = hearth::webauthn::list(&state.db, auth.user.id)
                .await
                .unwrap_or_default();
            let available = hearth::webauthn::available(&state);
            let csrf = csrf::compute_token(&state.csrf_secret, auth.session_id);
            let ctx = views::ChromeContext {
                instance_name: &state.instance_name,
                user: &auth.user,
                csrf_token: &csrf,
                pending_count: None,
            };
            let oob = views::passkey_credentials_section(
                &ctx,
                &creds,
                views::SectionMode::Normal,
                available,
                /* oob = */ true,
            );
            Html(format!(
                "{}{}",
                views::passkey_enrolled_success_content().into_string(),
                oob.into_string(),
            ))
            .into_response()
        }
        Err(err) => {
            tracing::warn!(?err, "passkey_finish: registration rejected");
            // Re-render the reauth modal slot with a retryable error.
            Html(
                views::passkey_error_content(
                    "We couldn't register that passkey. Please try again.",
                )
                .into_string(),
            )
            .into_response()
        }
    }
}

/// `GET /me/passkey/section` — re-render the passkeys island.
pub async fn me_passkey_section(
    State(state): State<AppState>,
    BrowserAuth(auth): BrowserAuth,
) -> Response {
    passkey_section_response(&state, &auth, views::SectionMode::Normal).await
}

/// `GET /me/passkey/{id}/edit` — island with one row in rename mode.
pub async fn me_passkey_edit(
    State(state): State<AppState>,
    BrowserAuth(auth): BrowserAuth,
    axum::extract::Path(cred_id): axum::extract::Path<uuid::Uuid>,
) -> Response {
    passkey_section_response(&state, &auth, views::SectionMode::Renaming(cred_id)).await
}

/// `POST /me/passkey/{id}/rename` — rename a passkey (no reauth).
pub async fn me_passkey_rename(
    State(state): State<AppState>,
    BrowserAuth(auth): BrowserAuth,
    axum::extract::Path(cred_id): axum::extract::Path<uuid::Uuid>,
    Form(form): Form<MeTotpRenameForm>,
) -> Response {
    if let Err(resp) = check_csrf_token(&state, auth.session_id, &form.csrf_token) {
        return resp;
    }
    let label = clean_label(&form.label);
    if let Err(err) = hearth::webauthn::rename(&state.db, auth.user.id, cred_id, &label).await {
        tracing::error!(?err, "passkey_rename");
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error");
    }
    passkey_section_response(&state, &auth, views::SectionMode::Normal).await
}

/// `GET /me/passkey/{id}/confirm-delete` — island with one row in
/// delete-confirm mode.
pub async fn me_passkey_confirm_delete(
    State(state): State<AppState>,
    BrowserAuth(auth): BrowserAuth,
    axum::extract::Path(cred_id): axum::extract::Path<uuid::Uuid>,
) -> Response {
    passkey_section_response(&state, &auth, views::SectionMode::ConfirmDelete(cred_id)).await
}

/// `POST /me/passkey/{id}/delete` — remove one passkey. Reauth-gated, for
/// the same reason as authenticator removal (see [`me_totp_delete`]).
pub async fn me_passkey_delete(
    State(state): State<AppState>,
    BrowserAuth(auth): BrowserAuth,
    headers: axum::http::HeaderMap,
    axum::extract::Path(cred_id): axum::extract::Path<uuid::Uuid>,
    Form(form): Form<MeTotpDeleteForm>,
) -> Response {
    if let Err(resp) = check_csrf_token(&state, auth.session_id, &form.csrf_token) {
        return resp;
    }
    if let Err(resp) = require_sudo(&state, &headers, auth.user.id) {
        return resp;
    }
    let actor = audit::Actor {
        user_id: auth.user.id,
        display_name: auth.user.display_name.clone(),
    };
    let result: anyhow::Result<()> = async {
        let removed = hearth::webauthn::delete(&state.db, auth.user.id, cred_id).await?;
        if removed {
            let mut tx = state.db.begin().await?;
            audit::append(
                &mut tx,
                Some(&actor),
                None,
                "passkey_removed",
                serde_json::json!({ "credential_id": cred_id }),
            )
            .await?;
            tx.commit().await?;
        }
        Ok(())
    }
    .await;
    if let Err(err) = result {
        tracing::error!(?err, "passkey_delete");
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error");
    }
    passkey_removed_response(&state, &auth).await
}

/// Reauth-modal confirmation ("Passkey removed") plus an out-of-band
/// refresh of `#passkey-section`. Mirror of [`totp_removed_response`].
async fn passkey_removed_response(
    state: &AppState,
    auth: &hearth::auth_routes::AuthenticatedUser,
) -> Response {
    let creds = match hearth::webauthn::list(&state.db, auth.user.id).await {
        Ok(c) => c,
        Err(err) => {
            tracing::error!(?err, "passkey removed: list");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error");
        }
    };
    let available = hearth::webauthn::available(state);
    let csrf_token = csrf::compute_token(&state.csrf_secret, auth.session_id);
    let ctx = views::ChromeContext {
        instance_name: &state.instance_name,
        user: &auth.user,
        csrf_token: &csrf_token,
        pending_count: None,
    };
    let message = if creds.is_empty() {
        "That was your last passkey."
    } else {
        "The passkey has been removed."
    };
    let body = format!(
        "{}{}",
        views::factor_removed_content("Passkey removed", message).into_string(),
        views::passkey_credentials_section(&ctx, &creds, views::SectionMode::Normal, available, true)
            .into_string(),
    );
    Html(body).into_response()
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
        &cookie_value(SESSION_COOKIE_NAME, "", /* clearing = */ true, cookie_secure(&state)),
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

/// Whether auth cookies should carry the `Secure` flag — true when the
/// instance is served over HTTPS (so dev over plain-HTTP localhost still
/// works, while a real https deployment never sends the session cookie in
/// cleartext). Derived from the configured public base URL scheme.
pub(crate) fn cookie_secure(state: &AppState) -> bool {
    state.public_base_url.starts_with("https://")
}

/// Format a `Set-Cookie` header value. When `clearing` is true, sets
/// `Max-Age=0` to instruct the browser to delete the cookie immediately.
///
/// Flags:
/// - `HttpOnly` — JS in the page can't read the value (matches the
///   defense-in-depth posture we want for session credentials).
/// - `SameSite=Lax` — sent on top-level navigations + GET cross-site;
///   blocked on cross-site POST. Good default for an admin UI.
/// - `Secure` — added when `secure` (HTTPS deployment) so the cookie is
///   never transmitted over plaintext; see [`cookie_secure`].
fn cookie_value(name: &str, value: &str, clearing: bool, secure: bool) -> String {
    let sec = if secure { "; Secure" } else { "" };
    if clearing {
        format!("{name}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax{sec}")
    } else {
        format!("{name}={value}; Path=/; HttpOnly; SameSite=Lax{sec}")
    }
}

/// Append a `Set-Cookie` header instead of replacing. Needed when a
/// single response sets more than one cookie (the recovery-reset
/// completion sets the new session cookie *and* clears the recovery
/// cookie) — `set_cookie_header`'s `insert` would drop the first.
fn append_cookie_header(response: &mut Response, value: &str) {
    match value.parse::<axum::http::HeaderValue>() {
        Ok(v) => {
            response.headers_mut().append(axum::http::header::SET_COOKIE, v);
        }
        Err(err) => {
            tracing::error!(?err, raw = value, "cookie header parse failed (impossible)");
        }
    }
}

// ────────────────────────────────────────────────────────────────────────
// /recover — offline forgot-password flow (recovery code → new password)
// ────────────────────────────────────────────────────────────────────────

/// Cookie carrying the single-purpose reset token between `POST
/// /recover` and the `/recover/reset` step. HttpOnly + SameSite=Lax
/// (so a cross-site POST can't drive the reset), short-lived.
const RECOVERY_COOKIE_NAME: &str = "hearth_recovery";

/// How long a verified recovery grant is good for before the user must
/// re-enter their code. 10 minutes — enough to pick a password, short
/// enough that a leaked token has a tiny window.
const RESET_TTL_SECS: i64 = 600;

fn recovery_cookie_value(token: &str, clearing: bool, secure: bool) -> String {
    let sec = if secure { "; Secure" } else { "" };
    if clearing {
        format!("{RECOVERY_COOKIE_NAME}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax{sec}")
    } else {
        format!(
            "{RECOVERY_COOKIE_NAME}={token}; Path=/; Max-Age={RESET_TTL_SECS}; HttpOnly; SameSite=Lax{sec}"
        )
    }
}

/// Pull a named cookie's value out of the `Cookie` request header.
fn read_cookie(headers: &axum::http::HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    raw.split(';')
        .filter_map(|kv| kv.trim().split_once('='))
        .find(|(n, _)| *n == name)
        .map(|(_, value)| value.to_string())
}

/// Resolve the recovery cookie to a verified `UserId`, or `None` if it's
/// missing / tampered / expired.
fn recovery_user_id(
    state: &AppState,
    headers: &axum::http::HeaderMap,
) -> Option<identity::UserId> {
    let token = read_cookie(headers, RECOVERY_COOKIE_NAME)?;
    let now = chrono::Utc::now().timestamp();
    hearth::signed_token::verify(
        &state.csrf_secret,
        hearth::signed_token::PURPOSE_RECOVERY_RESET,
        &token,
        now,
    )
    .map(identity::UserId::new)
}

// ────────────────────────────────────────────────────────────────────────
// /login/verify — second-factor challenge (TOTP, recovery-code bypass)
// ────────────────────────────────────────────────────────────────────────

/// Cookie carrying the "password verified, awaiting second factor" token
/// between `POST /login` and `/login/verify`. Same posture as the
/// recovery cookie: HttpOnly + SameSite=Lax + short-lived.
const MFA_COOKIE_NAME: &str = "hearth_mfa";
/// How long the password-verified grant lasts before the user must
/// re-enter their password. 10 minutes.
const MFA_PENDING_TTL_SECS: i64 = 600;

fn mfa_cookie_value(token: &str, clearing: bool, secure: bool) -> String {
    let sec = if secure { "; Secure" } else { "" };
    if clearing {
        format!("{MFA_COOKIE_NAME}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax{sec}")
    } else {
        format!(
            "{MFA_COOKIE_NAME}={token}; Path=/; Max-Age={MFA_PENDING_TTL_SECS}; HttpOnly; SameSite=Lax{sec}"
        )
    }
}

/// Mint the `hearth_mfa` cookie for a user who passed the password step
/// but still owes a second factor. Used by both web and (indirectly) the
/// login flow.
pub(crate) fn mfa_pending_cookie(state: &AppState, user_id: identity::UserId) -> String {
    let expires_at = chrono::Utc::now().timestamp() + MFA_PENDING_TTL_SECS;
    let token = hearth::signed_token::sign(
        &state.csrf_secret,
        hearth::signed_token::PURPOSE_MFA_PENDING,
        user_id.0,
        expires_at,
    );
    mfa_cookie_value(&token, /* clearing = */ false, cookie_secure(state))
}

/// Resolve the `hearth_mfa` cookie to the pending user, or `None` if it's
/// missing / tampered / expired.
fn mfa_pending_user_id(
    state: &AppState,
    headers: &axum::http::HeaderMap,
) -> Option<identity::UserId> {
    let token = read_cookie(headers, MFA_COOKIE_NAME)?;
    let now = chrono::Utc::now().timestamp();
    hearth::signed_token::verify(
        &state.csrf_secret,
        hearth::signed_token::PURPOSE_MFA_PENDING,
        &token,
        now,
    )
    .map(identity::UserId::new)
}

/// `(has_totp, has_passkey)` for a user — drives both the login challenge
/// page and the step-up reauth modal. Errors degrade to `false`.
async fn enrolled_factors(state: &AppState, user_id: identity::UserId) -> (bool, bool) {
    let has_totp = auth::user_totp::is_enrolled(&state.db, user_id)
        .await
        .unwrap_or(false);
    let has_passkey = hearth::webauthn::has_any(&state.db, user_id)
        .await
        .unwrap_or(false);
    (has_totp, has_passkey)
}

// ── Step-up reauth ("sudo") grant ─────────────────────────────────────────

/// Cookie carrying the "recently reauthenticated" grant that unlocks
/// sensitive actions for a short window. Same posture as `hearth_mfa`:
/// HttpOnly + SameSite=Lax + `Secure` on https + short-lived.
const SUDO_COOKIE_NAME: &str = "hearth_sudo";
/// How long a single reauth stays valid before the user must confirm
/// again. 5 minutes — long enough for a burst of actions, short enough
/// that a walked-up-to session can't act indefinitely.
const SUDO_TTL_SECS: i64 = 300;

fn sudo_cookie_value(token: &str, clearing: bool, secure: bool) -> String {
    let sec = if secure { "; Secure" } else { "" };
    if clearing {
        format!("{SUDO_COOKIE_NAME}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax{sec}")
    } else {
        format!(
            "{SUDO_COOKIE_NAME}={token}; Path=/; Max-Age={SUDO_TTL_SECS}; HttpOnly; SameSite=Lax{sec}"
        )
    }
}

/// Mint the `hearth_sudo` grant for a user who just passed step-up reauth.
fn sudo_grant_cookie(state: &AppState, user_id: identity::UserId) -> String {
    let expires_at = chrono::Utc::now().timestamp() + SUDO_TTL_SECS;
    let token = hearth::signed_token::sign(
        &state.csrf_secret,
        hearth::signed_token::PURPOSE_REAUTH,
        user_id.0,
        expires_at,
    );
    sudo_cookie_value(&token, /* clearing = */ false, cookie_secure(state))
}

/// Resolve the `hearth_sudo` cookie to the user it was granted to, or
/// `None` if missing / tampered / expired.
fn sudo_user_id(state: &AppState, headers: &axum::http::HeaderMap) -> Option<identity::UserId> {
    let token = read_cookie(headers, SUDO_COOKIE_NAME)?;
    let now = chrono::Utc::now().timestamp();
    hearth::signed_token::verify(
        &state.csrf_secret,
        hearth::signed_token::PURPOSE_REAUTH,
        &token,
        now,
    )
    .map(identity::UserId::new)
}

/// Whether the request carries a fresh sudo grant **for this exact user**
/// (so user A's grant can't authorize an action as user B). This is the
/// single check every reauth-gated handler makes.
pub(crate) fn require_fresh_sudo(
    state: &AppState,
    headers: &axum::http::HeaderMap,
    user_id: identity::UserId,
) -> bool {
    sudo_user_id(state, headers) == Some(user_id)
}

/// Gate a sensitive action on a fresh sudo grant. `Ok(())` proceeds; the
/// `Err` is a 403 the operator effectively never sees — the reauth chain
/// pre-checks the grant via `GET /modals/reauth` before submitting, so
/// reaching a handler without one means a direct POST or a grant that
/// expired in the millisecond between the pre-check and the submit.
#[allow(clippy::result_large_err)]
pub(crate) fn require_sudo(
    state: &AppState,
    headers: &axum::http::HeaderMap,
    user_id: identity::UserId,
) -> Result<(), Response> {
    if require_fresh_sudo(state, headers, user_id) {
        Ok(())
    } else {
        Err((
            StatusCode::FORBIDDEN,
            "Please confirm it's you and try again.",
        )
            .into_response())
    }
}

/// `GET /login/verify` — render the second-factor challenge. Bounces to
/// `/login` without a valid pending-MFA cookie.
pub async fn login_verify_page(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Response {
    match mfa_pending_user_id(&state, &headers) {
        Some(uid) => {
            let (has_totp, has_passkey) = enrolled_factors(&state, uid).await;
            Html(views::login_verify_page(None, has_totp, has_passkey).into_string())
                .into_response()
        }
        None => Redirect::to("/login").into_response(),
    }
}

#[derive(Deserialize)]
pub struct LoginVerifyForm {
    pub code: Option<String>,
    pub recovery_code: Option<String>,
    /// WebAuthn assertion JSON (passkey path) + its challenge id.
    pub passkey: Option<String>,
    pub challenge_id: Option<uuid::Uuid>,
}

/// `POST /login/verify` — finish sign-in by checking the second factor:
/// a passkey assertion, a TOTP code, or a recovery code (break-glass).
/// On success issues the real session, clears the pending cookie, and
/// lands `/me`. Rate-limited per user (`mfa:{id}`).
pub async fn login_verify_submit(
    State(state): State<AppState>,
    hearth::rate_limit::ClientIp(client_ip): hearth::rate_limit::ClientIp,
    headers: axum::http::HeaderMap,
    Form(form): Form<LoginVerifyForm>,
) -> Response {
    let user_agent = hearth::rate_limit::user_agent(&headers);
    let user_id = match mfa_pending_user_id(&state, &headers) {
        Some(id) => id,
        None => return Redirect::to("/login").into_response(),
    };
    let (has_totp, has_passkey) = enrolled_factors(&state, user_id).await;

    let rl_key = format!("mfa:{}", user_id.0);
    if !state.rate_limiter.allowed(&rl_key) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Html(
                views::login_verify_page(
                    Some("Too many attempts. Wait a moment and try again."),
                    has_totp,
                    has_passkey,
                )
                .into_string(),
            ),
        )
            .into_response();
    }

    let user = match state.users.find_by_id(user_id).await {
        Ok(Some(u)) => u,
        Ok(None) => return Redirect::to("/login").into_response(),
        Err(err) => {
            tracing::error!(?err, "login_verify: user lookup");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error");
        }
    };

    // Passkey path: a WebAuthn assertion (+ its challenge id), produced
    // by the navigator.credentials.get ceremony.
    if let Some(assertion) = form.passkey.as_deref().filter(|c| !c.is_empty()) {
        let Some(challenge_id) = form.challenge_id else {
            return Redirect::to("/login/verify").into_response();
        };
        match hearth::webauthn::finish_authentication(&state, user_id, challenge_id, assertion).await
        {
            Ok(true) => {
                return issue_session_after_mfa(
                    &state,
                    &user,
                    MfaFactor::Passkey,
                    user_agent.as_deref(),
                    Some(client_ip.as_str()),
                )
                .await;
            }
            Ok(false) => {
                state.rate_limiter.record_failure(&rl_key);
                audit_mfa_failed(&state, &user, "passkey").await;
                return Html(
                    views::login_verify_page(
                        Some("That passkey didn't work. Try again."),
                        has_totp,
                        has_passkey,
                    )
                    .into_string(),
                )
                .into_response();
            }
            Err(err) => {
                tracing::error!(?err, "login_verify: passkey finish");
                return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error");
            }
        }
    }

    // TOTP code path. Verify against every enrolled authenticator and
    // consume the matching one (single-use — a code can't be replayed
    // within its window).
    if let Some(code) = form.code.as_deref().map(str::trim).filter(|c| !c.is_empty()) {
        let now = chrono::Utc::now().timestamp();
        match auth::user_totp::verify_and_consume(&state.db, &state.secret_key, user_id, code, now)
            .await
        {
            Ok(Some(cred_id)) => {
                return issue_session_after_mfa(
                    &state,
                    &user,
                    MfaFactor::Totp(cred_id),
                    user_agent.as_deref(),
                    Some(client_ip.as_str()),
                )
                .await;
            }
            Ok(None) => {
                state.rate_limiter.record_failure(&rl_key);
                audit_mfa_failed(&state, &user, "totp").await;
                return Html(
                    views::login_verify_page(
                        Some("That code didn't match. Try again."),
                        has_totp,
                        has_passkey,
                    )
                    .into_string(),
                )
                .into_response();
            }
            Err(err) => {
                tracing::error!(?err, "login_verify: totp verify");
                return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error");
            }
        }
    }

    // Recovery-code break-glass path.
    if let Some(rc) = form
        .recovery_code
        .as_deref()
        .map(str::trim)
        .filter(|c| !c.is_empty())
    {
        let ok = match verify_recovery_code(&state, user_id, rc).await {
            Ok(ok) => ok,
            Err(err) => {
                tracing::error!(?err, "login_verify: recovery verify");
                return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error");
            }
        };
        if ok {
            return issue_session_after_mfa(
                &state,
                &user,
                MfaFactor::RecoveryCode,
                user_agent.as_deref(),
                Some(client_ip.as_str()),
            )
            .await;
        }
        state.rate_limiter.record_failure(&rl_key);
        audit_mfa_failed(&state, &user, "recovery_code").await;
        return Html(
            views::login_verify_page(
                Some("That recovery code didn't match."),
                has_totp,
                has_passkey,
            )
            .into_string(),
        )
        .into_response();
    }

    Html(
        views::login_verify_page(
            Some("Choose a verification method to continue."),
            has_totp,
            has_passkey,
        )
        .into_string(),
    )
    .into_response()
}

#[derive(Clone, Copy)]
enum MfaFactor {
    /// TOTP, carrying the credential id that accepted the code (stamped
    /// as last-used when the session is issued).
    Totp(uuid::Uuid),
    /// Passkey — `finish_authentication` already stamped the matched
    /// credential, so no id is threaded here.
    Passkey,
    RecoveryCode,
}

impl MfaFactor {
    fn label(self) -> &'static str {
        match self {
            MfaFactor::Totp(_) => "totp",
            MfaFactor::Passkey => "passkey",
            MfaFactor::RecoveryCode => "recovery_code",
        }
    }
}

/// `POST /login/verify/passkey/start` — begin a passkey assertion for the
/// pending-MFA user. Returns the WebAuthn request options (+ a challenge
/// id) as JSON for the browser ceremony. Gated by the `hearth_mfa` cookie.
pub async fn login_verify_passkey_start(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Response {
    let user_id = match mfa_pending_user_id(&state, &headers) {
        Some(id) => id,
        None => {
            return (StatusCode::UNAUTHORIZED, "session expired").into_response();
        }
    };
    match hearth::webauthn::start_authentication(&state, user_id).await {
        Ok(Some((challenge_id, options))) => axum::Json(serde_json::json!({
            "challenge_id": challenge_id,
            "options": options,
        }))
        .into_response(),
        Ok(None) => (StatusCode::BAD_REQUEST, "no passkeys").into_response(),
        Err(err) => {
            tracing::error!(?err, "login_verify_passkey_start");
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        }
    }
}

/// Verify a recovery code for `user_id` (stamps `last_used_at`). Its own
/// transaction; the code stays valid for reuse as the recovery factor.
async fn verify_recovery_code(
    state: &AppState,
    user_id: identity::UserId,
    presented: &str,
) -> anyhow::Result<bool> {
    let mut tx = state.db.begin().await?;
    let ok = auth::user_recovery_code::verify_and_stamp(&mut tx, user_id, presented).await?;
    tx.commit().await?;
    Ok(ok)
}

/// Issue the real session once the second factor has passed: create the
/// session, stamp TOTP usage (if that was the factor), audit
/// `signin_success {mfa}`, set `hearth_session`, clear `hearth_mfa`.
async fn issue_session_after_mfa(
    state: &AppState,
    user: &identity::User,
    factor: MfaFactor,
    user_agent: Option<&str>,
    ip_address: Option<&str>,
) -> Response {
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
            user_agent,
            ip_address,
        )
        .await?;
        if let MfaFactor::Totp(cred_id) = factor {
            auth::user_totp::stamp_used(&mut tx, cred_id).await?;
        }
        audit::append(
            &mut tx,
            Some(&actor),
            None,
            "signin_success",
            serde_json::json!({
                "email": user.email,
                "session_id": session.id,
                "via": "web",
                "mfa": factor.label(),
            }),
        )
        .await?;
        tx.commit().await?;
        Ok(token)
    }
    .await;

    match result {
        Ok(token) => {
            let mut resp = Redirect::to("/me").into_response();
            append_cookie_header(
                &mut resp,
                &cookie_value(SESSION_COOKIE_NAME, &token, /* clearing = */ false, cookie_secure(state)),
            );
            append_cookie_header(&mut resp, &mfa_cookie_value("", /* clearing = */ true, cookie_secure(state)));
            resp
        }
        Err(err) => {
            tracing::error!(?err, "login_verify: issue session");
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        }
    }
}

/// Best-effort audit of a failed second-factor attempt.
async fn audit_mfa_failed(state: &AppState, user: &identity::User, factor: &str) {
    let actor = audit::Actor {
        user_id: user.id,
        display_name: user.display_name.clone(),
    };
    let logged: anyhow::Result<()> = async {
        let mut tx = state.db.begin().await?;
        audit::append(
            &mut tx,
            Some(&actor),
            None,
            "mfa_failed",
            serde_json::json!({ "via": "web", "factor": factor }),
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }
    .await;
    if let Err(err) = logged {
        tracing::error!(?err, "login_verify: audit mfa_failed");
    }
}

#[derive(Deserialize)]
pub struct RecoverForm {
    pub email: String,
    pub recovery_code: String,
}

/// Generic "didn't match" message — never reveals whether it was the
/// email or the code that was wrong, so the page can't be used to probe
/// which emails have accounts.
const RECOVER_GENERIC_ERROR: &str =
    "That email and recovery code didn't match. Check both and try again.";

/// `GET /recover` — public start of the recovery flow.
pub async fn recover_page() -> Response {
    Html(views::recover_page(None).into_string()).into_response()
}

/// `POST /recover` — verify email + recovery code. On success, stamp
/// the code's `last_used_at`, mint a short-lived reset cookie, and send
/// the user to `/recover/reset`. On any failure, re-render with a
/// generic error. Audits `recovery_started` / `recovery_failed`.
pub async fn recover_submit(
    State(state): State<AppState>,
    hearth::rate_limit::ClientIp(client_ip): hearth::rate_limit::ClientIp,
    Form(form): Form<RecoverForm>,
) -> Response {
    let rl_key = format!("recover:{client_ip}");
    if !state.rate_limiter.allowed(&rl_key) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Html(
                views::recover_page(Some(
                    "Too many attempts. Wait a moment and try again.",
                ))
                .into_string(),
            ),
        )
            .into_response();
    }

    let email = form.email.trim();
    let code = form.recovery_code.trim();
    let users = identity::UserRepository::new(state.db.clone());

    let candidate = match users.find_by_email(email).await {
        Ok(u) => u,
        Err(err) => {
            tracing::error!(?err, "recover: user lookup");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error");
        }
    };

    let verified = match candidate {
        Some(user) if user.lifecycle == identity::UserLifecycle::Active => {
            let actor = audit::Actor {
                user_id: user.id,
                display_name: user.display_name.clone(),
            };
            let outcome: anyhow::Result<bool> = async {
                let mut tx = state.db.begin().await?;
                let ok = auth::user_recovery_code::verify_and_stamp(&mut tx, user.id, code).await?;
                let event = if ok { "recovery_started" } else { "recovery_failed" };
                audit::append(
                    &mut tx,
                    Some(&actor),
                    None,
                    event,
                    serde_json::json!({ "via": "web" }),
                )
                .await?;
                tx.commit().await?;
                Ok(ok)
            }
            .await;
            match outcome {
                Ok(true) => Some(user.id),
                Ok(false) => None,
                Err(err) => {
                    tracing::error!(?err, "recover: verify recovery code");
                    return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error");
                }
            }
        }
        _ => {
            // Unknown email or non-active account. Record the attempt
            // (no actor — there may be no real user) without telling the
            // caller which half failed.
            let logged: anyhow::Result<()> = async {
                let mut tx = state.db.begin().await?;
                audit::append(
                    &mut tx,
                    None,
                    None,
                    "recovery_failed",
                    serde_json::json!({ "email": email, "reason": "unknown_or_inactive" }),
                )
                .await?;
                tx.commit().await?;
                Ok(())
            }
            .await;
            if let Err(err) = logged {
                tracing::error!(?err, "recover: audit failed attempt");
            }
            None
        }
    };

    match verified {
        Some(user_id) => {
            let expires_at = chrono::Utc::now().timestamp() + RESET_TTL_SECS;
            let token = hearth::signed_token::sign(
                &state.csrf_secret,
                hearth::signed_token::PURPOSE_RECOVERY_RESET,
                user_id.0,
                expires_at,
            );
            let mut resp = Redirect::to("/recover/reset").into_response();
            set_cookie_header(&mut resp, &recovery_cookie_value(&token, false, cookie_secure(&state)));
            resp
        }
        None => {
            state.rate_limiter.record_failure(&rl_key);
            Html(views::recover_page(Some(RECOVER_GENERIC_ERROR)).into_string()).into_response()
        }
    }
}

#[derive(Deserialize)]
pub struct RecoverResetForm {
    pub new_password: String,
    pub confirm_password: String,
}

/// `GET /recover/reset` — the new-password form, gated by a valid reset
/// cookie. Without one, bounce back to `/recover` to start over.
pub async fn recover_reset_page(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Response {
    match recovery_user_id(&state, &headers) {
        Some(_) => Html(views::recover_reset_page(None).into_string()).into_response(),
        None => Redirect::to("/recover").into_response(),
    }
}

/// `POST /recover/reset` — set the new password. Atomically: update the
/// hash, **rotate the recovery code** (the presented one is burned),
/// revoke every existing session, and issue a fresh session for this
/// device. Shows the new recovery code once, then Continue → `/me`.
/// Audits `recovery_succeeded`.
pub async fn recover_reset_submit(
    State(state): State<AppState>,
    hearth::rate_limit::ClientIp(client_ip): hearth::rate_limit::ClientIp,
    headers: axum::http::HeaderMap,
    Form(form): Form<RecoverResetForm>,
) -> Response {
    let user_id = match recovery_user_id(&state, &headers) {
        Some(id) => id,
        None => return Redirect::to("/recover").into_response(),
    };

    if form.new_password.is_empty() {
        return Html(
            views::recover_reset_page(Some("Enter a new password.")).into_string(),
        )
        .into_response();
    }
    if form.new_password != form.confirm_password {
        return Html(
            views::recover_reset_page(Some("Those passwords don't match.")).into_string(),
        )
        .into_response();
    }

    let users = identity::UserRepository::new(state.db.clone());
    let user = match users.find_any(user_id).await {
        Ok(Some(u)) => u,
        Ok(None) => return Redirect::to("/recover").into_response(),
        Err(err) => {
            tracing::error!(?err, "recover_reset: user lookup");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error");
        }
    };

    let new_phc = match auth::hash_password(&form.new_password) {
        Ok(h) => h,
        Err(err) => {
            tracing::error!(?err, "recover_reset: hash");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error");
        }
    };
    let new_code = auth::recovery_code::generate_code();
    let actor = audit::Actor {
        user_id: user.id,
        display_name: user.display_name.clone(),
    };

    let user_agent = hearth::rate_limit::user_agent(&headers);
    let result: anyhow::Result<String> = async {
        let mut tx = state.db.begin().await?;
        auth::update_password_hash(&mut tx, user.id, &new_phc).await?;
        auth::user_recovery_code::rotate(&mut tx, user.id, &new_code).await?;
        let revoked = auth::SessionRepository::revoke_all_for_user(&mut tx, user.id).await?;
        let (session, token) = auth::SessionRepository::create(
            &mut tx,
            user.id,
            auth::DEFAULT_SESSION_TTL,
            user_agent.as_deref(),
            Some(client_ip.as_str()),
        )
        .await?;
        audit::append(
            &mut tx,
            Some(&actor),
            None,
            "recovery_succeeded",
            serde_json::json!({ "sessions_revoked": revoked, "session_id": session.id }),
        )
        .await?;
        tx.commit().await?;
        Ok(token)
    }
    .await;

    let token = match result {
        Ok(t) => t,
        Err(err) => {
            tracing::error!(?err, "recover_reset: apply");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error");
        }
    };

    // Log this device in (new session) and clear the spent reset cookie.
    let mut resp =
        Html(views::accept_invite_recovery_code_page(&new_code).into_string()).into_response();
    append_cookie_header(
        &mut resp,
        &cookie_value(SESSION_COOKIE_NAME, &token, /* clearing = */ false, cookie_secure(&state)),
    );
    append_cookie_header(&mut resp, &recovery_cookie_value("", /* clearing = */ true, cookie_secure(&state)));
    resp
}

pub(crate) fn error_response(status: StatusCode, message: &str) -> Response {
    (
        status,
        Html(views::error_page(status.as_u16(), message).into_string()),
    )
        .into_response()
}
