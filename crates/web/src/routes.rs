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
/// authenticated, bounce them to `/me` instead.
pub async fn login_page(auth: Option<BrowserAuth>) -> Response {
    if auth.is_some() {
        Redirect::to("/me").into_response()
    } else {
        Html(views::login_page(None).into_string()).into_response()
    }
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
            return Html(
                views::login_page(Some("Invalid email or password."))
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
            let mut response = Redirect::to("/me").into_response();
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
    let ctx = views::ChromeContext {
        instance_name: &state.instance_name,
        user: &auth.user,
        csrf_token: &csrf_token,
    };
    Html(views::me_page(&ctx).into_string()).into_response()
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
    let ctx = views::ChromeContext {
        instance_name: &state.instance_name,
        user: &auth.user,
        csrf_token: &csrf_token,
    };
    let banner = views::MembersBanner {
        action: query.action.as_deref(),
        target: query.target.as_deref(),
        error: query.error.as_deref(),
    };
    Html(
        views::members_page(&ctx, page_slice, banner, sort, filter, pagination)
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

/// Percent-encode a string for safe use in a URL query value. Keeps
/// unreserved ASCII verbatim and percent-encodes everything else
/// (including non-ASCII UTF-8 bytes).
pub(crate) fn url_encode(s: &str) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(s.len());
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            _ => {
                let _ = write!(out, "%{byte:02X}");
            }
        }
    }
    out
}

/// `POST /logout` — revoke the current session, clear the cookie, bounce
/// to `/login`. Idempotent (modulo CSRF — a missing/bad token still
/// returns 403, so a malicious cross-site form can't log the user out).
pub async fn logout_submit(
    State(state): State<AppState>,
    BrowserAuth(auth): BrowserAuth,
    Form(form): Form<CsrfForm>,
) -> Response {
    if let Err(resp) = check_csrf(&state, auth.session_id, &form) {
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

    let mut response = Redirect::to("/login").into_response();
    set_cookie_header(
        &mut response,
        &cookie_value(SESSION_COOKIE_NAME, "", /* clearing = */ true),
    );
    response
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
