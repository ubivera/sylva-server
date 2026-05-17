use axum::{
    Form,
    extract::{FromRequestParts, OptionalFromRequestParts, State},
    http::{StatusCode, request::Parts},
    response::{Html, IntoResponse, Redirect, Response},
};
use hearth::{app::AppState, auth_routes::SESSION_COOKIE_NAME};
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

/// `GET /me` — render the authenticated user's account page.
pub async fn me_page(BrowserAuth(auth): BrowserAuth) -> Response {
    Html(views::me_page(&auth.user).into_string()).into_response()
}

/// `POST /logout` — revoke the current session, clear the cookie, bounce
/// to `/login`. Idempotent.
pub async fn logout_submit(
    State(state): State<AppState>,
    BrowserAuth(auth): BrowserAuth,
) -> Response {
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

fn error_response(status: StatusCode, message: &str) -> Response {
    (
        status,
        Html(views::error_page(status.as_u16(), message).into_string()),
    )
        .into_response()
}
