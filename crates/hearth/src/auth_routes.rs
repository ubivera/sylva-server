use audit::Actor;
use auth::{CredentialOutcome, SessionRepository};
use axum::{
    Json,
    extract::{FromRequestParts, State},
    http::{StatusCode, header::AUTHORIZATION, request::Parts},
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Utc};
use identity::{InstanceRole, User, UserId};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::app::AppState;

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub token: String,
    pub expires_at: DateTime<Utc>,
    pub user_id: Uuid,
}

#[derive(Serialize)]
pub struct ErrorResponse {
    pub error: &'static str,
}

/// How long the "password verified, awaiting second factor" token is
/// valid (seconds). Mirrors the web `hearth_mfa` cookie TTL.
const MFA_PENDING_TTL_SECS: i64 = 600;

/// Returned by `/auth/login` (200) when the account has a second factor:
/// the client must call `/auth/login/verify` with `mfa_token` + a code.
#[derive(Serialize)]
pub struct MfaRequiredResponse {
    pub mfa_required: bool,
    pub mfa_token: String,
}

#[derive(Deserialize)]
pub struct LoginVerifyRequest {
    pub mfa_token: String,
    pub code: Option<String>,
    pub recovery_code: Option<String>,
}

/// `POST /auth/login` - exchange `{email, password}` for a session token.
///
/// On success: 200 + `{token, expires_at, user_id}`. The token is bearer
/// material; the client should treat it as a credential.
///
/// On failure (unknown email or wrong password): 401 + a generic error.
/// We deliberately don't tell the client which failure mode hit - the
/// distinction is recorded in the audit log only.
pub async fn login(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<LoginRequest>,
) -> impl IntoResponse {
    // Shares the per-IP "login:" bucket with the web form — both are
    // password guesses from the same client.
    let rl_key = format!("login:{}", crate::rate_limit::client_key(&headers));
    if !state.rate_limiter.allowed(&rl_key) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(ErrorResponse { error: "rate_limited" }),
        )
            .into_response();
    }

    let outcome = match auth::verify_credentials(&state.db, &req.email, &req.password).await {
        Ok(outcome) => outcome,
        Err(err) => {
            tracing::error!(?err, "verify_credentials failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: "internal" }),
            )
                .into_response();
        }
    };

    match outcome {
        Ok(user) => {
            // Password is correct. If the user has a second factor, hand
            // back a single-purpose token instead of a session — the
            // client must complete `/auth/login/verify`.
            match auth::user_totp::is_enrolled(&state.db, user.id).await {
                Ok(true) => {
                    let expires_at =
                        chrono::Utc::now().timestamp() + MFA_PENDING_TTL_SECS;
                    let mfa_token = crate::signed_token::sign(
                        &state.csrf_secret,
                        crate::signed_token::PURPOSE_MFA_PENDING,
                        user.id.0,
                        expires_at,
                    );
                    (StatusCode::OK, Json(MfaRequiredResponse { mfa_required: true, mfa_token }))
                        .into_response()
                }
                Ok(false) => match issue_session(&state, user).await {
                    Ok(resp) => (StatusCode::OK, Json(resp)).into_response(),
                    Err(err) => {
                        tracing::error!(?err, "issuing session");
                        (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(ErrorResponse { error: "internal" }),
                        )
                            .into_response()
                    }
                },
                Err(err) => {
                    tracing::error!(?err, "totp enrollment check");
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ErrorResponse { error: "internal" }),
                    )
                        .into_response()
                }
            }
        }
        Err(why) => {
            state.rate_limiter.record_failure(&rl_key);
            if let Err(err) = audit_signin_failure(&state, &req.email, why).await {
                tracing::error!(?err, "auditing signin failure");
            }
            (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse { error: "invalid_credentials" }),
            )
                .into_response()
        }
    }
}

/// `POST /auth/login/verify` — complete sign-in with a second factor.
/// Takes the `mfa_token` from `/auth/login` plus either a TOTP `code` or
/// a `recovery_code` (break-glass). Rate-limited per user.
pub async fn login_verify(
    State(state): State<AppState>,
    Json(req): Json<LoginVerifyRequest>,
) -> impl IntoResponse {
    let now = chrono::Utc::now().timestamp();
    let user_id = match crate::signed_token::verify(
        &state.csrf_secret,
        crate::signed_token::PURPOSE_MFA_PENDING,
        &req.mfa_token,
        now,
    ) {
        Some(uid) => UserId::new(uid),
        None => {
            return (StatusCode::UNAUTHORIZED, Json(ErrorResponse { error: "mfa_token_invalid" }))
                .into_response();
        }
    };

    let rl_key = format!("mfa:{}", user_id.0);
    if !state.rate_limiter.allowed(&rl_key) {
        return (StatusCode::TOO_MANY_REQUESTS, Json(ErrorResponse { error: "rate_limited" }))
            .into_response();
    }

    let user = match state.users.find_by_id(user_id).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            return (StatusCode::UNAUTHORIZED, Json(ErrorResponse { error: "mfa_token_invalid" }))
                .into_response();
        }
        Err(err) => {
            tracing::error!(?err, "login_verify: user lookup");
            return internal_error().into_response();
        }
    };

    // TOTP code (primary).
    if let Some(code) = req.code.as_deref().map(str::trim).filter(|c| !c.is_empty()) {
        let secret = match auth::user_totp::load_verified_secret(
            &state.db,
            &state.secret_key,
            user_id,
        )
        .await
        {
            Ok(Some(s)) => s,
            Ok(None) => {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(ErrorResponse { error: "mfa_token_invalid" }),
                )
                    .into_response();
            }
            Err(err) => {
                tracing::error!(?err, "login_verify: load secret");
                return internal_error().into_response();
            }
        };
        if auth::totp::verify_code(&secret, code, now) {
            return finish_mfa_session(&state, user, "totp").await;
        }
        state.rate_limiter.record_failure(&rl_key);
        return (StatusCode::UNAUTHORIZED, Json(ErrorResponse { error: "invalid_code" }))
            .into_response();
    }

    // Recovery-code break-glass.
    if let Some(rc) = req
        .recovery_code
        .as_deref()
        .map(str::trim)
        .filter(|c| !c.is_empty())
    {
        let ok = match verify_recovery_code(&state, user_id, rc).await {
            Ok(ok) => ok,
            Err(err) => {
                tracing::error!(?err, "login_verify: recovery verify");
                return internal_error().into_response();
            }
        };
        if ok {
            return finish_mfa_session(&state, user, "recovery_code").await;
        }
        state.rate_limiter.record_failure(&rl_key);
        return (StatusCode::UNAUTHORIZED, Json(ErrorResponse { error: "invalid_code" }))
            .into_response();
    }

    (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: "code_required" })).into_response()
}

async fn verify_recovery_code(
    state: &AppState,
    user_id: UserId,
    presented: &str,
) -> anyhow::Result<bool> {
    let mut tx = state.db.begin().await?;
    let ok = auth::user_recovery_code::verify_and_stamp(&mut tx, user_id, presented).await?;
    tx.commit().await?;
    Ok(ok)
}

async fn finish_mfa_session(state: &AppState, user: User, factor: &str) -> Response {
    match issue_session_with_mfa(state, user, Some(factor)).await {
        Ok(resp) => (StatusCode::OK, Json(resp)).into_response(),
        Err(err) => {
            tracing::error!(?err, "login_verify: issue session");
            internal_error().into_response()
        }
    }
}

async fn issue_session(state: &AppState, user: User) -> anyhow::Result<LoginResponse> {
    issue_session_with_mfa(state, user, None).await
}

/// Issue a session, recording in the audit event which second factor (if
/// any) was used. When the factor was TOTP, also stamps its `last_used_at`
/// in the same transaction.
async fn issue_session_with_mfa(
    state: &AppState,
    user: User,
    mfa: Option<&str>,
) -> anyhow::Result<LoginResponse> {
    let mut tx = state.db.begin().await?;
    let (session, token) =
        SessionRepository::create(&mut tx, user.id, auth::DEFAULT_SESSION_TTL).await?;

    if mfa == Some("totp") {
        auth::user_totp::stamp_used(&mut tx, user.id).await?;
    }

    let mut data = serde_json::json!({
        "email": user.email,
        "session_id": session.id,
    });
    if let Some(factor) = mfa {
        data["mfa"] = serde_json::Value::from(factor);
    }
    audit::append(
        &mut tx,
        Some(&Actor {
            user_id: user.id,
            display_name: user.display_name.clone(),
        }),
        None,
        "signin_success",
        data,
    )
    .await?;

    tx.commit().await?;

    Ok(LoginResponse {
        token,
        expires_at: session.expires_at,
        user_id: user.id.0,
    })
}

async fn audit_signin_failure(
    state: &AppState,
    attempted_email: &str,
    why: CredentialOutcome,
) -> anyhow::Result<()> {
    let mut tx = state.db.begin().await?;

    let (event_type, actor) = match why {
        CredentialOutcome::UnknownEmail => ("signin_failed_unknown_email", None),
        CredentialOutcome::WrongPassword => {
            let user: Option<User> =
                state.users.find_by_email(attempted_email).await.ok().flatten();
            let actor = user.map(|u| Actor {
                user_id: u.id,
                display_name: u.display_name,
            });
            ("signin_failed_password", actor)
        }
    };

    audit::append(
        &mut tx,
        actor.as_ref(),
        None,
        event_type,
        serde_json::json!({ "attempted_email": attempted_email }),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Axum extractor that requires a valid Bearer session token. Eager-loads
/// the full `User` record so handlers (and downstream extractors like
/// `AdminUser`) don't pay for a second DB query.
///
/// 401 on missing, malformed, expired, or revoked tokens. 401 if the
/// associated user vanished between session creation and now (shouldn't
/// happen given FK CASCADE, but defensive).
#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    pub session_id: Uuid,
    pub user: User,
}

impl AuthenticatedUser {
    pub fn actor(&self) -> Actor {
        Actor {
            user_id: self.user.id,
            display_name: self.user.display_name.clone(),
        }
    }
}

/// Name of the cookie carrying the session token for browser clients.
/// API clients still use `Authorization: Bearer <token>`; the extractor
/// accepts either.
pub const SESSION_COOKIE_NAME: &str = "hearth_session";

/// Pull a named cookie's value out of the `Cookie` request header.
/// Returns `None` when the header is missing, unparseable, or the named
/// cookie isn't present.
pub fn extract_cookie(parts: &Parts, name: &str) -> Option<String> {
    let header = parts.headers.get(axum::http::header::COOKIE)?;
    let s = header.to_str().ok()?;
    for kv in s.split(';') {
        let kv = kv.trim();
        if let Some(rest) = kv.strip_prefix(name)
            && let Some(value) = rest.strip_prefix('=')
        {
            return Some(value.to_string());
        }
    }
    None
}

impl FromRequestParts<AppState> for AuthenticatedUser {
    type Rejection = (StatusCode, Json<ErrorResponse>);

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        // Try `Authorization: Bearer <token>` first (API clients), fall back
        // to the `hearth_session` cookie (browser clients). Both reference
        // the same session row.
        let token = bearer_token(parts).or_else(|| extract_cookie(parts, SESSION_COOKIE_NAME));
        let Some(token) = token else {
            return Err(unauthorized("missing_authorization"));
        };
        let token = token.trim();
        if token.is_empty() {
            return Err(unauthorized("empty_token"));
        }

        let session = state
            .sessions
            .find_active(token)
            .await
            .map_err(|err| {
                tracing::error!(?err, "session lookup failed");
                internal_error()
            })?
            .ok_or_else(|| unauthorized("invalid_session"))?;

        let user = state
            .users
            .find_by_id(UserId::new(session.user_id))
            .await
            .map_err(|err| {
                tracing::error!(?err, "user lookup failed");
                internal_error()
            })?
            .ok_or_else(|| unauthorized("user_not_found"))?;

        Ok(AuthenticatedUser {
            session_id: session.id,
            user,
        })
    }
}

/// Extract the bearer token from the `Authorization` header, if present.
fn bearer_token(parts: &Parts) -> Option<String> {
    let header = parts.headers.get(AUTHORIZATION)?.to_str().ok()?;
    header
        .strip_prefix("Bearer ")
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
}

/// Axum extractor that requires an authenticated user *and* at least the
/// `Admin` instance role. Wraps `AuthenticatedUser`; rejects with 403 if
/// the user is below Admin (per `authz::satisfies`).
#[derive(Debug, Clone)]
pub struct AdminUser(pub AuthenticatedUser);

impl AdminUser {
    pub fn actor(&self) -> Actor {
        self.0.actor()
    }
}

impl FromRequestParts<AppState> for AdminUser {
    type Rejection = (StatusCode, Json<ErrorResponse>);

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let authed = AuthenticatedUser::from_request_parts(parts, state).await?;
        if authz::satisfies(authed.user.instance_role, InstanceRole::Admin) {
            Ok(AdminUser(authed))
        } else {
            Err((
                StatusCode::FORBIDDEN,
                Json(ErrorResponse { error: "forbidden" }),
            ))
        }
    }
}

fn unauthorized(reason: &'static str) -> (StatusCode, Json<ErrorResponse>) {
    (StatusCode::UNAUTHORIZED, Json(ErrorResponse { error: reason }))
}

fn internal_error() -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorResponse { error: "internal" }),
    )
}

/// `POST /auth/logout` - revoke the session token in the Authorization
/// header. Idempotent.
pub async fn logout(
    State(state): State<AppState>,
    user: AuthenticatedUser,
) -> impl IntoResponse {
    let actor = user.actor();
    let session_id = user.session_id;

    let result: anyhow::Result<()> = async {
        let mut tx = state.db.begin().await?;
        SessionRepository::revoke(&mut tx, session_id).await?;
        audit::append(
            &mut tx,
            Some(&actor),
            None,
            "signout",
            serde_json::json!({ "session_id": session_id }),
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }
    .await;

    match result {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(err) => {
            tracing::error!(?err, "logout");
            internal_error().into_response()
        }
    }
}

#[derive(Serialize)]
pub struct MeResponse {
    pub id: Uuid,
    pub email: String,
    pub display_name: String,
    pub instance_role: InstanceRole,
}

/// `GET /me` - return the current authenticated user.
pub async fn me(user: AuthenticatedUser) -> impl IntoResponse {
    let AuthenticatedUser { user, .. } = user;
    (
        StatusCode::OK,
        Json(MeResponse {
            id: user.id.0,
            email: user.email,
            display_name: user.display_name,
            instance_role: user.instance_role,
        }),
    )
}

#[derive(Deserialize)]
pub struct AcceptInviteRequest {
    pub token: String,
    pub display_name: String,
    pub password: String,
}

/// `POST /auth/accept-invite` success response. Mirrors `LoginResponse`'s
/// session shape and adds the one-time `recovery_code` plaintext. The
/// code is the offline-first recovery factor for forgot-password / lost-
/// MFA / lost-passkey flows; the caller must surface it to the new user
/// once and warn them that it won't be shown again.
#[derive(Serialize)]
pub struct AcceptInviteResponse {
    pub token: String,
    pub expires_at: DateTime<Utc>,
    pub user_id: Uuid,
    pub recovery_code: String,
}

/// What `perform_accept_invite` returns on success: the new user id,
/// the issued session row, the raw session token to hand to the caller
/// (cookie for web, JSON for API), and the one-time-display recovery
/// code stamped into `auth.user_recovery_codes`. The session row is
/// included for `expires_at` so JSON callers can mirror the
/// `/auth/login` shape.
///
/// `recovery_code` is plaintext — the only place it ever leaves the DB.
/// The web caller renders it in a one-time interstitial; the JSON caller
/// returns it in the response body. Callers must treat it like a
/// password: never log, never persist.
pub struct AcceptInviteOutcome {
    pub user_id: UserId,
    pub session: auth::Session,
    pub raw_session_token: String,
    pub recovery_code: String,
}

#[derive(thiserror::Error, Debug)]
pub enum AcceptInviteError {
    #[error("display_name_required")]
    DisplayNameRequired,
    #[error("password_required")]
    PasswordRequired,
    #[error("invalid_or_expired_token")]
    InvalidOrExpiredToken,
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

/// Materialize an account from a one-time invitation token. Creates the
/// user, stores the password hash, marks the invitation accepted, and
/// issues a session — all in a single transaction so a partial accept
/// can't leave the invitation row inconsistent with the user/credential
/// rows. Shared by the JSON [`accept_invite`] handler and the web
/// `/invite/{token}` flow.
pub async fn perform_accept_invite(
    state: &AppState,
    raw_invite_token: &str,
    display_name: &str,
    password: &str,
) -> Result<AcceptInviteOutcome, AcceptInviteError> {
    let trimmed_name = display_name.trim();
    if trimmed_name.is_empty() {
        return Err(AcceptInviteError::DisplayNameRequired);
    }
    if password.is_empty() {
        return Err(AcceptInviteError::PasswordRequired);
    }

    let invitation = state
        .invitations
        .find_active(raw_invite_token)
        .await
        .map_err(|e| AcceptInviteError::Internal(e.into()))?
        .ok_or(AcceptInviteError::InvalidOrExpiredToken)?;

    let password_hash =
        auth::hash_password(password).map_err(|e| AcceptInviteError::Internal(e.into()))?;

    let display_name_owned = trimmed_name.to_string();
    let invitation_id = invitation.id;
    let invitation_email = invitation.email.clone();
    let invitation_role = invitation.instance_role;

    let result: anyhow::Result<AcceptInviteOutcome> = async {
        let mut tx = state.db.begin().await?;

        // Create the user with the role embedded in the invitation. The
        // `kind` column defaults to `'member'` per the migration so we
        // don't need to set it explicitly.
        let new_user_id: Uuid = sqlx::query_scalar(
            "INSERT INTO identity.users (email, display_name, lifecycle, instance_role)
             VALUES ($1, $2, 'active', $3)
             RETURNING id",
        )
        .bind(&invitation_email)
        .bind(&display_name_owned)
        .bind(invitation_role)
        .fetch_one(&mut *tx)
        .await?;

        sqlx::query(
            "INSERT INTO auth.credentials (user_id, password_hash) VALUES ($1, $2)",
        )
        .bind(new_user_id)
        .bind(&password_hash)
        .execute(&mut *tx)
        .await?;

        identity::InvitationRepository::mark_accepted(
            &mut tx,
            invitation_id,
            UserId::new(new_user_id),
        )
        .await?;

        let (session, raw_session_token) = SessionRepository::create(
            &mut tx,
            UserId::new(new_user_id),
            auth::DEFAULT_SESSION_TTL,
        )
        .await?;

        // Generate the user's offline recovery code and bootstrap the
        // `auth.user_recovery_codes` row in the same transaction so the
        // code's existence is atomic with the account itself — we never
        // ship a member account without a recovery code. Plaintext is
        // returned to the caller for one-time display; only the SHA-256
        // hash goes to the DB.
        let recovery_code = auth::recovery_code::generate_code();
        auth::user_recovery_code::bootstrap(
            &mut tx,
            UserId::new(new_user_id),
            &recovery_code,
        )
        .await?;

        let actor = Actor {
            user_id: UserId::new(new_user_id),
            display_name: display_name_owned.clone(),
        };
        audit::append(
            &mut tx,
            Some(&actor),
            None,
            "invite_accepted",
            serde_json::json!({
                "invitation_id": invitation_id.0,
                "email": invitation_email,
                "instance_role": invitation_role,
                "session_id": session.id,
            }),
        )
        .await?;
        // Separate audit row for the recovery code so an ops reader can
        // see "code was generated at invite acceptance" in the log
        // without having to infer it from the `invite_accepted` payload.
        // The plaintext is intentionally *not* in the event — only the
        // fact that a code was issued.
        audit::append(
            &mut tx,
            Some(&actor),
            None,
            "recovery_code_generated",
            serde_json::json!({
                "via": "invite_accepted",
                "user_id": new_user_id,
            }),
        )
        .await?;

        tx.commit().await?;

        Ok(AcceptInviteOutcome {
            user_id: UserId::new(new_user_id),
            session,
            raw_session_token,
            recovery_code,
        })
    }
    .await;

    result.map_err(AcceptInviteError::Internal)
}

/// `POST /auth/accept-invite` - public endpoint. Given a valid one-time
/// invitation token plus a display name and password, creates the user,
/// stores their password hash, marks the invitation accepted, and issues
/// a session in a single transaction. Returns the same shape as `/auth/login`
/// so the client can drop the response straight into its auth state.
pub async fn accept_invite(
    State(state): State<AppState>,
    Json(req): Json<AcceptInviteRequest>,
) -> Response {
    match perform_accept_invite(&state, &req.token, &req.display_name, &req.password).await {
        Ok(outcome) => {
            // Distinct shape from `LoginResponse` so the recovery code
            // surfaces exactly here and nowhere else — sign-in via
            // `/auth/login` doesn't and shouldn't return it. Adding it
            // to `LoginResponse` would be additive and backward-compat
            // but would imply the code rides every auth response.
            let resp = AcceptInviteResponse {
                token: outcome.raw_session_token,
                expires_at: outcome.session.expires_at,
                user_id: outcome.user_id.0,
                recovery_code: outcome.recovery_code,
            };
            (StatusCode::CREATED, Json(resp)).into_response()
        }
        Err(AcceptInviteError::DisplayNameRequired) => (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse { error: "display_name_required" }),
        )
            .into_response(),
        Err(AcceptInviteError::PasswordRequired) => (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse { error: "password_required" }),
        )
            .into_response(),
        Err(AcceptInviteError::InvalidOrExpiredToken) => (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse { error: "invalid_or_expired_token" }),
        )
            .into_response(),
        Err(AcceptInviteError::Internal(err)) => {
            tracing::error!(?err, "accepting invitation");
            internal_error().into_response()
        }
    }
}
