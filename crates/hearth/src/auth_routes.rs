use audit::Actor;
use auth::{CredentialOutcome, SessionRepository};
use axum::{
    Json,
    extract::{FromRequestParts, State},
    http::{StatusCode, header::AUTHORIZATION, request::Parts},
    response::IntoResponse,
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
    Json(req): Json<LoginRequest>,
) -> impl IntoResponse {
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
        Ok(user) => match issue_session(&state, user).await {
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
        Err(why) => {
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

async fn issue_session(state: &AppState, user: User) -> anyhow::Result<LoginResponse> {
    let mut tx = state.db.begin().await?;
    let (session, token) =
        SessionRepository::create(&mut tx, user.id, auth::DEFAULT_SESSION_TTL).await?;

    audit::append(
        &mut tx,
        Some(&Actor {
            user_id: user.id,
            display_name: user.display_name.clone(),
        }),
        None,
        "signin_success",
        serde_json::json!({
            "email": user.email,
            "session_id": session.id,
        }),
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

impl FromRequestParts<AppState> for AuthenticatedUser {
    type Rejection = (StatusCode, Json<ErrorResponse>);

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let header = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| unauthorized("missing_authorization"))?;

        let token = header
            .strip_prefix("Bearer ")
            .ok_or_else(|| unauthorized("missing_bearer_prefix"))?
            .trim();
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

/// `POST /auth/accept-invite` - public endpoint. Given a valid one-time
/// invitation token plus a display name and password, creates the user,
/// stores their password hash, marks the invitation accepted, and issues
/// a session in a single transaction. Returns the same shape as `/auth/login`
/// so the client can drop the response straight into its auth state.
pub async fn accept_invite(
    State(state): State<AppState>,
    Json(req): Json<AcceptInviteRequest>,
) -> impl IntoResponse {
    if req.display_name.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "display_name_required",
            }),
        )
            .into_response();
    }
    if req.password.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "password_required",
            }),
        )
            .into_response();
    }

    let invitation = match state.invitations.find_active(&req.token).await {
        Ok(Some(inv)) => inv,
        Ok(None) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "invalid_or_expired_token",
                }),
            )
                .into_response();
        }
        Err(err) => {
            tracing::error!(?err, "looking up invitation");
            return internal_error().into_response();
        }
    };

    let password_hash = match auth::hash_password(&req.password) {
        Ok(h) => h,
        Err(err) => {
            tracing::error!(?err, "hashing password");
            return internal_error().into_response();
        }
    };

    let result: anyhow::Result<LoginResponse> = async {
        let mut tx = state.db.begin().await?;

        // Create the user with the role embedded in the invitation.
        let new_user_id: Uuid = sqlx::query_scalar(
            "INSERT INTO identity.users (email, display_name, lifecycle, instance_role)
             VALUES ($1, $2, 'active', $3)
             RETURNING id",
        )
        .bind(&invitation.email)
        .bind(req.display_name.trim())
        .bind(invitation.instance_role)
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
            invitation.id,
            UserId::new(new_user_id),
        )
        .await?;

        let (session, raw_token) = SessionRepository::create(
            &mut tx,
            UserId::new(new_user_id),
            auth::DEFAULT_SESSION_TTL,
        )
        .await?;

        let actor = Actor {
            user_id: UserId::new(new_user_id),
            display_name: req.display_name.trim().to_string(),
        };
        audit::append(
            &mut tx,
            Some(&actor),
            None,
            "invite_accepted",
            serde_json::json!({
                "invitation_id": invitation.id.0,
                "email": invitation.email,
                "instance_role": invitation.instance_role,
                "session_id": session.id,
            }),
        )
        .await?;

        tx.commit().await?;

        Ok(LoginResponse {
            token: raw_token,
            expires_at: session.expires_at,
            user_id: new_user_id,
        })
    }
    .await;

    match result {
        Ok(resp) => (StatusCode::CREATED, Json(resp)).into_response(),
        Err(err) => {
            tracing::error!(?err, "accepting invitation");
            internal_error().into_response()
        }
    }
}
