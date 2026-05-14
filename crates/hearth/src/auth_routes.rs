use audit::Actor;
use auth::{CredentialOutcome, SessionRepository};
use axum::{
    Json,
    extract::{FromRequestParts, State},
    http::{StatusCode, header::AUTHORIZATION, request::Parts},
    response::IntoResponse,
};
use chrono::{DateTime, Utc};
use identity::{User, UserId};
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

/// Axum extractor that requires a valid Bearer session token.
///
/// Use as a handler parameter:
/// ```ignore
/// async fn handler(user: AuthenticatedUser) -> ... { ... }
/// ```
///
/// 401 on missing, malformed, expired, or revoked tokens.
#[derive(Debug, Clone, Copy)]
pub struct AuthenticatedUser {
    pub user_id: UserId,
    pub session_id: Uuid,
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
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse { error: "internal" }),
                )
            })?
            .ok_or_else(|| unauthorized("invalid_session"))?;

        Ok(AuthenticatedUser {
            user_id: UserId::new(session.user_id),
            session_id: session.id,
        })
    }
}

fn unauthorized(reason: &'static str) -> (StatusCode, Json<ErrorResponse>) {
    (StatusCode::UNAUTHORIZED, Json(ErrorResponse { error: reason }))
}

/// `POST /auth/logout` - revoke the session token in the Authorization
/// header. Idempotent.
pub async fn logout(
    State(state): State<AppState>,
    user: AuthenticatedUser,
) -> impl IntoResponse {
    let actor = state
        .users
        .find_by_id(user.user_id)
        .await
        .ok()
        .flatten()
        .map(|u| Actor {
            user_id: u.id,
            display_name: u.display_name,
        });

    let result: anyhow::Result<()> = async {
        let mut tx = state.db.begin().await?;
        SessionRepository::revoke(&mut tx, user.session_id).await?;
        audit::append(
            &mut tx,
            actor.as_ref(),
            None,
            "signout",
            serde_json::json!({ "session_id": user.session_id }),
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
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: "internal" }),
            )
                .into_response()
        }
    }
}

#[derive(Serialize)]
pub struct MeResponse {
    pub id: Uuid,
    pub email: String,
    pub display_name: String,
    pub instance_role: identity::InstanceRole,
}

/// `GET /me` - return the current authenticated user.
pub async fn me(
    State(state): State<AppState>,
    user: AuthenticatedUser,
) -> impl IntoResponse {
    match state.users.find_by_id(user.user_id).await {
        Ok(Some(u)) => (
            StatusCode::OK,
            Json(MeResponse {
                id: u.id.0,
                email: u.email,
                display_name: u.display_name,
                instance_role: u.instance_role,
            }),
        )
            .into_response(),
        Ok(None) => unauthorized("user_not_found").into_response(),
        Err(err) => {
            tracing::error!(?err, "loading user for /me");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: "internal" }),
            )
                .into_response()
        }
    }
}

