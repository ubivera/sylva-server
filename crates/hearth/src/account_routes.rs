use audit::ListFilter;
use auth::SessionRepository;
use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use chrono::{DateTime, Utc};
use identity::{InstanceRole, UserRepository};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    app::AppState,
    auth_routes::AuthenticatedUser,
    views::{AuditEventView, PaginatedAudit, SessionView},
};

#[derive(Serialize)]
struct ErrorResponse {
    error: &'static str,
}

fn err(code: StatusCode, error: &'static str) -> (StatusCode, Json<ErrorResponse>) {
    (code, Json(ErrorResponse { error }))
}

#[derive(Deserialize)]
pub struct ActivityQuery {
    pub limit: Option<u32>,
    pub cursor: Option<i64>,
    pub since: Option<DateTime<Utc>>,
}

/// `GET /account/activity` — paginated audit log scoped to the calling
/// user (`actor_user_id = self`). Newest first.
pub async fn activity(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Query(q): Query<ActivityQuery>,
) -> impl IntoResponse {
    let filter = ListFilter {
        actor: Some(user.user.id.0),
        since: q.since,
        before_seqno: q.cursor,
        limit: q.limit,
    };

    match audit::list(&state.db, &filter).await {
        Ok(events) => {
            let next_cursor = next_cursor(&events, q.limit);
            let items: Vec<AuditEventView> = events.into_iter().map(Into::into).collect();
            (StatusCode::OK, Json(PaginatedAudit { items, next_cursor })).into_response()
        }
        Err(e) => {
            tracing::error!(?e, "listing personal activity");
            err(StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response()
        }
    }
}

/// `GET /account/sessions` — the caller's sessions (active + historical).
/// The session making this request is flagged with `is_current: true`.
pub async fn list_sessions(
    State(state): State<AppState>,
    user: AuthenticatedUser,
) -> impl IntoResponse {
    match state.sessions.list_for_user(user.user.id).await {
        Ok(sessions) => {
            let current = user.session_id;
            let views: Vec<SessionView> = sessions
                .into_iter()
                .map(|s| SessionView::from_with_current(s, current))
                .collect();
            (StatusCode::OK, Json(views)).into_response()
        }
        Err(e) => {
            tracing::error!(?e, "listing my sessions");
            err(StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response()
        }
    }
}

/// `POST /account/sessions/{id}/revoke` — revoke one of my own sessions.
///
/// Returns 404 (not 403) if the session doesn't exist *or* belongs to
/// another user, so this endpoint can't be used to probe which session
/// IDs exist across the system.
pub async fn revoke_session(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(session_id): Path<Uuid>,
) -> impl IntoResponse {
    let session = match state.sessions.find_by_id(session_id).await {
        Ok(Some(s)) => s,
        Ok(None) => return err(StatusCode::NOT_FOUND, "session_not_found").into_response(),
        Err(e) => {
            tracing::error!(?e, "lookup session");
            return err(StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response();
        }
    };

    if session.user_id != user.user.id.0 {
        return err(StatusCode::NOT_FOUND, "session_not_found").into_response();
    }

    let actor = user.actor();
    let result: anyhow::Result<()> = async {
        let mut tx = state.db.begin().await?;
        SessionRepository::revoke(&mut tx, session_id).await?;
        audit::append(
            &mut tx,
            Some(&actor),
            None,
            "session_revoked_by_user",
            serde_json::json!({
                "session_id": session_id,
                "was_current": session_id == user.session_id,
            }),
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }
    .await;

    match result {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => {
            tracing::error!(?e, "revoking session");
            err(StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response()
        }
    }
}

#[derive(Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

#[derive(Serialize)]
pub struct ChangePasswordResponse {
    pub sessions_revoked: u64,
}

/// `POST /account/password` — change the caller's password.
///
/// Verifies the current password first (auth check). On success, hashes
/// the new password, replaces the stored verifier, **revokes every other
/// active session for this user** (so stolen tokens stop working), and
/// emits a `password_changed` audit event. The current session stays
/// active so the caller doesn't get logged out by their own action.
pub async fn change_password(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Json(req): Json<ChangePasswordRequest>,
) -> impl IntoResponse {
    if req.new_password.is_empty() {
        return err(StatusCode::BAD_REQUEST, "new_password_required").into_response();
    }

    let outcome = match auth::verify_credentials(
        &state.db,
        &user.user.email,
        &req.current_password,
    )
    .await
    {
        Ok(o) => o,
        Err(e) => {
            tracing::error!(?e, "verifying current password");
            return err(StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response();
        }
    };

    if outcome.is_err() {
        return err(StatusCode::UNAUTHORIZED, "current_password_wrong").into_response();
    }

    let new_phc = match auth::hash_password(&req.new_password) {
        Ok(h) => h,
        Err(e) => {
            tracing::error!(?e, "hashing new password");
            return err(StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response();
        }
    };

    let actor = user.actor();
    let user_id = user.user.id;
    let session_id = user.session_id;

    let result: anyhow::Result<u64> = async {
        let mut tx = state.db.begin().await?;
        auth::update_password_hash(&mut tx, user_id, &new_phc).await?;
        let revoked = SessionRepository::revoke_all_for_user_except(
            &mut tx, user_id, session_id,
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
        Ok(revoked)
    }
    .await;

    match result {
        Ok(revoked) => (
            StatusCode::OK,
            Json(ChangePasswordResponse {
                sessions_revoked: revoked,
            }),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(?e, "changing password");
            err(StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response()
        }
    }
}

#[derive(Deserialize)]
pub struct UpdateProfileRequest {
    /// `Some(name)` to set; `None` (or absent) to leave unchanged.
    pub display_name: Option<String>,
    /// Same semantics. Locale is stored as a free-form string.
    pub locale: Option<String>,
}

#[derive(Serialize)]
pub struct ProfileResponse {
    pub id: Uuid,
    pub email: String,
    pub display_name: String,
    pub instance_role: InstanceRole,
    pub locale: Option<String>,
    pub updated_at: DateTime<Utc>,
}

/// `PATCH /account/profile` — partial profile update for the caller.
///
/// At least one of `display_name` / `locale` must be present; provided
/// fields are written, omitted fields are left alone. Display name is
/// trimmed and rejected if empty. Emits `profile_updated` audit event
/// with the changed fields.
pub async fn update_profile(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Json(req): Json<UpdateProfileRequest>,
) -> impl IntoResponse {
    let display_name = match req.display_name.as_deref().map(str::trim) {
        Some("") => return err(StatusCode::BAD_REQUEST, "display_name_empty").into_response(),
        Some(name) => Some(name.to_string()),
        None => None,
    };
    let locale = req.locale.as_deref().map(str::trim).map(str::to_string);

    if display_name.is_none() && locale.is_none() {
        return err(StatusCode::BAD_REQUEST, "no_changes_specified").into_response();
    }

    let old_display_name = user.user.display_name.clone();
    let old_locale = user.user.locale.clone();
    let user_id = user.user.id;
    let actor = user.actor();

    let result: anyhow::Result<ProfileResponse> = async {
        let mut tx = state.db.begin().await?;
        let updated = UserRepository::update_profile(
            &mut tx,
            user_id,
            display_name.as_deref(),
            locale.as_deref(),
        )
        .await?;

        let mut changes = serde_json::Map::new();
        if let Some(ref new) = display_name
            && *new != old_display_name
        {
            changes.insert(
                "display_name".into(),
                serde_json::json!({ "from": old_display_name, "to": new }),
            );
        }
        if let Some(ref new) = locale
            && Some(new.as_str()) != old_locale.as_deref()
        {
            changes.insert(
                "locale".into(),
                serde_json::json!({ "from": old_locale, "to": new }),
            );
        }

        audit::append(
            &mut tx,
            Some(&actor),
            None,
            "profile_updated",
            serde_json::Value::Object(changes),
        )
        .await?;
        tx.commit().await?;

        Ok(ProfileResponse {
            id: updated.id.0,
            email: updated.email,
            display_name: updated.display_name,
            instance_role: updated.instance_role,
            locale: updated.locale,
            updated_at: updated.updated_at,
        })
    }
    .await;

    match result {
        Ok(resp) => (StatusCode::OK, Json(resp)).into_response(),
        Err(e) => {
            tracing::error!(?e, "updating profile");
            err(StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response()
        }
    }
}

/// Returns `Some(seqno_of_last_item)` when we should expect a next page,
/// `None` when the page is short of `limit` (so the caller has reached the end).
fn next_cursor(events: &[audit::AuditEvent], requested_limit: Option<u32>) -> Option<i64> {
    let limit = requested_limit
        .unwrap_or(audit::DEFAULT_PAGE_SIZE)
        .clamp(1, audit::MAX_PAGE_SIZE) as usize;
    if events.len() < limit {
        None
    } else {
        events.last().map(|e| e.seqno)
    }
}

