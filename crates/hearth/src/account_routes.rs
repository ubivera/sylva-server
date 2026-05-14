use audit::ListFilter;
use auth::SessionRepository;
use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use chrono::{DateTime, Utc};
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

