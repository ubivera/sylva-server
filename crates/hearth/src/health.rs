use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use serde::Serialize;

use crate::app::AppState;

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub version: &'static str,
    pub uptime_seconds: u64,
    pub db: &'static str,
    /// `None` when the DB is unreachable; otherwise the count of non-purged
    /// rows in `identity.users`.
    pub users_count: Option<i64>,
    /// `None` when the DB is unreachable; otherwise the count of rows in
    /// `audit.events`.
    pub audit_events_count: Option<i64>,
    /// `None` when the DB is unreachable; otherwise the count of active
    /// (non-revoked, non-expired) rows in `auth.sessions`.
    pub active_sessions_count: Option<i64>,
    /// `None` when the DB is unreachable; otherwise the count of pending
    /// invitations (not accepted, not revoked, not expired).
    pub pending_invitations_count: Option<i64>,
}

pub async fn handler(State(state): State<AppState>) -> impl IntoResponse {
    let db_ok = sqlx::query_scalar::<_, i32>("SELECT 1")
        .fetch_one(&state.db)
        .await
        .is_ok();

    let (users_count, audit_events_count, active_sessions_count, pending_invitations_count) =
        if db_ok {
            (
                state.users.count().await.ok(),
                audit::count(&state.db).await.ok(),
                state.sessions.count_active().await.ok(),
                state.invitations.count_pending().await.ok(),
            )
        } else {
            (None, None, None, None)
        };

    let body = HealthResponse {
        status: if db_ok { "ok" } else { "degraded" },
        version: env!("CARGO_PKG_VERSION"),
        uptime_seconds: state.started_at.elapsed().as_secs(),
        db: if db_ok { "ok" } else { "down" },
        users_count,
        audit_events_count,
        active_sessions_count,
        pending_invitations_count,
    };

    let code = if db_ok {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (code, Json(body))
}
