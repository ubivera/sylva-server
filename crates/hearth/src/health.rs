use std::time::Instant;

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use serde::Serialize;
use sqlx::PgPool;

#[derive(Clone)]
pub struct HealthState {
    pub started_at: Instant,
    pub db: PgPool,
}

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub version: &'static str,
    pub uptime_seconds: u64,
    pub db: &'static str,
}

pub async fn handler(State(state): State<HealthState>) -> impl IntoResponse {
    let db_ok = sqlx::query_scalar::<_, i32>("SELECT 1")
        .fetch_one(&state.db)
        .await
        .is_ok();

    let body = HealthResponse {
        status: if db_ok { "ok" } else { "degraded" },
        version: env!("CARGO_PKG_VERSION"),
        uptime_seconds: state.started_at.elapsed().as_secs(),
        db: if db_ok { "ok" } else { "down" },
    };

    let code = if db_ok {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (code, Json(body))
}
