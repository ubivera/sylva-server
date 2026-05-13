use std::time::Instant;

use axum::{extract::State, Json};
use serde::Serialize;

#[derive(Clone)]
pub struct HealthState {
    pub started_at: Instant,
}

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub version: &'static str,
    pub uptime_seconds: u64,
}

pub async fn handler(State(state): State<HealthState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
        uptime_seconds: state.started_at.elapsed().as_secs(),
    })
}
