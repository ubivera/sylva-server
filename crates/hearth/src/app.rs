use std::time::Instant;

use axum::{routing::get, Router};
use tower_http::trace::TraceLayer;

use crate::health::{self, HealthState};

pub fn router(started_at: Instant) -> Router {
    Router::new()
        .route("/health", get(health::handler))
        .with_state(HealthState { started_at })
        .layer(TraceLayer::new_for_http())
}
