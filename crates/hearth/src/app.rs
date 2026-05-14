use std::time::Instant;

use axum::{Router, routing::get};
use sqlx::PgPool;
use tower_http::trace::TraceLayer;

use crate::health::{self, HealthState};

pub fn router(started_at: Instant, db: PgPool) -> Router {
    Router::new()
        .route("/health", get(health::handler))
        .with_state(HealthState { started_at, db })
        .layer(TraceLayer::new_for_http())
}
