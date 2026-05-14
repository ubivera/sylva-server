use std::time::Instant;

use axum::{Router, routing::get};
use identity::UserRepository;
use sqlx::PgPool;
use tower_http::trace::TraceLayer;

use crate::health::{self, HealthState};

pub fn router(started_at: Instant, db: PgPool, users: UserRepository) -> Router {
    Router::new()
        .route("/health", get(health::handler))
        .with_state(HealthState {
            started_at,
            db,
            users,
        })
        .layer(TraceLayer::new_for_http())
}
