use std::time::Instant;

use auth::SessionRepository;
use axum::{Router, routing::{get, post}};
use identity::UserRepository;
use sqlx::PgPool;
use tower_http::trace::TraceLayer;

use crate::{auth_routes, health};

/// Shared state for every Hearth HTTP handler. Cloning is cheap - every
/// field is itself a handle (Pool, Repository wrappers, Instant).
#[derive(Clone)]
pub struct AppState {
    pub started_at: Instant,
    pub db: PgPool,
    pub users: UserRepository,
    pub sessions: SessionRepository,
}

pub fn router(
    started_at: Instant,
    db: PgPool,
    users: UserRepository,
    sessions: SessionRepository,
) -> Router {
    let state = AppState {
        started_at,
        db,
        users,
        sessions,
    };

    Router::new()
        .route("/health", get(health::handler))
        .route("/auth/login", post(auth_routes::login))
        .route("/auth/logout", post(auth_routes::logout))
        .route("/me", get(auth_routes::me))
        .with_state(state)
        .layer(TraceLayer::new_for_http())
}
