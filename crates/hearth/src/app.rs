use std::time::Instant;

use auth::SessionRepository;
use axum::{Router, routing::{get, patch, post}};
use identity::{InvitationRepository, UserRepository};
use sqlx::PgPool;
use tower_http::trace::TraceLayer;

use crate::{account_routes, admin_routes, auth_routes, health};

/// Shared state for every Hearth HTTP handler. Cloning is cheap - every
/// field is itself a handle (Pool, Repository wrappers, Instant).
#[derive(Clone)]
pub struct AppState {
    pub started_at: Instant,
    pub db: PgPool,
    pub users: UserRepository,
    pub sessions: SessionRepository,
    pub invitations: InvitationRepository,
}

pub fn router(
    started_at: Instant,
    db: PgPool,
    users: UserRepository,
    sessions: SessionRepository,
    invitations: InvitationRepository,
) -> Router {
    let state = AppState {
        started_at,
        db,
        users,
        sessions,
        invitations,
    };

    Router::new()
        .route("/health", get(health::handler))
        .route("/auth/login", post(auth_routes::login))
        .route("/auth/logout", post(auth_routes::logout))
        .route("/auth/accept-invite", post(auth_routes::accept_invite))
        .route("/me", get(auth_routes::me))
        .route("/account/activity", get(account_routes::activity))
        .route("/account/password", post(account_routes::change_password))
        .route("/account/profile", patch(account_routes::update_profile))
        .route("/account/sessions", get(account_routes::list_sessions))
        .route(
            "/account/sessions/{id}/revoke",
            post(account_routes::revoke_session),
        )
        .route("/admin/users", get(admin_routes::list_users))
        .route(
            "/admin/invites",
            get(admin_routes::list_invites).post(admin_routes::create_invite),
        )
        .route(
            "/admin/invites/{id}/revoke",
            post(admin_routes::revoke_invite),
        )
        .route("/admin/audit", get(admin_routes::list_audit))
        .route("/admin/sessions", get(admin_routes::list_sessions))
        .route(
            "/admin/sessions/{id}/revoke",
            post(admin_routes::revoke_session),
        )
        .with_state(state)
        .layer(TraceLayer::new_for_http())
}
