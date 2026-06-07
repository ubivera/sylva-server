use std::sync::Arc;
use std::time::Instant;

use auth::SessionRepository;
use axum::{Router, routing::{get, patch, post}};
use identity::{InvitationRepository, UserRepository};
use sqlx::PgPool;
use tower_http::trace::TraceLayer;

use crate::{account_routes, admin_routes, auth_routes, csrf, health};

/// Shared state for every Hearth HTTP handler. Cloning is cheap - every
/// field is itself a handle (Pool, Repository wrappers, Instant, Arc).
#[derive(Clone)]
pub struct AppState {
    pub started_at: Instant,
    pub db: PgPool,
    pub users: UserRepository,
    pub sessions: SessionRepository,
    pub invitations: InvitationRepository,
    /// Public-facing base URL used when building links inside outbound
    /// emails (e.g., the invitation accept URL). Set from
    /// `HEARTH_PUBLIC_BASE_URL`; reverse proxies in production override
    /// the default loopback value.
    pub public_base_url: String,
    /// Operator-chosen display name for this Hearth instance. Shown in
    /// the admin UI chrome and page titles. Set from
    /// `HEARTH_INSTANCE_NAME` (default `"Hearth"`).
    pub instance_name: String,
    /// Per-process secret for deriving CSRF tokens from session ids.
    /// Generated on startup; restart invalidates in-flight forms but not
    /// sessions. Behind an `Arc` so cloning [`AppState`] doesn't copy 32
    /// bytes per request.
    pub csrf_secret: Arc<[u8; csrf::SECRET_LEN]>,
    /// Per-client throttle for the brute-forceable auth endpoints
    /// (login / recover). Process-local; see [`crate::rate_limit`].
    pub rate_limiter: Arc<crate::rate_limit::RateLimiter>,
}

/// Convenience used by the integration test harness. Constructs the
/// shared [`AppState`] and returns the JSON API surface nested under
/// `/api`. Production composition happens in
/// [`crate::run`] and composes a UI router alongside this.
pub fn router(
    started_at: Instant,
    db: PgPool,
    users: UserRepository,
    sessions: SessionRepository,
    invitations: InvitationRepository,
    public_base_url: String,
    instance_name: String,
) -> Router {
    let state = AppState {
        started_at,
        db,
        users,
        sessions,
        invitations,
        public_base_url,
        instance_name,
        csrf_secret: Arc::new(csrf::generate_secret()),
        rate_limiter: Arc::new(crate::rate_limit::RateLimiter::auth_default()),
    };

    let health = Router::new()
        .route("/health", get(health::handler))
        .with_state(state.clone());

    Router::new()
        .nest("/api", api_router(state))
        .merge(health)
        .layer(TraceLayer::new_for_http())
}

/// Build the JSON API router with state already applied. Returned with
/// **no path prefix** — callers nest it (e.g. under `/api`) themselves.
/// `/health` is intentionally not here; it lives at the root because
/// it's an ops endpoint, not part of the API.
pub fn api_router(state: AppState) -> Router {
    Router::new()
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
        .route("/admin/members", get(admin_routes::list_members))
        .route(
            "/admin/members/{id}/deactivate",
            post(admin_routes::deactivate_member),
        )
        .route(
            "/admin/members/{id}/reactivate",
            post(admin_routes::reactivate_member),
        )
        .route("/admin/members/{id}/delete", post(admin_routes::delete_member))
        .route("/admin/members/{id}/purge", post(admin_routes::purge_member))
        .route(
            "/admin/members/{id}/role",
            post(admin_routes::change_member_role),
        )
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
        .route(
            "/admin/notifications",
            get(admin_routes::list_notifications),
        )
        .route(
            "/admin/pending-transitions",
            get(admin_routes::list_pending_transitions),
        )
        .route(
            "/admin/pending-transitions/{id}/veto",
            post(admin_routes::veto_pending_transition),
        )
        .route(
            "/admin/pending-transitions/{id}/cancel",
            post(admin_routes::cancel_pending_transition),
        )
        .route(
            "/admin/server/recovery-code",
            get(admin_routes::get_recovery_code_metadata),
        )
        .route(
            "/admin/server/recovery-code/rotate",
            post(admin_routes::rotate_recovery_code),
        )
        .with_state(state)
}
