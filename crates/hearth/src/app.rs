use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Instant;

use arc_swap::ArcSwap;

use auth::SessionRepository;
use axum::{Router, routing::{get, patch, post}};
use identity::{InvitationRepository, UserRepository};
use sqlx::PgPool;

use crate::{account_routes, admin_routes, auth_routes, csrf};

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
    /// Operator-chosen display name for this instance, shown in the chrome +
    /// page titles. Hot-swappable: seeded at startup from the DB override or
    /// `HEARTH_INSTANCE_NAME`, and replaced live when an Owner edits it on the
    /// Settings page. Read via `.load()` at use-time.
    pub instance_name: Arc<ArcSwap<String>>,
    /// Shared, hot-swappable notification backend. Same cell the notification
    /// worker drains from, so an Owner saving new SMTP config on the Settings
    /// page takes effect on the next send (no restart). See `crate::instance`.
    pub notifier: Arc<ArcSwap<notifications::NotifierImpl>>,
    /// The frozen env/startup [`crate::config::Config`] — the baseline the
    /// Owner Settings page overlays DB overrides on. Held so a save can
    /// recompute the effective config ([`crate::instance::effective`]) and
    /// re-seed the hot-swappable cells above. See [`crate::settings_logic`].
    pub env_config: Arc<crate::config::Config>,
    /// Per-process secret for deriving CSRF tokens from session ids.
    /// Generated on startup; restart invalidates in-flight forms but not
    /// sessions. Behind an `Arc` so cloning [`AppState`] doesn't copy 32
    /// bytes per request.
    pub csrf_secret: Arc<[u8; csrf::SECRET_LEN]>,
    /// Per-client throttle for the brute-forceable auth endpoints
    /// (login / recover). Process-local; see [`crate::rate_limit`].
    pub rate_limiter: Arc<crate::rate_limit::RateLimiter>,
    /// Persistent per-instance key for at-rest encryption of recoverable
    /// secrets (TOTP shared secrets). Stable across restarts — unlike
    /// `csrf_secret` — so sealed data stays decryptable.
    pub secret_key: Arc<[u8; 32]>,
    /// Whether `X-Forwarded-For` / `X-Real-IP` are trusted for rate-limit
    /// client-IP keying (set behind a reverse proxy). Off → key on the
    /// socket peer. See [`crate::rate_limit`].
    pub trust_proxy: bool,
    /// Cached "instance has been closed" flag (the last user closed their
    /// account). Seeded from `hearth_meta.instance.closed_at` at startup and
    /// flipped when a close empties the instance, so the closed-page
    /// middleware never hits the DB on the hot path. See [`crate::instance`].
    pub instance_closed: Arc<AtomicBool>,
}

/// Build the JSON API router with state already applied. Returned with
/// **no path prefix** — callers nest it (e.g. under `/api`) themselves.
/// `/health` is intentionally not here; it lives at the root because
/// it's an ops endpoint, not part of the API.
pub fn api_router(state: AppState) -> Router {
    Router::new()
        .route("/auth/login", post(auth_routes::login))
        .route("/auth/login/verify", post(auth_routes::login_verify))
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
        .route("/admin/members/{id}/anonymize", post(admin_routes::anonymize_member))
        .route("/admin/members/{id}/delete", post(admin_routes::delete_member))
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
