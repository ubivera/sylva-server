pub mod admin_routes;
pub mod routes;
pub mod views;

use axum::{
    Router,
    routing::{get, post},
};
use hearth::app::AppState;
use tower_http::services::ServeDir;

/// Filesystem path to the static asset directory, relative to the crate
/// root. Resolved at request time via [`tower_http::services::ServeDir`].
fn assets_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("assets")
}

/// Build the HTML / asset router with state applied. Returned with no
/// path prefix; the caller merges it alongside the JSON API router.
pub fn ui_router(state: AppState) -> Router {
    Router::new()
        .route("/", get(routes::root_redirect))
        .route("/login", get(routes::login_page).post(routes::login_submit))
        .route("/me", get(routes::me_page))
        .route("/users", get(routes::users_page))
        .route("/users/{id}/deactivate", post(admin_routes::deactivate_user))
        .route("/users/{id}/reactivate", post(admin_routes::reactivate_user))
        .route("/users/{id}/delete", post(admin_routes::delete_user))
        .route("/users/{id}/purge", post(admin_routes::purge_user))
        .route("/users/{id}/role", post(admin_routes::change_user_role))
        .route("/logout", post(routes::logout_submit))
        .nest_service("/assets", ServeDir::new(assets_dir()))
        .with_state(state)
}
