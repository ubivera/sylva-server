pub mod admin_routes;
pub mod pending_routes;
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
        .route(
            "/invite/{token}",
            get(routes::accept_invite_form).post(routes::accept_invite_submit),
        )
        .route("/me", get(routes::me_page))
        .route("/me/profile", post(routes::me_profile_submit))
        .route("/me/email", post(routes::me_email_submit))
        // On-demand modal fragments. The shell ships an empty
        // `#modal-host`; the client fetches these when a modal is
        // opened and removes the markup on close, so no modal lives in
        // the page source at rest.
        .route("/modals/account-settings", get(routes::account_settings_modal))
        .route("/modals/reauth", get(routes::reauth_modal))
        .route("/members", get(routes::members_page))
        .route(
            "/members/invite",
            get(admin_routes::invite_form).post(admin_routes::invite_submit),
        )
        .route(
            "/members/invitations/{id}/revoke",
            post(admin_routes::revoke_invitation),
        )
        .route(
            "/members/invitations/{id}/reissue",
            post(admin_routes::reissue_invitation),
        )
        // On-demand modal fragments for per-row member actions, the
        // invite modal, pending-invitation actions, and veto — fetched
        // when opened, removed on close. No modal markup ships in the
        // page source. `{action}` is matched in the handler.
        .route(
            "/members/{id}/modal/{action}",
            get(admin_routes::member_action_modal),
        )
        .route(
            "/members/invitations/{id}/modal/{action}",
            get(admin_routes::invitation_action_modal),
        )
        .route("/modals/invite", get(admin_routes::invite_modal_fragment))
        .route("/pending/{id}/modal/veto", get(admin_routes::veto_modal))
        .route("/members/{id}/deactivate", post(admin_routes::deactivate_member))
        .route("/members/{id}/reactivate", post(admin_routes::reactivate_member))
        .route("/members/{id}/delete", post(admin_routes::delete_member))
        .route("/members/{id}/purge", post(admin_routes::purge_member))
        .route("/members/{id}/role", post(admin_routes::change_member_role))
        .route("/pending", get(pending_routes::pending_page))
        .route(
            "/pending/{id}/veto",
            post(pending_routes::veto_pending),
        )
        .route("/logout", post(routes::logout_submit))
        .nest_service("/assets", ServeDir::new(assets_dir()))
        .with_state(state)
}
