//! Owner-only registered-apps admin page (`/apps`).
//!
//! Read-only window onto `platform.registered_apps` (CP1): each registered app
//! plus a live count of the resources it stores. Apps register over the platform
//! gRPC API; lifecycle controls (enable/disable, uninstall) and a resource
//! browser land in later checkpoints. Owner-only — tighter than `/events`
//! (Admin+Owner) because it exposes cross-user resource metadata and will gain
//! destructive controls.

use axum::{
    extract::State,
    http::StatusCode,
    response::{Html, IntoResponse, Response},
};
use hearth::{app::AppState, csrf};
use identity::InstanceRole;

use crate::{
    routes::{BrowserAuth, error_response, pending_count_for},
    views,
};

/// `GET /apps` — registered apps with their resource counts. Owner-only.
pub async fn apps_page(State(state): State<AppState>, BrowserAuth(auth): BrowserAuth) -> Response {
    if !matches!(auth.user.instance_role, InstanceRole::Owner) {
        return error_response(StatusCode::FORBIDDEN, "Owners only.");
    }

    let apps = match platform::registry::list_apps_with_counts(&state.db).await {
        Ok(a) => a,
        Err(err) => {
            tracing::error!(?err, "listing registered apps for /apps");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error");
        }
    };

    let now = chrono::Utc::now();
    let csrf_token = csrf::compute_token(&state.csrf_secret, auth.session_id);
    let pending_count = pending_count_for(&state, auth.user.instance_role).await;
    let ctx = views::ChromeContext {
        instance_name: state.instance_name.load_full(),
        user: &auth.user,
        csrf_token: &csrf_token,
        pending_count,
    };
    Html(views::apps_page(&ctx, &apps, now).into_string()).into_response()
}
