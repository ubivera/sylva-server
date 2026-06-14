//! Admin/Owner-only audit-log viewer (`/events`).
//!
//! Read-only window onto the hash-chained `audit.events` log. Newest first,
//! cursor-paginated via `?before=<seqno>` (the audit crate's native paging).
//! The role gate mirrors `/members` (Admins + Owners); the sidebar entry is
//! hidden from Members, and this re-checks the role server-side.

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
};
use hearth::{app::AppState, csrf};
use identity::InstanceRole;
use serde::Deserialize;

use crate::{
    routes::{BrowserAuth, error_response, pending_count_for},
    views,
};

#[derive(Deserialize)]
pub struct EventsPageQuery {
    /// Cursor: show events with `seqno < before`. Absent → the newest page.
    pub before: Option<i64>,
}

/// `GET /events` — paginated audit log, newest first. Admins + Owners only.
pub async fn events_page(
    State(state): State<AppState>,
    BrowserAuth(auth): BrowserAuth,
    Query(query): Query<EventsPageQuery>,
) -> Response {
    if !matches!(
        auth.user.instance_role,
        InstanceRole::Admin | InstanceRole::Owner
    ) {
        return error_response(StatusCode::FORBIDDEN, "Admins only.");
    }

    let filter = audit::ListFilter {
        actor: None,
        since: None,
        before_seqno: query.before,
        limit: None,
    };
    let events = match audit::list(&state.db, &filter).await {
        Ok(events) => events,
        Err(err) => {
            tracing::error!(?err, "listing audit events for /events");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error");
        }
    };

    // A full page implies more history behind it; a short page is the tail.
    let older_cursor = if events.len() < audit::DEFAULT_PAGE_SIZE as usize {
        None
    } else {
        events.last().map(|e| e.seqno)
    };
    let has_newer = query.before.is_some();

    let now = chrono::Utc::now();
    let csrf_token = csrf::compute_token(&state.csrf_secret, auth.session_id);
    let pending_count = pending_count_for(&state, auth.user.instance_role).await;
    let ctx = views::ChromeContext {
        instance_name: state.instance_name.load_full(),
        user: &auth.user,
        csrf_token: &csrf_token,
        pending_count,
    };
    Html(views::events_page(&ctx, &events, now, older_cursor, has_newer).into_string())
        .into_response()
}
