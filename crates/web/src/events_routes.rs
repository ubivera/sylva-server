//! Admin/Owner-only audit-log viewer (`/events`) + the single-event detail
//! modal.
//!
//! Read-only window onto the hash-chained `audit.events` log. Newest first,
//! offset-paginated (Members-style bar), with a free-text search and an
//! event-type filter. Clicking a row opens a detail modal carrying the full
//! `event_data` and the chain hashes. The role gate mirrors `/members`.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
};
use server::{app::AppState, csrf};
use identity::InstanceRole;
use serde::Deserialize;

use crate::{
    routes::{BrowserAuth, error_response, pending_count_for},
    views,
};

fn is_admin(role: InstanceRole) -> bool {
    matches!(role, InstanceRole::Admin | InstanceRole::Owner)
}

#[derive(Deserialize)]
pub struct EventsPageQuery {
    pub q: Option<String>,
    pub r#type: Option<String>,
    pub page: Option<u32>,
    pub rows: Option<u32>,
}

/// `GET /events` — paginated, searchable, filterable audit log. Admins + Owners.
pub async fn events_page(
    State(state): State<AppState>,
    BrowserAuth(auth): BrowserAuth,
    Query(query): Query<EventsPageQuery>,
) -> Response {
    if !is_admin(auth.user.instance_role) {
        return error_response(StatusCode::FORBIDDEN, "Admins only.");
    }

    let search = clean(query.q);
    let type_filter = clean(query.r#type);
    let rows = query
        .rows
        .filter(|r| views::ROWS_PER_PAGE_OPTIONS.contains(r))
        .unwrap_or(views::DEFAULT_ROWS_PER_PAGE);

    // Count first (same content predicates, no pagination) so we can clamp the
    // requested page and render "of N".
    let count_filter = audit::ListFilter {
        event_type: type_filter.clone(),
        search: search.clone(),
        ..Default::default()
    };
    let total = match audit::count_filtered(&state.db, &count_filter).await {
        Ok(n) => n.max(0) as u32,
        Err(err) => {
            tracing::error!(?err, "counting audit events for /events");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error");
        }
    };
    let total_pages = total.div_ceil(rows).max(1);
    let page = query.page.unwrap_or(1).clamp(1, total_pages);
    let offset = i64::from((page - 1) * rows);

    let filter = audit::ListFilter {
        limit: Some(rows),
        offset: Some(offset),
        event_type: type_filter.clone(),
        search: search.clone(),
        ..Default::default()
    };
    let events = match audit::list(&state.db, &filter).await {
        Ok(e) => e,
        Err(err) => {
            tracing::error!(?err, "listing audit events for /events");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error");
        }
    };
    let types = audit::distinct_event_types(&state.db).await.unwrap_or_default();

    let now = chrono::Utc::now();
    let csrf_token = csrf::compute_token(&state.csrf_secret, auth.session_id);
    let pending_count = pending_count_for(&state, auth.user.instance_role).await;
    let ctx = views::ChromeContext {
        instance_name: state.instance_name.load_full(),
        user: &auth.user,
        csrf_token: &csrf_token,
        pending_count,
    };
    let view = views::EventsView {
        search: search.as_deref().unwrap_or(""),
        type_filter: type_filter.as_deref().unwrap_or(""),
        types: &types,
        pagination: views::PaginationState {
            current_page: page,
            total_pages,
            rows_per_page: rows,
            total_rows: total,
        },
    };
    Html(views::events_page(&ctx, &events, now, &view).into_string()).into_response()
}

/// `GET /events/{seqno}/modal` — full detail (event_data + chain hashes) for
/// one event, fetched into `#modal-host` when a row is clicked.
pub async fn event_detail_modal(
    State(state): State<AppState>,
    BrowserAuth(auth): BrowserAuth,
    Path(seqno): Path<i64>,
) -> Response {
    if !is_admin(auth.user.instance_role) {
        return error_response(StatusCode::FORBIDDEN, "Admins only.");
    }
    match audit::get(&state.db, seqno).await {
        Ok(Some(event)) => Html(views::event_detail_modal(&event).into_string()).into_response(),
        Ok(None) => error_response(StatusCode::NOT_FOUND, "Event not found."),
        Err(err) => {
            tracing::error!(?err, "fetching audit event {seqno}");
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        }
    }
}

/// Trim + drop empty query strings to `None`.
fn clean(value: Option<String>) -> Option<String> {
    value.map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}
