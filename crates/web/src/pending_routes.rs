use axum::{
    Form,
    extract::{Path, Query, State},
    http::HeaderMap,
    response::{Html, IntoResponse, Response},
};
use hearth::{admin_logic, app::AppState, csrf};
use identity::InstanceRole;
use serde::Deserialize;
use uuid::Uuid;

use crate::{
    admin_routes::{LifecycleActionForm, is_htmx, redirect_or_hx_redirect, require_password},
    routes::{BrowserAuth, check_csrf_token, error_response},
    views,
};

/// Query params recognised on `GET /pending`. All optional — the
/// page renders with empty data when none are present.
#[derive(Deserialize, Default)]
pub struct PendingPageQuery {
    /// "vetoed" — success banner. Set by the veto handler's redirect.
    pub action: Option<String>,
    /// "transition_not_found", "not_pending", "invalid_password".
    /// Set by the veto handler on the various failure paths.
    pub error: Option<String>,
}

/// `GET /pending` — Owners-only directory of currently-pending
/// Owner-on-Owner transitions.
///
/// Members and Admins get a 403 page. The sidebar link is hidden from
/// them too, so this gate is defense in depth.
pub async fn pending_page(
    State(state): State<AppState>,
    BrowserAuth(auth): BrowserAuth,
    Query(query): Query<PendingPageQuery>,
) -> Response {
    if auth.user.instance_role != InstanceRole::Owner {
        return error_response(axum::http::StatusCode::FORBIDDEN, "Owners only.");
    }
    let csrf_token = csrf::compute_token(&state.csrf_secret, auth.session_id);

    // Fetch active + recent-history rows + the user records they
    // reference. Three round-trips total: one for each row set, one
    // bulk user lookup over the union of every user mentioned
    // (initiator, target, resolver across all rows).
    let active = match pending::list_active(&state.db).await {
        Ok(r) => r,
        Err(err) => {
            tracing::error!(?err, "listing active pending transitions for /pending");
            return error_response(
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Internal error",
            );
        }
    };
    let history = match pending::list_recent_resolved(&state.db, HISTORY_LIMIT).await {
        Ok(r) => r,
        Err(err) => {
            tracing::error!(?err, "listing resolved pending transitions for /pending");
            return error_response(
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Internal error",
            );
        }
    };

    // Collect every user id referenced in either set. Resolver shows
    // up only in history (active rows haven't been resolved yet).
    let mut user_ids: Vec<identity::UserId> = active
        .iter()
        .chain(history.iter())
        .flat_map(|r| {
            [
                r.initiator_user_id,
                r.target_user_id,
                r.resolved_by_user_id,
            ]
            .into_iter()
            .flatten()
            .map(identity::UserId::new)
            .collect::<Vec<_>>()
        })
        .collect();
    user_ids.sort_by_key(|u| u.0);
    user_ids.dedup_by_key(|u| u.0);

    let users = match state.users.list_by_ids(&user_ids).await {
        Ok(u) => u,
        Err(err) => {
            tracing::error!(?err, "fetching users for /pending");
            return error_response(
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Internal error",
            );
        }
    };

    let pending_count = Some(active.len() as u32);
    let ctx = views::ChromeContext {
        instance_name: &state.instance_name,
        user: &auth.user,
        csrf_token: &csrf_token,
        pending_count,
    };
    let banner = views::PendingBanner {
        action: query.action.as_deref(),
        error: query.error.as_deref(),
    };
    Html(views::pending_page(&ctx, &active, &history, &users, banner).into_string())
        .into_response()
}

/// How many resolved transitions to surface in the History section.
/// Tradeoff: enough to give recent context for "what did we just
/// veto/apply?" without inflating the page for high-activity instances.
/// Older rows still live in the audit log and can be reached via
/// future filters there.
const HISTORY_LIMIT: i64 = 50;

/// `POST /pending/{id}/veto` — web wrapper around the shared
/// [`admin_logic::perform_veto_pending`] helper.
///
/// Reuses the same CSRF + reauth chain pattern as the destructive
/// member actions: the row's Veto button opens a confirmation dialog,
/// which chains into `dlg-reauth`. The actual POST that lands here
/// carries both the operator's password (re-verified) and the original
/// `csrf_token`. HTMX callers get an `HX-Redirect` on success and a
/// reauth partial with an error banner when the password is wrong;
/// non-HTMX callers get a redirect-with-query-param banner.
pub async fn veto_pending(
    State(state): State<AppState>,
    BrowserAuth(auth): BrowserAuth,
    headers: HeaderMap,
    Path(transition_id): Path<Uuid>,
    Form(form): Form<LifecycleActionForm>,
) -> Response {
    if let Err(resp) = check_csrf_token(&state, auth.session_id, &form.csrf_token) {
        return resp;
    }
    if auth.user.instance_role != InstanceRole::Owner {
        return error_response(axum::http::StatusCode::FORBIDDEN, "Owners only.");
    }
    // Re-use the AdminUser wrapper because `perform_veto_pending`
    // takes it (Owners satisfy the Admin gate). The wrapper carries
    // the session id + user so audit attribution lines up.
    let admin = hearth::auth_routes::AdminUser(auth);
    let htmx = is_htmx(&headers);
    let action_url = format!("/pending/{transition_id}/veto");
    if let Err(resp) =
        require_password(&state, &admin, &form.password, htmx, &action_url, &[]).await
    {
        return resp;
    }

    match admin_logic::perform_veto_pending(&state, &admin, transition_id).await {
        Ok(_row) => {
            // Refresh the page so the now-resolved row drops out of
            // the active list and the sidebar count badge updates.
            redirect_or_hx_redirect("/pending?action=vetoed", htmx)
        }
        Err(admin_logic::VetoError::NotOwner) => {
            // Defense in depth — we already checked above, but
            // `perform_veto_pending` enforces it too in case the
            // public API ever loosens.
            error_response(axum::http::StatusCode::FORBIDDEN, "Owners only.")
        }
        Err(admin_logic::VetoError::NotFound) => {
            redirect_or_hx_redirect("/pending?error=transition_not_found", htmx)
        }
        Err(admin_logic::VetoError::NotPending) => {
            // Race: someone else resolved (vetoed/cancelled/applied)
            // the row between page load and our submit. Bounce back to
            // the page so the operator sees the current state.
            redirect_or_hx_redirect("/pending?error=not_pending", htmx)
        }
        Err(admin_logic::VetoError::Internal(err)) => {
            tracing::error!(?err, "vetoing pending transition (web)");
            error_response(
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Internal error",
            )
        }
    }
}

