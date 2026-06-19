use axum::{
    Form,
    extract::{Path, Query, State},
    http::HeaderMap,
    response::{Html, IntoResponse, Response},
};
use server::{admin_logic, app::AppState, csrf};
use identity::InstanceRole;
use serde::Deserialize;
use uuid::Uuid;

use crate::{
    admin_routes::{
        LifecycleActionForm, is_htmx, redirect_or_hx_redirect, redirect_with_action_toast,
        redirect_with_error_toast, with_toast,
    },
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
        instance_name: state.instance_name.load_full(),
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
    let admin = server::auth_routes::AdminUser(auth);
    let htmx = is_htmx(&headers);
    if let Err(resp) =
        crate::routes::require_sudo(&state, &headers, admin.0.user.id)
    {
        return resp;
    }

    match admin_logic::perform_veto_pending(&state, &admin, transition_id).await {
        Ok(_row) => {
            // Refresh the page so the now-resolved row drops out of
            // the active list and the sidebar count badge updates.
            // Toast travels via HX-Trigger (client-side renders it
            // after the soft-navigation completes).
            redirect_with_action_toast("/pending", htmx, "vetoed", None)
        }
        Err(admin_logic::VetoError::NotOwner) => {
            // Defense in depth — we already checked above, but
            // `perform_veto_pending` enforces it too in case the
            // public API ever loosens.
            error_response(axum::http::StatusCode::FORBIDDEN, "Owners only.")
        }
        Err(admin_logic::VetoError::NotFound) => {
            redirect_with_error_toast("/pending", htmx, "transition_not_found")
        }
        Err(admin_logic::VetoError::NotPending) => {
            // Race: someone else resolved (vetoed/cancelled/applied)
            // the row between page load and our submit. Bounce back to
            // the page so the operator sees the current state.
            redirect_with_error_toast("/pending", htmx, "not_pending")
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

/// Force-apply form fields. The recovery code is the break-glass authorization.
#[derive(Deserialize)]
pub struct ForceApplyForm {
    pub csrf_token: String,
    #[serde(default)]
    pub recovery_code: String,
}

/// `GET /pending/{id}/modal/force-apply` — the recovery-code force-apply dialog
/// for a pending Owner-on-Owner transition. Owners only.
pub async fn force_apply_modal(
    State(state): State<AppState>,
    BrowserAuth(auth): BrowserAuth,
    Path(transition_id): Path<Uuid>,
) -> Response {
    if auth.user.instance_role != InstanceRole::Owner {
        return error_response(axum::http::StatusCode::FORBIDDEN, "Owners only.");
    }
    match pending::find_by_id(&state.db, transition_id).await {
        Ok(Some(r)) if r.state == pending::TransitionState::Pending => {}
        Ok(_) => {
            return error_response(
                axum::http::StatusCode::NOT_FOUND,
                "That pending action no longer exists.",
            );
        }
        Err(err) => {
            tracing::error!(?err, "loading transition for force-apply modal");
            return error_response(
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Internal error",
            );
        }
    }
    let (target_name, action_label) = transition_labels(&state, transition_id).await;
    let csrf_token = csrf::compute_token(&state.csrf_secret, auth.session_id);
    Html(
        views::force_apply_dialog(transition_id, &target_name, &action_label, &csrf_token)
            .into_string(),
    )
    .into_response()
}

/// `POST /pending/{id}/force-apply` — break-glass: apply a pending transition
/// immediately, bypassing the 72h veto window, authorized by the **server
/// recovery code** (the mechanism for one Owner to force out another). Owners
/// only + CSRF. A wrong code re-renders the dialog form inline; success /
/// already-resolved redirect back to `/pending` with a toast.
pub async fn force_apply_pending(
    State(state): State<AppState>,
    BrowserAuth(auth): BrowserAuth,
    headers: HeaderMap,
    Path(transition_id): Path<Uuid>,
    Form(form): Form<ForceApplyForm>,
) -> Response {
    if let Err(resp) = check_csrf_token(&state, auth.session_id, &form.csrf_token) {
        return resp;
    }
    if auth.user.instance_role != InstanceRole::Owner {
        return error_response(axum::http::StatusCode::FORBIDDEN, "Owners only.");
    }
    let htmx = is_htmx(&headers);

    // The server recovery code is the authorization for bypassing the veto.
    let valid = match auth::recovery_code::verify(&state.db, &form.recovery_code).await {
        Ok(opt) => opt.is_some(),
        Err(err) => {
            tracing::error!(?err, "verifying recovery code for force-apply");
            return error_response(
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Internal error",
            );
        }
    };
    if !valid {
        // Re-render the dialog form with the error (swapped into the modal).
        let csrf_token = csrf::compute_token(&state.csrf_secret, auth.session_id);
        let (target_name, action_label) = transition_labels(&state, transition_id).await;
        return Html(
            views::force_apply_form(
                transition_id,
                &target_name,
                &action_label,
                &csrf_token,
                Some("That server recovery code is not valid."),
            )
            .into_string(),
        )
        .into_response();
    }

    let worker = pending::Worker::new(state.db.clone());
    match worker.force_apply(transition_id, auth.user.id).await {
        Ok(pending::ForceApplyOutcome::Applied(_)) => {
            // Destructive but intentional → neutral "done" toast. The apply
            // itself recorded the audit event (via=recovery_bypass + forced_by).
            let toast = views::Toast::new(
                views::ToastKind::Info,
                "Applied",
                "The pending action was forced through with the recovery code.",
            );
            with_toast(redirect_or_hx_redirect("/pending", htmx), Some(toast))
        }
        Ok(pending::ForceApplyOutcome::NotFound) => {
            redirect_with_error_toast("/pending", htmx, "transition_not_found")
        }
        Ok(pending::ForceApplyOutcome::NotPending) => {
            redirect_with_error_toast("/pending", htmx, "not_pending")
        }
        Err(err) => {
            tracing::error!(?err, "force-applying pending transition (web)");
            error_response(
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Internal error",
            )
        }
    }
}

/// Best-effort `(target display name, action label)` for the force-apply
/// dialog. Falls back to placeholders so the dialog still renders.
async fn transition_labels(state: &AppState, transition_id: Uuid) -> (String, String) {
    match pending::find_by_id(&state.db, transition_id).await.ok().flatten() {
        Some(row) => {
            let users = identity::UserRepository::new(state.db.clone());
            let target_name = match row.target_user_id {
                Some(tid) => users
                    .find_any(identity::UserId::new(tid))
                    .await
                    .ok()
                    .flatten()
                    .map(|u| u.display_name)
                    .unwrap_or_else(|| "(unknown member)".to_string()),
                None => "(unknown member)".to_string(),
            };
            (target_name, views::pending_action_label(&row))
        }
        None => ("(unknown member)".to_string(), "action".to_string()),
    }
}

