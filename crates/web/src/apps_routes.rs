//! Owner-only registered-apps admin (`/apps`).
//!
//! A window onto `platform.registered_apps`: which apps have registered over
//! the platform gRPC API and what they're storing, plus lifecycle controls.
//! Owner-only — tighter than `/events` (Admin+Owner) because it exposes
//! cross-user resource metadata and destructive controls.
//!
//! CP1 was the read-only list. CP2 adds lifecycle: **enable/disable** (a
//! disabled app can't create or modify resources — the gRPC create path already
//! enforces `status = 'enabled'`) and **uninstall**, which removes the
//! registration and cascade-deletes the app's resources via the
//! `resources.app_id` FK. Mutations are CSRF- + reauth-gated (the dialogs chain
//! into the shared reauth modal) and audited, mirroring the Members row actions.

use axum::{
    Form,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
};
use server::{app::AppState, csrf};
use identity::InstanceRole;
use serde::Deserialize;
use uuid::Uuid;

use crate::{
    admin_routes::{is_htmx, redirect_with_action_toast, redirect_with_error_toast},
    routes::{BrowserAuth, check_csrf_token, error_response, pending_count_for, require_sudo},
    views,
};

/// Reauth-gated action form: carries only the CSRF token. The action is
/// authorized by the short-lived `sylva_sudo` grant (checked via
/// `require_sudo`); the reauth chain strips any password before submitting.
#[derive(Deserialize)]
pub struct AppActionForm {
    pub csrf_token: String,
}

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

/// `GET /apps/{id}/modal/{action}` — confirmation dialog for `enable` /
/// `disable` / `uninstall`, fetched into `#modal-host` when a kebab item is
/// clicked. Owner-only; unknown ids 404 and unknown actions 404.
pub async fn app_action_modal(
    State(state): State<AppState>,
    BrowserAuth(auth): BrowserAuth,
    Path((id, action)): Path<(Uuid, String)>,
) -> Response {
    if !matches!(auth.user.instance_role, InstanceRole::Owner) {
        return error_response(StatusCode::FORBIDDEN, "Owners only.");
    }
    let app = match platform::registry::get_app(&state.db, id).await {
        Ok(Some(a)) => a,
        Ok(None) => return error_response(StatusCode::NOT_FOUND, "App not found."),
        Err(err) => {
            tracing::error!(?err, "loading app for action modal");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error");
        }
    };
    let resource_count = match platform::registry::count_app_resources(&state.db, id).await {
        Ok(n) => n,
        Err(err) => {
            tracing::error!(?err, "counting app resources for modal");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error");
        }
    };
    let csrf_token = csrf::compute_token(&state.csrf_secret, auth.session_id);
    match views::app_action_dialog(&action, &app, resource_count, &csrf_token) {
        Some(markup) => Html(markup.into_string()).into_response(),
        None => error_response(StatusCode::NOT_FOUND, "Unknown action."),
    }
}

/// `POST /apps/{id}/enable` — re-enable a disabled app. Owner + CSRF + reauth.
pub async fn enable_app(
    State(state): State<AppState>,
    BrowserAuth(auth): BrowserAuth,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Form(form): Form<AppActionForm>,
) -> Response {
    if let Err(resp) = check_csrf_token(&state, auth.session_id, &form.csrf_token) {
        return resp;
    }
    if !matches!(auth.user.instance_role, InstanceRole::Owner) {
        return error_response(StatusCode::FORBIDDEN, "Owners only.");
    }
    let htmx = is_htmx(&headers);
    if let Err(resp) = require_sudo(&state, &headers, auth.user.id) {
        return resp;
    }
    let actor = actor_of(&auth);
    match set_status_audited(&state, &actor, id, "enabled", "app_enabled").await {
        Ok(Some(app)) => {
            redirect_with_action_toast("/apps", htmx, "app_enabled", Some(&app.display_name))
        }
        Ok(None) => redirect_with_error_toast("/apps", htmx, "app_not_found"),
        Err(err) => {
            tracing::error!(?err, "enabling app");
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        }
    }
}

/// `POST /apps/{id}/disable` — block an app from creating/modifying resources.
/// Owner + CSRF + reauth. Existing data is kept; the registration stays.
pub async fn disable_app(
    State(state): State<AppState>,
    BrowserAuth(auth): BrowserAuth,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Form(form): Form<AppActionForm>,
) -> Response {
    if let Err(resp) = check_csrf_token(&state, auth.session_id, &form.csrf_token) {
        return resp;
    }
    if !matches!(auth.user.instance_role, InstanceRole::Owner) {
        return error_response(StatusCode::FORBIDDEN, "Owners only.");
    }
    let htmx = is_htmx(&headers);
    if let Err(resp) = require_sudo(&state, &headers, auth.user.id) {
        return resp;
    }
    let actor = actor_of(&auth);
    match set_status_audited(&state, &actor, id, "disabled", "app_disabled").await {
        Ok(Some(app)) => {
            redirect_with_action_toast("/apps", htmx, "app_disabled", Some(&app.display_name))
        }
        Ok(None) => redirect_with_error_toast("/apps", htmx, "app_not_found"),
        Err(err) => {
            tracing::error!(?err, "disabling app");
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        }
    }
}

/// `POST /apps/{id}/uninstall` — remove the registration; its resources
/// cascade-delete via the FK. Owner + CSRF + reauth. Irreversible.
pub async fn uninstall_app(
    State(state): State<AppState>,
    BrowserAuth(auth): BrowserAuth,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Form(form): Form<AppActionForm>,
) -> Response {
    if let Err(resp) = check_csrf_token(&state, auth.session_id, &form.csrf_token) {
        return resp;
    }
    if !matches!(auth.user.instance_role, InstanceRole::Owner) {
        return error_response(StatusCode::FORBIDDEN, "Owners only.");
    }
    let htmx = is_htmx(&headers);
    if let Err(resp) = require_sudo(&state, &headers, auth.user.id) {
        return resp;
    }
    let actor = actor_of(&auth);
    match uninstall_audited(&state, &actor, id).await {
        Ok(Some(app)) => {
            redirect_with_action_toast("/apps", htmx, "app_uninstalled", Some(&app.display_name))
        }
        Ok(None) => redirect_with_error_toast("/apps", htmx, "app_not_found"),
        Err(err) => {
            tracing::error!(?err, "uninstalling app");
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        }
    }
}

/// Build the audit actor from the authenticated owner.
fn actor_of(auth: &server::auth_routes::AuthenticatedUser) -> audit::Actor {
    audit::Actor {
        user_id: auth.user.id,
        display_name: auth.user.display_name.clone(),
    }
}

// ── Per-app resource browser (CP3) ─────────────────────────────────────────

/// Newest-N cap on the resource listing. The GUID search reaches any single
/// resource regardless of position, so this only bounds raw browsing.
const RESOURCE_LIST_CAP: i64 = 200;

#[derive(Deserialize)]
pub struct ResourcesQuery {
    pub q: Option<String>,
    pub r#type: Option<String>,
    pub deleted: Option<String>,
}

/// Trim + drop empty query strings to `None`.
fn clean(value: Option<String>) -> Option<String> {
    value.map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

/// `GET /apps/{id}/resources` — the per-app resource browser. Owner-only.
pub async fn app_resources_page(
    State(state): State<AppState>,
    BrowserAuth(auth): BrowserAuth,
    Path(app_id): Path<Uuid>,
    Query(query): Query<ResourcesQuery>,
) -> Response {
    if !matches!(auth.user.instance_role, InstanceRole::Owner) {
        return error_response(StatusCode::FORBIDDEN, "Owners only.");
    }
    let app = match platform::registry::get_app(&state.db, app_id).await {
        Ok(Some(a)) => a,
        Ok(None) => return error_response(StatusCode::NOT_FOUND, "App not found."),
        Err(err) => {
            tracing::error!(?err, "loading app for resources page");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error");
        }
    };
    let search = clean(query.q);
    let type_filter = clean(query.r#type);
    let include_deleted = query.deleted.as_deref() == Some("1");
    // GUID search is exact (server id or the app's own resource id). A
    // non-empty, non-UUID query matches nothing rather than listing everything.
    let (guid, invalid_search) = match search.as_deref() {
        Some(s) => match Uuid::parse_str(s) {
            Ok(u) => (Some(u), false),
            Err(_) => (None, true),
        },
        None => (None, false),
    };
    let (rows, total) = if invalid_search {
        (Vec::new(), 0)
    } else {
        match platform::resources::admin_list(
            &state.db,
            app_id,
            type_filter.as_deref(),
            guid,
            include_deleted,
            RESOURCE_LIST_CAP,
        )
        .await
        {
            Ok(r) => r,
            Err(err) => {
                tracing::error!(?err, "listing resources for /apps/{app_id}/resources");
                return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error");
            }
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
    let view = views::AppResourcesView {
        app: &app,
        rows: &rows,
        total,
        cap: RESOURCE_LIST_CAP,
        type_filter: type_filter.as_deref().unwrap_or(""),
        search: search.as_deref().unwrap_or(""),
        include_deleted,
        now,
    };
    Html(views::app_resources_page(&ctx, &view).into_string()).into_response()
}

/// `GET /apps/{id}/resources/{rid}/modal` — metadata detail + delete action.
pub async fn app_resource_modal(
    State(state): State<AppState>,
    BrowserAuth(auth): BrowserAuth,
    Path((app_id, rid)): Path<(Uuid, Uuid)>,
) -> Response {
    if !matches!(auth.user.instance_role, InstanceRole::Owner) {
        return error_response(StatusCode::FORBIDDEN, "Owners only.");
    }
    let row = match platform::resources::admin_get(&state.db, app_id, rid).await {
        Ok(Some(r)) => r,
        Ok(None) => return error_response(StatusCode::NOT_FOUND, "Resource not found."),
        Err(err) => {
            tracing::error!(?err, "loading resource detail");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error");
        }
    };
    let csrf_token = csrf::compute_token(&state.csrf_secret, auth.session_id);
    Html(views::app_resource_detail_modal(app_id, &row, &csrf_token).into_string()).into_response()
}

/// `POST /apps/{id}/resources/{rid}/delete` — permanently purge one resource.
/// Owner + CSRF + reauth. Hard delete (no tombstone); audited.
pub async fn delete_resource(
    State(state): State<AppState>,
    BrowserAuth(auth): BrowserAuth,
    headers: HeaderMap,
    Path((app_id, rid)): Path<(Uuid, Uuid)>,
    Form(form): Form<AppActionForm>,
) -> Response {
    if let Err(resp) = check_csrf_token(&state, auth.session_id, &form.csrf_token) {
        return resp;
    }
    if !matches!(auth.user.instance_role, InstanceRole::Owner) {
        return error_response(StatusCode::FORBIDDEN, "Owners only.");
    }
    let htmx = is_htmx(&headers);
    if let Err(resp) = require_sudo(&state, &headers, auth.user.id) {
        return resp;
    }
    let actor = actor_of(&auth);
    let back = format!("/apps/{app_id}/resources");
    match delete_resource_audited(&state, &actor, app_id, rid).await {
        Ok(Some(_)) => redirect_with_action_toast(&back, htmx, "resource_deleted", None),
        Ok(None) => redirect_with_error_toast(&back, htmx, "resource_not_found"),
        Err(err) => {
            tracing::error!(?err, "deleting resource");
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        }
    }
}

/// Hard-delete a resource + write the audit event in one transaction. Returns
/// the deleted row's key fields, or `None` if no such resource existed.
async fn delete_resource_audited(
    state: &AppState,
    actor: &audit::Actor,
    app_id: Uuid,
    rid: Uuid,
) -> anyhow::Result<Option<platform::resources::DeletedResource>> {
    let mut tx = state.db.begin().await?;
    let deleted = platform::resources::admin_hard_delete(&mut *tx, app_id, rid).await?;
    if let Some(d) = &deleted {
        audit::append(
            &mut tx,
            Some(actor),
            None,
            "resource_deleted",
            serde_json::json!({
                "resource_id": d.id,
                "app_id": d.app_id,
                "resource_type": d.resource_type,
                "app_resource_id": d.app_resource_id,
                "owner_user_id": d.owner_user_id,
            }),
        )
        .await?;
    }
    tx.commit().await?;
    Ok(deleted)
}

// ── Trusted publishers (CP4) ───────────────────────────────────────────────

#[derive(Deserialize)]
pub struct PublishersAddForm {
    pub csrf_token: String,
    pub publisher: String,
    pub public_key: String,
}

#[derive(Deserialize)]
pub struct RemovePublisherForm {
    pub csrf_token: String,
    pub publisher: String,
}

#[derive(Deserialize)]
pub struct RemoveModalQuery {
    pub publisher: String,
}

/// Parse a 64-character hex string (whitespace ignored) into 32 raw key bytes.
/// `None` if it isn't exactly 32 bytes of hex.
fn parse_ed25519_hex(input: &str) -> Option<Vec<u8>> {
    let s: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(32);
    let mut i = 0;
    while i < 64 {
        let hi = (bytes[i] as char).to_digit(16)?;
        let lo = (bytes[i + 1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
        i += 2;
    }
    Some(out)
}

/// `GET /apps/publishers` — list + add form. Owner-only.
pub async fn publishers_page(
    State(state): State<AppState>,
    BrowserAuth(auth): BrowserAuth,
) -> Response {
    if !matches!(auth.user.instance_role, InstanceRole::Owner) {
        return error_response(StatusCode::FORBIDDEN, "Owners only.");
    }
    let publishers = match platform::registry::list_trusted_publishers(&state.db).await {
        Ok(p) => p,
        Err(err) => {
            tracing::error!(?err, "listing trusted publishers");
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
    Html(views::trusted_publishers_page(&ctx, &publishers, now).into_string()).into_response()
}

/// `POST /apps/publishers` — add (or replace) a trusted publisher. Owner + CSRF
/// + reauth. The key is a 64-char hex Ed25519 public key.
pub async fn add_publisher(
    State(state): State<AppState>,
    BrowserAuth(auth): BrowserAuth,
    headers: HeaderMap,
    Form(form): Form<PublishersAddForm>,
) -> Response {
    if let Err(resp) = check_csrf_token(&state, auth.session_id, &form.csrf_token) {
        return resp;
    }
    if !matches!(auth.user.instance_role, InstanceRole::Owner) {
        return error_response(StatusCode::FORBIDDEN, "Owners only.");
    }
    let htmx = is_htmx(&headers);
    if let Err(resp) = require_sudo(&state, &headers, auth.user.id) {
        return resp;
    }
    let publisher = form.publisher.trim().to_string();
    if publisher.is_empty() {
        return redirect_with_error_toast("/apps/publishers", htmx, "publisher_name_required");
    }
    let key = match parse_ed25519_hex(&form.public_key) {
        Some(k) => k,
        None => return redirect_with_error_toast("/apps/publishers", htmx, "invalid_publisher_key"),
    };
    let actor = actor_of(&auth);
    match add_publisher_audited(&state, &actor, &publisher, &key).await {
        Ok(()) => redirect_with_action_toast("/apps/publishers", htmx, "publisher_added", Some(&publisher)),
        Err(err) => {
            tracing::error!(?err, "adding trusted publisher");
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        }
    }
}

/// `GET /apps/publishers/remove-modal?publisher=…` — remove confirmation dialog.
pub async fn remove_publisher_modal(
    State(state): State<AppState>,
    BrowserAuth(auth): BrowserAuth,
    Query(query): Query<RemoveModalQuery>,
) -> Response {
    if !matches!(auth.user.instance_role, InstanceRole::Owner) {
        return error_response(StatusCode::FORBIDDEN, "Owners only.");
    }
    let csrf_token = csrf::compute_token(&state.csrf_secret, auth.session_id);
    Html(views::remove_publisher_dialog(&query.publisher, &csrf_token).into_string()).into_response()
}

/// `POST /apps/publishers/remove` — remove a trusted publisher. Owner + CSRF +
/// reauth. The publisher (the PK) rides in the body, not the path.
pub async fn remove_publisher(
    State(state): State<AppState>,
    BrowserAuth(auth): BrowserAuth,
    headers: HeaderMap,
    Form(form): Form<RemovePublisherForm>,
) -> Response {
    if let Err(resp) = check_csrf_token(&state, auth.session_id, &form.csrf_token) {
        return resp;
    }
    if !matches!(auth.user.instance_role, InstanceRole::Owner) {
        return error_response(StatusCode::FORBIDDEN, "Owners only.");
    }
    let htmx = is_htmx(&headers);
    if let Err(resp) = require_sudo(&state, &headers, auth.user.id) {
        return resp;
    }
    let actor = actor_of(&auth);
    match remove_publisher_audited(&state, &actor, &form.publisher).await {
        Ok(true) => {
            redirect_with_action_toast("/apps/publishers", htmx, "publisher_removed", Some(&form.publisher))
        }
        Ok(false) => redirect_with_error_toast("/apps/publishers", htmx, "publisher_not_found"),
        Err(err) => {
            tracing::error!(?err, "removing trusted publisher");
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        }
    }
}

/// Add/replace a trusted publisher + audit event in one transaction.
async fn add_publisher_audited(
    state: &AppState,
    actor: &audit::Actor,
    publisher: &str,
    public_key: &[u8],
) -> anyhow::Result<()> {
    let mut tx = state.db.begin().await?;
    platform::registry::add_trusted_publisher(&mut *tx, publisher, public_key, Some(actor.user_id.0))
        .await?;
    audit::append(
        &mut tx,
        Some(actor),
        None,
        "trusted_publisher_added",
        serde_json::json!({ "publisher": publisher }),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Remove a trusted publisher + audit event in one transaction. Returns whether
/// a row was actually removed.
async fn remove_publisher_audited(
    state: &AppState,
    actor: &audit::Actor,
    publisher: &str,
) -> anyhow::Result<bool> {
    let mut tx = state.db.begin().await?;
    let removed = platform::registry::remove_trusted_publisher(&mut *tx, publisher).await?;
    if removed {
        audit::append(
            &mut tx,
            Some(actor),
            None,
            "trusted_publisher_removed",
            serde_json::json!({ "publisher": publisher }),
        )
        .await?;
    }
    tx.commit().await?;
    Ok(removed)
}

/// Set an app's status + write the audit event in one transaction. Returns the
/// updated row, or `None` if no app had that id.
async fn set_status_audited(
    state: &AppState,
    actor: &audit::Actor,
    id: Uuid,
    status: &str,
    event_type: &str,
) -> anyhow::Result<Option<platform::registry::RegisteredAppRow>> {
    let mut tx = state.db.begin().await?;
    let row = platform::registry::set_app_status(&mut *tx, id, status).await?;
    if let Some(app) = &row {
        audit::append(
            &mut tx,
            Some(actor),
            None,
            event_type,
            serde_json::json!({
                "app_id": app.id,
                "app_identifier": app.app_identifier,
                "status": app.status,
            }),
        )
        .await?;
    }
    tx.commit().await?;
    Ok(row)
}

/// Delete an app (cascading its resources) + write the audit event in one
/// transaction. Returns the deleted row, or `None` if no app had that id.
async fn uninstall_audited(
    state: &AppState,
    actor: &audit::Actor,
    id: Uuid,
) -> anyhow::Result<Option<platform::registry::RegisteredAppRow>> {
    let mut tx = state.db.begin().await?;
    let row = platform::registry::delete_app(&mut *tx, id).await?;
    if let Some(app) = &row {
        audit::append(
            &mut tx,
            Some(actor),
            None,
            "app_uninstalled",
            serde_json::json!({
                "app_id": app.id,
                "app_identifier": app.app_identifier,
            }),
        )
        .await?;
    }
    tx.commit().await?;
    Ok(row)
}
