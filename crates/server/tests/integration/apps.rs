//! Owner-only registered-apps admin page (`/apps`, CP1 — read-only list).
//!
//! Seeds apps + resources directly in the DB (registration itself is covered by
//! the gRPC tests), logs in via the web cookie flow, and asserts the page shows
//! each app with a live resource count — and that the page + its nav link are
//! Owner-only.

use axum::http::{Method, StatusCode, header};
use identity::InstanceRole;
use platform::registry::{self, AppDeclaration};
use platform::resources::{NewResource, ResourceRepository};
use uuid::Uuid;

use super::common::TestApp;

/// POST `/login` (form-encoded) and return the `sylva_session=<token>` cookie.
async fn web_login(app: &TestApp, email: &str, password: &str) -> String {
    let body = format!("email={}&password={}", enc(email), enc(password));
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri("/login")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(axum::body::Body::from(body))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER, "login should redirect");
    let set_cookie = resp
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .expect("login sets a cookie");
    set_cookie.split(';').next().unwrap_or("").to_string()
}

/// Minimal application/x-www-form-urlencoded escaping for our test inputs.
fn enc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => out.push(c),
            ' ' => out.push('+'),
            other => out.push_str(&format!("%{:02X}", other as u32)),
        }
    }
    out
}

async fn get_with_cookie(app: &TestApp, path: &str, cookie: &str) -> (StatusCode, String) {
    let req = axum::http::Request::builder()
        .method(Method::GET)
        .uri(path)
        .header(header::COOKIE, cookie)
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

fn sample_decl() -> AppDeclaration {
    AppDeclaration {
        app_identifier: "garden.ubivera.tasks".to_string(),
        display_name: "Tasks".to_string(),
        publisher: "Ubivera, LLC".to_string(),
        app_public_key: vec![9u8; 32],
        schema_version: 1,
        resource_types: vec!["task".to_string(), "project".to_string()],
    }
}

/// Create a resource owned by `owner` under `app_id`; returns its server id.
async fn seed_resource(app: &TestApp, app_id: Uuid, owner: Uuid) -> Uuid {
    let repo = ResourceRepository::new(app.pool.clone());
    repo.create(&NewResource {
        app_id,
        resource_type: "task".to_string(),
        app_resource_id: Uuid::new_v4(),
        parent_resource_id: None,
        owner_user_id: owner,
        content_blob: b"ct".to_vec(),
        content_signature: b"sig".to_vec(),
        schema_version: 1,
    })
    .await
    .unwrap()
    .id
}

#[tokio::test]
async fn owner_sees_registered_apps_with_counts() {
    let app = TestApp::new().await;
    let owner = app
        .seed_user("owner@test.local", "Olivia", "pw", InstanceRole::Owner)
        .await;

    // Register an app, then give it two live resources and one tombstoned one —
    // the count must exclude the soft-deleted resource.
    let registered = registry::upsert_app(&app.pool, &sample_decl(), Some(owner.id.0))
        .await
        .unwrap();
    seed_resource(&app, registered.id, owner.id.0).await;
    seed_resource(&app, registered.id, owner.id.0).await;
    let doomed = seed_resource(&app, registered.id, owner.id.0).await;
    ResourceRepository::new(app.pool.clone())
        .soft_delete_owned(doomed, owner.id.0)
        .await
        .unwrap();

    let cookie = web_login(&app, "owner@test.local", "pw").await;
    let (status, body) = get_with_cookie(&app, "/apps", &cookie).await;

    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("garden.ubivera.tasks"), "shows the app identifier");
    assert!(body.contains("Tasks"), "shows the display name");
    assert!(body.contains("Ubivera, LLC"), "shows the publisher");
    assert!(body.contains("task"), "shows declared resource types");
    // Count cell links to the resource browser and shows 2 (live only), not 3.
    assert!(
        body.contains(&format!("/apps/{}/resources\">2</a>", registered.id)),
        "resource count should link through showing 2 (excludes the tombstone); body: {body}"
    );
    // The Owner sees the Apps nav link.
    assert!(body.contains("href=\"/apps\""), "Apps nav link present for owner");
}

#[tokio::test]
async fn admin_is_forbidden_and_has_no_apps_nav_link() {
    let app = TestApp::new().await;
    app.seed_user("admin@test.local", "Adam", "pw", InstanceRole::Admin)
        .await;
    let cookie = web_login(&app, "admin@test.local", "pw").await;

    // The page itself is Owner-only.
    let (status, _) = get_with_cookie(&app, "/apps", &cookie).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // And the Apps nav entry isn't rendered for an Admin (checked on a page
    // they *can* see).
    let (members_status, members_body) = get_with_cookie(&app, "/members", &cookie).await;
    assert_eq!(members_status, StatusCode::OK);
    assert!(
        !members_body.contains("href=\"/apps\""),
        "Admin must not see the Apps nav link"
    );
}

#[tokio::test]
async fn apps_page_shows_empty_state() {
    let app = TestApp::new().await;
    app.seed_user("owner@test.local", "Olivia", "pw", InstanceRole::Owner)
        .await;
    let cookie = web_login(&app, "owner@test.local", "pw").await;

    let (status, body) = get_with_cookie(&app, "/apps", &cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("No apps have registered yet."),
        "empty-state copy present; body: {body}"
    );
}

// ── CP2: lifecycle (enable/disable, uninstall) ─────────────────────────────

/// Log in via the web form and return (session cookie, session id) so the
/// caller can compute CSRF tokens + mint sudo grants.
async fn login_session(app: &TestApp, email: &str, pw: &str) -> (String, Uuid) {
    let cookie = web_login(app, email, pw).await;
    let session_id = app.session_id_for_cookie(&cookie).await;
    (cookie, session_id)
}

fn location(resp: &axum::response::Response) -> String {
    resp.headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string()
}

/// POST a reauth-gated app action: mints a `sylva_sudo` grant from the
/// password (as the reauth chain does in the browser) and attaches it.
async fn post_action(
    app: &TestApp,
    path: &str,
    cookie: &str,
    session_id: Uuid,
    password: &str,
) -> (StatusCode, String) {
    let csrf = app.csrf_for(session_id);
    let sudo = app.sudo_cookie(cookie, &csrf, password).await;
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri(path)
        .header(header::COOKIE, format!("{cookie}; {sudo}"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(axum::body::Body::from(format!("csrf_token={csrf}")))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    (resp.status(), location(&resp))
}

/// POST an app action without minting a sudo grant — exercises the reauth gate.
async fn post_action_no_sudo(app: &TestApp, path: &str, cookie: &str, session_id: Uuid) -> StatusCode {
    let csrf = app.csrf_for(session_id);
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri(path)
        .header(header::COOKIE, cookie.to_string())
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(axum::body::Body::from(format!("csrf_token={csrf}")))
        .unwrap();
    tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap().status()
}

async fn app_status(app: &TestApp, id: Uuid) -> Option<String> {
    registry::get_app(&app.pool, id).await.unwrap().map(|a| a.status)
}

async fn count_all_resources(app: &TestApp, app_id: Uuid) -> i64 {
    let (n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM platform.resources WHERE app_id = $1")
        .bind(app_id)
        .fetch_one(&app.pool)
        .await
        .unwrap();
    n
}

#[tokio::test]
async fn owner_can_disable_and_re_enable_an_app() {
    let app = TestApp::new().await;
    app.seed_user("owner@test.local", "Olivia", "pw", InstanceRole::Owner)
        .await;
    let registered = registry::upsert_app(&app.pool, &sample_decl(), None)
        .await
        .unwrap();
    let (cookie, sid) = login_session(&app, "owner@test.local", "pw").await;

    let (status, loc) =
        post_action(&app, &format!("/apps/{}/disable", registered.id), &cookie, sid, "pw").await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(loc, "/apps");
    assert_eq!(app_status(&app, registered.id).await.as_deref(), Some("disabled"));

    let (status, _) =
        post_action(&app, &format!("/apps/{}/enable", registered.id), &cookie, sid, "pw").await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(app_status(&app, registered.id).await.as_deref(), Some("enabled"));
}

#[tokio::test]
async fn owner_can_uninstall_an_app_and_its_resources_cascade() {
    let app = TestApp::new().await;
    let owner = app
        .seed_user("owner@test.local", "Olivia", "pw", InstanceRole::Owner)
        .await;
    let registered = registry::upsert_app(&app.pool, &sample_decl(), None)
        .await
        .unwrap();
    seed_resource(&app, registered.id, owner.id.0).await;
    seed_resource(&app, registered.id, owner.id.0).await;
    assert_eq!(count_all_resources(&app, registered.id).await, 2);

    let (cookie, sid) = login_session(&app, "owner@test.local", "pw").await;
    let (status, loc) =
        post_action(&app, &format!("/apps/{}/uninstall", registered.id), &cookie, sid, "pw").await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(loc, "/apps");
    assert!(app_status(&app, registered.id).await.is_none(), "app row removed");
    assert_eq!(
        count_all_resources(&app, registered.id).await,
        0,
        "resources cascade-deleted with the app"
    );
}

#[tokio::test]
async fn lifecycle_actions_require_owner() {
    let app = TestApp::new().await;
    app.seed_user("admin@test.local", "Adam", "pw", InstanceRole::Admin)
        .await;
    let registered = registry::upsert_app(&app.pool, &sample_decl(), None)
        .await
        .unwrap();
    let (cookie, sid) = login_session(&app, "admin@test.local", "pw").await;

    let (status, _) =
        post_action(&app, &format!("/apps/{}/disable", registered.id), &cookie, sid, "pw").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(
        app_status(&app, registered.id).await.as_deref(),
        Some("enabled"),
        "status unchanged by a forbidden request"
    );
}

#[tokio::test]
async fn lifecycle_actions_require_a_reauth_grant() {
    let app = TestApp::new().await;
    app.seed_user("owner@test.local", "Olivia", "pw", InstanceRole::Owner)
        .await;
    let registered = registry::upsert_app(&app.pool, &sample_decl(), None)
        .await
        .unwrap();
    let (cookie, sid) = login_session(&app, "owner@test.local", "pw").await;

    let status =
        post_action_no_sudo(&app, &format!("/apps/{}/disable", registered.id), &cookie, sid).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(
        app_status(&app, registered.id).await.as_deref(),
        Some("enabled"),
        "no reauth grant → action refused, status unchanged"
    );
}

#[tokio::test]
async fn uninstall_modal_renders_and_list_exposes_the_kebab() {
    let app = TestApp::new().await;
    let owner = app
        .seed_user("owner@test.local", "Olivia", "pw", InstanceRole::Owner)
        .await;
    let registered = registry::upsert_app(&app.pool, &sample_decl(), None)
        .await
        .unwrap();
    seed_resource(&app, registered.id, owner.id.0).await;
    let cookie = web_login(&app, "owner@test.local", "pw").await;

    let (status, body) =
        get_with_cookie(&app, &format!("/apps/{}/modal/uninstall", registered.id), &cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Uninstall"), "dialog title present; body: {body}");
    assert!(
        body.contains(&format!("/apps/{}/uninstall", registered.id)),
        "dialog form posts to the uninstall route"
    );

    let (_, list) = get_with_cookie(&app, "/apps", &cookie).await;
    assert!(
        list.contains(&format!("/apps/{}/modal/uninstall", registered.id)),
        "the apps list exposes the uninstall kebab item"
    );
}

// ── CP3: per-app resource browser + delete by GUID ─────────────────────────

/// Seed a resource of a given type owned by `owner`; returns the full row so
/// the caller has both the server id and the app's own resource id.
async fn seed_typed(
    app: &TestApp,
    app_id: Uuid,
    owner: Uuid,
    rtype: &str,
) -> platform::resources::ResourceRow {
    ResourceRepository::new(app.pool.clone())
        .create(&NewResource {
            app_id,
            resource_type: rtype.to_string(),
            app_resource_id: Uuid::new_v4(),
            parent_resource_id: None,
            owner_user_id: owner,
            content_blob: b"ciphertext".to_vec(),
            content_signature: b"sig".to_vec(),
            schema_version: 1,
        })
        .await
        .unwrap()
}

#[tokio::test]
async fn resource_browser_lists_filters_and_searches() {
    let app = TestApp::new().await;
    let owner = app
        .seed_user("owner@test.local", "Olivia", "pw", InstanceRole::Owner)
        .await;
    let registered = registry::upsert_app(&app.pool, &sample_decl(), None)
        .await
        .unwrap();
    let task = seed_typed(&app, registered.id, owner.id.0, "task").await;
    seed_typed(&app, registered.id, owner.id.0, "project").await;
    let gone = seed_typed(&app, registered.id, owner.id.0, "task").await;
    ResourceRepository::new(app.pool.clone())
        .soft_delete_owned(gone.id, owner.id.0)
        .await
        .unwrap();
    let cookie = web_login(&app, "owner@test.local", "pw").await;
    let base = format!("/apps/{}/resources", registered.id);

    // Default view: live resources only (the tombstone is hidden).
    let (status, body) = get_with_cookie(&app, &base, &cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Showing 2 of 2"), "two live resources; body: {body}");
    assert!(body.contains(&task.app_resource_id.to_string()));

    // Type filter narrows to one.
    let (_, body) = get_with_cookie(&app, &format!("{base}?type=project"), &cookie).await;
    assert!(body.contains("Showing 1 of 1"));
    assert!(
        !body.contains(&task.app_resource_id.to_string()),
        "the task resource is filtered out"
    );

    // Exact GUID search (by the app's own resource id) finds just that one.
    let (_, body) = get_with_cookie(&app, &format!("{base}?q={}", task.app_resource_id), &cookie).await;
    assert!(body.contains("Showing 1 of 1"));
    assert!(body.contains(&task.app_resource_id.to_string()));

    // Including tombstones surfaces the soft-deleted one.
    let (_, body) = get_with_cookie(&app, &format!("{base}?deleted=1"), &cookie).await;
    assert!(body.contains("Showing 3 of 3"));
    assert!(body.contains("Deleted"), "tombstone status shown");
}

#[tokio::test]
async fn resource_detail_modal_renders_metadata_and_delete() {
    let app = TestApp::new().await;
    let owner = app
        .seed_user("owner@test.local", "Olivia", "pw", InstanceRole::Owner)
        .await;
    let registered = registry::upsert_app(&app.pool, &sample_decl(), None)
        .await
        .unwrap();
    let r = seed_typed(&app, registered.id, owner.id.0, "task").await;
    let cookie = web_login(&app, "owner@test.local", "pw").await;

    let (status, body) = get_with_cookie(
        &app,
        &format!("/apps/{}/resources/{}/modal", registered.id, r.id),
        &cookie,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains(&r.app_resource_id.to_string()), "shows the resource id");
    assert!(body.contains("encrypted (not shown)"), "blob stays opaque");
    assert!(body.contains("Delete permanently"), "offers a delete action");
    assert!(
        body.contains(&format!("/apps/{}/resources/{}/delete", registered.id, r.id)),
        "delete form targets this resource"
    );
}

#[tokio::test]
async fn owner_can_hard_delete_a_resource_by_id() {
    let app = TestApp::new().await;
    let owner = app
        .seed_user("owner@test.local", "Olivia", "pw", InstanceRole::Owner)
        .await;
    let registered = registry::upsert_app(&app.pool, &sample_decl(), None)
        .await
        .unwrap();
    let r = seed_typed(&app, registered.id, owner.id.0, "task").await;
    let (cookie, sid) = login_session(&app, "owner@test.local", "pw").await;

    let (status, loc) = post_action(
        &app,
        &format!("/apps/{}/resources/{}/delete", registered.id, r.id),
        &cookie,
        sid,
        "pw",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(loc, format!("/apps/{}/resources", registered.id));
    // Hard delete — the row is gone entirely, not tombstoned.
    assert_eq!(count_all_resources(&app, registered.id).await, 0);
}

#[tokio::test]
async fn resource_actions_are_owner_and_reauth_gated() {
    let app = TestApp::new().await;
    let owner = app
        .seed_user("owner@test.local", "Olivia", "pw", InstanceRole::Owner)
        .await;
    app.seed_user("admin@test.local", "Adam", "pw", InstanceRole::Admin)
        .await;
    let registered = registry::upsert_app(&app.pool, &sample_decl(), None)
        .await
        .unwrap();
    let r = seed_typed(&app, registered.id, owner.id.0, "task").await;
    let page = format!("/apps/{}/resources", registered.id);
    let del = format!("/apps/{}/resources/{}/delete", registered.id, r.id);

    // Admin: can't browse, can't delete.
    let (admin_cookie, admin_sid) = login_session(&app, "admin@test.local", "pw").await;
    let (s, _) = get_with_cookie(&app, &page, &admin_cookie).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _) = post_action(&app, &del, &admin_cookie, admin_sid, "pw").await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    // Owner without a reauth grant: refused.
    let (owner_cookie, owner_sid) = login_session(&app, "owner@test.local", "pw").await;
    let s = post_action_no_sudo(&app, &del, &owner_cookie, owner_sid).await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    assert_eq!(
        count_all_resources(&app, registered.id).await,
        1,
        "resource survives the refused deletes"
    );
}

// ── CP4: trusted-publisher management ──────────────────────────────────────

/// POST a reauth-gated form carrying extra fields (beyond csrf): mints a sudo
/// grant from the password and url-encodes each field.
async fn post_form(
    app: &TestApp,
    path: &str,
    cookie: &str,
    session_id: Uuid,
    password: &str,
    fields: &[(&str, &str)],
) -> (StatusCode, String) {
    let csrf = app.csrf_for(session_id);
    let sudo = app.sudo_cookie(cookie, &csrf, password).await;
    let mut body = format!("csrf_token={csrf}");
    for (k, v) in fields {
        body.push('&');
        body.push_str(&format!("{k}={}", enc(v)));
    }
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri(path)
        .header(header::COOKIE, format!("{cookie}; {sudo}"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(axum::body::Body::from(body))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    (resp.status(), location(&resp))
}

/// Like [`post_form`] but attaches no sudo grant (exercises the reauth gate).
async fn post_form_no_sudo(
    app: &TestApp,
    path: &str,
    cookie: &str,
    session_id: Uuid,
    fields: &[(&str, &str)],
) -> StatusCode {
    let csrf = app.csrf_for(session_id);
    let mut body = format!("csrf_token={csrf}");
    for (k, v) in fields {
        body.push('&');
        body.push_str(&format!("{k}={}", enc(v)));
    }
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri(path)
        .header(header::COOKIE, cookie.to_string())
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(axum::body::Body::from(body))
        .unwrap();
    tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap().status()
}

/// A valid 64-char hex Ed25519 public key (32 bytes of 0x07).
fn sample_key_hex() -> String {
    "07".repeat(32)
}

#[tokio::test]
async fn publishers_page_lists_and_shows_empty_state() {
    let app = TestApp::new().await;
    app.seed_user("owner@test.local", "Olivia", "pw", InstanceRole::Owner)
        .await;
    let cookie = web_login(&app, "owner@test.local", "pw").await;

    // Empty first.
    let (status, body) = get_with_cookie(&app, "/apps/publishers", &cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("No trusted publishers yet."), "empty state; body: {body}");

    // Seed one directly and confirm it lists.
    registry::add_trusted_publisher(&app.pool, "Ubivera, LLC", &[7u8; 32], None)
        .await
        .unwrap();
    let (_, body) = get_with_cookie(&app, "/apps/publishers", &cookie).await;
    assert!(body.contains("Ubivera, LLC"), "lists the publisher");
}

#[tokio::test]
async fn owner_can_add_a_trusted_publisher() {
    let app = TestApp::new().await;
    app.seed_user("owner@test.local", "Olivia", "pw", InstanceRole::Owner)
        .await;
    let (cookie, sid) = login_session(&app, "owner@test.local", "pw").await;

    let (status, loc) = post_form(
        &app,
        "/apps/publishers",
        &cookie,
        sid,
        "pw",
        &[("publisher", "Ubivera, LLC"), ("public_key", &sample_key_hex())],
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(loc, "/apps/publishers");

    let stored = registry::get_trusted_publisher(&app.pool, "Ubivera, LLC")
        .await
        .unwrap()
        .expect("publisher persisted");
    assert_eq!(stored.public_key, vec![7u8; 32], "key decoded from hex");
}

#[tokio::test]
async fn add_publisher_rejects_a_bad_key_and_empty_name() {
    let app = TestApp::new().await;
    app.seed_user("owner@test.local", "Olivia", "pw", InstanceRole::Owner)
        .await;
    let (cookie, sid) = login_session(&app, "owner@test.local", "pw").await;

    // Non-hex / wrong-length key → refused, nothing stored.
    let (status, _) = post_form(
        &app,
        "/apps/publishers",
        &cookie,
        sid,
        "pw",
        &[("publisher", "Ubivera, LLC"), ("public_key", "not-a-key")],
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER); // redirect carrying an error toast
    assert!(
        registry::get_trusted_publisher(&app.pool, "Ubivera, LLC")
            .await
            .unwrap()
            .is_none(),
        "a bad key must not be stored"
    );

    // Empty name → refused.
    let (status, _) = post_form(
        &app,
        "/apps/publishers",
        &cookie,
        sid,
        "pw",
        &[("publisher", ""), ("public_key", &sample_key_hex())],
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn owner_can_remove_a_trusted_publisher() {
    let app = TestApp::new().await;
    app.seed_user("owner@test.local", "Olivia", "pw", InstanceRole::Owner)
        .await;
    registry::add_trusted_publisher(&app.pool, "Ubivera, LLC", &[7u8; 32], None)
        .await
        .unwrap();
    let (cookie, sid) = login_session(&app, "owner@test.local", "pw").await;

    let (status, loc) = post_form(
        &app,
        "/apps/publishers/remove",
        &cookie,
        sid,
        "pw",
        &[("publisher", "Ubivera, LLC")],
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(loc, "/apps/publishers");
    assert!(
        registry::get_trusted_publisher(&app.pool, "Ubivera, LLC")
            .await
            .unwrap()
            .is_none(),
        "publisher removed"
    );
}

#[tokio::test]
async fn publisher_actions_are_owner_and_reauth_gated() {
    let app = TestApp::new().await;
    app.seed_user("owner@test.local", "Olivia", "pw", InstanceRole::Owner)
        .await;
    app.seed_user("admin@test.local", "Adam", "pw", InstanceRole::Admin)
        .await;

    // Admin can't view the page or add.
    let (admin_cookie, admin_sid) = login_session(&app, "admin@test.local", "pw").await;
    let (s, _) = get_with_cookie(&app, "/apps/publishers", &admin_cookie).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _) = post_form(
        &app,
        "/apps/publishers",
        &admin_cookie,
        admin_sid,
        "pw",
        &[("publisher", "Evil, Inc"), ("public_key", &sample_key_hex())],
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    // Owner without a reauth grant can't add.
    let (owner_cookie, owner_sid) = login_session(&app, "owner@test.local", "pw").await;
    let s = post_form_no_sudo(
        &app,
        "/apps/publishers",
        &owner_cookie,
        owner_sid,
        &[("publisher", "Ubivera, LLC"), ("public_key", &sample_key_hex())],
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    assert!(
        registry::get_trusted_publisher(&app.pool, "Ubivera, LLC")
            .await
            .unwrap()
            .is_none(),
        "no publisher stored by the refused requests"
    );
}
