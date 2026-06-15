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

/// POST `/login` (form-encoded) and return the `hearth_session=<token>` cookie.
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
    // Count cell shows 2 (live only), not 3.
    assert!(
        body.contains("col-count\">2<"),
        "resource count should be 2 (excludes the tombstone); body: {body}"
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
