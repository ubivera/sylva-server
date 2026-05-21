//! Integration tests for the per-row admin action endpoints
//! (`/users/{id}/deactivate`, `/reactivate`, `/delete`, `/purge`,
//! `/role`) and the surrounding CSRF + kebab UI behavior.

use axum::http::{Method, StatusCode, header};
use identity::InstanceRole;
use uuid::Uuid;

use super::common::TestApp;

const ADMIN_EMAIL: &str = "admin@test.local";
const ADMIN_PW: &str = "adminpw";

/// URL-encode a string for x-www-form-urlencoded form bodies.
fn urlencoding(s: &str) -> String {
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

fn cookie_name_value(set_cookie: &str) -> String {
    set_cookie.split(';').next().unwrap_or("").to_string()
}

/// Log in via the web form and return (cookie, session_id) so the
/// caller can sign requests + compute CSRF tokens.
async fn web_login_session(
    app: &TestApp,
    email: &str,
    password: &str,
) -> (String, Uuid) {
    let body = format!(
        "email={}&password={}",
        urlencoding(email),
        urlencoding(password)
    );
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri("/login")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(axum::body::Body::from(body))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let set_cookie = resp
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .unwrap()
        .to_string();
    let cookie = cookie_name_value(&set_cookie);
    let session_id = app.session_id_for_cookie(&cookie).await;
    (cookie, session_id)
}

/// POST a form to `path` with the given cookie + form body (already
/// `&`-joined `key=value` pairs), returning the response.
async fn post_form(
    app: &TestApp,
    path: &str,
    cookie: &str,
    body: String,
) -> axum::response::Response {
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri(path)
        .header(header::COOKIE, cookie)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(axum::body::Body::from(body))
        .unwrap();
    tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap()
}

fn location(resp: &axum::response::Response) -> String {
    resp.headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string()
}

// ────────────────────────────────────────────────────────────────────────
// CSRF
// ────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn deactivate_without_csrf_returns_403() {
    let app = TestApp::new().await;
    app.seed_user(ADMIN_EMAIL, "Adm", ADMIN_PW, InstanceRole::Admin)
        .await;
    let target = app
        .seed_user("u@test.local", "U", "pw", InstanceRole::Member)
        .await;
    let (cookie, _) = web_login_session(&app, ADMIN_EMAIL, ADMIN_PW).await;

    let resp = post_form(
        &app,
        &format!("/members/{}/deactivate", target.id.0),
        &cookie,
        // Empty body → form deserialization fails OR csrf check fails
        String::new(),
    )
    .await;
    // axum's Form extractor returns 422 for malformed bodies; either way
    // we want a non-success that isn't a redirect-completed action.
    assert!(
        resp.status() == StatusCode::FORBIDDEN
            || resp.status() == StatusCode::UNPROCESSABLE_ENTITY
            || resp.status() == StatusCode::BAD_REQUEST,
        "expected client error, got {}",
        resp.status()
    );
}

#[tokio::test]
async fn deactivate_with_wrong_csrf_returns_403() {
    let app = TestApp::new().await;
    app.seed_user(ADMIN_EMAIL, "Adm", ADMIN_PW, InstanceRole::Admin)
        .await;
    let target = app
        .seed_user("u@test.local", "U", "pw", InstanceRole::Member)
        .await;
    let (cookie, _) = web_login_session(&app, ADMIN_EMAIL, ADMIN_PW).await;

    let resp = post_form(
        &app,
        &format!("/members/{}/deactivate", target.id.0),
        &cookie,
        "csrf_token=00000000000000000000000000000000".to_string(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// ────────────────────────────────────────────────────────────────────────
// Role gating
// ────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn regular_user_cannot_invoke_row_actions() {
    let app = TestApp::new().await;
    app.seed_user("u@test.local", "U", "pw", InstanceRole::Member)
        .await;
    let target = app
        .seed_user("target@test.local", "T", "pw", InstanceRole::Member)
        .await;
    let (cookie, session_id) = web_login_session(&app, "u@test.local", "pw").await;
    let csrf = app.csrf_for(session_id);

    let resp = post_form(
        &app,
        &format!("/members/{}/deactivate", target.id.0),
        &cookie,
        format!("csrf_token={}", urlencoding(&csrf)),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// ────────────────────────────────────────────────────────────────────────
// Happy paths
// ────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn admin_deactivates_user_redirects_with_banner_params() {
    let app = TestApp::new().await;
    app.seed_user(ADMIN_EMAIL, "Adm", ADMIN_PW, InstanceRole::Admin)
        .await;
    let target = app
        .seed_user("alice@test.local", "Alice", "pw", InstanceRole::Member)
        .await;
    let (cookie, session_id) = web_login_session(&app, ADMIN_EMAIL, ADMIN_PW).await;
    let csrf = app.csrf_for(session_id);

    let resp = post_form(
        &app,
        &format!("/members/{}/deactivate", target.id.0),
        &cookie,
        format!("csrf_token={}", urlencoding(&csrf)),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = location(&resp);
    assert!(loc.starts_with("/members?action=deactivated"), "got {loc}");
    assert!(loc.contains("target=Alice"), "got {loc}");

    // Confirm DB-side state changed.
    let lifecycle: String = sqlx::query_scalar(
        "SELECT lifecycle::text FROM identity.users WHERE id = $1",
    )
    .bind(target.id.0)
    .fetch_one(&app.pool)
    .await
    .unwrap();
    assert_eq!(lifecycle, "deactivated");
}

#[tokio::test]
async fn admin_reactivates_deactivated_user() {
    let app = TestApp::new().await;
    app.seed_user(ADMIN_EMAIL, "Adm", ADMIN_PW, InstanceRole::Admin)
        .await;
    let target = app
        .seed_user("alice@test.local", "Alice", "pw", InstanceRole::Member)
        .await;
    sqlx::query("UPDATE identity.users SET lifecycle = 'deactivated' WHERE id = $1")
        .bind(target.id.0)
        .execute(&app.pool)
        .await
        .unwrap();

    let (cookie, session_id) = web_login_session(&app, ADMIN_EMAIL, ADMIN_PW).await;
    let csrf = app.csrf_for(session_id);

    let resp = post_form(
        &app,
        &format!("/members/{}/reactivate", target.id.0),
        &cookie,
        format!("csrf_token={}", urlencoding(&csrf)),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert!(location(&resp).starts_with("/members?action=reactivated"));
}

#[tokio::test]
async fn admin_deletes_user() {
    let app = TestApp::new().await;
    app.seed_user(ADMIN_EMAIL, "Adm", ADMIN_PW, InstanceRole::Admin)
        .await;
    let target = app
        .seed_user("alice@test.local", "Alice", "pw", InstanceRole::Member)
        .await;
    let (cookie, session_id) = web_login_session(&app, ADMIN_EMAIL, ADMIN_PW).await;
    let csrf = app.csrf_for(session_id);

    let resp = post_form(
        &app,
        &format!("/members/{}/delete", target.id.0),
        &cookie,
        format!("csrf_token={}", urlencoding(&csrf)),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert!(location(&resp).starts_with("/members?action=deleted"));

    let lifecycle: String = sqlx::query_scalar(
        "SELECT lifecycle::text FROM identity.users WHERE id = $1",
    )
    .bind(target.id.0)
    .fetch_one(&app.pool)
    .await
    .unwrap();
    assert_eq!(lifecycle, "soft_deleted");
}

#[tokio::test]
async fn admin_purges_user() {
    let app = TestApp::new().await;
    app.seed_user(ADMIN_EMAIL, "Adm", ADMIN_PW, InstanceRole::Admin)
        .await;
    let target = app
        .seed_user("alice@test.local", "Alice", "pw", InstanceRole::Member)
        .await;
    let (cookie, session_id) = web_login_session(&app, ADMIN_EMAIL, ADMIN_PW).await;
    let csrf = app.csrf_for(session_id);

    let resp = post_form(
        &app,
        &format!("/members/{}/purge", target.id.0),
        &cookie,
        format!("csrf_token={}", urlencoding(&csrf)),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert!(location(&resp).starts_with("/members?action=purged"));
}

#[tokio::test]
async fn owner_changes_user_role() {
    let app = TestApp::new().await;
    app.seed_user("owner@test.local", "Big", "ownerpw", InstanceRole::Owner)
        .await;
    let target = app
        .seed_user("alice@test.local", "Alice", "pw", InstanceRole::Member)
        .await;
    let (cookie, session_id) = web_login_session(&app, "owner@test.local", "ownerpw").await;
    let csrf = app.csrf_for(session_id);

    let resp = post_form(
        &app,
        &format!("/members/{}/role", target.id.0),
        &cookie,
        format!("csrf_token={}&role=admin", urlencoding(&csrf)),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert!(location(&resp).starts_with("/members?action=role_changed"));

    let role: String = sqlx::query_scalar(
        "SELECT instance_role::text FROM identity.users WHERE id = $1",
    )
    .bind(target.id.0)
    .fetch_one(&app.pool)
    .await
    .unwrap();
    assert_eq!(role, "admin");
}

#[tokio::test]
async fn admin_cannot_change_role() {
    let app = TestApp::new().await;
    app.seed_user(ADMIN_EMAIL, "Adm", ADMIN_PW, InstanceRole::Admin)
        .await;
    let target = app
        .seed_user("alice@test.local", "Alice", "pw", InstanceRole::Member)
        .await;
    let (cookie, session_id) = web_login_session(&app, ADMIN_EMAIL, ADMIN_PW).await;
    let csrf = app.csrf_for(session_id);

    let resp = post_form(
        &app,
        &format!("/members/{}/role", target.id.0),
        &cookie,
        format!("csrf_token={}&role=admin", urlencoding(&csrf)),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert!(location(&resp).contains("error=forbidden"));
}

// ────────────────────────────────────────────────────────────────────────
// Authz edge cases
// ────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn admin_cannot_target_owner() {
    let app = TestApp::new().await;
    app.seed_user(ADMIN_EMAIL, "Adm", ADMIN_PW, InstanceRole::Admin)
        .await;
    let owner = app
        .seed_user("o@test.local", "Owner", "pw", InstanceRole::Owner)
        .await;
    let (cookie, session_id) = web_login_session(&app, ADMIN_EMAIL, ADMIN_PW).await;
    let csrf = app.csrf_for(session_id);

    let resp = post_form(
        &app,
        &format!("/members/{}/deactivate", owner.id.0),
        &cookie,
        format!("csrf_token={}", urlencoding(&csrf)),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert!(location(&resp).contains("error=cannot_target_peer_or_higher"));
}

#[tokio::test]
async fn cannot_target_self() {
    let app = TestApp::new().await;
    let admin = app
        .seed_user(ADMIN_EMAIL, "Adm", ADMIN_PW, InstanceRole::Admin)
        .await;
    let (cookie, session_id) = web_login_session(&app, ADMIN_EMAIL, ADMIN_PW).await;
    let csrf = app.csrf_for(session_id);

    let resp = post_form(
        &app,
        &format!("/members/{}/deactivate", admin.id.0),
        &cookie,
        format!("csrf_token={}", urlencoding(&csrf)),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert!(location(&resp).contains("error=cannot_target_self"));
}

// ────────────────────────────────────────────────────────────────────────
// Owner-on-Owner pending flow
// ────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn owner_on_owner_deactivate_routes_to_pending() {
    let app = TestApp::new().await;
    app.seed_user("o1@test.local", "Owner One", "pw", InstanceRole::Owner)
        .await;
    let other = app
        .seed_user("o2@test.local", "Owner Two", "pw", InstanceRole::Owner)
        .await;
    let (cookie, session_id) = web_login_session(&app, "o1@test.local", "pw").await;
    let csrf = app.csrf_for(session_id);

    let resp = post_form(
        &app,
        &format!("/members/{}/deactivate", other.id.0),
        &cookie,
        format!("csrf_token={}", urlencoding(&csrf)),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&resp), "/members?action=pending_deactivate");

    // Confirm target is still Active and a pending row exists.
    let lifecycle: String = sqlx::query_scalar(
        "SELECT lifecycle::text FROM identity.users WHERE id = $1",
    )
    .bind(other.id.0)
    .fetch_one(&app.pool)
    .await
    .unwrap();
    assert_eq!(lifecycle, "active");

    let pending_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pending.transitions \
         WHERE target_user_id = $1 AND state = 'pending'",
    )
    .bind(other.id.0)
    .fetch_one(&app.pool)
    .await
    .unwrap();
    assert_eq!(pending_count, 1);
}

// ────────────────────────────────────────────────────────────────────────
// Page rendering
// ────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn kebab_omitted_on_self_row() {
    let app = TestApp::new().await;
    app.seed_user(ADMIN_EMAIL, "Adm", ADMIN_PW, InstanceRole::Admin)
        .await;
    let (cookie, _) = web_login_session(&app, ADMIN_EMAIL, ADMIN_PW).await;

    let req = axum::http::Request::builder()
        .method(Method::GET)
        .uri("/members")
        .header(header::COOKIE, cookie)
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let body = String::from_utf8_lossy(&body_bytes);

    // Admin is the only user → only their own row exists → no kebab
    // forms should appear anywhere on the page.
    assert!(!body.contains("/deactivate"));
    assert!(!body.contains("/delete"));
    assert!(!body.contains("/purge"));
}

#[tokio::test]
async fn kebab_omitted_for_admin_viewing_owner() {
    let app = TestApp::new().await;
    app.seed_user(ADMIN_EMAIL, "Adm", ADMIN_PW, InstanceRole::Admin)
        .await;
    let owner = app
        .seed_user("o@test.local", "Owner", "pw", InstanceRole::Owner)
        .await;
    let (cookie, _) = web_login_session(&app, ADMIN_EMAIL, ADMIN_PW).await;

    let req = axum::http::Request::builder()
        .method(Method::GET)
        .uri("/members")
        .header(header::COOKIE, cookie)
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let body = String::from_utf8_lossy(&body_bytes);

    // No action form should target the Owner's id.
    let owner_id = owner.id.0;
    assert!(
        !body.contains(&format!("/members/{owner_id}/deactivate")),
        "found owner deactivate action in admin view: {body}"
    );
    assert!(!body.contains(&format!("/members/{owner_id}/delete")));
    assert!(!body.contains(&format!("/members/{owner_id}/purge")));
}

#[tokio::test]
async fn kebab_shown_for_owner_viewing_other_owner() {
    let app = TestApp::new().await;
    app.seed_user("o1@test.local", "Owner One", "pw", InstanceRole::Owner)
        .await;
    let other = app
        .seed_user("o2@test.local", "Owner Two", "pw", InstanceRole::Owner)
        .await;
    let (cookie, _) = web_login_session(&app, "o1@test.local", "pw").await;

    let req = axum::http::Request::builder()
        .method(Method::GET)
        .uri("/members")
        .header(header::COOKIE, cookie)
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let body = String::from_utf8_lossy(&body_bytes);

    // Other-owner actions should be present (they'll route to pending
    // when invoked, but the UI surface is identical).
    let other_id = other.id.0;
    assert!(body.contains(&format!("/members/{other_id}/deactivate")));
    assert!(body.contains(&format!("/members/{other_id}/role")));
}

#[tokio::test]
async fn success_banner_renders_from_query_params() {
    let app = TestApp::new().await;
    app.seed_user(ADMIN_EMAIL, "Adm", ADMIN_PW, InstanceRole::Admin)
        .await;
    let (cookie, _) = web_login_session(&app, ADMIN_EMAIL, ADMIN_PW).await;

    let req = axum::http::Request::builder()
        .method(Method::GET)
        .uri("/members?action=deactivated&target=Alice")
        .header(header::COOKIE, cookie)
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let body = String::from_utf8_lossy(&body_bytes);

    assert!(body.contains("banner-success"));
    assert!(body.contains("Alice has been deactivated"));
}

#[tokio::test]
async fn error_banner_renders_from_query_params() {
    let app = TestApp::new().await;
    app.seed_user(ADMIN_EMAIL, "Adm", ADMIN_PW, InstanceRole::Admin)
        .await;
    let (cookie, _) = web_login_session(&app, ADMIN_EMAIL, ADMIN_PW).await;

    let req = axum::http::Request::builder()
        .method(Method::GET)
        .uri("/members?error=cannot_target_peer_or_higher")
        .header(header::COOKIE, cookie)
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let body = String::from_utf8_lossy(&body_bytes);

    assert!(body.contains("banner-error"));
    assert!(body.contains("peer or higher"));
}

#[tokio::test]
async fn delete_dialog_renders_with_csrf_input() {
    let app = TestApp::new().await;
    app.seed_user(ADMIN_EMAIL, "Adm", ADMIN_PW, InstanceRole::Admin)
        .await;
    let target = app
        .seed_user("alice@test.local", "Alice", "pw", InstanceRole::Member)
        .await;
    let (cookie, _) = web_login_session(&app, ADMIN_EMAIL, ADMIN_PW).await;

    let req = axum::http::Request::builder()
        .method(Method::GET)
        .uri("/members")
        .header(header::COOKIE, cookie)
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let body = String::from_utf8_lossy(&body_bytes);

    // The delete dialog should be present with a csrf_token hidden input.
    let target_id = target.id.0;
    assert!(body.contains(&format!(r#"id="dlg-delete-{target_id}""#)));
    assert!(body.contains(r#"name="csrf_token""#));
    assert!(body.contains(&format!(r#"action="/members/{target_id}/delete""#)));
}
