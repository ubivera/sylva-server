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
async fn self_row_kebab_renders_locked_items_only() {
    let app = TestApp::new().await;
    let admin = app
        .seed_user(ADMIN_EMAIL, "Adm", ADMIN_PW, InstanceRole::Admin)
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

    // Admin viewing themselves: the kebab IS rendered (so they see
    // what would be possible on a non-self target) but every item is
    // locked — no form `action=` URLs targeting their own user id.
    assert!(
        body.contains("row-actions-trigger"),
        "self-row kebab trigger should be rendered"
    );
    assert!(
        body.contains("row-action-locked"),
        "self-row items should carry the locked class"
    );
    // The page renders the invite modal too (action="/members/invite"),
    // so we narrow the negative assertion to the self user's per-row
    // action URLs: those must not appear.
    let self_id = admin.id.0;
    for verb in ["deactivate", "reactivate", "delete", "purge", "role"] {
        let url = format!(r#"action="/members/{self_id}/{verb}""#);
        assert!(
            !body.contains(&url),
            "expected no {verb} form for self-row: {url} present in body"
        );
    }
    // Lock-icon SVG sits inside each locked item.
    assert!(body.contains("row-action-icon"));
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

// ────────────────────────────────────────────────────────────────────────
// /members/invite — invite a new member
// ────────────────────────────────────────────────────────────────────────

async fn get(app: &TestApp, path: &str, cookie: &str) -> axum::response::Response {
    let req = axum::http::Request::builder()
        .method(Method::GET)
        .uri(path)
        .header(header::COOKIE, cookie)
        .body(axum::body::Body::empty())
        .unwrap();
    tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap()
}

async fn body_text(resp: axum::response::Response) -> String {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    String::from_utf8_lossy(&bytes).into_owned()
}

#[tokio::test]
async fn invite_form_renders_for_admin() {
    let app = TestApp::new().await;
    app.seed_user(ADMIN_EMAIL, "Adm", ADMIN_PW, InstanceRole::Admin)
        .await;
    let (cookie, _) = web_login_session(&app, ADMIN_EMAIL, ADMIN_PW).await;

    let resp = get(&app, "/members/invite", &cookie).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_text(resp).await;
    assert!(body.contains(r#"action="/members/invite""#));
    assert!(body.contains(r#"name="email""#));
    assert!(body.contains(r#"name="role""#));
    assert!(body.contains(r#"name="csrf_token""#));
    // Per the modal redesign, admins no longer see role choice in the
    // UI — they get a hidden role=member input. The segmented control
    // with Admin/Owner segments only appears for Owner viewers.
    assert!(
        body.contains(r#"type="hidden" name="role" value="member""#),
        "admin form should pin role=member via hidden input: {body}"
    );
    assert!(!body.contains(r#"value="admin""#));
    assert!(!body.contains(r#"value="owner""#));
}

#[tokio::test]
async fn invite_form_offers_all_roles_to_owner() {
    let app = TestApp::new().await;
    app.seed_user("owner@test.local", "Owner", "pw", InstanceRole::Owner)
        .await;
    let (cookie, _) = web_login_session(&app, "owner@test.local", "pw").await;

    let resp = get(&app, "/members/invite", &cookie).await;
    let body = body_text(resp).await;
    assert!(body.contains(r#"value="member""#));
    assert!(body.contains(r#"value="admin""#));
    assert!(body.contains(r#"value="owner""#));
}

#[tokio::test]
async fn invite_form_forbidden_for_regular_member() {
    let app = TestApp::new().await;
    app.seed_user("m@test.local", "M", "pw", InstanceRole::Member)
        .await;
    let (cookie, _) = web_login_session(&app, "m@test.local", "pw").await;

    let resp = get(&app, "/members/invite", &cookie).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn invite_form_without_cookie_redirects_to_login() {
    let app = TestApp::new().await;
    let req = axum::http::Request::builder()
        .method(Method::GET)
        .uri("/members/invite")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn invite_submit_happy_path_renders_token_inline() {
    let app = TestApp::new().await;
    app.seed_user(ADMIN_EMAIL, "Adm", ADMIN_PW, InstanceRole::Admin)
        .await;
    let (cookie, session_id) = web_login_session(&app, ADMIN_EMAIL, ADMIN_PW).await;
    let csrf = app.csrf_for(session_id);

    let body = format!(
        "csrf_token={}&email={}&role=member",
        urlencoding(&csrf),
        urlencoding("newbie@test.local"),
    );
    let resp = post_form(&app, "/members/invite", &cookie, body).await;
    // Direct render — no 303 redirect (keeps token out of URL bar).
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_text(resp).await;
    assert!(body.contains("Invitation sent"));
    assert!(body.contains("newbie@test.local"));
    // The accept URL contains "/invite/<token>" — token is rendered inline.
    assert!(
        body.contains("/invite/"),
        "expected /invite/<token> in body: {body}"
    );
    assert!(body.contains(r#"id="invite-url""#));

    // DB-side: an invitation row exists for the invited email.
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM identity.invitations \
         WHERE email = $1 AND revoked_at IS NULL AND accepted_at IS NULL",
    )
    .bind("newbie@test.local")
    .fetch_one(&app.pool)
    .await
    .unwrap();
    assert_eq!(count, 1);
}

#[tokio::test]
async fn invite_submit_empty_email_rerenders_form_with_error() {
    let app = TestApp::new().await;
    app.seed_user(ADMIN_EMAIL, "Adm", ADMIN_PW, InstanceRole::Admin)
        .await;
    let (cookie, session_id) = web_login_session(&app, ADMIN_EMAIL, ADMIN_PW).await;
    let csrf = app.csrf_for(session_id);

    let body = format!("csrf_token={}&email=&role=member", urlencoding(&csrf));
    let resp = post_form(&app, "/members/invite", &cookie, body).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_text(resp).await;
    // The form is re-rendered (not redirected) with a banner.
    assert!(body.contains("banner-error"));
    assert!(body.contains("Enter an email address"));
    assert!(body.contains(r#"action="/members/invite""#));
}

#[tokio::test]
async fn invite_submit_duplicate_email_returns_form_error() {
    let app = TestApp::new().await;
    app.seed_user(ADMIN_EMAIL, "Adm", ADMIN_PW, InstanceRole::Admin)
        .await;
    app.seed_user("existing@test.local", "Existing", "pw", InstanceRole::Member)
        .await;
    let (cookie, session_id) = web_login_session(&app, ADMIN_EMAIL, ADMIN_PW).await;
    let csrf = app.csrf_for(session_id);

    let body = format!(
        "csrf_token={}&email={}&role=member",
        urlencoding(&csrf),
        urlencoding("existing@test.local"),
    );
    let resp = post_form(&app, "/members/invite", &cookie, body).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_text(resp).await;
    assert!(body.contains("banner-error"));
    assert!(body.contains("already exists"));
    // The form preserves the entered email.
    assert!(body.contains(r#"value="existing@test.local""#));
}

#[tokio::test]
async fn invite_submit_admin_cannot_invite_owner() {
    let app = TestApp::new().await;
    app.seed_user(ADMIN_EMAIL, "Adm", ADMIN_PW, InstanceRole::Admin)
        .await;
    let (cookie, session_id) = web_login_session(&app, ADMIN_EMAIL, ADMIN_PW).await;
    let csrf = app.csrf_for(session_id);

    let body = format!(
        "csrf_token={}&email={}&role=owner",
        urlencoding(&csrf),
        urlencoding("would-be-owner@test.local"),
    );
    let resp = post_form(&app, "/members/invite", &cookie, body).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_text(resp).await;
    assert!(body.contains("banner-error"));
    assert!(body.contains("higher role"));
}

#[tokio::test]
async fn invite_submit_without_csrf_returns_403() {
    let app = TestApp::new().await;
    app.seed_user(ADMIN_EMAIL, "Adm", ADMIN_PW, InstanceRole::Admin)
        .await;
    let (cookie, _) = web_login_session(&app, ADMIN_EMAIL, ADMIN_PW).await;

    let body = format!(
        "csrf_token=00000000000000000000000000000000&email={}&role=member",
        urlencoding("x@test.local")
    );
    let resp = post_form(&app, "/members/invite", &cookie, body).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// ────────────────────────────────────────────────────────────────────────
// /invite/{token} — public acceptance page (closes the invite loop)
// ────────────────────────────────────────────────────────────────────────

/// Seed an admin and create an invitation via the actual web flow.
/// Returns the raw acceptance token so tests can hit `/invite/{token}`.
async fn seed_pending_invite(app: &TestApp, target_email: &str) -> String {
    app.seed_user(ADMIN_EMAIL, "Adm", ADMIN_PW, InstanceRole::Admin)
        .await;
    let (cookie, session_id) = web_login_session(app, ADMIN_EMAIL, ADMIN_PW).await;
    let csrf = app.csrf_for(session_id);
    let body = format!(
        "csrf_token={}&email={}&role=member",
        urlencoding(&csrf),
        urlencoding(target_email),
    );
    let resp = post_form(app, "/members/invite", &cookie, body).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let body = String::from_utf8_lossy(&body_bytes);
    // Token is rendered in the value="/invite/<token>" input on the
    // result page. Pull it out.
    let needle = "/invite/";
    let start = body.find(needle).expect("invite URL in result page") + needle.len();
    let end = start
        + body[start..]
            .find('"')
            .expect("closing quote after token");
    body[start..end].to_string()
}

#[tokio::test]
async fn accept_invite_form_renders_for_valid_token() {
    let app = TestApp::new().await;
    let token = seed_pending_invite(&app, "newbie@test.local").await;

    let req = axum::http::Request::builder()
        .method(Method::GET)
        .uri(format!("/invite/{token}"))
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_text(resp).await;
    assert!(body.contains("Accept invitation"));
    assert!(body.contains("newbie@test.local"));
    assert!(body.contains(&format!(r#"action="/invite/{token}""#)));
    assert!(body.contains(r#"name="display_name""#));
    assert!(body.contains(r#"name="password""#));
    // Public shell — no sidebar / user card.
    assert!(!body.contains(r#"class="sidebar""#));
}

#[tokio::test]
async fn accept_invite_form_unknown_token_shows_unavailable_page() {
    let app = TestApp::new().await;
    let req = axum::http::Request::builder()
        .method(Method::GET)
        .uri("/invite/notarealtokenatall000000000000000000000000")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let body = body_text(resp).await;
    assert!(body.contains("Invitation unavailable"));
    assert!(!body.contains(r#"name="password""#));
}

#[tokio::test]
async fn accept_invite_submit_creates_account_and_sets_session_cookie() {
    let app = TestApp::new().await;
    let token = seed_pending_invite(&app, "newbie@test.local").await;

    let body = format!(
        "display_name={}&password={}",
        urlencoding("Newbie"),
        urlencoding("longenoughpw"),
    );
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri(format!("/invite/{token}"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(axum::body::Body::from(body))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        resp.headers().get(header::LOCATION).and_then(|v| v.to_str().ok()),
        Some("/me")
    );
    let set_cookie = resp
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .unwrap();
    assert!(set_cookie.starts_with("hearth_session="));
    assert!(set_cookie.contains("HttpOnly"));

    // DB: user row exists and is active.
    let row: (String, String) = sqlx::query_as(
        "SELECT email, lifecycle::text FROM identity.users WHERE display_name = $1",
    )
    .bind("Newbie")
    .fetch_one(&app.pool)
    .await
    .unwrap();
    assert_eq!(row.0, "newbie@test.local");
    assert_eq!(row.1, "active");
}

#[tokio::test]
async fn accept_invite_submit_empty_display_name_rerenders_form_with_error() {
    let app = TestApp::new().await;
    let token = seed_pending_invite(&app, "newbie@test.local").await;

    let body = format!(
        "display_name=&password={}",
        urlencoding("longenoughpw"),
    );
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri(format!("/invite/{token}"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(axum::body::Body::from(body))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_text(resp).await;
    assert!(body.contains("banner-error"));
    assert!(body.contains("display name"));
    // The form is re-rendered (same action URL with the token).
    assert!(body.contains(&format!(r#"action="/invite/{token}""#)));
}

#[tokio::test]
async fn accept_invite_submit_second_time_returns_unavailable() {
    let app = TestApp::new().await;
    let token = seed_pending_invite(&app, "newbie@test.local").await;

    // First accept — success.
    let body = format!(
        "display_name={}&password={}",
        urlencoding("Newbie"),
        urlencoding("longenoughpw"),
    );
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri(format!("/invite/{token}"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(axum::body::Body::from(body))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);

    // Second accept with the same token — invalid (marked accepted).
    let body = format!(
        "display_name={}&password={}",
        urlencoding("Replay"),
        urlencoding("longenoughpw"),
    );
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri(format!("/invite/{token}"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(axum::body::Body::from(body))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let body = body_text(resp).await;
    assert!(body.contains("Invitation unavailable"));
}

#[tokio::test]
async fn invite_submit_htmx_returns_success_partial_not_full_page() {
    let app = TestApp::new().await;
    app.seed_user(ADMIN_EMAIL, "Adm", ADMIN_PW, InstanceRole::Admin)
        .await;
    let (cookie, session_id) = web_login_session(&app, ADMIN_EMAIL, ADMIN_PW).await;
    let csrf = app.csrf_for(session_id);

    let body = format!(
        "csrf_token={}&email={}&role=member",
        urlencoding(&csrf),
        urlencoding("htmx@test.local"),
    );
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri("/members/invite")
        .header(header::COOKIE, cookie)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("HX-Request", "true")
        .body(axum::body::Body::from(body))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_text(resp).await;

    // Partial response — no <html>/<body> chrome, no sidebar.
    assert!(!body.contains("<!DOCTYPE html>"));
    assert!(!body.contains(r#"class="sidebar""#));
    // Success content visible: title, accept URL, Done + Invite-another.
    assert!(body.contains("Invitation sent"));
    assert!(body.contains("/invite/"));
    assert!(body.contains("dialog-icon-success"));
    // "Invite another" wired via HTMX to GET the form partial.
    assert!(body.contains(r#"hx-get="/members/invite""#));
}

#[tokio::test]
async fn invite_submit_htmx_error_returns_form_partial_with_banner() {
    let app = TestApp::new().await;
    app.seed_user(ADMIN_EMAIL, "Adm", ADMIN_PW, InstanceRole::Admin)
        .await;
    let (cookie, session_id) = web_login_session(&app, ADMIN_EMAIL, ADMIN_PW).await;
    let csrf = app.csrf_for(session_id);

    // Empty email → validation error.
    let body = format!("csrf_token={}&email=&role=member", urlencoding(&csrf));
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri("/members/invite")
        .header(header::COOKIE, cookie)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("HX-Request", "true")
        .body(axum::body::Body::from(body))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_text(resp).await;
    // Partial (no full-page chrome) with the form + error banner.
    assert!(!body.contains("<!DOCTYPE html>"));
    assert!(body.contains("banner-error"));
    assert!(body.contains("Enter an email address"));
    // Form is still HTMX-enabled for the next attempt.
    assert!(body.contains(r#"hx-post="/members/invite""#));
}

#[tokio::test]
async fn members_page_renders_invite_cta_and_modal() {
    let app = TestApp::new().await;
    app.seed_user(ADMIN_EMAIL, "Adm", ADMIN_PW, InstanceRole::Admin)
        .await;
    let (cookie, _) = web_login_session(&app, ADMIN_EMAIL, ADMIN_PW).await;

    let resp = get(&app, "/members", &cookie).await;
    let body = body_text(resp).await;
    // CTA is now a button that opens the always-rendered <dialog>.
    assert!(body.contains(r#"data-open-dialog="dlg-invite""#));
    assert!(body.contains("Invite member"));
    // The dialog itself renders inline on /members.
    assert!(body.contains(r#"id="dlg-invite""#));
    // The dialog's form still POSTs to the same endpoint.
    assert!(body.contains(r#"action="/members/invite""#));
}
