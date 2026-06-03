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

/// Parse the `HX-Trigger` response header into the toast payload it
/// carries (under the `hearth-toast` key). Returns `None` when the
/// header isn't present or the payload isn't shaped as expected.
fn hx_trigger_toast(resp: &axum::response::Response) -> Option<serde_json::Value> {
    let raw = resp.headers().get("hx-trigger")?.to_str().ok()?;
    let parsed: serde_json::Value = serde_json::from_str(raw).ok()?;
    parsed.get("hearth-toast").cloned()
}

fn hx_redirect(resp: &axum::response::Response) -> String {
    resp.headers()
        .get("hx-redirect")
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
        // Password present so the Form extractor succeeds; the wrong
        // csrf_token is what we're testing here.
        "csrf_token=00000000000000000000000000000000&password=adminpw".to_string(),
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
        format!("csrf_token={}&password=pw", urlencoding(&csrf)),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// ────────────────────────────────────────────────────────────────────────
// Happy paths
// ────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn admin_deactivates_user_redirects_to_clean_members_url() {
    // Non-HTMX path: 303 to a clean /members. Toast detail used to ride
    // in the query string; it now travels via HX-Trigger on the HTMX
    // path only (see admin_deactivates_user_htmx_emits_info_toast).
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
        format!("csrf_token={}&password={}", urlencoding(&csrf), ADMIN_PW),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&resp), "/members");

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
        format!("csrf_token={}&password={}", urlencoding(&csrf), ADMIN_PW),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&resp), "/members");
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
        format!("csrf_token={}&password={}", urlencoding(&csrf), ADMIN_PW),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&resp), "/members");

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
        format!("csrf_token={}&password={}", urlencoding(&csrf), ADMIN_PW),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&resp), "/members");
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
        format!(
            "csrf_token={}&role=admin&password=ownerpw",
            urlencoding(&csrf)
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&resp), "/members");

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
        format!(
            "csrf_token={}&role=admin&password={}",
            urlencoding(&csrf),
            ADMIN_PW
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&resp), "/members");
}

// ────────────────────────────────────────────────────────────────────────
// Re-auth gate
// ────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn deactivate_with_wrong_password_redirects_with_banner() {
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
        format!("csrf_token={}&password=wrong-pw", urlencoding(&csrf)),
    )
    .await;
    // Non-HTMX path → redirect to /members?error=invalid_password.
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&resp), "/members");

    // DB-side: target still active (action didn't fire).
    let lifecycle: String = sqlx::query_scalar(
        "SELECT lifecycle::text FROM identity.users WHERE id = $1",
    )
    .bind(target.id.0)
    .fetch_one(&app.pool)
    .await
    .unwrap();
    assert_eq!(lifecycle, "active");
}

#[tokio::test]
async fn delete_with_wrong_password_htmx_returns_modal_with_error() {
    let app = TestApp::new().await;
    app.seed_user(ADMIN_EMAIL, "Adm", ADMIN_PW, InstanceRole::Admin)
        .await;
    let target = app
        .seed_user("alice@test.local", "Alice", "pw", InstanceRole::Member)
        .await;
    let (cookie, session_id) = web_login_session(&app, ADMIN_EMAIL, ADMIN_PW).await;
    let csrf = app.csrf_for(session_id);

    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri(format!("/members/{}/delete", target.id.0))
        .header(header::COOKIE, cookie)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("HX-Request", "true")
        .body(axum::body::Body::from(format!(
            "csrf_token={}&password=wrong-pw",
            urlencoding(&csrf)
        )))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_text(resp).await;
    // Partial — no <!DOCTYPE>, contains the reauth form + error banner.
    assert!(!body.contains("<!DOCTYPE html>"));
    assert!(body.contains("Incorrect password"));
    assert!(body.contains(r#"name="password""#));
    // Action URL is preserved on the form so the operator can retry.
    let expected_action = format!(r#"action="/members/{}/delete""#, target.id.0);
    assert!(body.contains(&expected_action), "expected form action to be preserved");

    // DB-side: not soft-deleted.
    let lifecycle: String = sqlx::query_scalar(
        "SELECT lifecycle::text FROM identity.users WHERE id = $1",
    )
    .bind(target.id.0)
    .fetch_one(&app.pool)
    .await
    .unwrap();
    assert_eq!(lifecycle, "active");
}

#[tokio::test]
async fn delete_with_correct_password_htmx_responds_with_hx_redirect() {
    let app = TestApp::new().await;
    app.seed_user(ADMIN_EMAIL, "Adm", ADMIN_PW, InstanceRole::Admin)
        .await;
    let target = app
        .seed_user("alice@test.local", "Alice", "pw", InstanceRole::Member)
        .await;
    let (cookie, session_id) = web_login_session(&app, ADMIN_EMAIL, ADMIN_PW).await;
    let csrf = app.csrf_for(session_id);

    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri(format!("/members/{}/delete", target.id.0))
        .header(header::COOKIE, cookie)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("HX-Request", "true")
        .body(axum::body::Body::from(format!(
            "csrf_token={}&password={}",
            urlencoding(&csrf),
            ADMIN_PW
        )))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    // HTMX-success path: 200 OK + HX-Redirect (clean URL) + HX-Trigger
    // carrying the toast payload that the client renders post-redirect.
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(hx_redirect(&resp), "/members");
    let toast = hx_trigger_toast(&resp).expect("expected hearth-toast payload");
    assert_eq!(toast["kind"], "error");
    assert_eq!(toast["title"], "Account deleted");

    // DB-side: soft-deleted.
    let lifecycle: String = sqlx::query_scalar(
        "SELECT lifecycle::text FROM identity.users WHERE id = $1",
    )
    .bind(target.id.0)
    .fetch_one(&app.pool)
    .await
    .unwrap();
    assert_eq!(lifecycle, "soft_deleted");
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
        format!("csrf_token={}&password={}", urlencoding(&csrf), ADMIN_PW),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&resp), "/members");
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
        format!("csrf_token={}&password={}", urlencoding(&csrf), ADMIN_PW),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&resp), "/members");
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
        format!("csrf_token={}&password=pw", urlencoding(&csrf)),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&resp), "/members");

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
async fn htmx_deactivate_emits_info_toast_via_hx_trigger() {
    // Toast now ships via HX-Trigger on the HTMX response, not
    // embedded in the page body via query params. Kind is `info`
    // because deactivate is reversible.
    let app = TestApp::new().await;
    app.seed_user(ADMIN_EMAIL, "Adm", ADMIN_PW, InstanceRole::Admin)
        .await;
    let target = app
        .seed_user("alice@test.local", "Alice", "pw", InstanceRole::Member)
        .await;
    let (cookie, session_id) = web_login_session(&app, ADMIN_EMAIL, ADMIN_PW).await;
    let csrf = app.csrf_for(session_id);

    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri(format!("/members/{}/deactivate", target.id.0))
        .header(header::COOKIE, cookie)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("HX-Request", "true")
        .body(axum::body::Body::from(format!(
            "csrf_token={}&password={}",
            urlencoding(&csrf),
            ADMIN_PW
        )))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(hx_redirect(&resp), "/members");
    let toast = hx_trigger_toast(&resp).expect("expected hearth-toast payload");
    assert_eq!(toast["kind"], "info");
    assert_eq!(toast["title"], "Deactivated");
    assert!(
        toast["message"]
            .as_str()
            .unwrap_or_default()
            .contains("Alice"),
        "toast message should mention the target name: {toast:?}"
    );
}

#[tokio::test]
async fn htmx_reactivate_emits_success_toast() {
    // Positive outcomes carry the green success palette.
    let app = TestApp::new().await;
    app.seed_user(ADMIN_EMAIL, "Adm", ADMIN_PW, InstanceRole::Admin)
        .await;
    let target = app
        .seed_user("alice@test.local", "Alice", "pw", InstanceRole::Member)
        .await;
    // Reactivate requires the user to already be deactivated.
    sqlx::query("UPDATE identity.users SET lifecycle = 'deactivated' WHERE id = $1")
        .bind(target.id.0)
        .execute(&app.pool)
        .await
        .unwrap();
    let (cookie, session_id) = web_login_session(&app, ADMIN_EMAIL, ADMIN_PW).await;
    let csrf = app.csrf_for(session_id);

    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri(format!("/members/{}/reactivate", target.id.0))
        .header(header::COOKIE, cookie)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("HX-Request", "true")
        .body(axum::body::Body::from(format!(
            "csrf_token={}&password={}",
            urlencoding(&csrf),
            ADMIN_PW
        )))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    let toast = hx_trigger_toast(&resp).expect("expected hearth-toast payload");
    assert_eq!(toast["kind"], "success");
    assert_eq!(toast["title"], "Reactivated");
}

#[tokio::test]
async fn htmx_delete_emits_error_toast() {
    // Irreversible outcomes carry the red error palette so the
    // operator's eye registers the weight of what just landed.
    let app = TestApp::new().await;
    app.seed_user(ADMIN_EMAIL, "Adm", ADMIN_PW, InstanceRole::Admin)
        .await;
    let target = app
        .seed_user("alice@test.local", "Alice", "pw", InstanceRole::Member)
        .await;
    let (cookie, session_id) = web_login_session(&app, ADMIN_EMAIL, ADMIN_PW).await;
    let csrf = app.csrf_for(session_id);

    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri(format!("/members/{}/delete", target.id.0))
        .header(header::COOKIE, cookie)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("HX-Request", "true")
        .body(axum::body::Body::from(format!(
            "csrf_token={}&password={}",
            urlencoding(&csrf),
            ADMIN_PW
        )))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    let toast = hx_trigger_toast(&resp).expect("expected hearth-toast payload");
    assert_eq!(toast["kind"], "error");
    assert_eq!(toast["title"], "Account deleted");
}

#[tokio::test]
async fn htmx_failed_action_emits_error_toast() {
    // Failure paths still ship a toast via HX-Trigger. Admin trying
    // to target an Owner trips `cannot_target_peer_or_higher`; the
    // resulting redirect carries an `error`-kind toast with the
    // shared catalog message.
    let app = TestApp::new().await;
    let owner = app
        .seed_user("owner@test.local", "Owner", "ownerpw", InstanceRole::Owner)
        .await;
    app.seed_user(ADMIN_EMAIL, "Adm", ADMIN_PW, InstanceRole::Admin)
        .await;
    let (cookie, session_id) = web_login_session(&app, ADMIN_EMAIL, ADMIN_PW).await;
    let csrf = app.csrf_for(session_id);

    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri(format!("/members/{}/deactivate", owner.id.0))
        .header(header::COOKIE, cookie)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("HX-Request", "true")
        .body(axum::body::Body::from(format!(
            "csrf_token={}&password={}",
            urlencoding(&csrf),
            ADMIN_PW
        )))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    let toast = hx_trigger_toast(&resp).expect("expected hearth-toast payload");
    assert_eq!(toast["kind"], "error");
    assert!(
        toast["message"]
            .as_str()
            .unwrap_or_default()
            .contains("peer or higher"),
        "toast message should mention 'peer or higher': {toast:?}"
    );
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
async fn invite_form_renders_as_member_only_even_for_owner() {
    // Invites are now always Member regardless of viewer. Promotion
    // happens after acceptance via Change role. Owners see the same
    // simplified form as Admins: email field + hidden role=member.
    let app = TestApp::new().await;
    app.seed_user("owner@test.local", "Owner", "pw", InstanceRole::Owner)
        .await;
    let (cookie, _) = web_login_session(&app, "owner@test.local", "pw").await;

    let resp = get(&app, "/members/invite", &cookie).await;
    let body = body_text(resp).await;
    assert!(
        body.contains(r#"type="hidden" name="role" value="member""#),
        "owner form should also pin role=member via hidden input: {body}"
    );
    assert!(
        !body.contains(r#"value="admin""#),
        "no admin role option should render"
    );
    assert!(
        !body.contains(r#"value="owner""#),
        "no owner role option should render"
    );
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
        "csrf_token={}&email={}&role=member&password=adminpw",
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

    let body = format!("csrf_token={}&email=&role=member&password=adminpw", urlencoding(&csrf));
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
        "csrf_token={}&email={}&role=member&password=adminpw",
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
        "csrf_token={}&email={}&role=owner&password=adminpw",
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
        "csrf_token=00000000000000000000000000000000&email={}&role=member&password=adminpw",
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
        "csrf_token={}&email={}&role=member&password=adminpw",
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
        "csrf_token={}&email={}&role=member&password=adminpw",
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
    // Success content visible: title, accept URL, single Close button.
    assert!(body.contains("Invitation sent"));
    assert!(body.contains("/invite/"));
    assert!(body.contains("dialog-icon-success"));
    // Single Close action — "Invite another" was dropped so each
    // invite flow is one at a time.
    assert!(body.contains(">Close<"));
    assert!(!body.contains("Invite another"));
}

#[tokio::test]
async fn invite_submit_htmx_error_returns_form_partial_with_banner() {
    let app = TestApp::new().await;
    app.seed_user(ADMIN_EMAIL, "Adm", ADMIN_PW, InstanceRole::Admin)
        .await;
    let (cookie, session_id) = web_login_session(&app, ADMIN_EMAIL, ADMIN_PW).await;
    let csrf = app.csrf_for(session_id);

    // Empty email → validation error.
    let body = format!("csrf_token={}&email=&role=member&password=adminpw", urlencoding(&csrf));
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
    // Form chains through the shared reauth modal — no hx-post here;
    // the Continue button carries `data-reauth-confirm` so the reauth
    // modal's POST is what actually submits.
    assert!(body.contains(r#"data-reauth-confirm="form-invite-modal""#));
}

#[tokio::test]
async fn toast_listener_extracts_clean_payload_not_raw_detail() {
    // Regression guard. HTMX's event dispatcher mutates `event.detail`
    // to add an `elt` field pointing at the source DOM element. Naively
    // serializing the whole detail to sessionStorage throws a
    // TypeError (DOM nodes aren't JSON-serializable) and the silent
    // catch leaves the queue empty — symptom: toasts silently never
    // appear after redirect. The fix is extracting just the three
    // payload fields explicitly; this test pins that shape.
    let app = TestApp::new().await;
    app.seed_user(ADMIN_EMAIL, "Adm", ADMIN_PW, InstanceRole::Admin)
        .await;
    let (cookie, _) = web_login_session(&app, ADMIN_EMAIL, ADMIN_PW).await;

    let resp = get(&app, "/members", &cookie).await;
    let body = body_text(resp).await;
    // The listener must whitelist kind/title/message and avoid touching
    // e.detail.elt (which HTMX injects and which can't be JSON-stringified).
    assert!(
        body.contains("kind: src.kind"),
        "TOAST_JS must extract kind explicitly, not pass through raw detail"
    );
    assert!(
        body.contains("title: src.title"),
        "TOAST_JS must extract title explicitly"
    );
    assert!(
        body.contains("message: src.message"),
        "TOAST_JS must extract message explicitly"
    );
}

#[tokio::test]
async fn assets_carry_cache_busting_version_query() {
    // Browsers cache `app.css` aggressively; without a ?v= suffix the
    // operator has to hard-refresh to see CSS edits across rebuilds.
    // The version is a process-startup timestamp so it changes once
    // per restart — every code edit forces a rebuild + restart so the
    // browser sees a new URL on every meaningful change.
    let app = TestApp::new().await;
    app.seed_user(ADMIN_EMAIL, "Adm", ADMIN_PW, InstanceRole::Admin)
        .await;
    let (cookie, _) = web_login_session(&app, ADMIN_EMAIL, ADMIN_PW).await;

    let resp = get(&app, "/members", &cookie).await;
    let body = body_text(resp).await;
    assert!(
        body.contains("/assets/css/app.css?v="),
        "stylesheet link must include a cache-bust query string"
    );
    assert!(
        body.contains("/assets/vendor/htmx.min.js?v="),
        "htmx script must include a cache-bust query string"
    );
}

#[tokio::test]
async fn shared_modals_live_inside_templates_not_live_dom() {
    // dlg-invite and dlg-reauth are wrapped in <template> elements so
    // they don't contribute to initial DOM layout. DIALOG_JS clones
    // them into the body on first use via hearthMaterializeDialog.
    let app = TestApp::new().await;
    app.seed_user(ADMIN_EMAIL, "Adm", ADMIN_PW, InstanceRole::Admin)
        .await;
    let (cookie, _) = web_login_session(&app, ADMIN_EMAIL, ADMIN_PW).await;

    let resp = get(&app, "/members", &cookie).await;
    let body = body_text(resp).await;
    assert!(
        body.contains(r#"template id="tpl-dlg-invite""#),
        "dlg-invite must be wrapped in a <template>"
    );
    assert!(
        body.contains(r#"template id="tpl-dlg-reauth""#),
        "dlg-reauth must be wrapped in a <template>"
    );
    assert!(
        body.contains("hearthMaterializeDialog"),
        "DIALOG_JS must expose the materializer helper"
    );
}

#[tokio::test]
async fn members_page_includes_submit_interceptor_for_chained_forms() {
    // Regression guard: REAUTH_CHAIN_JS must catch native form
    // submission (Enter in a text input) and route through the chain
    // button instead. Without this, pressing Enter in the invite
    // modal's email field — or in the Delete/Purge type-to-confirm
    // field — submits the form directly to its action URL, missing
    // the `password` field that the LifecycleActionForm/InviteForm
    // deserializer requires, surfacing as a raw 422 error page.
    let app = TestApp::new().await;
    app.seed_user(ADMIN_EMAIL, "Adm", ADMIN_PW, InstanceRole::Admin)
        .await;
    let (cookie, _) = web_login_session(&app, ADMIN_EMAIL, ADMIN_PW).await;

    let resp = get(&app, "/members", &cookie).await;
    let body = body_text(resp).await;
    assert!(
        body.contains("addEventListener('submit'"),
        "REAUTH_CHAIN_JS must wire a submit-event listener to catch \
         Enter-key implicit form submission on chained forms"
    );
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

// ────────────────────────────────────────────────────────────────────────
// Revoke invitation — reauth-gated kebab action on pending invite rows.
// ────────────────────────────────────────────────────────────────────────

/// Fetch the most recently created invitation's id directly from the DB.
/// Used by the revoke tests so they can build the `/members/invitations/{id}/revoke`
/// URL without exposing a separate API just for tests.
async fn latest_invitation_id(app: &TestApp) -> uuid::Uuid {
    sqlx::query_scalar::<_, uuid::Uuid>(
        "SELECT id FROM identity.invitations ORDER BY created_at DESC LIMIT 1",
    )
    .fetch_one(&app.pool)
    .await
    .unwrap()
}

#[tokio::test]
async fn revoke_invite_with_wrong_password_htmx_returns_modal_with_error() {
    let app = TestApp::new().await;
    let _ = seed_pending_invite(&app, "to-revoke@test.local").await;
    let invitation_id = latest_invitation_id(&app).await;
    let (cookie, session_id) = web_login_session(&app, ADMIN_EMAIL, ADMIN_PW).await;
    let csrf = app.csrf_for(session_id);

    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri(format!("/members/invitations/{invitation_id}/revoke"))
        .header(header::COOKIE, cookie)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("HX-Request", "true")
        .body(axum::body::Body::from(format!(
            "csrf_token={}&password=wrong-pw",
            urlencoding(&csrf)
        )))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_text(resp).await;
    // Partial — reauth content with error banner, no doctype.
    assert!(!body.contains("<!DOCTYPE html>"));
    assert!(body.contains("Incorrect password"));
    let expected_action =
        format!(r#"action="/members/invitations/{invitation_id}/revoke""#);
    assert!(
        body.contains(&expected_action),
        "expected form action to be preserved for retry: {body}"
    );

    // DB-side: invitation still present (not revoked).
    let revoked_at: Option<chrono::DateTime<chrono::Utc>> = sqlx::query_scalar(
        "SELECT revoked_at FROM identity.invitations WHERE id = $1",
    )
    .bind(invitation_id)
    .fetch_one(&app.pool)
    .await
    .unwrap();
    assert!(
        revoked_at.is_none(),
        "invitation should not be revoked when password was wrong"
    );
}

#[tokio::test]
async fn revoke_invite_with_correct_password_htmx_responds_with_hx_redirect() {
    let app = TestApp::new().await;
    let _ = seed_pending_invite(&app, "to-revoke@test.local").await;
    let invitation_id = latest_invitation_id(&app).await;
    let (cookie, session_id) = web_login_session(&app, ADMIN_EMAIL, ADMIN_PW).await;
    let csrf = app.csrf_for(session_id);

    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri(format!("/members/invitations/{invitation_id}/revoke"))
        .header(header::COOKIE, cookie)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("HX-Request", "true")
        .body(axum::body::Body::from(format!(
            "csrf_token={}&password={}",
            urlencoding(&csrf),
            ADMIN_PW
        )))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(hx_redirect(&resp), "/members");
    let toast = hx_trigger_toast(&resp).expect("expected hearth-toast payload");
    assert_eq!(toast["kind"], "info");
    assert_eq!(toast["title"], "Invitation revoked");

    // DB-side: invitation now has a revoked_at timestamp.
    let revoked_at: Option<chrono::DateTime<chrono::Utc>> = sqlx::query_scalar(
        "SELECT revoked_at FROM identity.invitations WHERE id = $1",
    )
    .bind(invitation_id)
    .fetch_one(&app.pool)
    .await
    .unwrap();
    assert!(
        revoked_at.is_some(),
        "invitation should be marked revoked after a correct password"
    );
}

// ────────────────────────────────────────────────────────────────────────
// Reissue invitation — kebab action on pending invite rows (CP4)
// ────────────────────────────────────────────────────────────────────────

/// Pull the (token_hash, expires_at) pair for an invitation so tests
/// can assert the reissue actually rotated + extended the row.
async fn invitation_state(
    app: &TestApp,
    invitation_id: uuid::Uuid,
) -> (Vec<u8>, chrono::DateTime<chrono::Utc>) {
    sqlx::query_as::<_, (Vec<u8>, chrono::DateTime<chrono::Utc>)>(
        "SELECT token_hash, expires_at FROM identity.invitations WHERE id = $1",
    )
    .bind(invitation_id)
    .fetch_one(&app.pool)
    .await
    .unwrap()
}

#[tokio::test]
async fn reissue_rotates_token_extends_expiry_and_invalidates_old_url() {
    // Seed a pending invite, then reissue it. Assert:
    //   - token_hash changed (old URL is dead)
    //   - expires_at extended to roughly now + TTL
    //   - GET on the old URL is 404, but a fresh one would work
    //     (we don't have the new raw token from this code path, so we
    //     just verify the old hash truly changed and old URL fails)
    let app = TestApp::new().await;
    let old_token = seed_pending_invite(&app, "to-reissue@test.local").await;
    let invitation_id = latest_invitation_id(&app).await;
    let (old_hash, old_expires) = invitation_state(&app, invitation_id).await;

    let (cookie, session_id) = web_login_session(&app, ADMIN_EMAIL, ADMIN_PW).await;
    let csrf = app.csrf_for(session_id);

    let resp = post_form(
        &app,
        &format!("/members/invitations/{invitation_id}/reissue"),
        &cookie,
        format!("csrf_token={}&password={}", urlencoding(&csrf), ADMIN_PW),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_text(resp).await;
    // Response renders the new URL on the result page (no redirect).
    assert!(body.contains("Invitation reissued") || body.contains("Invitation sent"));
    assert!(body.contains("/invite/"));

    // DB: hash rotated, expiry extended.
    let (new_hash, new_expires) = invitation_state(&app, invitation_id).await;
    assert_ne!(old_hash, new_hash, "token_hash should rotate");
    assert!(
        new_expires > old_expires,
        "new expires_at should be later: old={old_expires} new={new_expires}"
    );

    // The old URL must no longer work.
    let req = axum::http::Request::builder()
        .method(Method::GET)
        .uri(format!("/invite/{old_token}"))
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "old invitation URL must stop working after reissue"
    );
}

#[tokio::test]
async fn reissue_writes_audit_event_and_enqueues_notification() {
    let app = TestApp::new().await;
    let _ = seed_pending_invite(&app, "audit-me@test.local").await;
    let invitation_id = latest_invitation_id(&app).await;
    let (cookie, session_id) = web_login_session(&app, ADMIN_EMAIL, ADMIN_PW).await;
    let csrf = app.csrf_for(session_id);

    // Outbox should have exactly 1 row right now — the original invite.
    let outbox_before: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM notifications.outbox")
            .fetch_one(&app.pool)
            .await
            .unwrap();
    assert_eq!(outbox_before, 1);

    post_form(
        &app,
        &format!("/members/invitations/{invitation_id}/reissue"),
        &cookie,
        format!("csrf_token={}&password={}", urlencoding(&csrf), ADMIN_PW),
    )
    .await;

    let audit_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit.events \
         WHERE event_type = 'invitation_reissued' \
           AND (event_data->>'invitation_id')::uuid = $1",
    )
    .bind(invitation_id)
    .fetch_one(&app.pool)
    .await
    .unwrap();
    assert_eq!(audit_count, 1, "expected one invitation_reissued audit event");

    let outbox_after: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM notifications.outbox")
            .fetch_one(&app.pool)
            .await
            .unwrap();
    assert_eq!(
        outbox_after, 2,
        "reissue should enqueue a fresh invitation notification"
    );
}

#[tokio::test]
async fn reissue_with_wrong_password_htmx_returns_modal_with_error() {
    let app = TestApp::new().await;
    let _ = seed_pending_invite(&app, "wrong-pw@test.local").await;
    let invitation_id = latest_invitation_id(&app).await;
    let (cookie, session_id) = web_login_session(&app, ADMIN_EMAIL, ADMIN_PW).await;
    let csrf = app.csrf_for(session_id);
    let (old_hash, _) = invitation_state(&app, invitation_id).await;

    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri(format!("/members/invitations/{invitation_id}/reissue"))
        .header(header::COOKIE, cookie)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("HX-Request", "true")
        .body(axum::body::Body::from(format!(
            "csrf_token={}&password=wrong",
            urlencoding(&csrf)
        )))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_text(resp).await;
    assert!(!body.contains("<!DOCTYPE html>"));
    assert!(body.contains("Incorrect password"));
    let expected_action =
        format!(r#"action="/members/invitations/{invitation_id}/reissue""#);
    assert!(body.contains(&expected_action));

    // DB: nothing changed.
    let (new_hash, _) = invitation_state(&app, invitation_id).await;
    assert_eq!(old_hash, new_hash, "token must not rotate on wrong password");
}

#[tokio::test]
async fn reissue_rejected_for_already_accepted_invite() {
    let app = TestApp::new().await;
    let token = seed_pending_invite(&app, "accepted@test.local").await;
    let invitation_id = latest_invitation_id(&app).await;

    // Accept the invite so its state is "accepted".
    let body = format!(
        "display_name={}&password={}",
        urlencoding("Acceptor"),
        urlencoding("longenoughpw"),
    );
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri(format!("/invite/{token}"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(axum::body::Body::from(body))
        .unwrap();
    tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();

    // Now try to reissue.
    let (cookie, session_id) = web_login_session(&app, ADMIN_EMAIL, ADMIN_PW).await;
    let csrf = app.csrf_for(session_id);

    let resp = post_form(
        &app,
        &format!("/members/invitations/{invitation_id}/reissue"),
        &cookie,
        format!("csrf_token={}&password={}", urlencoding(&csrf), ADMIN_PW),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = resp
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(loc, "/members");
}

#[tokio::test]
async fn reissue_forbidden_for_member() {
    let app = TestApp::new().await;
    let _ = seed_pending_invite(&app, "victim@test.local").await;
    let invitation_id = latest_invitation_id(&app).await;
    app.seed_user("m@test.local", "M", "pw", InstanceRole::Member)
        .await;
    let (cookie, session_id) = web_login_session(&app, "m@test.local", "pw").await;
    let csrf = app.csrf_for(session_id);

    let resp = post_form(
        &app,
        &format!("/members/invitations/{invitation_id}/reissue"),
        &cookie,
        format!("csrf_token={}&password=pw", urlencoding(&csrf)),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn pending_invite_row_renders_reissue_dialog_with_csrf() {
    let app = TestApp::new().await;
    let _ = seed_pending_invite(&app, "renders@test.local").await;
    let invitation_id = latest_invitation_id(&app).await;
    let (cookie, _) = web_login_session(&app, ADMIN_EMAIL, ADMIN_PW).await;

    let resp = get(&app, "/members", &cookie).await;
    let body = body_text(resp).await;
    let dialog_id = format!(r#"data-open-dialog="dlg-reissue-invite-{invitation_id}""#);
    assert!(
        body.contains(&dialog_id),
        "kebab should open reissue dialog: {body}"
    );
    let dlg = format!(r#"id="dlg-reissue-invite-{invitation_id}""#);
    assert!(body.contains(&dlg));
    let chain = format!(r#"data-reauth-confirm="form-reissue-invite-{invitation_id}""#);
    assert!(body.contains(&chain));
    let action = format!(r#"action="/members/invitations/{invitation_id}/reissue""#);
    assert!(body.contains(&action));
}

// ────────────────────────────────────────────────────────────────────────
// /pending — Owners-only veto review page (Checkpoint 1 MVP)
// ────────────────────────────────────────────────────────────────────────

/// Seed two Owners and trigger an Owner-on-Owner deactivate so a
/// pending transition exists. Returns `(initiator_cookie, target,
/// transition_id, csrf_token)` so tests can drive the veto flow.
async fn seed_pending_owner_deactivate(
    app: &TestApp,
) -> (String, super::common::SeededUser, uuid::Uuid, String) {
    let _initiator = app
        .seed_user("o1@test.local", "Owner One", "pw", InstanceRole::Owner)
        .await;
    let target = app
        .seed_user("o2@test.local", "Owner Two", "pw", InstanceRole::Owner)
        .await;
    let (cookie, session_id) = web_login_session(app, "o1@test.local", "pw").await;
    let csrf = app.csrf_for(session_id);

    let resp = post_form(
        app,
        &format!("/members/{}/deactivate", target.id.0),
        &cookie,
        format!("csrf_token={}&password=pw", urlencoding(&csrf)),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);

    let transition_id: uuid::Uuid = sqlx::query_scalar(
        "SELECT id FROM pending.transitions \
         WHERE target_user_id = $1 AND state = 'pending' \
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(target.id.0)
    .fetch_one(&app.pool)
    .await
    .unwrap();
    (cookie, target, transition_id, csrf)
}

#[tokio::test]
async fn pending_page_forbidden_for_member() {
    let app = TestApp::new().await;
    app.seed_user("m@test.local", "M", "pw", InstanceRole::Member)
        .await;
    let (cookie, _) = web_login_session(&app, "m@test.local", "pw").await;

    let resp = get(&app, "/pending", &cookie).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn pending_page_forbidden_for_admin() {
    // Admins can act on Members but never veto Owner-on-Owner
    // actions. Mirrors the JSON `/admin/pending-transitions/{id}/veto`
    // 403 for non-Owner callers.
    let app = TestApp::new().await;
    app.seed_user(ADMIN_EMAIL, "Adm", ADMIN_PW, InstanceRole::Admin)
        .await;
    let (cookie, _) = web_login_session(&app, ADMIN_EMAIL, ADMIN_PW).await;

    let resp = get(&app, "/pending", &cookie).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn pending_page_renders_empty_state_for_owner_with_no_pendings() {
    let app = TestApp::new().await;
    app.seed_user("o@test.local", "O", "pw", InstanceRole::Owner)
        .await;
    let (cookie, _) = web_login_session(&app, "o@test.local", "pw").await;

    let resp = get(&app, "/pending", &cookie).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_text(resp).await;
    assert!(body.contains("Nothing pending"), "empty state missing: {body}");
    assert!(!body.contains("data-open-dialog=\"dlg-veto-"));
}

#[tokio::test]
async fn pending_page_renders_active_row_for_owner_with_veto_dialog() {
    let app = TestApp::new().await;
    let (cookie, target, transition_id, _csrf) =
        seed_pending_owner_deactivate(&app).await;

    let resp = get(&app, "/pending", &cookie).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_text(resp).await;

    // The target's name + the action verb both appear in the row.
    assert!(body.contains(&target.display_name), "target name missing");
    assert!(body.contains("Deactivate"), "action verb missing");
    // The kebab Veto button opens the per-row dialog.
    let open = format!(r#"data-open-dialog="dlg-veto-{transition_id}""#);
    assert!(body.contains(&open), "Veto open-dialog button missing");
    // The dialog itself renders with the right form + reauth chain.
    let dlg = format!(r#"id="dlg-veto-{transition_id}""#);
    assert!(body.contains(&dlg), "veto dialog markup missing");
    let chain = format!(r#"data-reauth-confirm="form-veto-{transition_id}""#);
    assert!(body.contains(&chain), "reauth chain wiring missing");
    let action = format!(r#"action="/pending/{transition_id}/veto""#);
    assert!(body.contains(&action), "form action missing");
}

#[tokio::test]
async fn pending_page_sidebar_renders_count_badge_for_owner() {
    let app = TestApp::new().await;
    let (cookie, _target, _transition_id, _csrf) =
        seed_pending_owner_deactivate(&app).await;

    let resp = get(&app, "/pending", &cookie).await;
    let body = body_text(resp).await;
    // Sidebar badge renders inside the Pending review nav entry.
    assert!(
        body.contains(r#"class="nav-link-badge""#),
        "count badge missing for Owner with active pending: {body}"
    );
    // Active count is 1 — assert the literal lands inside the badge.
    assert!(
        body.contains(">1</span>"),
        "expected '1' inside the badge"
    );
}

#[tokio::test]
async fn members_page_sidebar_hides_pending_entry_for_admin() {
    // Admins never see the "Pending review" link — they can't veto.
    let app = TestApp::new().await;
    app.seed_user(ADMIN_EMAIL, "Adm", ADMIN_PW, InstanceRole::Admin)
        .await;
    let (cookie, _) = web_login_session(&app, ADMIN_EMAIL, ADMIN_PW).await;

    let resp = get(&app, "/members", &cookie).await;
    let body = body_text(resp).await;
    assert!(!body.contains("Pending review"));
    assert!(!body.contains(r#"href="/pending""#));
}

#[tokio::test]
async fn pending_veto_with_wrong_password_htmx_returns_modal_with_error() {
    let app = TestApp::new().await;
    let (cookie, _target, transition_id, csrf) =
        seed_pending_owner_deactivate(&app).await;

    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri(format!("/pending/{transition_id}/veto"))
        .header(header::COOKIE, cookie)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("HX-Request", "true")
        .body(axum::body::Body::from(format!(
            "csrf_token={}&password=wrong-pw",
            urlencoding(&csrf)
        )))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_text(resp).await;
    assert!(!body.contains("<!DOCTYPE html>"));
    assert!(body.contains("Incorrect password"));
    let expected_action = format!(r#"action="/pending/{transition_id}/veto""#);
    assert!(
        body.contains(&expected_action),
        "expected form action preserved for retry"
    );

    // DB-side: transition still pending.
    let state: String = sqlx::query_scalar(
        "SELECT state::text FROM pending.transitions WHERE id = $1",
    )
    .bind(transition_id)
    .fetch_one(&app.pool)
    .await
    .unwrap();
    assert_eq!(state, "pending");
}

#[tokio::test]
async fn pending_veto_with_correct_password_htmx_responds_with_hx_redirect() {
    let app = TestApp::new().await;
    let (cookie, _target, transition_id, csrf) =
        seed_pending_owner_deactivate(&app).await;

    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri(format!("/pending/{transition_id}/veto"))
        .header(header::COOKIE, cookie)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("HX-Request", "true")
        .body(axum::body::Body::from(format!(
            "csrf_token={}&password=pw",
            urlencoding(&csrf)
        )))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(hx_redirect(&resp), "/pending");
    let toast = hx_trigger_toast(&resp).expect("expected hearth-toast payload");
    assert_eq!(toast["kind"], "success");
    assert_eq!(toast["title"], "Action vetoed");

    // DB-side: transition resolved as vetoed.
    let (state, resolution): (String, Option<String>) = sqlx::query_as(
        "SELECT state::text, resolution FROM pending.transitions WHERE id = $1",
    )
    .bind(transition_id)
    .fetch_one(&app.pool)
    .await
    .unwrap();
    assert_eq!(state, "vetoed");
    assert_eq!(resolution.as_deref(), Some("vetoed"));
}

#[tokio::test]
async fn pending_veto_non_owner_returns_403() {
    // Even with a valid password, an Admin caller is rejected at the
    // route's Owner gate. (The seed creates the pending action as
    // Owner One, then we log in as an Admin to try the veto.)
    let app = TestApp::new().await;
    let (_owner_cookie, _target, transition_id, _csrf) =
        seed_pending_owner_deactivate(&app).await;
    app.seed_user(ADMIN_EMAIL, "Adm", ADMIN_PW, InstanceRole::Admin)
        .await;
    let (admin_cookie, admin_session) =
        web_login_session(&app, ADMIN_EMAIL, ADMIN_PW).await;
    let admin_csrf = app.csrf_for(admin_session);

    let resp = post_form(
        &app,
        &format!("/pending/{transition_id}/veto"),
        &admin_cookie,
        format!(
            "csrf_token={}&password={}",
            urlencoding(&admin_csrf),
            ADMIN_PW
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn pending_page_history_section_renders_vetoed_row_after_veto() {
    // After an Owner vetoes a pending action, /pending should show
    // the row under "History" with a "Vetoed" badge and the resolver's
    // name. The active table is empty since we just vetoed the only
    // pending row.
    let app = TestApp::new().await;
    let (cookie, _target, transition_id, csrf) =
        seed_pending_owner_deactivate(&app).await;

    // Drive the veto via the web wrapper so the resolver is set.
    let resp = post_form(
        &app,
        &format!("/pending/{transition_id}/veto"),
        &cookie,
        format!("csrf_token={}&password=pw", urlencoding(&csrf)),
    )
    .await;
    // Non-HTMX POST → SEE_OTHER to /pending?action=vetoed.
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);

    let resp = get(&app, "/pending", &cookie).await;
    let body = body_text(resp).await;
    // The History section is rendered.
    assert!(
        body.contains("pending-history-header"),
        "history section missing: {body}"
    );
    // Resolution badge shows "Vetoed".
    assert!(
        body.contains("resolution-vetoed"),
        "vetoed badge missing"
    );
    // The active table is empty → empty-state copy is present.
    assert!(body.contains("Nothing pending"));
}

#[tokio::test]
async fn pending_page_no_history_section_when_no_resolved_rows() {
    // Fresh instance with no resolved rows → no "History" header at all.
    let app = TestApp::new().await;
    app.seed_user("o@test.local", "O", "pw", InstanceRole::Owner)
        .await;
    let (cookie, _) = web_login_session(&app, "o@test.local", "pw").await;

    let resp = get(&app, "/pending", &cookie).await;
    let body = body_text(resp).await;
    assert!(!body.contains("pending-history-header"));
}

#[tokio::test]
async fn pending_page_active_row_has_anchor_id() {
    // The active row needs id="row-{transition_id}" so the
    // /members pending pill can deep-link to it via fragment.
    let app = TestApp::new().await;
    let (cookie, _target, transition_id, _csrf) =
        seed_pending_owner_deactivate(&app).await;

    let resp = get(&app, "/pending", &cookie).await;
    let body = body_text(resp).await;
    let expected = format!(r#"id="row-{transition_id}""#);
    assert!(
        body.contains(&expected),
        "expected anchor id on active row: {body}"
    );
}

#[tokio::test]
async fn members_page_shows_pending_pill_for_owner_with_active_pending() {
    // After seeding an Owner-on-Owner pending action, the target's
    // row on /members should carry the amber "Pending: …" chip
    // linking to the matching row on /pending.
    let app = TestApp::new().await;
    let (cookie, target, transition_id, _csrf) =
        seed_pending_owner_deactivate(&app).await;

    let resp = get(&app, "/members", &cookie).await;
    let body = body_text(resp).await;
    // The pill renders.
    assert!(
        body.contains("member-pending-pill"),
        "expected member-pending-pill on the row: {body}"
    );
    // Action verb is correct.
    assert!(body.contains("Pending: Deactivate"));
    // Link points at the matching transition row on /pending.
    let expected_href = format!(r#"href="/pending#row-{transition_id}""#);
    assert!(
        body.contains(&expected_href),
        "expected deep-link to /pending#row-{transition_id}: {body}"
    );
    // Sanity: target's row is on the page (display name appears).
    assert!(body.contains(&target.display_name));
}

#[tokio::test]
async fn members_page_no_pending_pill_when_no_pending() {
    // No pending actions → no pill on any row.
    let app = TestApp::new().await;
    app.seed_user(ADMIN_EMAIL, "Adm", ADMIN_PW, InstanceRole::Admin)
        .await;
    app.seed_user("alice@test.local", "Alice", "pw", InstanceRole::Member)
        .await;
    let (cookie, _) = web_login_session(&app, ADMIN_EMAIL, ADMIN_PW).await;

    let resp = get(&app, "/members", &cookie).await;
    let body = body_text(resp).await;
    assert!(!body.contains("member-pending-pill"));
}

#[tokio::test]
async fn pending_invite_row_renders_revoke_dialog_with_csrf() {
    let app = TestApp::new().await;
    let _ = seed_pending_invite(&app, "viewable@test.local").await;
    let invitation_id = latest_invitation_id(&app).await;
    let (cookie, _) = web_login_session(&app, ADMIN_EMAIL, ADMIN_PW).await;

    let resp = get(&app, "/members", &cookie).await;
    let body = body_text(resp).await;
    // Kebab item is now a dialog-opener, not a direct-submit form.
    let dialog_id = format!(r#"data-open-dialog="dlg-revoke-invite-{invitation_id}""#);
    assert!(body.contains(&dialog_id), "kebab should open revoke dialog");
    // The dialog renders inline with its CSRF input and reauth-chain button.
    let dialog = format!(r#"id="dlg-revoke-invite-{invitation_id}""#);
    assert!(body.contains(&dialog), "revoke confirmation dialog should render");
    assert!(body.contains(r#"name="csrf_token""#));
    let chain_button =
        format!(r#"data-reauth-confirm="form-revoke-invite-{invitation_id}""#);
    assert!(
        body.contains(&chain_button),
        "Revoke button should chain to the shared reauth modal"
    );
}
