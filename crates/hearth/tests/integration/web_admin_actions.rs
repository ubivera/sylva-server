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

/// Pull a `key=value` field out of a urlencoded form body.
fn form_field(body: &str, key: &str) -> Option<String> {
    body.split('&').find_map(|kv| {
        let (k, v) = kv.split_once('=')?;
        (k == key).then(|| v.to_string())
    })
}

/// Mint a step-up sudo grant by POSTing the body's password+csrf to
/// `/me/reauth` (the no-2FA path), returning the `hearth_sudo=…` cookie
/// pair on success. Reauth-gated actions are now authorized by this grant
/// rather than a password in the action body.
async fn mint_sudo_cookie(app: &TestApp, cookie: &str, body: &str) -> Option<String> {
    let csrf = form_field(body, "csrf_token")?;
    let password = form_field(body, "password")?;
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri("/me/reauth")
        .header(header::COOKIE, cookie)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(axum::body::Body::from(format!(
            "csrf_token={csrf}&password={password}"
        )))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    for v in resp.headers().get_all(header::SET_COOKIE) {
        if let Ok(s) = v.to_str()
            && s.starts_with("hearth_sudo=")
        {
            return Some(cookie_name_value(s));
        }
    }
    None
}

/// POST a form to `path` with the given cookie + form body. For
/// reauth-gated actions the body still carries the operator password
/// (legacy shape); we transparently mint a `hearth_sudo` grant from it
/// and attach the cookie, so the action's `require_sudo` check passes.
async fn post_form(
    app: &TestApp,
    path: &str,
    cookie: &str,
    body: String,
) -> axum::response::Response {
    let cookie_header = match mint_sudo_cookie(app, cookie, &body).await {
        Some(sudo) => format!("{cookie}; {sudo}"),
        None => cookie.to_string(),
    };
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri(path)
        .header(header::COOKIE, cookie_header)
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
    // Non-HTMX path: 303 to a clean /members. Toast detail travels via
    // HX-Trigger on the HTMX path only (see
    // htmx_deactivate_emits_info_toast_via_hx_trigger).
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
async fn deactivate_with_wrong_password_is_refused() {
    let app = TestApp::new().await;
    app.seed_user(ADMIN_EMAIL, "Adm", ADMIN_PW, InstanceRole::Admin)
        .await;
    let target = app
        .seed_user("alice@test.local", "Alice", "pw", InstanceRole::Member)
        .await;
    let (cookie, session_id) = web_login_session(&app, ADMIN_EMAIL, ADMIN_PW).await;
    let csrf = app.csrf_for(session_id);

    // A wrong password mints no sudo grant (`post_form`'s /me/reauth step
    // fails), so the action is refused for lack of a fresh grant.
    let resp = post_form(
        &app,
        &format!("/members/{}/deactivate", target.id.0),
        &cookie,
        format!("csrf_token={}&password=wrong-pw", urlencoding(&csrf)),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

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
async fn delete_without_grant_is_refused() {
    let app = TestApp::new().await;
    app.seed_user(ADMIN_EMAIL, "Adm", ADMIN_PW, InstanceRole::Admin)
        .await;
    let target = app
        .seed_user("alice@test.local", "Alice", "pw", InstanceRole::Member)
        .await;
    let (cookie, session_id) = web_login_session(&app, ADMIN_EMAIL, ADMIN_PW).await;
    let csrf = app.csrf_for(session_id);

    // No sudo grant cookie attached → the action is refused (the reauth
    // chain would have minted one via /me/reauth before submitting).
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri(format!("/members/{}/delete", target.id.0))
        .header(header::COOKIE, cookie)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("HX-Request", "true")
        .body(axum::body::Body::from(format!(
            "csrf_token={}",
            urlencoding(&csrf)
        )))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

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
    let sudo = app.sudo_cookie(&cookie, &csrf, ADMIN_PW).await;

    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri(format!("/members/{}/delete", target.id.0))
        .header(header::COOKIE, format!("{cookie}; {sudo}"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("HX-Request", "true")
        .body(axum::body::Body::from(format!(
            "csrf_token={}",
            urlencoding(&csrf),
        )))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    // HTMX-success path: 200 OK + HX-Redirect (clean URL) + HX-Trigger
    // carrying the toast payload that the client renders post-redirect.
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(hx_redirect(&resp), "/members");
    let toast = hx_trigger_toast(&resp).expect("expected hearth-toast payload");
    assert_eq!(toast["kind"], "error");
    // UI calls the soft-delete action "Anonymize".
    assert_eq!(toast["title"], "Account anonymized");

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

    // Other-owner actions should be present as on-demand modal
    // triggers (they'll route to pending when invoked, but the UI
    // surface is identical). The dialog markup itself is fetched on
    // open, not inline.
    let other_id = other.id.0;
    assert!(body.contains(&format!(r#"data-open-modal="/members/{other_id}/modal/deactivate""#)));
    assert!(body.contains(&format!(r#"data-open-modal="/members/{other_id}/modal/role""#)));
}

#[tokio::test]
async fn htmx_deactivate_emits_info_toast_via_hx_trigger() {
    // Toast ships via HX-Trigger on the HTMX response. Kind is `info`
    // because deactivate is reversible.
    let app = TestApp::new().await;
    app.seed_user(ADMIN_EMAIL, "Adm", ADMIN_PW, InstanceRole::Admin)
        .await;
    let target = app
        .seed_user("alice@test.local", "Alice", "pw", InstanceRole::Member)
        .await;
    let (cookie, session_id) = web_login_session(&app, ADMIN_EMAIL, ADMIN_PW).await;
    let csrf = app.csrf_for(session_id);
    let sudo = app.sudo_cookie(&cookie, &csrf, ADMIN_PW).await;

    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri(format!("/members/{}/deactivate", target.id.0))
        .header(header::COOKIE, format!("{cookie}; {sudo}"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("HX-Request", "true")
        .body(axum::body::Body::from(format!(
            "csrf_token={}",
            urlencoding(&csrf),
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

    let sudo = app.sudo_cookie(&cookie, &csrf, ADMIN_PW).await;
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri(format!("/members/{}/reactivate", target.id.0))
        .header(header::COOKIE, format!("{cookie}; {sudo}"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("HX-Request", "true")
        .body(axum::body::Body::from(format!(
            "csrf_token={}",
            urlencoding(&csrf),
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

    let sudo = app.sudo_cookie(&cookie, &csrf, ADMIN_PW).await;
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri(format!("/members/{}/delete", target.id.0))
        .header(header::COOKIE, format!("{cookie}; {sudo}"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("HX-Request", "true")
        .body(axum::body::Body::from(format!(
            "csrf_token={}",
            urlencoding(&csrf),
        )))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    let toast = hx_trigger_toast(&resp).expect("expected hearth-toast payload");
    assert_eq!(toast["kind"], "error");
    // UI calls the soft-delete action "Anonymize"; backend route stays /delete.
    assert_eq!(toast["title"], "Account anonymized");
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

    let sudo = app.sudo_cookie(&cookie, &csrf, ADMIN_PW).await;
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri(format!("/members/{}/deactivate", owner.id.0))
        .header(header::COOKIE, format!("{cookie}; {sudo}"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("HX-Request", "true")
        .body(axum::body::Body::from(format!(
            "csrf_token={}",
            urlencoding(&csrf),
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
async fn delete_dialog_fetched_on_demand_with_csrf_input() {
    let app = TestApp::new().await;
    app.seed_user(ADMIN_EMAIL, "Adm", ADMIN_PW, InstanceRole::Admin)
        .await;
    let target = app
        .seed_user("alice@test.local", "Alice", "pw", InstanceRole::Member)
        .await;
    let (cookie, _) = web_login_session(&app, ADMIN_EMAIL, ADMIN_PW).await;
    let target_id = target.id.0;

    // The members page ships only the kebab item that fetches the
    // dialog markup on demand, not the dialog itself.
    let page = body_text(get(&app, "/members", &cookie).await).await;
    assert!(
        !page.contains(&format!(r#"id="dlg-delete-{target_id}""#)),
        "delete dialog must NOT be inline in the members page"
    );
    assert!(
        page.contains(&format!(r#"data-open-modal="/members/{target_id}/modal/delete""#)),
        "kebab should carry the on-demand modal trigger"
    );

    // The fragment endpoint serves the dialog with its CSRF input + form.
    let frag = body_text(
        get(&app, &format!("/members/{target_id}/modal/delete"), &cookie).await,
    )
    .await;
    assert!(!frag.contains("<html"), "fragment must not be a full page");
    assert!(frag.contains(&format!(r#"id="dlg-delete-{target_id}""#)));
    assert!(frag.contains(r#"name="csrf_token""#));
    assert!(frag.contains(&format!(r#"action="/members/{target_id}/delete""#)));
}

/// The on-demand member-action modal endpoint enforces the same authz
/// the kebab uses: an Admin can't fetch an action modal targeting an
/// Owner (the kebab wouldn't show it), so a direct GET 403s.
#[tokio::test]
async fn member_action_modal_forbidden_for_admin_targeting_owner() {
    let app = TestApp::new().await;
    app.seed_user(ADMIN_EMAIL, "Adm", ADMIN_PW, InstanceRole::Admin)
        .await;
    let owner = app
        .seed_user("owner2@test.local", "Owner Two", "pw", InstanceRole::Owner)
        .await;
    let (cookie, _) = web_login_session(&app, ADMIN_EMAIL, ADMIN_PW).await;

    let resp = get(&app, &format!("/members/{}/modal/delete", owner.id.0), &cookie).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
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
    // Admins don't see role choice in the UI — they get a hidden
    // role=member input.
    assert!(
        body.contains(r#"type="hidden" name="role" value="member""#),
        "admin form should pin role=member via hidden input: {body}"
    );
    assert!(!body.contains(r#"value="admin""#));
    assert!(!body.contains(r#"value="owner""#));
}

#[tokio::test]
async fn invite_form_renders_as_member_only_even_for_owner() {
    // Invites are always Member regardless of viewer. Promotion
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
    // Success renders the recovery-code interstitial directly (no
    // redirect) so the one-time code never lands in a URL, history
    // entry, or referer header. The session cookie still rides the
    // same response.
    assert_eq!(resp.status(), StatusCode::OK);
    let set_cookie = resp
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .unwrap();
    assert!(set_cookie.starts_with("hearth_session="));
    assert!(set_cookie.contains("HttpOnly"));

    let body = body_text(resp).await;
    // Interstitial markers: heading + readonly code input + Continue
    // form pointing at /me. We don't assert the literal code text;
    // that's covered by JSON-path tests.
    assert!(body.contains("Save your recovery code"));
    assert!(body.contains(r#"id="recovery-code""#));
    assert!(body.contains(r#"action="/me""#));

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

/// The recovery-code interstitial renders the freshly-stamped code,
/// and the SHA-256 of the rendered code matches the row in
/// `auth.user_recovery_codes`. This is the regression guard for the
/// "code surfaces exactly once, then ceases to exist" property: we
/// pluck the code from the interstitial body, then assert the DB
/// stores its canonical hash and the plaintext isn't logged or
/// echoed anywhere else.
#[tokio::test]
async fn accept_invite_interstitial_renders_recovery_code_matching_db_hash() {
    let app = TestApp::new().await;
    let token = seed_pending_invite(&app, "code@test.local").await;

    let body = format!(
        "display_name={}&password={}",
        urlencoding("CodeUser"),
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

    // The code lives in the readonly input's value attribute. Pull it
    // out by anchoring on the input id we render in the template.
    let anchor = r#"id="recovery-code""#;
    let id_pos = body.find(anchor).expect("recovery-code input in body");
    let value_anchor = "value=\"";
    let value_start = body[id_pos..]
        .find(value_anchor)
        .expect("value attribute on recovery-code input")
        + id_pos
        + value_anchor.len();
    let value_end = value_start
        + body[value_start..]
            .find('"')
            .expect("closing quote on value");
    let rendered_code = &body[value_start..value_end];

    // Format sanity: 8 groups of 4 Crockford base32 chars + 7 hyphens.
    assert_eq!(rendered_code.len(), 39, "got: {rendered_code:?}");
    assert_eq!(rendered_code.split('-').count(), 8);

    // The hash stored against the new user's row matches the rendered
    // plaintext canonicalized via `recovery_code::hash_code`.
    let row: (Vec<u8>,) = sqlx::query_as(
        "SELECT urc.code_hash
         FROM auth.user_recovery_codes urc
         JOIN identity.users u ON u.id = urc.user_id
         WHERE u.display_name = $1",
    )
    .bind("CodeUser")
    .fetch_one(&app.pool)
    .await
    .expect("user_recovery_codes row should exist after accept");
    let expected = auth::recovery_code::hash_code(rendered_code);
    assert_eq!(row.0.as_slice(), &expected[..]);
}

/// Re-posting the same `/invite/{token}` after a successful acceptance
/// must NOT leak a second copy of the recovery code. The token is
/// already burned, so the route renders the standard "invitation
/// unavailable" page — same behaviour as any other already-accepted
/// invite. Critical for the interstitial's refresh-safety story.
#[tokio::test]
async fn resubmitting_used_invite_renders_invalid_page_not_recovery_code() {
    let app = TestApp::new().await;
    let token = seed_pending_invite(&app, "refresh@test.local").await;

    let form_body = format!(
        "display_name={}&password={}",
        urlencoding("Refresh"),
        urlencoding("longenoughpw"),
    );

    // First accept — renders the interstitial with the code.
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri(format!("/invite/{token}"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(axum::body::Body::from(form_body.clone()))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let first_body = body_text(resp).await;
    assert!(first_body.contains("Save your recovery code"));

    // Second accept (mimics browser refresh that resubmits the POST):
    // invitation is already accepted, so the route falls back to the
    // "invitation unavailable" page — *not* a second recovery code.
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri(format!("/invite/{token}"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(axum::body::Body::from(form_body))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let second_body = body_text(resp).await;
    assert!(second_body.contains("Invitation unavailable"));
    assert!(
        !second_body.contains("Save your recovery code"),
        "second POST must not re-render the recovery interstitial"
    );
    assert!(
        !second_body.contains(r#"id="recovery-code""#),
        "second POST must not echo a recovery code input"
    );
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

    // First accept — success. Body is the recovery-code interstitial
    // (rendered with 200 OK rather than a redirect so the code rides
    // one HTTP response and never lands in a URL/history).
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
    assert_eq!(resp.status(), StatusCode::OK);

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
    let sudo = app.sudo_cookie(&cookie, &csrf, ADMIN_PW).await;

    let body = format!(
        "csrf_token={}&email={}&role=member",
        urlencoding(&csrf),
        urlencoding("htmx@test.local"),
    );
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri("/members/invite")
        .header(header::COOKIE, format!("{cookie}; {sudo}"))
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
    // Single Close action — no "Invite another"; each invite flow is
    // one at a time.
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
    let sudo = app.sudo_cookie(&cookie, &csrf, ADMIN_PW).await;
    let body = format!("csrf_token={}&email=&role=member", urlencoding(&csrf));
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri("/members/invite")
        .header(header::COOKIE, format!("{cookie}; {sudo}"))
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
async fn members_page_includes_invite_copy_handler() {
    // Regression guard. The invite + reissue success modals render
    // a Copy URL button into the dlg-invite dialog via HX-Retarget;
    // without INVITE_COPY_JS on /members the button has no click
    // handler. (The standalone /members/invite fallback page bundles
    // it separately; the modal-only flow needs the script here too.)
    let app = TestApp::new().await;
    app.seed_user(ADMIN_EMAIL, "Adm", ADMIN_PW, InstanceRole::Admin)
        .await;
    let (cookie, _) = web_login_session(&app, ADMIN_EMAIL, ADMIN_PW).await;

    let resp = get(&app, "/members", &cookie).await;
    let body = body_text(resp).await;
    assert!(
        body.contains("data-copy-target"),
        "the copy-handler hook (data-copy-target) must be present"
    );
    // The IIFE's identifying selector — proves the script is on the page.
    assert!(
        body.contains("e.target.closest('[data-copy-target]')"),
        "INVITE_COPY_JS must be wired into the /members script block"
    );
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
async fn shared_modals_not_baked_into_live_dom() {
    // No modal markup ships in the page source — everything (reauth,
    // invite, per-row actions) is fetched on demand into #modal-host
    // and removed on close. The page carries only the empty host, the
    // fetch helpers, and the kebab/CTA triggers.
    let app = TestApp::new().await;
    app.seed_user(ADMIN_EMAIL, "Adm", ADMIN_PW, InstanceRole::Admin)
        .await;
    // Seed a non-self member so the kebab renders actionable (unlocked)
    // items carrying the on-demand triggers.
    app.seed_user("target@test.local", "Target", "pw", InstanceRole::Member)
        .await;
    let (cookie, _) = web_login_session(&app, ADMIN_EMAIL, ADMIN_PW).await;

    let resp = get(&app, "/members", &cookie).await;
    let body = body_text(resp).await;
    assert!(
        body.contains(r#"id="modal-host""#),
        "the empty #modal-host injection point must be present"
    );
    // Reauth is on-demand: no template, no live dialog in the source.
    assert!(
        !body.contains(r#"tpl-dlg-reauth""#),
        "reauth must NOT ship as a <template> — it's fetched on demand"
    );
    assert!(
        !body.contains(r#"id="dlg-reauth""#),
        "reauth dialog must NOT be in the page source"
    );
    // The fetch helper is exposed for the on-demand open + reauth chain.
    assert!(
        body.contains("hearthOpenModal"),
        "DIALOG_JS must expose the on-demand open helper"
    );
    // Invite modal is on-demand — no template, no live dialog.
    assert!(
        !body.contains(r#"tpl-dlg-invite""#),
        "invite modal must NOT ship as a <template> — it's fetched on demand"
    );
    assert!(
        !body.contains(r#"id="dlg-invite""#),
        "invite dialog must NOT be in the page source"
    );
    // Per-row action dialogs are not in the source — only the kebab
    // triggers remain.
    assert!(
        !body.contains(r#"id="dlg-delete-"#),
        "per-row delete dialogs must NOT be inline"
    );
    assert!(
        body.contains(r#"data-open-modal="/members/"#),
        "kebab items should carry on-demand modal triggers"
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

    // CTA fetches the invite modal on demand; the dialog markup itself
    // is not in the page.
    let body = body_text(get(&app, "/members", &cookie).await).await;
    assert!(body.contains(r#"data-open-modal="/modals/invite""#));
    assert!(body.contains("Invite member"));
    assert!(
        !body.contains(r#"id="dlg-invite""#),
        "invite dialog must not be inline on /members"
    );

    // The /modals/invite fragment serves the dialog + its form.
    let frag = body_text(get(&app, "/modals/invite", &cookie).await).await;
    assert!(!frag.contains("<html"), "fragment must not be a full page");
    assert!(frag.contains(r#"id="dlg-invite""#));
    assert!(frag.contains(r#"action="/members/invite""#));
    assert!(frag.contains(r#"data-keep-source"#), "invite send button must keep the source modal alive");
}

/// `/modals/invite` is admin-gated — a regular Member fetching it 403s.
#[tokio::test]
async fn invite_modal_fragment_forbidden_for_member() {
    let app = TestApp::new().await;
    app.seed_user("m@test.local", "Mem", "pw", InstanceRole::Member)
        .await;
    let (cookie, _) = web_login_session(&app, "m@test.local", "pw").await;
    let resp = get(&app, "/modals/invite", &cookie).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
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
async fn revoke_invite_without_grant_is_refused() {
    let app = TestApp::new().await;
    let _ = seed_pending_invite(&app, "to-revoke@test.local").await;
    let invitation_id = latest_invitation_id(&app).await;
    let (cookie, session_id) = web_login_session(&app, ADMIN_EMAIL, ADMIN_PW).await;
    let csrf = app.csrf_for(session_id);

    // No sudo grant attached → the action is refused.
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri(format!("/members/invitations/{invitation_id}/revoke"))
        .header(header::COOKIE, cookie)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("HX-Request", "true")
        .body(axum::body::Body::from(format!(
            "csrf_token={}",
            urlencoding(&csrf)
        )))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

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

    let sudo = app.sudo_cookie(&cookie, &csrf, ADMIN_PW).await;
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri(format!("/members/invitations/{invitation_id}/revoke"))
        .header(header::COOKIE, format!("{cookie}; {sudo}"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("HX-Request", "true")
        .body(axum::body::Body::from(format!(
            "csrf_token={}",
            urlencoding(&csrf),
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
// Reissue invitation — kebab action on pending invite rows
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
async fn reissue_without_grant_is_refused() {
    let app = TestApp::new().await;
    let _ = seed_pending_invite(&app, "wrong-pw@test.local").await;
    let invitation_id = latest_invitation_id(&app).await;
    let (cookie, session_id) = web_login_session(&app, ADMIN_EMAIL, ADMIN_PW).await;
    let csrf = app.csrf_for(session_id);
    let (old_hash, _) = invitation_state(&app, invitation_id).await;

    // No sudo grant → refused; the token must not rotate.
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri(format!("/members/invitations/{invitation_id}/reissue"))
        .header(header::COOKIE, cookie)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("HX-Request", "true")
        .body(axum::body::Body::from(format!(
            "csrf_token={}",
            urlencoding(&csrf)
        )))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

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
async fn pending_invite_row_reissue_dialog_fetched_on_demand() {
    let app = TestApp::new().await;
    let _ = seed_pending_invite(&app, "renders@test.local").await;
    let invitation_id = latest_invitation_id(&app).await;
    let (cookie, _) = web_login_session(&app, ADMIN_EMAIL, ADMIN_PW).await;

    // The row carries the on-demand trigger, not the inline dialog.
    let page = body_text(get(&app, "/members", &cookie).await).await;
    let trigger = format!(r#"data-open-modal="/members/invitations/{invitation_id}/modal/reissue""#);
    assert!(page.contains(&trigger), "kebab should fetch reissue dialog on demand");
    assert!(
        !page.contains(&format!(r#"id="dlg-reissue-invite-{invitation_id}""#)),
        "reissue dialog must not be inline"
    );

    // The fragment endpoint serves the dialog with form + chain hook.
    let frag = body_text(
        get(&app, &format!("/members/invitations/{invitation_id}/modal/reissue"), &cookie).await,
    )
    .await;
    assert!(frag.contains(&format!(r#"id="dlg-reissue-invite-{invitation_id}""#)));
    assert!(frag.contains(&format!(r#"data-reauth-confirm="form-reissue-invite-{invitation_id}""#)));
    assert!(frag.contains(&format!(r#"action="/members/invitations/{invitation_id}/reissue""#)));
}

// ────────────────────────────────────────────────────────────────────────
// /pending — Owners-only veto review page
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
    assert!(!body.contains("data-open-modal=\"/pending/"));
}

#[tokio::test]
async fn pending_page_active_row_veto_dialog_fetched_on_demand() {
    let app = TestApp::new().await;
    let (cookie, target, transition_id, _csrf) =
        seed_pending_owner_deactivate(&app).await;

    let resp = get(&app, "/pending", &cookie).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_text(resp).await;

    // The target's name + the action verb both appear in the row.
    assert!(body.contains(&target.display_name), "target name missing");
    assert!(body.contains("Deactivate"), "action verb missing");
    // The Veto button fetches the dialog on demand; no inline markup.
    let open = format!(r#"data-open-modal="/pending/{transition_id}/modal/veto""#);
    assert!(body.contains(&open), "Veto on-demand trigger missing");
    assert!(
        !body.contains(&format!(r#"id="dlg-veto-{transition_id}""#)),
        "veto dialog must not be inline"
    );

    // The fragment endpoint serves the dialog + form + reauth chain.
    let frag = body_text(
        get(&app, &format!("/pending/{transition_id}/modal/veto"), &cookie).await,
    )
    .await;
    assert!(frag.contains(&format!(r#"id="dlg-veto-{transition_id}""#)), "veto dialog markup missing");
    assert!(frag.contains(&format!(r#"data-reauth-confirm="form-veto-{transition_id}""#)));
    assert!(frag.contains(&format!(r#"action="/pending/{transition_id}/veto""#)));
}

#[tokio::test]
async fn members_sidebar_renders_count_badge_for_owner_with_pendings() {
    // The pending-action count badge lives on the Members nav entry
    // and only renders when count > 0 and the viewer is an Owner.
    let app = TestApp::new().await;
    let (cookie, _target, _transition_id, _csrf) =
        seed_pending_owner_deactivate(&app).await;

    let resp = get(&app, "/members", &cookie).await;
    let body = body_text(resp).await;
    assert!(
        body.contains(r#"class="nav-link-badge""#),
        "count badge missing for Owner with active pending: {body}"
    );
    assert!(
        body.contains(">1</span>"),
        "expected '1' inside the badge"
    );
    // The sidebar should not carry a nav-link pointing at /pending.
    // (The /pending page itself still exists, reachable via the alert
    // CTA's btn — that's not a `.nav-link`.)
    assert!(
        !body.contains(r#"<a class="nav-link" href="/pending">"#)
        && !body.contains(r#"<a class="nav-link active" href="/pending">"#),
        "Pending review nav entry should be removed from the sidebar"
    );
}

#[tokio::test]
async fn members_sidebar_hides_badge_for_admin() {
    // Admins can't veto, so the count badge stays hidden even when
    // there's something pending. The label stays the plain "Members".
    let app = TestApp::new().await;
    app.seed_user(ADMIN_EMAIL, "Adm", ADMIN_PW, InstanceRole::Admin)
        .await;
    let (cookie, _) = web_login_session(&app, ADMIN_EMAIL, ADMIN_PW).await;

    let resp = get(&app, "/members", &cookie).await;
    let body = body_text(resp).await;
    assert!(!body.contains("Pending review"));
    assert!(!body.contains(r#"class="nav-link-badge""#));
}

#[tokio::test]
async fn members_page_renders_pending_alert_for_owner_with_pendings() {
    // When at least one Owner-on-Owner pending transition is in
    // flight, /members renders a primary-tinted alert card between the
    // page header and the toolbar with a Review CTA linking to /pending.
    let app = TestApp::new().await;
    let (cookie, _target, _transition_id, _csrf) =
        seed_pending_owner_deactivate(&app).await;

    let resp = get(&app, "/members", &cookie).await;
    let body = body_text(resp).await;
    assert!(
        body.contains(r#"class="alert-card alert-card-primary""#),
        "pending-actions alert card missing: {body}"
    );
    assert!(
        body.contains("1 pending action awaiting review"),
        "expected singular title for count=1"
    );
    assert!(body.contains(r#"href="/pending""#));
}

#[tokio::test]
async fn members_page_alert_pluralizes_title_for_multiple_pendings() {
    // Seed two Owner-on-Owner pendings so the alert title flips to
    // the plural form. The seed helper already gives us one (Owner
    // One → Owner Two); we add a third Owner and queue Owner One →
    // Owner Three for the second pending against a fresh target.
    let app = TestApp::new().await;
    let (cookie, _target, _transition_id, _csrf) =
        seed_pending_owner_deactivate(&app).await;
    let owner3 = app
        .seed_user("o3@test.local", "Owner Three", "pw", InstanceRole::Owner)
        .await;
    // Use the SAME initiator session that already seeded the first
    // pending, so the CSRF token + cookie match. The seed helper
    // already logged O1 in; just re-grab the session id from the
    // existing cookie + ask the app for the matching csrf.
    let session_id = app.session_id_for_cookie(&cookie).await;
    let csrf = app.csrf_for(session_id);
    let resp = post_form(
        &app,
        &format!("/members/{}/deactivate", owner3.id.0),
        &cookie,
        format!("csrf_token={}&password=pw", urlencoding(&csrf)),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER, "second deactivate should queue, not fail");

    let resp = get(&app, "/members", &cookie).await;
    let body = body_text(resp).await;
    assert!(
        body.contains("2 pending actions awaiting review"),
        "expected plural title for count=2"
    );
}

#[tokio::test]
async fn members_page_alert_hidden_when_no_pendings() {
    // Empty queue → no alert card. Keeps the page clean for the
    // common case.
    let app = TestApp::new().await;
    app.seed_user("o@test.local", "O", "pw", InstanceRole::Owner)
        .await;
    let (cookie, _) = web_login_session(&app, "o@test.local", "pw").await;

    let resp = get(&app, "/members", &cookie).await;
    let body = body_text(resp).await;
    assert!(!body.contains("alert-card-primary"));
}

#[tokio::test]
async fn members_page_alert_hidden_for_admin_even_with_pendings() {
    // Admins can't veto; they shouldn't see the alert at all even
    // when Owner-on-Owner actions are pending.
    let app = TestApp::new().await;
    let _ = seed_pending_owner_deactivate(&app).await;
    app.seed_user(ADMIN_EMAIL, "Adm", ADMIN_PW, InstanceRole::Admin)
        .await;
    let (cookie, _) = web_login_session(&app, ADMIN_EMAIL, ADMIN_PW).await;

    let resp = get(&app, "/members", &cookie).await;
    let body = body_text(resp).await;
    assert!(!body.contains("alert-card-primary"));
}

#[tokio::test]
async fn pending_veto_without_grant_is_refused() {
    let app = TestApp::new().await;
    let (cookie, _target, transition_id, csrf) =
        seed_pending_owner_deactivate(&app).await;

    // No sudo grant → refused; the transition stays pending.
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri(format!("/pending/{transition_id}/veto"))
        .header(header::COOKIE, cookie)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("HX-Request", "true")
        .body(axum::body::Body::from(format!(
            "csrf_token={}",
            urlencoding(&csrf)
        )))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

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
    let sudo = app.sudo_cookie(&cookie, &csrf, "pw").await;

    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri(format!("/pending/{transition_id}/veto"))
        .header(header::COOKIE, format!("{cookie}; {sudo}"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("HX-Request", "true")
        .body(axum::body::Body::from(format!(
            "csrf_token={}",
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
async fn pending_invite_row_revoke_dialog_fetched_on_demand() {
    let app = TestApp::new().await;
    let _ = seed_pending_invite(&app, "viewable@test.local").await;
    let invitation_id = latest_invitation_id(&app).await;
    let (cookie, _) = web_login_session(&app, ADMIN_EMAIL, ADMIN_PW).await;

    // Kebab item fetches the revoke dialog on demand.
    let page = body_text(get(&app, "/members", &cookie).await).await;
    let trigger = format!(r#"data-open-modal="/members/invitations/{invitation_id}/modal/revoke""#);
    assert!(page.contains(&trigger), "kebab should fetch revoke dialog on demand");
    assert!(
        !page.contains(&format!(r#"id="dlg-revoke-invite-{invitation_id}""#)),
        "revoke dialog must not be inline"
    );

    // The fragment endpoint serves the dialog + CSRF + reauth-chain button.
    let frag = body_text(
        get(&app, &format!("/members/invitations/{invitation_id}/modal/revoke"), &cookie).await,
    )
    .await;
    assert!(frag.contains(&format!(r#"id="dlg-revoke-invite-{invitation_id}""#)));
    assert!(frag.contains(r#"name="csrf_token""#));
    assert!(frag.contains(&format!(r#"data-reauth-confirm="form-revoke-invite-{invitation_id}""#)));
}
