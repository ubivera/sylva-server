use axum::http::{Method, StatusCode, header};
use identity::InstanceRole;

use super::common::TestApp;

const OWNER_PW: &str = "ownerpw";

/// Helper: POST `/login` with form-urlencoded body and return the
/// `Set-Cookie` header value on success.
async fn web_login(app: &TestApp, email: &str, password: &str) -> Option<String> {
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
    let status = resp.status();
    if status != StatusCode::SEE_OTHER {
        return None;
    }
    resp.headers()
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
}

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

/// Pull just the `name=value` portion from a `Set-Cookie` header value
/// (drops attributes after the first `;`).
fn cookie_name_value(set_cookie: &str) -> String {
    set_cookie.split(';').next().unwrap_or("").to_string()
}

#[tokio::test]
async fn get_login_renders_form() {
    let app = TestApp::new().await;
    let resp = app.get("/login", None).await;
    resp.assert_status(StatusCode::OK);
    let body = resp.body_as_text();
    assert!(body.contains("<form"), "body should contain a form: {body}");
    assert!(body.contains("action=\"/login\""));
    assert!(body.contains("name=\"email\""));
    assert!(body.contains("name=\"password\""));
}

#[tokio::test]
async fn login_post_with_valid_creds_redirects_and_sets_cookie() {
    let app = TestApp::new().await;
    app.seed_user("owner@test.local", "Owner", OWNER_PW, InstanceRole::Owner)
        .await;

    let set_cookie = web_login(&app, "owner@test.local", OWNER_PW)
        .await
        .expect("login should succeed");
    assert!(set_cookie.starts_with("sylva_session="));
    assert!(set_cookie.contains("HttpOnly"));
    assert!(set_cookie.contains("SameSite=Lax"));
}

/// A browser login captures the device's User-Agent + client IP onto the
/// session row (drives the Devices panel). Tests trust the proxy header, so
/// `X-Forwarded-For` stands in for the socket peer.
#[tokio::test]
async fn login_records_device_metadata() {
    let app = TestApp::new().await;
    let user = app
        .seed_user("u@test.local", "U", "pw", InstanceRole::Member)
        .await;

    let body = format!("email={}&password=pw", urlencoding("u@test.local"));
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri("/login")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::USER_AGENT, "Mozilla/5.0 (Windows NT 10.0) TestBrowser/1.0")
        .header("x-forwarded-for", "203.0.113.7")
        .body(axum::body::Body::from(body))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);

    let (ua, ip): (Option<String>, Option<String>) =
        sqlx::query_as("SELECT user_agent, ip_address FROM auth.sessions WHERE user_id = $1")
            .bind(user.id.0)
            .fetch_one(&app.pool)
            .await
            .unwrap();
    assert_eq!(ua.as_deref(), Some("Mozilla/5.0 (Windows NT 10.0) TestBrowser/1.0"));
    assert_eq!(ip.as_deref(), Some("203.0.113.7"));
}

/// `last_seen_at` starts NULL and is bumped by the first authenticated
/// request (the throttled touch in the `AuthenticatedUser` extractor).
#[tokio::test]
async fn authed_request_touches_last_seen() {
    let app = TestApp::new().await;
    let user = app
        .seed_user("u@test.local", "U", "pw", InstanceRole::Member)
        .await;
    let cookie = cookie_name_value(&web_login(&app, "u@test.local", "pw").await.unwrap());

    let before: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT last_seen_at FROM auth.sessions WHERE user_id = $1")
            .bind(user.id.0)
            .fetch_one(&app.pool)
            .await
            .unwrap();
    assert!(before.is_none(), "fresh session should have no last_seen_at");

    let (status, _) = get_with_cookie(&app, "/me", Some(&cookie)).await;
    assert_eq!(status, StatusCode::OK);

    let after: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT last_seen_at FROM auth.sessions WHERE user_id = $1")
            .bind(user.id.0)
            .fetch_one(&app.pool)
            .await
            .unwrap();
    assert!(after.is_some(), "an authed request should set last_seen_at");
}

// ──────────────────────────────────────────────────────────────────────
// Devices panel — session list + sign-out (CP2)
// ──────────────────────────────────────────────────────────────────────

/// Log in carrying a `User-Agent` + `X-Forwarded-For`, returning the
/// session cookie. Lets device-panel tests get labelled rows.
async fn web_login_as_device(app: &TestApp, email: &str, password: &str, ua: &str) -> String {
    let body = format!("email={}&password={}", urlencoding(email), urlencoding(password));
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri("/login")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::USER_AGENT, ua)
        .header("x-forwarded-for", "198.51.100.9")
        .body(axum::body::Body::from(body))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    cookie_name_value(
        resp.headers()
            .get(header::SET_COOKIE)
            .and_then(|v| v.to_str().ok())
            .unwrap(),
    )
}

#[tokio::test]
async fn devices_panel_lists_current_device_with_label() {
    let app = TestApp::new().await;
    app.seed_user("u@test.local", "U", "pw", InstanceRole::Member)
        .await;
    let cookie = web_login_as_device(
        &app,
        "u@test.local",
        "pw",
        "Mozilla/5.0 (Windows NT 10.0; Win64) Chrome/120.0 Safari/537.36",
    )
    .await;

    let (status, body) = get_with_cookie(&app, "/modals/account-settings", Some(&cookie)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains(r#"id="devices-section""#));
    assert!(body.contains("Chrome on Windows"), "device label: {body}");
    assert!(body.contains("This device"));
    assert!(body.contains("198.51.100.9"));
    // The only (current) session renders no revoke form, and there's no
    // "sign out all others" with nothing else to sign out. (The pencil
    // rename endpoint is present — every row gets one.)
    assert!(!body.contains("/revoke"), "single current session: no revoke form");
}

#[tokio::test]
async fn session_revoke_signs_out_other_device() {
    let app = TestApp::new().await;
    app.seed_user("u@test.local", "U", "pw", InstanceRole::Member)
        .await;
    let c1 = cookie_name_value(&web_login(&app, "u@test.local", "pw").await.unwrap());
    let c2 = cookie_name_value(&web_login(&app, "u@test.local", "pw").await.unwrap());
    let sid1 = app.session_id_for_cookie(&c1).await;
    let sid2 = app.session_id_for_cookie(&c2).await;
    let csrf1 = app.csrf_for(sid1);

    // From session 1, sign out session 2.
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri(format!("/me/sessions/{sid2}/revoke"))
        .header(header::COOKIE, c1.clone())
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("hx-request", "true")
        .body(axum::body::Body::from(format!("csrf_token={}", urlencoding(&csrf1))))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Session 2 is dead (redirected to login); session 1 still works.
    let (s2, _) = get_with_cookie(&app, "/me", Some(&c2)).await;
    assert_eq!(s2, StatusCode::SEE_OTHER);
    let (s1, _) = get_with_cookie(&app, "/me", Some(&c1)).await;
    assert_eq!(s1, StatusCode::OK);
}

#[tokio::test]
async fn sessions_revoke_others_keeps_current() {
    let app = TestApp::new().await;
    app.seed_user("u@test.local", "U", "pw", InstanceRole::Member)
        .await;
    let c1 = cookie_name_value(&web_login(&app, "u@test.local", "pw").await.unwrap());
    let c2 = cookie_name_value(&web_login(&app, "u@test.local", "pw").await.unwrap());
    let c3 = cookie_name_value(&web_login(&app, "u@test.local", "pw").await.unwrap());
    let sid1 = app.session_id_for_cookie(&c1).await;
    let csrf1 = app.csrf_for(sid1);

    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri("/me/sessions/revoke-others")
        .header(header::COOKIE, c1.clone())
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("hx-request", "true")
        .body(axum::body::Body::from(format!("csrf_token={}", urlencoding(&csrf1))))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let (s1, _) = get_with_cookie(&app, "/me", Some(&c1)).await;
    assert_eq!(s1, StatusCode::OK, "current session survives");
    for other in [&c2, &c3] {
        let (s, _) = get_with_cookie(&app, "/me", Some(other)).await;
        assert_eq!(s, StatusCode::SEE_OTHER, "other sessions revoked");
    }
}

#[tokio::test]
async fn session_revoke_cross_user_is_noop() {
    let app = TestApp::new().await;
    app.seed_user("alice@test.local", "Alice", "pw", InstanceRole::Member)
        .await;
    app.seed_user("bob@test.local", "Bob", "pw", InstanceRole::Member)
        .await;
    let ca = cookie_name_value(&web_login(&app, "alice@test.local", "pw").await.unwrap());
    let cb = cookie_name_value(&web_login(&app, "bob@test.local", "pw").await.unwrap());
    let sid_a = app.session_id_for_cookie(&ca).await;
    let sid_b = app.session_id_for_cookie(&cb).await;
    let csrf_a = app.csrf_for(sid_a);

    // Alice tries to revoke Bob's session — must be a no-op (not owned).
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri(format!("/me/sessions/{sid_b}/revoke"))
        .header(header::COOKIE, ca)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("hx-request", "true")
        .body(axum::body::Body::from(format!("csrf_token={}", urlencoding(&csrf_a))))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Bob's session is untouched.
    let (sb, _) = get_with_cookie(&app, "/me", Some(&cb)).await;
    assert_eq!(sb, StatusCode::OK);
}

#[tokio::test]
async fn session_revoke_requires_csrf() {
    let app = TestApp::new().await;
    app.seed_user("u@test.local", "U", "pw", InstanceRole::Member)
        .await;
    let cookie = cookie_name_value(&web_login(&app, "u@test.local", "pw").await.unwrap());
    let sid = app.session_id_for_cookie(&cookie).await;

    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri(format!("/me/sessions/{sid}/revoke"))
        .header(header::COOKIE, cookie.clone())
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("hx-request", "true")
        .body(axum::body::Body::from("csrf_token=00000000000000000000000000000000"))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // Session still alive (revoke didn't go through).
    let (s, _) = get_with_cookie(&app, "/me", Some(&cookie)).await;
    assert_eq!(s, StatusCode::OK);
}

#[tokio::test]
async fn device_edit_renders_rename_form() {
    let app = TestApp::new().await;
    app.seed_user("u@test.local", "U", "pw", InstanceRole::Member)
        .await;
    let cookie = cookie_name_value(&web_login(&app, "u@test.local", "pw").await.unwrap());
    let sid = app.session_id_for_cookie(&cookie).await;

    let (status, body) =
        get_with_cookie(&app, &format!("/me/sessions/{sid}/edit"), Some(&cookie)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("totp-rename-input"), "rename input: {body}");
    assert!(body.contains(&format!(r#"/me/sessions/{sid}/rename"#)));
}

#[tokio::test]
async fn device_rename_sets_and_clears_custom_label() {
    let app = TestApp::new().await;
    let user = app
        .seed_user("u@test.local", "U", "pw", InstanceRole::Member)
        .await;
    let cookie = web_login_as_device(
        &app,
        "u@test.local",
        "pw",
        "Mozilla/5.0 (Windows NT 10.0; Win64) Chrome/120.0 Safari/537.36",
    )
    .await;
    let sid = app.session_id_for_cookie(&cookie).await;
    let csrf = app.csrf_for(sid);

    // Set a nickname.
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri(format!("/me/sessions/{sid}/rename"))
        .header(header::COOKIE, cookie.clone())
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("hx-request", "true")
        .body(axum::body::Body::from(format!(
            "csrf_token={}&label={}",
            urlencoding(&csrf),
            urlencoding("Work laptop")
        )))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let label: Option<String> =
        sqlx::query_scalar("SELECT label FROM auth.sessions WHERE id = $1")
            .bind(sid)
            .fetch_one(&app.pool)
            .await
            .unwrap();
    assert_eq!(label.as_deref(), Some("Work laptop"));

    // The panel shows the nickname AND the auto-detected device in the meta.
    let (_, body) = get_with_cookie(&app, "/modals/account-settings", Some(&cookie)).await;
    assert!(body.contains("Work laptop"));
    assert!(body.contains("Chrome on Windows"));

    // Clearing it (empty label) reverts to the auto label.
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri(format!("/me/sessions/{sid}/rename"))
        .header(header::COOKIE, cookie)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("hx-request", "true")
        .body(axum::body::Body::from(format!("csrf_token={}&label=", urlencoding(&csrf))))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let label2: Option<String> =
        sqlx::query_scalar("SELECT label FROM auth.sessions WHERE id = $1")
            .bind(sid)
            .fetch_one(&app.pool)
            .await
            .unwrap();
    assert!(label2.is_none(), "empty label clears the nickname");
    let _ = user;
}

#[tokio::test]
async fn login_post_with_wrong_password_renders_error() {
    let app = TestApp::new().await;
    app.seed_user("u@test.local", "U", "rightpw", InstanceRole::Member)
        .await;

    let body = "email=u%40test.local&password=wrongpw".to_string();
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri("/login")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(axum::body::Body::from(body))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let body = String::from_utf8_lossy(&body_bytes);
    assert!(body.contains("Invalid email or password"));
    assert!(body.contains("<form"));
}

#[tokio::test]
async fn me_page_without_cookie_redirects_to_login() {
    let app = TestApp::new().await;
    let req = axum::http::Request::builder()
        .method(Method::GET)
        .uri("/me")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        resp.headers().get(header::LOCATION).and_then(|v| v.to_str().ok()),
        Some("/login")
    );
}

#[tokio::test]
async fn me_page_with_cookie_renders_user() {
    let app = TestApp::new().await;
    app.seed_user("o@test.local", "Big Boss", OWNER_PW, InstanceRole::Owner)
        .await;
    let set_cookie = web_login(&app, "o@test.local", OWNER_PW).await.unwrap();
    let cookie = cookie_name_value(&set_cookie);

    let req = axum::http::Request::builder()
        .method(Method::GET)
        .uri("/me")
        .header(header::COOKIE, cookie)
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let body = String::from_utf8_lossy(&body_bytes);
    assert!(body.contains("Big Boss"));
    assert!(body.contains("o@test.local"));
    assert!(body.contains("Owner"));
}

#[tokio::test]
async fn app_shell_includes_instance_name_and_user_card() {
    let app = TestApp::new().await;
    app.seed_user("o@test.local", "Big Boss", OWNER_PW, InstanceRole::Owner)
        .await;
    let set_cookie = web_login(&app, "o@test.local", OWNER_PW).await.unwrap();
    let cookie = cookie_name_value(&set_cookie);

    let req = axum::http::Request::builder()
        .method(Method::GET)
        .uri("/me")
        .header(header::COOKIE, cookie)
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let body = String::from_utf8_lossy(&body_bytes);

    assert!(
        body.contains("test-instance"),
        "instance name should be visible in chrome: {body}"
    );
    assert!(body.contains("Sylva"));
    assert!(body.contains(r#"class="sidebar""#));
    assert!(body.contains(r#"href="/me""#));
    assert!(body.contains(r#"class="user-card""#));
    assert!(body.contains("Big Boss"));
    assert!(body.contains("o@test.local"));
    assert!(body.contains(r#"class="search-trigger""#));
}

#[tokio::test]
async fn login_page_uses_public_shell_not_app_shell() {
    let app = TestApp::new().await;
    let resp = app.get("/login", None).await;
    resp.assert_status(StatusCode::OK);
    let body = resp.body_as_text();
    // The login page should NOT carry the authenticated chrome.
    assert!(!body.contains(r#"class="sidebar""#));
    assert!(!body.contains(r#"class="user-card""#));
    assert!(!body.contains(r#"class="search-trigger""#));
    assert!(body.contains("/assets/css/app.css"));
    assert!(body.contains("Sylva Hearth"));
}

#[tokio::test]
async fn role_label_renders_on_me_page() {
    // The viewer's role is shown inside /me's content card as a plain
    // label. Asserts the label is present for the Member viewer and that
    // the Owner / Admin labels don't accidentally leak in.
    let app = TestApp::new().await;
    app.seed_user("u@test.local", "Reg User", "userpw", InstanceRole::Member)
        .await;
    let set_cookie = web_login(&app, "u@test.local", "userpw").await.unwrap();
    let cookie = cookie_name_value(&set_cookie);

    let req = axum::http::Request::builder()
        .method(Method::GET)
        .uri("/me")
        .header(header::COOKIE, cookie)
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let body = String::from_utf8_lossy(&body_bytes);
    assert!(body.contains("Member"));
    assert!(!body.contains(">Owner<"));
    assert!(!body.contains(">Admin<"));
}

#[tokio::test]
async fn active_nav_link_is_marked_on_me_page() {
    let app = TestApp::new().await;
    app.seed_user("u@test.local", "U", "pw", InstanceRole::Member)
        .await;
    let set_cookie = web_login(&app, "u@test.local", "pw").await.unwrap();
    let cookie = cookie_name_value(&set_cookie);

    let req = axum::http::Request::builder()
        .method(Method::GET)
        .uri("/me")
        .header(header::COOKIE, cookie)
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let body = String::from_utf8_lossy(&body_bytes);
    // The active link gets the `active` class. Profile is the current page.
    assert!(
        body.contains(r#"class="nav-link active""#) && body.contains(r#"href="/me""#),
        "Profile nav link should be marked active on /me: {body}"
    );
}

#[tokio::test]
async fn logout_clears_cookie_and_revokes_session() {
    let app = TestApp::new().await;
    let user = app
        .seed_user("u@test.local", "U", "pw", InstanceRole::Member)
        .await;
    let set_cookie = web_login(&app, "u@test.local", "pw").await.unwrap();
    let cookie = cookie_name_value(&set_cookie);

    let session_id = app.session_id_for_cookie(&cookie).await;
    let csrf = app.csrf_for(session_id);
    let body = format!("csrf_token={}", urlencoding(&csrf));
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri("/logout")
        .header(header::COOKIE, cookie.clone())
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(axum::body::Body::from(body))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        resp.headers().get(header::LOCATION).and_then(|v| v.to_str().ok()),
        Some("/login")
    );

    // Cookie was cleared (Max-Age=0).
    let new_cookie = resp
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .unwrap();
    assert!(new_cookie.contains("Max-Age=0"));

    // Session row revoked — using the cookie to access /me bounces.
    let req = axum::http::Request::builder()
        .method(Method::GET)
        .uri("/me")
        .header(header::COOKIE, cookie)
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let _ = user;
}

/// `/logout` accepts an optional `next` form field that overrides the
/// default `/login` redirect target. Used by the user-card popover's
/// "quick switch to another account" rows: clicking one POSTs to
/// `/logout` with `next=/login?email=…`, signing out the current user
/// and landing them on the login form pre-filled with the other email.
#[tokio::test]
async fn logout_redirects_to_next_when_same_origin() {
    let app = TestApp::new().await;
    app.seed_user("u@test.local", "U", "pw", InstanceRole::Member)
        .await;
    let set_cookie = web_login(&app, "u@test.local", "pw").await.unwrap();
    let cookie = cookie_name_value(&set_cookie);

    let session_id = app.session_id_for_cookie(&cookie).await;
    let csrf = app.csrf_for(session_id);
    let next_target = "/login?email=other%40test.local";
    let body = format!(
        "csrf_token={}&next={}",
        urlencoding(&csrf),
        urlencoding(next_target)
    );
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri("/logout")
        .header(header::COOKIE, cookie)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(axum::body::Body::from(body))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        resp.headers().get(header::LOCATION).and_then(|v| v.to_str().ok()),
        Some(next_target),
        "logout should honour the same-origin `next` redirect"
    );
}

/// Protocol-relative (`//host`) and absolute-URL `next` values are
/// rejected so the logout endpoint can't be turned into an open
/// redirect (e.g. phishing payload "sign out → land on attacker.com").
/// We try a few common payload shapes and assert every one falls back
/// to the safe default of `/login`.
#[tokio::test]
async fn logout_rejects_external_next() {
    let app = TestApp::new().await;
    app.seed_user("u@test.local", "U", "pw", InstanceRole::Member)
        .await;

    let hostile = [
        "//evil.example.com",           // protocol-relative
        "https://evil.example.com",     // explicit scheme
        "javascript:alert(1)",          // js: scheme
        "login",                        // missing leading slash
        "",                             // empty string
    ];

    for next in hostile {
        let set_cookie = web_login(&app, "u@test.local", "pw").await.unwrap();
        let cookie = cookie_name_value(&set_cookie);
        let session_id = app.session_id_for_cookie(&cookie).await;
        let csrf = app.csrf_for(session_id);
        let body = format!(
            "csrf_token={}&next={}",
            urlencoding(&csrf),
            urlencoding(next)
        );
        let req = axum::http::Request::builder()
            .method(Method::POST)
            .uri("/logout")
            .header(header::COOKIE, cookie)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(axum::body::Body::from(body))
            .unwrap();
        let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
        assert_eq!(
            resp.headers().get(header::LOCATION).and_then(|v| v.to_str().ok()),
            Some("/login"),
            "hostile next={next:?} should be rejected and fall back to /login"
        );
    }
}

/// The user-card popover wires up "quick switch to another account"
/// rows client-side from a `<template>` that lives in the chrome.
/// This is the regression guard for the markup — if someone drops the
/// template or its hooks, `MULTI_ACCOUNT_JS` silently can't render the
/// roster and the popover loses its multi-account feature.
#[tokio::test]
async fn app_shell_includes_user_card_popover_scaffolding() {
    let app = TestApp::new().await;
    app.seed_user("u@test.local", "U", "pw", InstanceRole::Member)
        .await;
    let set_cookie = web_login(&app, "u@test.local", "pw").await.unwrap();
    let cookie = cookie_name_value(&set_cookie);

    let req = axum::http::Request::builder()
        .method(Method::GET)
        .uri("/me")
        .header(header::COOKIE, cookie)
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let body = String::from_utf8_lossy(&body_bytes);

    // Current-account JSON blob stamped onto the accounts container.
    assert!(
        body.contains(r#"class="user-card-accounts""#),
        "expected `.user-card-accounts` container in chrome"
    );
    assert!(
        body.contains("data-current-account="),
        "expected `data-current-account` JSON blob on the accounts container"
    );
    // Template that `MULTI_ACCOUNT_JS` clones for each other account.
    assert!(
        body.contains(r#"id="tpl-user-card-other-account""#),
        "expected `<template id=tpl-user-card-other-account>` in chrome"
    );
    // Theme switcher buttons (auto/dark/light) — radio-group shape.
    assert!(body.contains(r#"data-theme-choice="auto""#));
    assert!(body.contains(r#"data-theme-choice="dark""#));
    assert!(body.contains(r#"data-theme-choice="light""#));
}

/// `THEME_BOOT_JS` runs *before* the stylesheet link in both the
/// authed shell and the public shell — without it, an operator who
/// picks "Light" theme, signs out and lands on `/login` would flash
/// system theme until they signed back in. This test asserts the
/// public shell carries the bootstrap.
#[tokio::test]
async fn public_shell_includes_theme_bootstrap() {
    let app = TestApp::new().await;
    let resp = app.get("/login", None).await;
    let body = resp.body_as_text();
    // The bootstrap is wrapped in an IIFE that reads the saved
    // choice; the storage key is the load-bearing string to look
    // for since the rest of the script is implementation detail.
    assert!(
        body.contains("sylva-theme"),
        "expected THEME_BOOT_JS to run in public shell head"
    );
}

#[tokio::test]
async fn root_redirects_based_on_auth() {
    let app = TestApp::new().await;
    app.seed_user("u@test.local", "U", "pw", InstanceRole::Member)
        .await;

    // Unauthed → /login
    let req = axum::http::Request::builder()
        .method(Method::GET)
        .uri("/")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        resp.headers().get(header::LOCATION).and_then(|v| v.to_str().ok()),
        Some("/login")
    );

    // Authed → /me
    let set_cookie = web_login(&app, "u@test.local", "pw").await.unwrap();
    let cookie = cookie_name_value(&set_cookie);
    let req = axum::http::Request::builder()
        .method(Method::GET)
        .uri("/")
        .header(header::COOKIE, cookie)
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        resp.headers().get(header::LOCATION).and_then(|v| v.to_str().ok()),
        Some("/me")
    );
}

#[tokio::test]
async fn cookie_auth_works_on_json_api_routes() {
    // The Authorization header + `sylva_session` cookie should both
    // satisfy the AuthenticatedUser extractor. This proves the cookie
    // fallback doesn't only work on web routes — the API surface is
    // also usable from a browser session if you ever want to.
    let app = TestApp::new().await;
    app.seed_user("u@test.local", "U", "pw", InstanceRole::Member)
        .await;
    let set_cookie = web_login(&app, "u@test.local", "pw").await.unwrap();
    let cookie = cookie_name_value(&set_cookie);

    let req = axum::http::Request::builder()
        .method(Method::GET)
        .uri("/api/me")
        .header(header::COOKIE, cookie)
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn already_authed_login_page_redirects_to_me() {
    let app = TestApp::new().await;
    app.seed_user("u@test.local", "U", "pw", InstanceRole::Member)
        .await;
    let set_cookie = web_login(&app, "u@test.local", "pw").await.unwrap();
    let cookie = cookie_name_value(&set_cookie);

    let req = axum::http::Request::builder()
        .method(Method::GET)
        .uri("/login")
        .header(header::COOKIE, cookie)
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        resp.headers().get(header::LOCATION).and_then(|v| v.to_str().ok()),
        Some("/me")
    );
}

// ─────────────────────────────────────────────────────────────────────────
// /users — admin directory page
// ─────────────────────────────────────────────────────────────────────────

/// Convenience for the /users tests: build a GET request with an optional
/// cookie and shoot it through the router.
async fn get_with_cookie(app: &TestApp, path: &str, cookie: Option<&str>) -> (StatusCode, String) {
    let mut builder = axum::http::Request::builder().method(Method::GET).uri(path);
    if let Some(c) = cookie {
        builder = builder.header(header::COOKIE, c);
    }
    let req = builder.body(axum::body::Body::empty()).unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    let status = resp.status();
    let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&body_bytes).into_owned())
}

#[tokio::test]
async fn users_page_without_cookie_redirects_to_login() {
    let app = TestApp::new().await;
    let (status, _) = get_with_cookie(&app, "/members", None).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn users_page_forbidden_for_regular_user() {
    let app = TestApp::new().await;
    app.seed_user("u@test.local", "U", "pw", InstanceRole::Member)
        .await;
    let set_cookie = web_login(&app, "u@test.local", "pw").await.unwrap();
    let cookie = cookie_name_value(&set_cookie);

    let (status, body) = get_with_cookie(&app, "/members", Some(&cookie)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(
        body.contains("Admins only"),
        "expected forbidden message in body: {body}"
    );
}

#[tokio::test]
async fn users_page_lists_all_users_for_admin() {
    let app = TestApp::new().await;
    app.seed_user("admin@test.local", "Adm In", "pw", InstanceRole::Admin)
        .await;
    app.seed_user("alice@test.local", "Alice", "pw", InstanceRole::Member)
        .await;
    app.seed_user("bob@test.local", "Bob", "pw", InstanceRole::Member)
        .await;
    let set_cookie = web_login(&app, "admin@test.local", "pw").await.unwrap();
    let cookie = cookie_name_value(&set_cookie);

    let (status, body) = get_with_cookie(&app, "/members", Some(&cookie)).await;
    assert_eq!(status, StatusCode::OK);

    // All three seeded users render with email + display name.
    for needle in [
        "admin@test.local",
        "alice@test.local",
        "bob@test.local",
        "Adm In",
        "Alice",
        "Bob",
    ] {
        assert!(body.contains(needle), "expected {needle:?} in: {body}");
    }
    // Role badges rendered.
    assert!(body.contains("role-admin"));
    assert!(body.contains("role-member"));
    // The viewing admin is tagged as "you".
    assert!(body.contains("row-self-tag"));
}

#[tokio::test]
async fn users_nav_link_hidden_for_regular_user() {
    let app = TestApp::new().await;
    app.seed_user("u@test.local", "U", "pw", InstanceRole::Member)
        .await;
    let set_cookie = web_login(&app, "u@test.local", "pw").await.unwrap();
    let cookie = cookie_name_value(&set_cookie);

    let (_, body) = get_with_cookie(&app, "/me", Some(&cookie)).await;
    assert!(
        !body.contains(r#"href="/members""#),
        "Users nav link should NOT appear for regular users: {body}"
    );
}

#[tokio::test]
async fn users_nav_link_visible_for_admin() {
    let app = TestApp::new().await;
    app.seed_user("admin@test.local", "Adm", "pw", InstanceRole::Admin)
        .await;
    let set_cookie = web_login(&app, "admin@test.local", "pw").await.unwrap();
    let cookie = cookie_name_value(&set_cookie);

    let (_, body) = get_with_cookie(&app, "/me", Some(&cookie)).await;
    assert!(
        body.contains(r#"href="/members""#),
        "Users nav link should appear for admins: {body}"
    );
}

#[tokio::test]
async fn active_nav_link_is_marked_on_users_page() {
    let app = TestApp::new().await;
    app.seed_user("admin@test.local", "Adm", "pw", InstanceRole::Admin)
        .await;
    let set_cookie = web_login(&app, "admin@test.local", "pw").await.unwrap();
    let cookie = cookie_name_value(&set_cookie);

    let (status, body) = get_with_cookie(&app, "/members", Some(&cookie)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains(r#"<a class="nav-link active" href="/members""#),
        "Users nav link should be marked active on /users: {body}"
    );
}

#[tokio::test]
async fn users_page_renders_search_input_and_data_search_attributes() {
    let app = TestApp::new().await;
    app.seed_user("admin@test.local", "Adm In", "pw", InstanceRole::Admin)
        .await;
    app.seed_user("alice@test.local", "Alice", "pw", InstanceRole::Member)
        .await;
    let set_cookie = web_login(&app, "admin@test.local", "pw").await.unwrap();
    let cookie = cookie_name_value(&set_cookie);

    let (status, body) = get_with_cookie(&app, "/members", Some(&cookie)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains(r#"id="users-search""#));
    assert!(body.contains("Search by name or email"));
    // Each row carries a lowercased data-search haystack of name + email.
    assert!(body.contains(r#"data-search="alice alice@test.local""#));
    assert!(body.contains(r#"data-search="adm in admin@test.local""#));
    assert!(body.contains("users-search"));
}

#[tokio::test]
async fn users_page_sort_default_is_joined_ascending() {
    let app = TestApp::new().await;
    app.seed_user("admin@test.local", "Z Admin", "pw", InstanceRole::Admin)
        .await;
    // Seed the userss in a non-alphabetical insert order so a default
    // "by joined ASC" sort can be observed.
    app.seed_user("alice@test.local", "Alice", "pw", InstanceRole::Member)
        .await;
    app.seed_user("bob@test.local", "Bob", "pw", InstanceRole::Member)
        .await;

    let set_cookie = web_login(&app, "admin@test.local", "pw").await.unwrap();
    let cookie = cookie_name_value(&set_cookie);

    let (_, body) = get_with_cookie(&app, "/members", Some(&cookie)).await;
    // Default sort is `joined`, asc → first-seeded user appears before
    // later-seeded users in the rendered body.
    let admin_pos = body.find("admin@test.local").expect("admin row");
    let alice_pos = body.find("alice@test.local").expect("alice row");
    let bob_pos = body.find("bob@test.local").expect("bob row");
    assert!(admin_pos < alice_pos, "admin should appear before alice");
    assert!(alice_pos < bob_pos, "alice should appear before bob");

    // `created_at` drives the default sort, so row order verifies the
    // ordering logic without needing an `aria-sort` chevron to test against.
}

#[tokio::test]
async fn users_page_sort_by_name_desc_reverses_order() {
    let app = TestApp::new().await;
    app.seed_user("admin@test.local", "M Admin", "pw", InstanceRole::Admin)
        .await;
    app.seed_user("alice@test.local", "Alice", "pw", InstanceRole::Member)
        .await;
    app.seed_user("bob@test.local", "Bob", "pw", InstanceRole::Member)
        .await;

    let set_cookie = web_login(&app, "admin@test.local", "pw").await.unwrap();
    let cookie = cookie_name_value(&set_cookie);

    let (_, body) = get_with_cookie(&app, "/members?sort=name&dir=desc", Some(&cookie)).await;
    // name desc → "M Admin" < "Bob" < "Alice" reverse-alphabetical
    // (case-insensitive comparison: alice < bob < m admin → reversed)
    let admin_pos = body.find("admin@test.local").expect("admin row");
    let alice_pos = body.find("alice@test.local").expect("alice row");
    let bob_pos = body.find("bob@test.local").expect("bob row");
    assert!(admin_pos < bob_pos, "M Admin should come before Bob when name desc");
    assert!(bob_pos < alice_pos, "Bob should come before Alice when name desc");
}

#[tokio::test]
async fn users_page_sort_header_link_flips_direction_on_active_column() {
    let app = TestApp::new().await;
    app.seed_user("admin@test.local", "Adm", "pw", InstanceRole::Admin)
        .await;
    let set_cookie = web_login(&app, "admin@test.local", "pw").await.unwrap();
    let cookie = cookie_name_value(&set_cookie);

    // Visit with sort=name&dir=asc — the "User" column should be active
    // (asc) and its link should flip to desc on the next click. Maud
    // HTML-escapes `&` in attribute values, so we match `&amp;`. The
    // href also carries `&filter=all` so flipping sort doesn't drop
    // any active filter.
    let (_, body) = get_with_cookie(&app, "/members?sort=name&dir=asc", Some(&cookie)).await;
    assert!(body.contains(r#"href="/members?sort=name&amp;dir=desc&amp;filter=all""#));
    // Other visible sortable column (Type) resets to asc when clicked
    // from a different sort.
    assert!(body.contains(r#"href="/members?sort=role&amp;dir=asc&amp;filter=all""#));
}

#[tokio::test]
async fn users_page_invalid_sort_param_falls_back_to_default() {
    let app = TestApp::new().await;
    app.seed_user("admin@test.local", "Adm", "pw", InstanceRole::Admin)
        .await;
    let set_cookie = web_login(&app, "admin@test.local", "pw").await.unwrap();
    let cookie = cookie_name_value(&set_cookie);

    let (status, body) = get_with_cookie(
        &app,
        "/members?sort=nonsense&dir=sideways",
        Some(&cookie),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    // Garbage params shouldn't crash; we fall back to joined asc.
    // The sort runs server-side — Member column's link should be the
    // asc form even after the garbage `dir=sideways` is rejected (the
    // unsorted default puts Member into the asc-clickable state).
    assert!(body.contains(r#"sort=name&amp;dir=asc"#));
}

#[tokio::test]
async fn users_page_renders_deactivated_avatar_lock_overlay() {
    let app = TestApp::new().await;
    app.seed_user("owner@test.local", "Big Boss", "pw", InstanceRole::Owner)
        .await;
    let deactivated = app
        .seed_user("ghost@test.local", "Ghost", "pw", InstanceRole::Member)
        .await;

    // Flip the lifecycle directly to skip the audit + session side effects
    // of the real deactivate path — we're testing the view, not the repo.
    sqlx::query("UPDATE identity.users SET lifecycle = 'deactivated' WHERE id = $1")
        .bind(deactivated.id.0)
        .execute(&app.pool)
        .await
        .expect("flipping ghost user to deactivated");

    let set_cookie = web_login(&app, "owner@test.local", "pw").await.unwrap();
    let cookie = cookie_name_value(&set_cookie);

    let (status, body) = get_with_cookie(&app, "/members", Some(&cookie)).await;
    assert_eq!(status, StatusCode::OK);
    // Deactivated members render with `avatar-deactivated` (greys the
    // initial) plus an `avatar-lock` overlay containing the lock icon.
    assert!(
        body.contains("avatar-deactivated"),
        "expected deactivated avatar class in: {body}"
    );
    assert!(
        body.contains("avatar-lock"),
        "expected lock overlay span in: {body}"
    );
    assert!(body.contains("Ghost"));
}

// ─────────────────────────────────────────────────────────────────────────
// Pagination
// ─────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn members_pagination_bar_renders_even_with_one_page() {
    let app = TestApp::new().await;
    app.seed_user("admin@test.local", "Adm", "pw", InstanceRole::Admin)
        .await;
    let set_cookie = web_login(&app, "admin@test.local", "pw").await.unwrap();
    let cookie = cookie_name_value(&set_cookie);

    let (status, body) = get_with_cookie(&app, "/members", Some(&cookie)).await;
    assert_eq!(status, StatusCode::OK);
    // Always-on pagination bar: page-jump input, "of 1", rows trigger.
    assert!(body.contains(r#"id="page-jump""#));
    assert!(body.contains("Rows per page"));
    // Current page is 1, total is 1 → first/last/prev/next disabled.
    assert!(body.contains("pagination-step-disabled"));
}

#[tokio::test]
async fn members_pagination_slices_to_requested_page() {
    let app = TestApp::new().await;
    // 12 members + 1 admin viewer = 13 rows total. With rows=10, page 2
    // should show exactly 3 rows.
    app.seed_user("admin@test.local", "Adm", "pw", InstanceRole::Admin)
        .await;
    for i in 0..12 {
        let email = format!("u{i}@test.local");
        let name = format!("User {i}");
        app.seed_user(&email, &name, "pw", InstanceRole::Member).await;
    }
    let set_cookie = web_login(&app, "admin@test.local", "pw").await.unwrap();
    let cookie = cookie_name_value(&set_cookie);

    // Page 1: 10 rows. With default sort=joined asc, admin is first,
    // then u0..u8.
    let (_, body) = get_with_cookie(&app, "/members?page=1&rows=10", Some(&cookie)).await;
    assert!(body.contains("admin@test.local"));
    assert!(body.contains("u8@test.local"));
    assert!(
        !body.contains("u9@test.local"),
        "u9 should be on page 2, not page 1"
    );

    // Page 2: 3 rows (u9, u10, u11).
    let (_, body) = get_with_cookie(&app, "/members?page=2&rows=10", Some(&cookie)).await;
    assert!(body.contains("u9@test.local"));
    assert!(body.contains("u11@test.local"));
    assert!(
        !body.contains("u0@test.local"),
        "u0 should be on page 1, not page 2"
    );
}

#[tokio::test]
async fn members_pagination_out_of_range_page_clamps_to_max() {
    let app = TestApp::new().await;
    app.seed_user("admin@test.local", "Adm", "pw", InstanceRole::Admin)
        .await;

    let (status, body) = get_with_cookie(&app, "/members?page=99&rows=10", Some(&cookie_from(&app).await)).await;
    assert_eq!(status, StatusCode::OK);
    // Should clamp to page 1 (which is the only page); admin row visible.
    assert!(body.contains("admin@test.local"));
}

async fn cookie_from(app: &TestApp) -> String {
    let set_cookie = web_login(app, "admin@test.local", "pw").await.unwrap();
    cookie_name_value(&set_cookie)
}

#[tokio::test]
async fn members_pagination_rows_per_page_respects_url_param() {
    let app = TestApp::new().await;
    app.seed_user("admin@test.local", "Adm", "pw", InstanceRole::Admin)
        .await;
    for i in 0..30 {
        let email = format!("u{i}@test.local");
        app.seed_user(&email, "User", "pw", InstanceRole::Member).await;
    }
    let set_cookie = web_login(&app, "admin@test.local", "pw").await.unwrap();
    let cookie = cookie_name_value(&set_cookie);

    // rows=25 → 31 total / 25 = 2 pages. Page-jump input max should be 2.
    let (_, body) = get_with_cookie(&app, "/members?rows=25", Some(&cookie)).await;
    assert!(
        body.contains(r#"max="2""#),
        "expected max=2 on page-jump input for rows=25"
    );
    // Invalid rows value clamps to default (10).
    let (_, body) = get_with_cookie(&app, "/members?rows=99", Some(&cookie)).await;
    assert!(
        body.contains(r#"max="4""#),
        "expected max=4 on page-jump input when rows clamps to 10"
    );
}

// ─────────────────────────────────────────────────────────────────────────
// Account settings modal
// ─────────────────────────────────────────────────────────────────────────

/// Modals are on-demand now: the page ships only an empty `#modal-host`
/// and a trigger that fetches the modal markup from `/modals/*`. The
/// account-settings dialog must NOT be baked into the page source. This
/// guards against regressing back to the `<template>`-in-every-page
/// approach (which left inert markup + a lingering materialized dialog
/// in the DOM).
#[tokio::test]
async fn account_settings_modal_is_on_demand_not_in_page_source() {
    let app = TestApp::new().await;
    app.seed_user("u@test.local", "U", "pw", InstanceRole::Member)
        .await;
    let set_cookie = web_login(&app, "u@test.local", "pw").await.unwrap();
    let cookie = cookie_name_value(&set_cookie);

    let (status, body) = get_with_cookie(&app, "/me", Some(&cookie)).await;
    assert_eq!(status, StatusCode::OK);
    // Empty injection host present; no modal markup baked in.
    assert!(
        body.contains(r#"id="modal-host""#),
        "expected the empty #modal-host injection point"
    );
    assert!(
        !body.contains(r#"id="tpl-dlg-account-settings""#),
        "account-settings should NOT ship as a <template> in the page"
    );
    assert!(
        !body.contains(r#"id="dlg-account-settings""#),
        "account-settings dialog should NOT be in the page source"
    );
    assert!(
        !body.contains(r#"id="tpl-dlg-reauth""#),
        "reauth should NOT ship as a <template> in the page"
    );
    // Triggers reference the fetch endpoint, not a DOM id.
    assert!(
        body.contains(r#"data-open-modal="/modals/account-settings""#),
        "expected Manage account button to fetch the modal on demand"
    );
}

/// The on-demand `GET /modals/account-settings` fragment carries the
/// full modal: header chrome, six-tab rail, and the Profile panel's
/// Account Information section with its two forms.
#[tokio::test]
async fn account_settings_modal_fragment_renders_full_modal() {
    let app = TestApp::new().await;
    app.seed_user("u@test.local", "U", "pw", InstanceRole::Member)
        .await;
    let set_cookie = web_login(&app, "u@test.local", "pw").await.unwrap();
    let cookie = cookie_name_value(&set_cookie);

    let (status, body) = get_with_cookie(&app, "/modals/account-settings", Some(&cookie)).await;
    assert_eq!(status, StatusCode::OK);
    // The fragment is the dialog itself, not a full page.
    assert!(!body.contains("<html"), "fragment should not be a full page");
    assert!(body.contains(r#"id="dlg-account-settings""#));
    // Six tabs.
    assert!(body.contains(r#"data-settings-tab="profile""#), "Profile");
    assert!(body.contains(r#"data-settings-tab="security""#), "Security");
    assert!(body.contains(r#"data-settings-tab="devices""#), "Devices");
    assert!(body.contains(r#"data-settings-tab="data""#), "Data Control");
    // Authenticators + Passkeys were folded into the Security tab as
    // sections, so their standalone tabs are gone.
    assert!(!body.contains(r#"data-settings-tab="authenticators""#));
    assert!(!body.contains(r#"data-settings-tab="passkeys""#));
    // Profile panel + Account Information section + the two forms.
    assert!(body.contains(r#"data-settings-panel="profile""#));
    assert!(body.contains("Account Information"));
    assert!(body.contains(r#"id="form-settings-name""#));
    assert!(body.contains(r#"id="form-settings-email""#));
    // Header chrome: gear-icon + tagline + Sign-out form.
    assert!(body.contains(r#"class="settings-header-icon""#));
    assert!(body.contains("Manage your preferences"));
    assert!(body.contains(r#"class="settings-header-signout-form""#));
    // Email submit is a reauth-chain trigger; no inline password or locale.
    assert!(body.contains(r#"data-reauth-confirm="form-settings-email""#));
    assert!(!body.contains(r#"id="settings-email-password""#));
    assert!(!body.contains(r#"id="settings-locale""#));
}

/// `GET /modals/account-settings` requires authentication — an
/// unauthenticated fetch bounces to /login like any other browser
/// route.
#[tokio::test]
async fn account_settings_modal_fragment_requires_auth() {
    let app = TestApp::new().await;
    let (status, _) = get_with_cookie(&app, "/modals/account-settings", None).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
}

/// The user-card popover's "Account settings" row fetches the modal on
/// demand (`data-open-modal`), not via a DOM-id opener or an anchor to
/// /me.
#[tokio::test]
async fn user_card_popover_account_settings_opens_modal() {
    let app = TestApp::new().await;
    app.seed_user("u@test.local", "U", "pw", InstanceRole::Member)
        .await;
    let set_cookie = web_login(&app, "u@test.local", "pw").await.unwrap();
    let cookie = cookie_name_value(&set_cookie);

    let (status, body) = get_with_cookie(&app, "/me", Some(&cookie)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains(r#"class="user-card-action""#)
            && body.contains(r#"data-open-modal="/modals/account-settings""#),
        "expected user-card-action button that fetches the modal on demand"
    );
    // Must not be the old anchor or the old data-open-dialog opener.
    assert!(
        !body.contains(r#"<a class="user-card-action" href="/me""#),
        "user-card-action anchor should be retired"
    );
    assert!(
        !body.contains(r#"data-open-dialog="dlg-account-settings""#),
        "old DOM-id opener should be gone"
    );
}

/// POST /me/profile updates the display name and writes a
/// `profile_updated` audit event. The HTMX response body is the
/// re-rendered name form partial (just the form contents), not a
/// full page.
#[tokio::test]
async fn me_profile_submit_updates_display_name() {
    let app = TestApp::new().await;
    let user = app
        .seed_user("u@test.local", "U", "pw", InstanceRole::Member)
        .await;
    let set_cookie = web_login(&app, "u@test.local", "pw").await.unwrap();
    let cookie = cookie_name_value(&set_cookie);
    let session_id = app.session_id_for_cookie(&cookie).await;
    let csrf = app.csrf_for(session_id);

    let body = format!(
        "csrf_token={}&display_name={}",
        urlencoding(&csrf),
        urlencoding("Updated Name"),
    );
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri("/me/profile")
        .header(header::COOKIE, cookie)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(axum::body::Body::from(body))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let body = String::from_utf8_lossy(&body_bytes);
    // Partial response: form contents only (no <html>/<body>).
    assert!(!body.contains("<html"));
    // Success feedback tile + the updated value pre-filled.
    assert!(body.contains("Profile updated."));
    assert!(body.contains(r#"value="Updated Name""#));
    // Assert the locale field is absent so a future regression that
    // re-introduces a locale input fails this test immediately.
    assert!(
        !body.contains(r#"name="locale""#),
        "locale field should be retired from the settings UI"
    );

    // DB row reflects the change + audit event was written.
    let row: (String,) = sqlx::query_as(
        "SELECT display_name FROM identity.users WHERE id = $1",
    )
    .bind(user.id.0)
    .fetch_one(&app.pool)
    .await
    .unwrap();
    assert_eq!(row.0, "Updated Name");

    let (audit_count,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM audit.events
         WHERE event_type = 'profile_updated' AND actor_user_id = $1",
    )
    .bind(user.id.0)
    .fetch_one(&app.pool)
    .await
    .unwrap();
    assert_eq!(audit_count, 1);
}

/// Empty display_name is rejected with an inline error. Display_name
/// is required everywhere it's used (sidebar user-card, member table,
/// audit actor) — blank values would break the visible identity story.
#[tokio::test]
async fn me_profile_submit_rejects_empty_display_name() {
    let app = TestApp::new().await;
    let user = app
        .seed_user("u@test.local", "Original", "pw", InstanceRole::Member)
        .await;
    let set_cookie = web_login(&app, "u@test.local", "pw").await.unwrap();
    let cookie = cookie_name_value(&set_cookie);
    let session_id = app.session_id_for_cookie(&cookie).await;
    let csrf = app.csrf_for(session_id);

    let body = format!(
        "csrf_token={}&display_name={}&locale={}",
        urlencoding(&csrf),
        urlencoding("   "), // whitespace-only
        urlencoding("en"),
    );
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri("/me/profile")
        .header(header::COOKIE, cookie)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(axum::body::Body::from(body))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = String::from_utf8_lossy(
        &axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap(),
    )
    .to_string();
    assert!(body.contains("Display name can't be blank."));

    let row: (String,) = sqlx::query_as(
        "SELECT display_name FROM identity.users WHERE id = $1",
    )
    .bind(user.id.0)
    .fetch_one(&app.pool)
    .await
    .unwrap();
    assert_eq!(row.0, "Original");
}

/// POST /me/email with the correct password updates the email and
/// writes an `email_changed` audit event. The new address can be used
/// to sign back in afterwards (the password hash isn't touched).
#[tokio::test]
async fn me_email_submit_changes_email_with_correct_password() {
    let app = TestApp::new().await;
    let user = app
        .seed_user("old@test.local", "U", "rightpw", InstanceRole::Member)
        .await;
    let set_cookie = web_login(&app, "old@test.local", "rightpw").await.unwrap();
    let cookie = cookie_name_value(&set_cookie);
    let session_id = app.session_id_for_cookie(&cookie).await;
    let csrf = app.csrf_for(session_id);
    // Step-up: mint a sudo grant (what the reauth chain does in-browser).
    let sudo = app.sudo_cookie(&cookie, &csrf, "rightpw").await;

    // The settings email form posts through the reauth chain; success
    // returns 200 with `HX-Redirect: /me` + a sylva-toast trigger.
    let body = format!(
        "csrf_token={}&email={}",
        urlencoding(&csrf),
        urlencoding("new@test.local"),
    );
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri("/me/email")
        .header(header::COOKIE, format!("{cookie}; {sudo}"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("hx-request", "true")
        .body(axum::body::Body::from(body))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get("HX-Redirect").and_then(|v| v.to_str().ok()),
        Some("/me"),
        "successful email change should HX-Redirect to /me"
    );
    let trigger = resp
        .headers()
        .get("HX-Trigger")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        trigger.contains("email_updated") || trigger.contains("Email updated"),
        "HX-Trigger should carry the email_updated toast payload: {trigger}"
    );

    let row: (String,) = sqlx::query_as(
        "SELECT email FROM identity.users WHERE id = $1",
    )
    .bind(user.id.0)
    .fetch_one(&app.pool)
    .await
    .unwrap();
    assert_eq!(row.0, "new@test.local");

    let (audit_count,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM audit.events
         WHERE event_type = 'email_changed' AND actor_user_id = $1",
    )
    .bind(user.id.0)
    .fetch_one(&app.pool)
    .await
    .unwrap();
    assert_eq!(audit_count, 1);

    // Login with the new email works.
    let new_set_cookie = web_login(&app, "new@test.local", "rightpw").await;
    assert!(new_set_cookie.is_some(), "login with new email should succeed");
}

/// A wrong password at the step-up gate (`POST /me/reauth`) re-renders
/// the modal with an error and mints **no** grant — so the email-change
/// action can't proceed (no `sylva_sudo` cookie). DB unchanged.
#[tokio::test]
async fn me_email_submit_rejects_wrong_password() {
    let app = TestApp::new().await;
    let user = app
        .seed_user("u@test.local", "U", "rightpw", InstanceRole::Member)
        .await;
    let set_cookie = web_login(&app, "u@test.local", "rightpw").await.unwrap();
    let cookie = cookie_name_value(&set_cookie);
    let session_id = app.session_id_for_cookie(&cookie).await;
    let csrf = app.csrf_for(session_id);

    // /me/reauth with the wrong password: 200 modal re-render, no grant.
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri("/me/reauth")
        .header(header::COOKIE, cookie.clone())
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("hx-request", "true")
        .body(axum::body::Body::from(format!(
            "csrf_token={}&password=wrongpw",
            urlencoding(&csrf)
        )))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        set_cookie_value(resp.headers(), "sylva_sudo").is_none(),
        "wrong password must not mint a sudo grant"
    );
    let body = String::from_utf8_lossy(
        &axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap(),
    )
    .to_string();
    assert!(
        body.contains("password is incorrect"),
        "reauth modal should show the wrong-password error: {body}"
    );

    // Without a grant, the email-change action is refused (403).
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri("/me/email")
        .header(header::COOKIE, cookie)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("hx-request", "true")
        .body(axum::body::Body::from(format!(
            "csrf_token={}&email={}",
            urlencoding(&csrf),
            urlencoding("new@test.local")
        )))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let row: (String,) = sqlx::query_as(
        "SELECT email FROM identity.users WHERE id = $1",
    )
    .bind(user.id.0)
    .fetch_one(&app.pool)
    .await
    .unwrap();
    assert_eq!(row.0, "u@test.local");

    let (audit_count,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM audit.events
         WHERE event_type = 'email_changed' AND actor_user_id = $1",
    )
    .bind(user.id.0)
    .fetch_one(&app.pool)
    .await
    .unwrap();
    assert_eq!(audit_count, 0);
}

/// Email already in use by another (manageable) account closes the
/// settings flow and HX-Redirects to /me with an `email_already_in_use`
/// error toast. Surfacing the conflict in the reauth modal would imply
/// the password was wrong; bouncing to /me with a clear red toast
/// matches the rest of the admin-action error vocabulary.
#[tokio::test]
async fn me_email_submit_rejects_email_in_use() {
    let app = TestApp::new().await;
    let _other = app
        .seed_user("taken@test.local", "Other", "pw", InstanceRole::Member)
        .await;
    let user = app
        .seed_user("u@test.local", "U", "rightpw", InstanceRole::Member)
        .await;
    let set_cookie = web_login(&app, "u@test.local", "rightpw").await.unwrap();
    let cookie = cookie_name_value(&set_cookie);
    let session_id = app.session_id_for_cookie(&cookie).await;
    let csrf = app.csrf_for(session_id);
    let sudo = app.sudo_cookie(&cookie, &csrf, "rightpw").await;

    let body = format!(
        "csrf_token={}&email={}",
        urlencoding(&csrf),
        urlencoding("taken@test.local"),
    );
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri("/me/email")
        .header(header::COOKIE, format!("{cookie}; {sudo}"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("hx-request", "true")
        .body(axum::body::Body::from(body))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get("HX-Redirect").and_then(|v| v.to_str().ok()),
        Some("/me"),
        "email-in-use should HX-Redirect to /me"
    );
    let trigger = resp
        .headers()
        .get("HX-Trigger")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        trigger.contains("already exists") || trigger.contains("already in use"),
        "HX-Trigger should carry the email_already_in_use error toast: {trigger}"
    );

    let row: (String,) = sqlx::query_as(
        "SELECT email FROM identity.users WHERE id = $1",
    )
    .bind(user.id.0)
    .fetch_one(&app.pool)
    .await
    .unwrap();
    assert_eq!(row.0, "u@test.local");
}

/// Missing `@` (or otherwise malformed shape) is caught server-side
/// and HX-Redirects to /me with an `email_required` toast. The native
/// HTML5 validation in the settings form usually catches this before
/// the reauth chain ever opens, but the server still guards against
/// scripted clients sending raw POSTs.
#[tokio::test]
async fn me_email_submit_invalid_email_shape_rejected() {
    let app = TestApp::new().await;
    let user = app
        .seed_user("u@test.local", "U", "rightpw", InstanceRole::Member)
        .await;
    let set_cookie = web_login(&app, "u@test.local", "rightpw").await.unwrap();
    let cookie = cookie_name_value(&set_cookie);
    let session_id = app.session_id_for_cookie(&cookie).await;
    let csrf = app.csrf_for(session_id);
    let sudo = app.sudo_cookie(&cookie, &csrf, "rightpw").await;

    let body = format!(
        "csrf_token={}&email={}&password={}",
        urlencoding(&csrf),
        urlencoding("not-an-email"),
        urlencoding("rightpw"),
    );
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri("/me/email")
        .header(header::COOKIE, format!("{cookie}; {sudo}"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("hx-request", "true")
        .body(axum::body::Body::from(body))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get("HX-Redirect").and_then(|v| v.to_str().ok()),
        Some("/me"),
        "invalid email shape should HX-Redirect to /me"
    );
    let trigger = resp
        .headers()
        .get("HX-Trigger")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        trigger.contains("email"),
        "HX-Trigger should carry the email_required error toast: {trigger}"
    );

    let row: (String,) = sqlx::query_as(
        "SELECT email FROM identity.users WHERE id = $1",
    )
    .bind(user.id.0)
    .fetch_one(&app.pool)
    .await
    .unwrap();
    assert_eq!(row.0, "u@test.local");
}

// ─────────────────────────────────────────────────────────────────────────
// Account settings — change password (Security tab)
// ─────────────────────────────────────────────────────────────────────────

/// The Security tab's change-password form ships in the on-demand
/// account-settings fragment: new-password field, client-side confirm
/// guard, and a reauth-chain submit (the current password is collected
/// by the reauth modal, not inline).
#[tokio::test]
async fn account_settings_security_renders_change_password_form() {
    let app = TestApp::new().await;
    app.seed_user("u@test.local", "U", "pw", InstanceRole::Member)
        .await;
    let set_cookie = web_login(&app, "u@test.local", "pw").await.unwrap();
    let cookie = cookie_name_value(&set_cookie);

    let (status, body) = get_with_cookie(&app, "/modals/account-settings", Some(&cookie)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains(r#"data-settings-panel="security""#));
    assert!(body.contains(r#"id="form-change-password""#));
    assert!(body.contains(r#"name="new_password""#));
    // A single field with a show/hide eye toggle (no confirm box).
    assert!(body.contains(r#"data-pw-toggle="change-pw-new""#));
    assert!(!body.contains(r#"data-pw-confirm"#));
    // Submit routes through the reauth chain, not a native submit; the
    // button lives in the section header now.
    assert!(body.contains(r#"data-reauth-confirm="form-change-password""#));
}

/// POST /me/password with the correct current password updates the
/// hash, writes a `password_changed` audit event, and the new password
/// works for sign-in while the old one no longer does.
#[tokio::test]
async fn me_password_change_succeeds_with_correct_current() {
    let app = TestApp::new().await;
    let user = app
        .seed_user("u@test.local", "U", "oldpw123", InstanceRole::Member)
        .await;
    let set_cookie = web_login(&app, "u@test.local", "oldpw123").await.unwrap();
    let cookie = cookie_name_value(&set_cookie);
    let session_id = app.session_id_for_cookie(&cookie).await;
    let csrf = app.csrf_for(session_id);
    let sudo = app.sudo_cookie(&cookie, &csrf, "oldpw123").await;

    let body = format!(
        "csrf_token={}&new_password={}",
        urlencoding(&csrf),
        urlencoding("brandnewpw456"),
    );
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri("/me/password")
        .header(header::COOKIE, format!("{cookie}; {sudo}"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("hx-request", "true")
        .body(axum::body::Body::from(body))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    // Success renders a confirmation into the (kept-open) reauth modal
    // instead of navigating away, so the settings modal stays open.
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        resp.headers().get("HX-Redirect").is_none(),
        "password change should no longer navigate away"
    );
    let body = String::from_utf8_lossy(
        &axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap(),
    )
    .to_string();
    assert!(
        body.contains("Password updated"),
        "should render the in-modal success confirmation: {body}"
    );

    let (audit_count,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM audit.events
         WHERE event_type = 'password_changed' AND actor_user_id = $1",
    )
    .bind(user.id.0)
    .fetch_one(&app.pool)
    .await
    .unwrap();
    assert_eq!(audit_count, 1);

    assert!(
        web_login(&app, "u@test.local", "brandnewpw456").await.is_some(),
        "new password should authenticate"
    );
    assert!(
        web_login(&app, "u@test.local", "oldpw123").await.is_none(),
        "old password should no longer authenticate"
    );
}

/// Wrong current password re-renders the reauth modal with the
/// `invalid_password` banner and the staged new password preserved;
/// the stored password is unchanged.
#[tokio::test]
async fn me_password_change_without_grant_is_refused() {
    let app = TestApp::new().await;
    app.seed_user("u@test.local", "U", "oldpw123", InstanceRole::Member)
        .await;
    let set_cookie = web_login(&app, "u@test.local", "oldpw123").await.unwrap();
    let cookie = cookie_name_value(&set_cookie);
    let session_id = app.session_id_for_cookie(&cookie).await;
    let csrf = app.csrf_for(session_id);

    // No sudo grant (the chain mints one via /me/reauth first) → refused.
    let body = format!(
        "csrf_token={}&new_password={}",
        urlencoding(&csrf),
        urlencoding("brandnewpw456"),
    );
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri("/me/password")
        .header(header::COOKIE, cookie)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("hx-request", "true")
        .body(axum::body::Body::from(body))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    assert!(
        web_login(&app, "u@test.local", "oldpw123").await.is_some(),
        "password must be unchanged when no grant authorizes the change"
    );
}

/// Empty new password is rejected (HX-Redirect to /me with an error
/// toast); the stored password is unchanged.
#[tokio::test]
async fn me_password_change_empty_new_rejected() {
    let app = TestApp::new().await;
    app.seed_user("u@test.local", "U", "oldpw123", InstanceRole::Member)
        .await;
    let set_cookie = web_login(&app, "u@test.local", "oldpw123").await.unwrap();
    let cookie = cookie_name_value(&set_cookie);
    let session_id = app.session_id_for_cookie(&cookie).await;
    let csrf = app.csrf_for(session_id);
    let sudo = app.sudo_cookie(&cookie, &csrf, "oldpw123").await;

    let body = format!(
        "csrf_token={}&new_password=",
        urlencoding(&csrf),
    );
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri("/me/password")
        .header(header::COOKIE, format!("{cookie}; {sudo}"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("hx-request", "true")
        .body(axum::body::Body::from(body))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get("HX-Redirect").and_then(|v| v.to_str().ok()),
        Some("/me"),
    );
    assert!(
        web_login(&app, "u@test.local", "oldpw123").await.is_some(),
        "password must be unchanged when new password is empty"
    );
}

/// Changing the password revokes every *other* active session for the
/// user, while the session that made the change stays alive. Mirrors
/// the JSON `change_password` behavior.
#[tokio::test]
async fn me_password_change_revokes_other_sessions() {
    let app = TestApp::new().await;
    app.seed_user("u@test.local", "U", "oldpw123", InstanceRole::Member)
        .await;
    let cookie_a = cookie_name_value(&web_login(&app, "u@test.local", "oldpw123").await.unwrap());
    let cookie_b = cookie_name_value(&web_login(&app, "u@test.local", "oldpw123").await.unwrap());
    let session_a = app.session_id_for_cookie(&cookie_a).await;
    let csrf_a = app.csrf_for(session_a);
    let sudo = app.sudo_cookie(&cookie_a, &csrf_a, "oldpw123").await;

    let body = format!(
        "csrf_token={}&new_password={}",
        urlencoding(&csrf_a),
        urlencoding("brandnewpw456"),
    );
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri("/me/password")
        .header(header::COOKIE, format!("{cookie_a}; {sudo}"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("hx-request", "true")
        .body(axum::body::Body::from(body))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let (status_b, _) = get_with_cookie(&app, "/me", Some(&cookie_b)).await;
    assert_eq!(status_b, StatusCode::SEE_OTHER, "other session should be revoked");
    let (status_a, _) = get_with_cookie(&app, "/me", Some(&cookie_a)).await;
    assert_eq!(status_a, StatusCode::OK, "current session should stay alive");
}

// ─────────────────────────────────────────────────────────────────────────
// Account settings — regenerate recovery code (Data Control tab)
// ─────────────────────────────────────────────────────────────────────────

/// The Data Control tab's Recovery code section ships in the on-demand
/// account-settings fragment with a reauth-chained Regenerate button.
#[tokio::test]
async fn account_settings_data_renders_recovery_section() {
    let app = TestApp::new().await;
    app.seed_user("u@test.local", "U", "pw", InstanceRole::Member)
        .await;
    let set_cookie = web_login(&app, "u@test.local", "pw").await.unwrap();
    let cookie = cookie_name_value(&set_cookie);

    let (status, body) = get_with_cookie(&app, "/modals/account-settings", Some(&cookie)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains(r#"data-settings-panel="data""#));
    assert!(body.contains("Recovery code"));
    assert!(body.contains(r#"id="form-regenerate-recovery""#));
    assert!(body.contains(r#"data-reauth-confirm="form-regenerate-recovery""#));
}

/// Regenerating with the correct password mints a new code (shown once
/// in the response), invalidates the old one, and audits
/// `recovery_code_rotated`. The displayed code's hash matches the new
/// DB row; the old code's hash no longer does.
#[tokio::test]
async fn me_recovery_regenerate_succeeds_and_rotates() {
    let app = TestApp::new().await;
    let user = app
        .seed_user("u@test.local", "U", "rightpw", InstanceRole::Member)
        .await;
    // Seed a known starting code so we can prove it's invalidated.
    let old_code = "OLD0-OLD0-OLD0-OLD0-OLD0-OLD0-OLD0-OLD0";
    {
        let mut tx = app.pool.begin().await.unwrap();
        auth::user_recovery_code::bootstrap(&mut tx, user.id, old_code)
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }

    let set_cookie = web_login(&app, "u@test.local", "rightpw").await.unwrap();
    let cookie = cookie_name_value(&set_cookie);
    let session_id = app.session_id_for_cookie(&cookie).await;
    let csrf = app.csrf_for(session_id);
    let sudo = app.sudo_cookie(&cookie, &csrf, "rightpw").await;

    let body = format!("csrf_token={}", urlencoding(&csrf));
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri("/me/recovery-code/regenerate")
        .header(header::COOKIE, format!("{cookie}; {sudo}"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("hx-request", "true")
        .body(axum::body::Body::from(body))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = String::from_utf8_lossy(
        &axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap(),
    )
    .to_string();
    // Fragment (not a full page) with the one-time code + copy button.
    assert!(!body.contains("<html"));
    assert!(body.contains(r#"data-copy-target="recovery-code""#));
    // Plus an out-of-band refresh of the Data Control "Status" line, so it
    // flips from "no code on file" to "Generated …" without reopening.
    assert!(body.contains(r#"id="recovery-status""#));
    assert!(body.contains("hx-swap-oob"));
    assert!(body.contains("Generated"));

    // Extract the displayed code from the readonly input's value.
    let anchor = r#"id="recovery-code""#;
    let id_pos = body.find(anchor).expect("recovery-code input in body");
    let v_anchor = "value=\"";
    let v_start = body[id_pos..].find(v_anchor).expect("value attr") + id_pos + v_anchor.len();
    let v_end = v_start + body[v_start..].find('"').expect("closing quote");
    let new_code = &body[v_start..v_end];
    assert_eq!(new_code.len(), 39, "got: {new_code:?}");

    // DB now stores the new code's hash, not the old one's.
    let row: (Vec<u8>,) = sqlx::query_as(
        "SELECT code_hash FROM auth.user_recovery_codes WHERE user_id = $1",
    )
    .bind(user.id.0)
    .fetch_one(&app.pool)
    .await
    .unwrap();
    let new_hash = auth::recovery_code::hash_code(new_code);
    let old_hash = auth::recovery_code::hash_code(old_code);
    assert_eq!(row.0.as_slice(), &new_hash[..], "DB should hold the new code's hash");
    assert_ne!(row.0.as_slice(), &old_hash[..], "old code must be invalidated");

    // Audit row written.
    let (count,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM audit.events
         WHERE event_type = 'recovery_code_rotated' AND actor_user_id = $1",
    )
    .bind(user.id.0)
    .fetch_one(&app.pool)
    .await
    .unwrap();
    assert_eq!(count, 1);
}

/// Wrong current password re-renders the reauth modal with the error
/// banner; the stored recovery code is left untouched.
#[tokio::test]
async fn me_recovery_regenerate_wrong_password_leaves_code() {
    let app = TestApp::new().await;
    let user = app
        .seed_user("u@test.local", "U", "rightpw", InstanceRole::Member)
        .await;
    let old_code = "KEEP-KEEP-KEEP-KEEP-KEEP-KEEP-KEEP-KEEP";
    {
        let mut tx = app.pool.begin().await.unwrap();
        auth::user_recovery_code::bootstrap(&mut tx, user.id, old_code)
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }
    let set_cookie = web_login(&app, "u@test.local", "rightpw").await.unwrap();
    let cookie = cookie_name_value(&set_cookie);
    let session_id = app.session_id_for_cookie(&cookie).await;
    let csrf = app.csrf_for(session_id);

    // No sudo grant attached (a wrong password mints none) → refused.
    let body = format!("csrf_token={}", urlencoding(&csrf));
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri("/me/recovery-code/regenerate")
        .header(header::COOKIE, cookie)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("hx-request", "true")
        .body(axum::body::Body::from(body))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // Stored code is unchanged.
    let row: (Vec<u8>,) = sqlx::query_as(
        "SELECT code_hash FROM auth.user_recovery_codes WHERE user_id = $1",
    )
    .bind(user.id.0)
    .fetch_one(&app.pool)
    .await
    .unwrap();
    assert_eq!(row.0.as_slice(), &auth::recovery_code::hash_code(old_code)[..]);
}

/// Step-up AAL: when the account has a second factor (TOTP), a password
/// alone at `/me/reauth` is rejected and mints **no** sudo grant — so a
/// stolen session that only knows the password can't reach the bar.
#[tokio::test]
async fn reauth_password_alone_rejected_when_totp_enrolled() {
    let app = TestApp::new().await;
    let user = app
        .seed_user("u@test.local", "U", "pw", InstanceRole::Member)
        .await;
    seed_verified_totp(&app, user.id).await;
    // TOTP-enrolled login completes the challenge; returns the session.
    let cookie = totp_login(&app, "u@test.local", "pw").await;
    let session_id = app.session_id_for_cookie(&cookie).await;
    let csrf = app.csrf_for(session_id);

    // Password only, no authenticator code → not AAL2 → no grant.
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri("/me/reauth")
        .header(header::COOKIE, cookie)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("hx-request", "true")
        .body(axum::body::Body::from(format!(
            "csrf_token={}&password=pw",
            urlencoding(&csrf)
        )))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        set_cookie_value(resp.headers(), "sylva_sudo").is_none(),
        "password alone must not mint a grant when TOTP is enrolled"
    );
}

// ─────────────────────────────────────────────────────────────────────────
// Offline forgot-password flow (/recover + /recover/reset)
// ─────────────────────────────────────────────────────────────────────────

/// Pull a named cookie's value out of a response's `Set-Cookie` headers.
fn set_cookie_value(headers: &axum::http::HeaderMap, name: &str) -> Option<String> {
    let prefix = format!("{name}=");
    for v in headers.get_all(header::SET_COOKIE) {
        if let Ok(s) = v.to_str()
            && let Some(rest) = s.strip_prefix(&prefix)
        {
            return Some(rest.split(';').next().unwrap_or("").to_string());
        }
    }
    None
}

#[tokio::test]
async fn login_page_links_to_recover() {
    let app = TestApp::new().await;
    let (status, body) = get_with_cookie(&app, "/login", None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains(r#"href="/recover""#), "login should offer a recovery link");
}

#[tokio::test]
async fn recover_page_renders_email_and_code_fields() {
    let app = TestApp::new().await;
    let (status, body) = get_with_cookie(&app, "/recover", None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains(r#"action="/recover""#));
    assert!(body.contains(r#"name="email""#));
    assert!(body.contains(r#"name="recovery_code""#));
}

/// End-to-end: a locked-out user proves email + recovery code, sets a
/// new password, and the old code is rotated. The new password works,
/// the old one doesn't, and the new code shown matches the DB.
#[tokio::test]
async fn recover_full_flow_resets_password_and_rotates_code() {
    let app = TestApp::new().await;
    let user = app
        .seed_user("locked@test.local", "Locked", "forgotten", InstanceRole::Member)
        .await;
    let old_code = "RCV0-RCV0-RCV0-RCV0-RCV0-RCV0-RCV0-RCV0";
    {
        let mut tx = app.pool.begin().await.unwrap();
        auth::user_recovery_code::bootstrap(&mut tx, user.id, old_code)
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }

    // Step 1: POST /recover with email + code → redirect + reset cookie.
    let body = format!(
        "email={}&recovery_code={}",
        urlencoding("locked@test.local"),
        urlencoding(old_code),
    );
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri("/recover")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(axum::body::Body::from(body))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        resp.headers().get(header::LOCATION).and_then(|v| v.to_str().ok()),
        Some("/recover/reset")
    );
    let reset_token = set_cookie_value(resp.headers(), "sylva_recovery")
        .expect("recover should set the reset cookie");
    assert!(!reset_token.is_empty());
    let reset_cookie = format!("sylva_recovery={reset_token}");

    // Step 2: GET /recover/reset with the cookie renders the form.
    let (status, reset_form) = get_with_cookie(&app, "/recover/reset", Some(&reset_cookie)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(reset_form.contains(r#"action="/recover/reset""#));

    // Step 3: POST the new password.
    let body = format!(
        "new_password={}&confirm_password={}",
        urlencoding("brand-new-pw"),
        urlencoding("brand-new-pw"),
    );
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri("/recover/reset")
        .header(header::COOKIE, reset_cookie)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(axum::body::Body::from(body))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let resp_headers = resp.headers().clone();
    // A fresh session is issued for this device.
    assert!(
        set_cookie_value(&resp_headers, "sylva_session").is_some(),
        "reset should log the device in"
    );
    let reset_body = String::from_utf8_lossy(
        &axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap(),
    )
    .to_string();
    // The new recovery code is shown once.
    let anchor = r#"id="recovery-code""#;
    let id_pos = reset_body.find(anchor).expect("interstitial shows the new code");
    let v_start = reset_body[id_pos..].find("value=\"").expect("value attr") + id_pos + 7;
    let v_end = v_start + reset_body[v_start..].find('"').unwrap();
    let new_code = &reset_body[v_start..v_end];
    assert_eq!(new_code.len(), 39);

    // Password rotated: new works, old fails.
    assert!(web_login(&app, "locked@test.local", "brand-new-pw").await.is_some());
    assert!(web_login(&app, "locked@test.local", "forgotten").await.is_none());

    // Recovery code rotated: DB holds the new code's hash, not the old.
    let row: (Vec<u8>,) = sqlx::query_as(
        "SELECT code_hash FROM auth.user_recovery_codes WHERE user_id = $1",
    )
    .bind(user.id.0)
    .fetch_one(&app.pool)
    .await
    .unwrap();
    assert_eq!(row.0.as_slice(), &auth::recovery_code::hash_code(new_code)[..]);
    assert_ne!(row.0.as_slice(), &auth::recovery_code::hash_code(old_code)[..]);

    // Audit trail recorded both ends.
    for event in ["recovery_started", "recovery_succeeded"] {
        let (count,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM audit.events WHERE event_type = $1 AND actor_user_id = $2",
        )
        .bind(event)
        .bind(user.id.0)
        .fetch_one(&app.pool)
        .await
        .unwrap();
        assert_eq!(count, 1, "expected one {event} event");
    }
}

/// A wrong recovery code yields the generic error, sets no reset cookie,
/// and records a failed attempt.
#[tokio::test]
async fn recover_wrong_code_is_generic_and_sets_no_cookie() {
    let app = TestApp::new().await;
    let user = app
        .seed_user("locked@test.local", "Locked", "pw", InstanceRole::Member)
        .await;
    {
        let mut tx = app.pool.begin().await.unwrap();
        auth::user_recovery_code::bootstrap(&mut tx, user.id, "GOOD-GOOD-GOOD-GOOD-GOOD-GOOD-GOOD-GOOD")
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }

    let body = format!(
        "email={}&recovery_code={}",
        urlencoding("locked@test.local"),
        urlencoding("WRONG-CODE"),
    );
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri("/recover")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(axum::body::Body::from(body))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(set_cookie_value(resp.headers(), "sylva_recovery").is_none());
    let body = String::from_utf8_lossy(
        &axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap(),
    )
    .to_string();
    assert!(body.contains("didn't match"), "should show the generic error");

    let (failed,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM audit.events WHERE event_type = 'recovery_failed'",
    )
    .fetch_one(&app.pool)
    .await
    .unwrap();
    assert_eq!(failed, 1);
}

/// Unknown email behaves identically to a wrong code (no enumeration).
#[tokio::test]
async fn recover_unknown_email_is_generic() {
    let app = TestApp::new().await;
    let body = format!(
        "email={}&recovery_code={}",
        urlencoding("nobody@test.local"),
        urlencoding("WHATEVER-CODE"),
    );
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri("/recover")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(axum::body::Body::from(body))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(set_cookie_value(resp.headers(), "sylva_recovery").is_none());
    let body = String::from_utf8_lossy(
        &axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap(),
    )
    .to_string();
    assert!(body.contains("didn't match"));
}

/// The reset step is gated by the cookie: no cookie → bounce to /recover.
#[tokio::test]
async fn recover_reset_without_cookie_redirects_to_recover() {
    let app = TestApp::new().await;
    // GET
    let (status, _) = get_with_cookie(&app, "/recover/reset", None).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    // POST
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri("/recover/reset")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(axum::body::Body::from("new_password=x&confirm_password=x"))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        resp.headers().get(header::LOCATION).and_then(|v| v.to_str().ok()),
        Some("/recover")
    );
}

/// A tampered/garbage reset cookie is rejected the same way.
#[tokio::test]
async fn recover_reset_with_garbage_cookie_redirects() {
    let app = TestApp::new().await;
    let (status, _) =
        get_with_cookie(&app, "/recover/reset", Some("sylva_recovery=not-a-valid-token")).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
}

/// Mismatched confirm re-renders with an error; password stays put.
#[tokio::test]
async fn recover_reset_password_mismatch_rerenders() {
    let app = TestApp::new().await;
    let user = app
        .seed_user("locked@test.local", "Locked", "original", InstanceRole::Member)
        .await;
    {
        let mut tx = app.pool.begin().await.unwrap();
        auth::user_recovery_code::bootstrap(&mut tx, user.id, "AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA")
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }
    // Get a valid reset cookie.
    let body = format!(
        "email={}&recovery_code={}",
        urlencoding("locked@test.local"),
        urlencoding("AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA"),
    );
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri("/recover")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(axum::body::Body::from(body))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    let reset_cookie = format!(
        "sylva_recovery={}",
        set_cookie_value(resp.headers(), "sylva_recovery").unwrap()
    );

    let body = "new_password=abcdefgh&confirm_password=DIFFERENT";
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri("/recover/reset")
        .header(header::COOKIE, reset_cookie)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(axum::body::Body::from(body))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = String::from_utf8_lossy(
        &axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap(),
    )
    .to_string();
    assert!(body.contains("don't match"));
    // Original password still works.
    assert!(web_login(&app, "locked@test.local", "original").await.is_some());
}

// ─────────────────────────────────────────────────────────────────────────
// Auth endpoint rate limiting
// ─────────────────────────────────────────────────────────────────────────

async fn post_form_with_ip(app: &TestApp, uri: &str, ip: &str, body: String) -> StatusCode {
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header("x-forwarded-for", ip)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(axum::body::Body::from(body))
        .unwrap();
    tower::ServiceExt::oneshot(app.router.clone(), req)
        .await
        .unwrap()
        .status()
}

/// After a burst of failed `/recover` attempts from one IP, the next is
/// throttled with 429 — while a different IP is unaffected (independent
/// buckets, keyed off `X-Forwarded-For`).
#[tokio::test]
async fn recover_is_rate_limited_per_ip() {
    let app = TestApp::new().await;
    let burst = server::rate_limit::DEFAULT_AUTH_BURST;
    let body = || {
        format!(
            "email={}&recovery_code={}",
            urlencoding("nobody@test.local"),
            urlencoding("WRONG"),
        )
    };

    for _ in 0..burst {
        assert_eq!(
            post_form_with_ip(&app, "/recover", "10.9.9.9", body()).await,
            StatusCode::OK
        );
    }
    assert_eq!(
        post_form_with_ip(&app, "/recover", "10.9.9.9", body()).await,
        StatusCode::TOO_MANY_REQUESTS,
        "burst+1 from the same IP should be throttled"
    );
    assert_eq!(
        post_form_with_ip(&app, "/recover", "10.9.9.10", body()).await,
        StatusCode::OK,
        "a different IP has its own bucket"
    );
}

/// The login form is throttled the same way. Unknown-email attempts
/// skip the Argon2 path, so draining the bucket stays cheap.
#[tokio::test]
async fn login_is_rate_limited_per_ip() {
    let app = TestApp::new().await;
    let burst = server::rate_limit::DEFAULT_AUTH_BURST;
    let body = || {
        format!(
            "email={}&password={}",
            urlencoding("nobody@test.local"),
            urlencoding("x"),
        )
    };

    for _ in 0..burst {
        assert_eq!(
            post_form_with_ip(&app, "/login", "10.8.8.8", body()).await,
            StatusCode::OK
        );
    }
    assert_eq!(
        post_form_with_ip(&app, "/login", "10.8.8.8", body()).await,
        StatusCode::TOO_MANY_REQUESTS
    );
}

/// A successful login does not consume the throttle budget — a user who
/// signs in correctly is never throttled by their own activity.
#[tokio::test]
async fn successful_login_does_not_consume_rate_budget() {
    let app = TestApp::new().await;
    app.seed_user("good@test.local", "Good", "rightpw", InstanceRole::Member)
        .await;
    let burst = server::rate_limit::DEFAULT_AUTH_BURST;
    for _ in 0..(burst + 2) {
        let ok = format!(
            "email={}&password={}",
            urlencoding("good@test.local"),
            urlencoding("rightpw"),
        );
        // 303 redirect to /me on success.
        assert_eq!(
            post_form_with_ip(&app, "/login", "10.7.7.7", ok).await,
            StatusCode::SEE_OTHER
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Two-factor (TOTP) — Security tab enrollment + login challenge
// ─────────────────────────────────────────────────────────────────────────

/// RFC-style 20-byte secrets used to seed TOTP enrollments in tests.
const TEST_TOTP_SECRET: &[u8] = b"12345678901234567890";
const TEST_TOTP_SECRET_2: &[u8] = b"ABCDEFGHIJ1234567890";

/// Seed a *verified* authenticator with a given secret + label,
/// encrypted under the app key exactly as the server does. Returns its id.
async fn seed_totp(
    app: &TestApp,
    user_id: identity::UserId,
    secret: &[u8],
    label: &str,
) -> uuid::Uuid {
    let mut tx = app.pool.begin().await.unwrap();
    let id = auth::user_totp::start_enrollment(&mut tx, &app.secret_key, user_id, secret)
        .await
        .unwrap();
    auth::user_totp::confirm(&mut tx, user_id, id, label).await.unwrap();
    tx.commit().await.unwrap();
    id
}

/// Convenience: seed one verified authenticator using the primary secret.
async fn seed_verified_totp(app: &TestApp, user_id: identity::UserId) -> uuid::Uuid {
    seed_totp(app, user_id, TEST_TOTP_SECRET, "Authenticator").await
}

fn code_for(secret: &[u8]) -> String {
    auth::totp::code_at(secret, chrono::Utc::now().timestamp())
}

fn current_totp_code() -> String {
    code_for(TEST_TOTP_SECRET)
}

#[tokio::test]
async fn security_tab_shows_totp_setup_when_not_enrolled() {
    let app = TestApp::new().await;
    app.seed_user("u@test.local", "U", "pw", InstanceRole::Member)
        .await;
    let cookie = cookie_name_value(&web_login(&app, "u@test.local", "pw").await.unwrap());
    let (status, body) = get_with_cookie(&app, "/modals/account-settings", Some(&cookie)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Registered Authenticators"));
    assert!(body.contains(r#"data-reauth-confirm="form-totp-start""#));
    assert!(body.contains("No authenticators yet"));
    // The explainer card.
    assert!(body.contains("What are authenticators?"));
}

#[tokio::test]
async fn security_tab_lists_enrolled_authenticators() {
    let app = TestApp::new().await;
    let user = app
        .seed_user("u@test.local", "U", "pw", InstanceRole::Member)
        .await;
    seed_totp(&app, user.id, TEST_TOTP_SECRET, "1Password").await;
    seed_totp(&app, user.id, TEST_TOTP_SECRET_2, "Ente Auth").await;
    // web_login can't reach a session for a TOTP user (it stops at the
    // challenge), so sign in via the full two-step flow.
    let session = totp_login(&app, "u@test.local", "pw").await;
    let (status, body) = get_with_cookie(&app, "/modals/account-settings", Some(&session)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("1Password"));
    assert!(body.contains("Ente Auth"));
    // Each row offers rename + remove affordances.
    assert!(body.contains("/edit"));
    assert!(body.contains("/confirm-delete"));
}

/// Drive the full password → TOTP challenge → session flow and return
/// the resulting `sylva_session` cookie (name=value).
async fn totp_login(app: &TestApp, email: &str, password: &str) -> String {
    // Step 1: password.
    let body = format!("email={}&password={}", urlencoding(email), urlencoding(password));
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri("/login")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(axum::body::Body::from(body))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let mfa_cookie = format!(
        "sylva_mfa={}",
        set_cookie_value(resp.headers(), "sylva_mfa").expect("mfa cookie")
    );
    // Step 2: TOTP code.
    let body = format!("code={}", urlencoding(&current_totp_code()));
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri("/login/verify")
        .header(header::COOKIE, mfa_cookie)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(axum::body::Body::from(body))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    format!(
        "sylva_session={}",
        set_cookie_value(resp.headers(), "sylva_session").expect("session cookie")
    )
}

#[tokio::test]
async fn login_with_totp_enrolled_defers_session() {
    let app = TestApp::new().await;
    let user = app
        .seed_user("u@test.local", "U", "pw", InstanceRole::Member)
        .await;
    seed_verified_totp(&app, user.id).await;

    let body = format!("email={}&password={}", urlencoding("u@test.local"), urlencoding("pw"));
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri("/login")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(axum::body::Body::from(body))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        resp.headers().get(header::LOCATION).and_then(|v| v.to_str().ok()),
        Some("/login/verify")
    );
    // No real session yet — only the pending-MFA cookie.
    assert!(set_cookie_value(resp.headers(), "sylva_mfa").is_some());
    assert!(set_cookie_value(resp.headers(), "sylva_session").is_none());
}

#[tokio::test]
async fn totp_code_is_single_use() {
    let app = TestApp::new().await;
    let user = app
        .seed_user("u@test.local", "U", "pw", InstanceRole::Member)
        .await;
    seed_verified_totp(&app, user.id).await;
    // The SAME code is presented twice (captured once, within one window).
    let code = current_totp_code();

    // First sign-in: password → pending cookie → code accepted.
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri("/login")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(axum::body::Body::from(format!(
            "email={}&password={}",
            urlencoding("u@test.local"),
            urlencoding("pw")
        )))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    let mfa1 = format!(
        "sylva_mfa={}",
        set_cookie_value(resp.headers(), "sylva_mfa").expect("mfa cookie")
    );
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri("/login/verify")
        .header(header::COOKIE, mfa1)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(axum::body::Body::from(format!("code={}", urlencoding(&code))))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert!(set_cookie_value(resp.headers(), "sylva_session").is_some());

    // Second sign-in: replaying the same code on a fresh challenge is
    // rejected — TOTP codes are single-use within their window.
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri("/login")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(axum::body::Body::from(format!(
            "email={}&password={}",
            urlencoding("u@test.local"),
            urlencoding("pw")
        )))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    let mfa2 = format!(
        "sylva_mfa={}",
        set_cookie_value(resp.headers(), "sylva_mfa").expect("mfa cookie")
    );
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri("/login/verify")
        .header(header::COOKIE, mfa2)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(axum::body::Body::from(format!("code={}", urlencoding(&code))))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK); // re-rendered challenge, not a redirect
    assert!(set_cookie_value(resp.headers(), "sylva_session").is_none());
}

#[tokio::test]
async fn login_verify_with_correct_totp_issues_session() {
    let app = TestApp::new().await;
    let user = app
        .seed_user("u@test.local", "U", "pw", InstanceRole::Member)
        .await;
    seed_verified_totp(&app, user.id).await;

    let session = totp_login(&app, "u@test.local", "pw").await;
    // The issued session authenticates.
    let (status, _) = get_with_cookie(&app, "/me", Some(&session)).await;
    assert_eq!(status, StatusCode::OK);

    let (count,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM audit.events
         WHERE event_type = 'signin_success'
           AND actor_user_id = $1
           AND event_data->>'mfa' = 'totp'",
    )
    .bind(user.id.0)
    .fetch_one(&app.pool)
    .await
    .unwrap();
    assert_eq!(count, 1);
}

#[tokio::test]
async fn login_verify_rejects_wrong_totp() {
    let app = TestApp::new().await;
    let user = app
        .seed_user("u@test.local", "U", "pw", InstanceRole::Member)
        .await;
    seed_verified_totp(&app, user.id).await;

    // Get a pending-MFA cookie.
    let body = format!("email={}&password={}", urlencoding("u@test.local"), urlencoding("pw"));
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri("/login")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(axum::body::Body::from(body))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    let mfa_cookie = format!(
        "sylva_mfa={}",
        set_cookie_value(resp.headers(), "sylva_mfa").unwrap()
    );

    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri("/login/verify")
        .header(header::COOKIE, mfa_cookie)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(axum::body::Body::from("code=000000"))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    // Re-render (200), no session issued.
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(set_cookie_value(resp.headers(), "sylva_session").is_none());

    let (failed,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM audit.events WHERE event_type = 'mfa_failed' AND actor_user_id = $1",
    )
    .bind(user.id.0)
    .fetch_one(&app.pool)
    .await
    .unwrap();
    assert_eq!(failed, 1);
}

#[tokio::test]
async fn login_verify_recovery_code_bypasses_totp() {
    let app = TestApp::new().await;
    let user = app
        .seed_user("u@test.local", "U", "pw", InstanceRole::Member)
        .await;
    seed_verified_totp(&app, user.id).await;
    let recovery = "BYP0-BYP0-BYP0-BYP0-BYP0-BYP0-BYP0-BYP0";
    {
        let mut tx = app.pool.begin().await.unwrap();
        auth::user_recovery_code::bootstrap(&mut tx, user.id, recovery)
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }

    // Password step → pending cookie.
    let body = format!("email={}&password={}", urlencoding("u@test.local"), urlencoding("pw"));
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri("/login")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(axum::body::Body::from(body))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    let mfa_cookie = format!(
        "sylva_mfa={}",
        set_cookie_value(resp.headers(), "sylva_mfa").unwrap()
    );

    // Recovery code instead of TOTP → session issued.
    let body = format!("recovery_code={}", urlencoding(recovery));
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri("/login/verify")
        .header(header::COOKIE, mfa_cookie)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(axum::body::Body::from(body))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert!(set_cookie_value(resp.headers(), "sylva_session").is_some());
}

#[tokio::test]
async fn login_verify_without_cookie_redirects_to_login() {
    let app = TestApp::new().await;
    let (status, _) = get_with_cookie(&app, "/login/verify", None).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn totp_confirm_enrolls_with_valid_code() {
    let app = TestApp::new().await;
    let user = app
        .seed_user("u@test.local", "U", "pw", InstanceRole::Member)
        .await;
    let cookie = cookie_name_value(&web_login(&app, "u@test.local", "pw").await.unwrap());
    let session_id = app.session_id_for_cookie(&cookie).await;
    let csrf = app.csrf_for(session_id);

    // Seed an unverified credential (the start step), then confirm via HTTP.
    let cred_id = {
        let mut tx = app.pool.begin().await.unwrap();
        let id = auth::user_totp::start_enrollment(&mut tx, &app.secret_key, user.id, TEST_TOTP_SECRET)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        id
    };
    assert!(!auth::user_totp::is_enrolled(&app.pool, user.id).await.unwrap());

    let body = format!(
        "csrf_token={}&cred_id={}&label={}&code={}",
        urlencoding(&csrf),
        urlencoding(&cred_id.to_string()),
        urlencoding("My Phone"),
        urlencoding(&current_totp_code()),
    );
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri("/me/totp/confirm")
        .header(header::COOKIE, cookie)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("hx-request", "true")
        .body(axum::body::Body::from(body))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = String::from_utf8_lossy(
        &axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap(),
    )
    .to_string();
    assert!(body.contains("Authenticator added"));
    // The response also carries an out-of-band refresh of the list so the
    // still-open settings modal updates live (keep-source-open flow).
    assert!(body.contains(r#"id="totp-section""#));
    assert!(body.contains(r#"hx-swap-oob="true""#));
    assert!(body.contains("My Phone"));
    assert!(auth::user_totp::is_enrolled(&app.pool, user.id).await.unwrap());
    // The chosen label stuck.
    let creds = auth::user_totp::list_verified(&app.pool, user.id).await.unwrap();
    assert_eq!(creds.len(), 1);
    assert_eq!(creds[0].label, "My Phone");

    let (count,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM audit.events WHERE event_type = 'totp_enrolled' AND actor_user_id = $1",
    )
    .bind(user.id.0)
    .fetch_one(&app.pool)
    .await
    .unwrap();
    assert_eq!(count, 1);
}

#[tokio::test]
async fn totp_rename_updates_label() {
    let app = TestApp::new().await;
    let user = app
        .seed_user("u@test.local", "U", "pw", InstanceRole::Member)
        .await;
    let cred_id = seed_totp(&app, user.id, TEST_TOTP_SECRET, "Old Name").await;
    let session = totp_login(&app, "u@test.local", "pw").await;
    let session_id = app.session_id_for_cookie(&session).await;
    let csrf = app.csrf_for(session_id);

    let body = format!("csrf_token={}&label={}", urlencoding(&csrf), urlencoding("New Name"));
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri(format!("/me/totp/{cred_id}/rename"))
        .header(header::COOKIE, session)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("hx-request", "true")
        .body(axum::body::Body::from(body))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = String::from_utf8_lossy(
        &axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap(),
    )
    .to_string();
    // The refreshed island shows the new name.
    assert!(body.contains("New Name"));
    assert!(!body.contains("Old Name"));
    let creds = auth::user_totp::list_verified(&app.pool, user.id).await.unwrap();
    assert_eq!(creds[0].label, "New Name");
}

/// Removing an authenticator is reauth-gated: without a fresh `sylva_sudo`
/// grant the action is refused (a stolen session can't strip 2FA), and both
/// authenticators remain. This is the regression test for the step-up hole.
#[tokio::test]
async fn totp_delete_without_grant_refused() {
    let app = TestApp::new().await;
    let user = app
        .seed_user("u@test.local", "U", "pw", InstanceRole::Member)
        .await;
    seed_totp(&app, user.id, TEST_TOTP_SECRET, "Keep").await;
    let drop = seed_totp(&app, user.id, TEST_TOTP_SECRET_2, "Drop").await;
    let session = totp_login(&app, "u@test.local", "pw").await;
    let session_id = app.session_id_for_cookie(&session).await;
    let csrf = app.csrf_for(session_id);

    // No sylva_sudo cookie attached → refused.
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri(format!("/me/totp/{drop}/delete"))
        .header(header::COOKIE, session)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("hx-request", "true")
        .body(axum::body::Body::from(format!("csrf_token={}", urlencoding(&csrf))))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // Both authenticators remain.
    let creds = auth::user_totp::list_verified(&app.pool, user.id).await.unwrap();
    assert_eq!(creds.len(), 2);
}

#[tokio::test]
async fn totp_delete_removes_one_of_several() {
    let app = TestApp::new().await;
    let user = app
        .seed_user("u@test.local", "U", "pw", InstanceRole::Member)
        .await;
    let keep = seed_totp(&app, user.id, TEST_TOTP_SECRET, "Keep").await;
    let drop = seed_totp(&app, user.id, TEST_TOTP_SECRET_2, "Drop").await;
    let _ = keep;
    let session = totp_login(&app, "u@test.local", "pw").await;
    let session_id = app.session_id_for_cookie(&session).await;
    let csrf = app.csrf_for(session_id);

    // Mint a sudo grant via the TOTP reauth path. `totp_login` already
    // consumed the `TEST_TOTP_SECRET` code (single-use), so reauth with the
    // second authenticator's code, which is still unused this time-step.
    let reauth_body = format!(
        "csrf_token={}&password=pw&code={}",
        urlencoding(&csrf),
        urlencoding(&code_for(TEST_TOTP_SECRET_2))
    );
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri("/me/reauth")
        .header(header::COOKIE, session.clone())
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("hx-request", "true")
        .body(axum::body::Body::from(reauth_body))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    let sudo = format!(
        "sylva_sudo={}",
        set_cookie_value(resp.headers(), "sylva_sudo").expect("reauth should mint a grant")
    );

    let body = format!("csrf_token={}", urlencoding(&csrf));
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri(format!("/me/totp/{drop}/delete"))
        .header(header::COOKIE, format!("{session}; {sudo}"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("hx-request", "true")
        .body(axum::body::Body::from(body))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    // Still enrolled (one remains); the dropped one is gone.
    let creds = auth::user_totp::list_verified(&app.pool, user.id).await.unwrap();
    assert_eq!(creds.len(), 1);
    assert_eq!(creds[0].label, "Keep");

    let (removed,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM audit.events WHERE event_type = 'totp_removed' AND actor_user_id = $1",
    )
    .bind(user.id.0)
    .fetch_one(&app.pool)
    .await
    .unwrap();
    assert_eq!(removed, 1);
}

#[tokio::test]
async fn login_verify_tries_all_authenticators() {
    let app = TestApp::new().await;
    let user = app
        .seed_user("u@test.local", "U", "pw", InstanceRole::Member)
        .await;
    // Two authenticators with different secrets.
    seed_totp(&app, user.id, TEST_TOTP_SECRET, "First").await;
    seed_totp(&app, user.id, TEST_TOTP_SECRET_2, "Second").await;

    // Password → pending cookie.
    let body = format!("email={}&password={}", urlencoding("u@test.local"), urlencoding("pw"));
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri("/login")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(axum::body::Body::from(body))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    let mfa_cookie = format!(
        "sylva_mfa={}",
        set_cookie_value(resp.headers(), "sylva_mfa").unwrap()
    );

    // Submit a code from the SECOND authenticator — the loop must find it.
    let body = format!("code={}", urlencoding(&code_for(TEST_TOTP_SECRET_2)));
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri("/login/verify")
        .header(header::COOKIE, mfa_cookie)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(axum::body::Body::from(body))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert!(set_cookie_value(resp.headers(), "sylva_session").is_some());
}

// ─────────────────────────────────────────────────────────────────────────
// Passkeys (WebAuthn) — Security tab rendering + endpoint gating
//
// The actual create/get ceremonies need a real browser authenticator, so
// they're validated manually; these cover the non-ceremony surface.
// ─────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn security_tab_shows_passkeys_section() {
    let app = TestApp::new().await;
    app.seed_user("u@test.local", "U", "pw", InstanceRole::Member)
        .await;
    let cookie = cookie_name_value(&web_login(&app, "u@test.local", "pw").await.unwrap());
    let (status, body) = get_with_cookie(&app, "/modals/account-settings", Some(&cookie)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains(r#"id="passkey-section""#));
    assert!(body.contains("What are passkeys?"));
    // Test harness base URL is localhost → WebAuthn is configurable, so
    // the reauth-chained Add button renders.
    assert!(body.contains(r#"data-reauth-confirm="form-passkey-start""#));
    assert!(body.contains("No passkeys yet"));
}

#[tokio::test]
async fn passkey_section_requires_auth() {
    let app = TestApp::new().await;
    let (status, _) = get_with_cookie(&app, "/me/passkey/section", None).await;
    assert_eq!(status, StatusCode::SEE_OTHER); // bounced to /login
}

#[tokio::test]
async fn passkey_section_renders_for_authed_user() {
    let app = TestApp::new().await;
    app.seed_user("u@test.local", "U", "pw", InstanceRole::Member)
        .await;
    let cookie = cookie_name_value(&web_login(&app, "u@test.local", "pw").await.unwrap());
    let (status, body) = get_with_cookie(&app, "/me/passkey/section", Some(&cookie)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains(r#"id="passkey-section""#));
}

/// Removing a passkey is reauth-gated too. Minting a passkey grant needs
/// the WebAuthn ceremony (browser-only), so this covers the security-
/// critical half: without a fresh `sylva_sudo` grant the removal is
/// refused and the passkey stays. We grab the session *before* enrolling
/// the passkey so login doesn't defer to the 2FA challenge.
#[tokio::test]
async fn passkey_delete_without_grant_refused() {
    let app = TestApp::new().await;
    let user = app
        .seed_user("u@test.local", "U", "pw", InstanceRole::Member)
        .await;
    let cookie = cookie_name_value(&web_login(&app, "u@test.local", "pw").await.unwrap());
    seed_stub_passkey(&app, user.id).await;
    let pk_id: uuid::Uuid =
        sqlx::query_scalar("SELECT id FROM auth.webauthn_credentials WHERE user_id = $1")
            .bind(user.id.0)
            .fetch_one(&app.pool)
            .await
            .unwrap();
    let session_id = app.session_id_for_cookie(&cookie).await;
    let csrf = app.csrf_for(session_id);

    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri(format!("/me/passkey/{pk_id}/delete"))
        .header(header::COOKIE, cookie)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("hx-request", "true")
        .body(axum::body::Body::from(format!("csrf_token={}", urlencoding(&csrf))))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // The passkey is still there.
    assert_eq!(server::webauthn::count(&app.pool, user.id).await.unwrap(), 1);
}

/// Insert a placeholder passkey row. The login-gating + page-rendering
/// paths only COUNT passkeys (they don't deserialize the credential), so
/// a stub credential is enough to simulate "this user has a passkey"
/// without a real WebAuthn ceremony.
async fn seed_stub_passkey(app: &TestApp, user_id: identity::UserId) {
    sqlx::query(
        "INSERT INTO auth.webauthn_credentials (user_id, label, credential)
         VALUES ($1, 'Test Passkey', '{}'::jsonb)",
    )
    .bind(user_id.0)
    .execute(&app.pool)
    .await
    .unwrap();
}

#[tokio::test]
async fn login_with_passkey_only_defers_session() {
    let app = TestApp::new().await;
    let user = app
        .seed_user("u@test.local", "U", "pw", InstanceRole::Member)
        .await;
    seed_stub_passkey(&app, user.id).await;

    // A user with only a passkey (no TOTP) must still be challenged.
    let body = format!("email={}&password={}", urlencoding("u@test.local"), urlencoding("pw"));
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri("/login")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(axum::body::Body::from(body))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        resp.headers().get(header::LOCATION).and_then(|v| v.to_str().ok()),
        Some("/login/verify")
    );
    let mfa_cookie = format!(
        "sylva_mfa={}",
        set_cookie_value(resp.headers(), "sylva_mfa").expect("pending cookie")
    );
    assert!(set_cookie_value(resp.headers(), "sylva_session").is_none());

    // The challenge page offers the passkey path.
    let (status, body) = get_with_cookie(&app, "/login/verify", Some(&mfa_cookie)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Use a passkey"));
    assert!(body.contains(r#"data-passkey-auth="/login/verify/passkey/start""#));
    // The ceremony JS must be loaded on this public page, or the button
    // is dead (regression guard: WEBAUTHN_JS belongs in shell_public).
    assert!(body.contains("__sylvaWebauthnLoaded"));
}

#[tokio::test]
async fn login_verify_passkey_start_requires_pending_cookie() {
    let app = TestApp::new().await;
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri("/login/verify/passkey/start")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ─────────────────────────────────────────────────────────────────────────
// Passwordless passkey sign-in (/login/passkey/{start,finish})
// ─────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn login_page_shows_passwordless_passkey_button() {
    let app = TestApp::new().await;
    let (status, body) = get_with_cookie(&app, "/login", None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Sign in with a passkey"));
    assert!(body.contains(r#"data-passkey-auth="/login/passkey/start""#));
    // The ceremony JS must be present on the public page.
    assert!(body.contains("__sylvaWebauthnLoaded"));
}

#[tokio::test]
async fn login_passkey_start_returns_challenge_options() {
    let app = TestApp::new().await;
    // No auth needed — discoverable start identifies the user later.
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri("/login/passkey/start")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let body = String::from_utf8(body_bytes.to_vec()).unwrap();
    assert!(body.contains("challenge_id"));
    // The WebAuthn request options for navigator.credentials.get.
    assert!(body.contains("publicKey"));
    assert!(body.contains("challenge"));
}

#[tokio::test]
async fn login_passkey_finish_rejects_bad_assertion() {
    let app = TestApp::new().await;
    let body = format!(
        "challenge_id={}&passkey={}",
        uuid::Uuid::new_v4(),
        urlencoding("not-a-valid-assertion")
    );
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri("/login/passkey/finish")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(axum::body::Body::from(body))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    // Re-renders the login page with an error; no session is issued.
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(set_cookie_value(resp.headers(), "sylva_session").is_none());
}

// ── Self-service account closure (anonymize / delete) ─────────────────────

/// Raw form POST with an explicit Cookie header, returning the full response
/// so a test can inspect status + `HX-Redirect` + `Set-Cookie`.
async fn post_form_raw(
    app: &TestApp,
    uri: &str,
    cookie: &str,
    body: String,
) -> axum::response::Response {
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::COOKIE, cookie)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(axum::body::Body::from(body))
        .unwrap();
    tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap()
}

async fn count(app: &TestApp, sql: &str, id: uuid::Uuid) -> i64 {
    sqlx::query_scalar(sql).bind(id).fetch_one(&app.pool).await.unwrap()
}

/// A normal sudo grant must NOT authorize an irreversible account action —
/// these always require a fresh *critical* re-auth. This is the server-side
/// half of the "always re-auth, ignore the 5-minute window" guarantee.
#[tokio::test]
async fn account_delete_with_normal_grant_only_is_refused() {
    let app = TestApp::new().await;
    let user = app
        .seed_user("leave@example.com", "Leaver", "rightpw", InstanceRole::Member)
        .await;
    let session = cookie_name_value(&web_login(&app, &user.email, "rightpw").await.unwrap());
    let sid = app.session_id_for_cookie(&session).await;
    let csrf = app.csrf_for(sid);
    // The everyday step-up grant — fresh, but the wrong kind for this action.
    let normal = app.sudo_cookie(&session, &csrf, "rightpw").await;
    assert!(!normal.is_empty(), "normal sudo grant should be minted");
    let cookie = format!("{session}; {normal}");
    let resp = post_form_raw(&app, "/me/account/delete", &cookie, format!("csrf_token={csrf}")).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        count(&app, "SELECT count(*) FROM identity.users WHERE id = $1", user.id.0).await,
        1,
        "account must survive a refused delete",
    );
}

/// With a fresh *critical* grant, delete physically removes the account and
/// everything tied to it, and redirects to the public goodbye page. Also
/// pins the audit-integrity fix: the actor id survives on past rows (no FK
/// SET NULL), so the hash chain stays valid through a physical delete.
#[tokio::test]
async fn account_delete_with_critical_grant_removes_everything() {
    let app = TestApp::new().await;
    // A co-owner keeps the instance non-empty, so deleting `user` exercises the
    // individual-delete mechanics without tripping the empty-instance teardown.
    let _owner = app
        .seed_user("keeper@example.com", "Keeper", "keeppw1", InstanceRole::Owner)
        .await;
    let user = app
        .seed_user("gone@example.com", "Goner", "rightpw", InstanceRole::Member)
        .await;
    let session = cookie_name_value(&web_login(&app, &user.email, "rightpw").await.unwrap());
    let sid = app.session_id_for_cookie(&session).await;
    let csrf = app.csrf_for(sid);
    let critical = app.sudo_critical_cookie(&session, &csrf, "rightpw").await;
    assert!(!critical.is_empty(), "critical grant should be minted");
    let cookie = format!("{session}; {critical}");
    let resp = post_form_raw(&app, "/me/account/delete", &cookie, format!("csrf_token={csrf}")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get("HX-Redirect").and_then(|v| v.to_str().ok()),
        Some("/goodbye?mode=deleted"),
    );
    assert_eq!(
        count(&app, "SELECT count(*) FROM identity.users WHERE id = $1", user.id.0).await,
        0,
        "user row must be physically deleted",
    );
    assert_eq!(
        count(&app, "SELECT count(*) FROM auth.credentials WHERE user_id = $1", user.id.0).await,
        0,
        "credentials must cascade away",
    );
    assert_eq!(
        count(&app, "SELECT count(*) FROM auth.sessions WHERE user_id = $1", user.id.0).await,
        0,
        "sessions must cascade away",
    );
    // The deletion event is recorded, with the actor snapshot retained...
    let deleted_actor: Option<uuid::Uuid> = sqlx::query_scalar(
        "SELECT actor_user_id FROM audit.events WHERE event_type = 'account_self_deleted'",
    )
    .fetch_one(&app.pool)
    .await
    .unwrap();
    assert_eq!(deleted_actor, Some(user.id.0), "deletion event keeps the actor snapshot");
    // ...and so do the user's *past* audit rows — proving the FK no longer
    // SET-NULLs them (which would invalidate their hashes).
    let seed_actor: Option<uuid::Uuid> = sqlx::query_scalar(
        "SELECT actor_user_id FROM audit.events \
         WHERE event_type = 'test_seed_user' AND actor_user_id = $1",
    )
    .bind(user.id.0)
    .fetch_one(&app.pool)
    .await
    .unwrap();
    assert_eq!(seed_actor, Some(user.id.0), "past audit rows keep their actor id after delete");
}

/// Anonymize keeps the row but redacts identity and deletes the password,
/// so the account is permanently inaccessible without losing the tombstone.
#[tokio::test]
async fn account_anonymize_redacts_and_locks_out() {
    let app = TestApp::new().await;
    // Co-owner keeps the instance non-empty (isolates the anonymize mechanics
    // from the empty-instance teardown).
    let _owner = app
        .seed_user("keeper2@example.com", "Keeper2", "keeppw2", InstanceRole::Owner)
        .await;
    let user = app
        .seed_user("hide@example.com", "Hider", "rightpw", InstanceRole::Member)
        .await;
    let session = cookie_name_value(&web_login(&app, &user.email, "rightpw").await.unwrap());
    let sid = app.session_id_for_cookie(&session).await;
    let csrf = app.csrf_for(sid);
    let critical = app.sudo_critical_cookie(&session, &csrf, "rightpw").await;
    let cookie = format!("{session}; {critical}");
    let resp =
        post_form_raw(&app, "/me/account/anonymize", &cookie, format!("csrf_token={csrf}")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get("HX-Redirect").and_then(|v| v.to_str().ok()),
        Some("/goodbye?mode=anonymized"),
    );
    let (email, display, lifecycle): (String, String, String) = sqlx::query_as(
        "SELECT email, display_name, lifecycle::text FROM identity.users WHERE id = $1",
    )
    .bind(user.id.0)
    .fetch_one(&app.pool)
    .await
    .unwrap();
    assert!(email.contains("@purged.invalid"), "email redacted: {email}");
    assert_eq!(display, "[deleted user]");
    assert_eq!(lifecycle, "anonymized");
    assert_eq!(
        count(&app, "SELECT count(*) FROM auth.credentials WHERE user_id = $1", user.id.0).await,
        0,
        "credentials deleted on anonymize",
    );
}

/// Account closure is CSRF protected — a bad token is rejected before any
/// destructive work, even with a valid critical grant attached.
#[tokio::test]
async fn account_delete_requires_csrf() {
    let app = TestApp::new().await;
    let user = app
        .seed_user("csrf@example.com", "Csrf", "rightpw", InstanceRole::Member)
        .await;
    let session = cookie_name_value(&web_login(&app, &user.email, "rightpw").await.unwrap());
    let sid = app.session_id_for_cookie(&session).await;
    let csrf = app.csrf_for(sid);
    let critical = app.sudo_critical_cookie(&session, &csrf, "rightpw").await;
    let cookie = format!("{session}; {critical}");
    let resp = post_form_raw(&app, "/me/account/delete", &cookie, "csrf_token=bogus".to_string()).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        count(&app, "SELECT count(*) FROM identity.users WHERE id = $1", user.id.0).await,
        1,
    );
}

/// The public `/goodbye` page renders mode-specific copy and needs no auth.
#[tokio::test]
async fn goodbye_page_renders_mode_copy() {
    let app = TestApp::new().await;
    let deleted = app.get("/goodbye?mode=deleted", None).await;
    deleted.assert_status(StatusCode::OK);
    assert!(deleted.body_as_text().contains("permanently removed"));
    let anon = app.get("/goodbye?mode=anonymized", None).await;
    anon.assert_status(StatusCode::OK);
    assert!(anon.body_as_text().contains("closed"));
}

/// The Data Control tab surfaces the two account-closure sections, each a
/// button that opens the matching confirm modal on demand.
#[tokio::test]
async fn account_settings_shows_close_account_sections() {
    let app = TestApp::new().await;
    let user = app
        .seed_user("dz@example.com", "Dz", "rightpw", InstanceRole::Member)
        .await;
    let session = cookie_name_value(&web_login(&app, &user.email, "rightpw").await.unwrap());
    let (status, body) = get_with_cookie(&app, "/modals/account-settings", Some(&session)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains(r#"data-open-modal="/modals/account/anonymize""#));
    assert!(body.contains(r#"data-open-modal="/modals/account/delete""#));
    assert!(body.contains("settings-section-danger"));
}

/// Each confirm modal carries both gates (acknowledge checkbox + type-your-
/// email) and a confirm button that drives the *critical* re-auth.
#[tokio::test]
async fn account_close_modals_render_gates() {
    let app = TestApp::new().await;
    let user = app
        .seed_user("gate@example.com", "Gate", "rightpw", InstanceRole::Member)
        .await;
    let session = cookie_name_value(&web_login(&app, &user.email, "rightpw").await.unwrap());

    for (slug, action) in [
        ("anonymize", "/me/account/anonymize"),
        ("delete", "/me/account/delete"),
    ] {
        let (status, body) =
            get_with_cookie(&app, &format!("/modals/account/{slug}"), Some(&session)).await;
        assert_eq!(status, StatusCode::OK, "{slug}: status");
        assert!(body.contains(&format!(r#"action="{action}""#)), "{slug}: form action");
        assert!(body.contains("data-close-ack"), "{slug}: acknowledge gate");
        assert!(
            body.contains(&format!(r#"data-close-email="{}""#, user.email)),
            "{slug}: email gate seeded with the account email",
        );
        assert!(body.contains("data-reauth-critical"), "{slug}: forced critical reauth");
        assert!(
            body.contains(r#"data-reauth-confirm="form-account-"#),
            "{slug}: chain binding",
        );
    }

    // An unknown action is a 404, not a silent render.
    let (status, _) = get_with_cookie(&app, "/modals/account/wat", Some(&session)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// The critical reauth modal never advertises a fresh grant — even when a
/// fresh *normal* sudo grant is present — and threads `critical=1` into the
/// verify form, so the chain always prompts and the verify mints the critical
/// grant. The non-critical modal, by contrast, does report the fresh grant.
#[tokio::test]
async fn reauth_modal_critical_forces_prompt() {
    let app = TestApp::new().await;
    let user = app
        .seed_user("crit@example.com", "Crit", "rightpw", InstanceRole::Member)
        .await;
    let session = cookie_name_value(&web_login(&app, &user.email, "rightpw").await.unwrap());
    let sid = app.session_id_for_cookie(&session).await;
    let csrf = app.csrf_for(sid);
    let normal = app.sudo_cookie(&session, &csrf, "rightpw").await;
    assert!(!normal.is_empty());
    let cookie = format!("{session}; {normal}");

    let (_, critical) = get_with_cookie(&app, "/modals/reauth?critical=1", Some(&cookie)).await;
    assert!(
        !critical.contains(r#"data-sudo-fresh="1""#),
        "critical modal must never report freshness",
    );
    assert!(
        critical.contains(r#"name="critical" value="1""#),
        "critical modal threads critical=1 into the verify form",
    );

    let (_, normal_modal) = get_with_cookie(&app, "/modals/reauth", Some(&cookie)).await;
    assert!(
        normal_modal.contains(r#"data-sudo-fresh="1""#),
        "the ordinary modal still honours the fresh grant",
    );
}

// ── Last-owner guard (can't close while others remain) ────────────────────

/// The last active Owner, with other users present, is blocked from closing:
/// the Data Control sections show the transfer-first note (no live trigger),
/// the confirm modal refuses the dangerous form, and the POST is a no-op even
/// with a valid critical grant.
#[tokio::test]
async fn last_owner_with_others_is_blocked_from_closing() {
    let app = TestApp::new().await;
    let owner = app
        .seed_user("owner@example.com", "Owner", "ownerpw", InstanceRole::Owner)
        .await;
    let _member = app
        .seed_user("m@example.com", "Mem", "mempw1", InstanceRole::Member)
        .await;
    let session = cookie_name_value(&web_login(&app, &owner.email, "ownerpw").await.unwrap());

    let (status, settings) = get_with_cookie(&app, "/modals/account-settings", Some(&session)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(settings.contains("settings-row-note"), "transfer-first note shown");
    assert!(settings.contains("Transfer ownership to someone"), "note copy");
    assert!(
        !settings.contains(r#"data-open-modal="/modals/account/delete""#),
        "the delete trigger is disabled (no open-modal handle)",
    );

    let (status, modal) = get_with_cookie(&app, "/modals/account/delete", Some(&session)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(modal.contains("Transfer ownership first"), "blocked content");
    assert!(!modal.contains("data-reauth-critical"), "no critical confirm button");

    // POST backstop: even with a fresh critical grant, the close is refused
    // (no HX-Redirect) and the account survives.
    let sid = app.session_id_for_cookie(&session).await;
    let csrf = app.csrf_for(sid);
    let critical = app.sudo_critical_cookie(&session, &csrf, "ownerpw").await;
    let cookie = format!("{session}; {critical}");
    let resp = post_form_raw(&app, "/me/account/delete", &cookie, format!("csrf_token={csrf}")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        resp.headers().get("HX-Redirect").is_none(),
        "blocked close must not redirect (it refused, not performed)",
    );
    assert_eq!(
        count(&app, "SELECT count(*) FROM identity.users WHERE id = $1", owner.id.0).await,
        1,
        "owner account survives a refused close",
    );
}

/// A non-last owner (2+ active owners) can close normally — the confirm form
/// renders and the section trigger is live.
#[tokio::test]
async fn non_last_owner_can_close() {
    let app = TestApp::new().await;
    let owner1 = app
        .seed_user("o1@example.com", "O1", "pw1pw1", InstanceRole::Owner)
        .await;
    let _owner2 = app
        .seed_user("o2@example.com", "O2", "pw2pw2", InstanceRole::Owner)
        .await;
    let session = cookie_name_value(&web_login(&app, &owner1.email, "pw1pw1").await.unwrap());

    let (status, modal) = get_with_cookie(&app, "/modals/account/delete", Some(&session)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(modal.contains("data-reauth-critical"), "real confirm form (not blocked)");
    assert!(!modal.contains("Transfer ownership first"));

    let (_, settings) = get_with_cookie(&app, "/modals/account-settings", Some(&session)).await;
    assert!(settings.contains(r#"data-open-modal="/modals/account/delete""#));
    assert!(!settings.contains("settings-row-note"));
}

/// A solo owner (the only active user) is NOT blocked — that's the
/// empty-instance teardown path, handled in CP2.
#[tokio::test]
async fn solo_owner_can_close() {
    let app = TestApp::new().await;
    let owner = app
        .seed_user("solo@example.com", "Solo", "solopw", InstanceRole::Owner)
        .await;
    let session = cookie_name_value(&web_login(&app, &owner.email, "solopw").await.unwrap());
    let (status, modal) = get_with_cookie(&app, "/modals/account/delete", Some(&session)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(modal.contains("data-reauth-critical"), "solo owner can close");
    assert!(!modal.contains("Transfer ownership first"));
}

// ── Empty-instance teardown (closed page + scorch) ────────────────────────

async fn table_count(app: &TestApp, table: &str) -> i64 {
    sqlx::query_scalar(&format!("SELECT count(*) FROM {table}"))
        .fetch_one(&app.pool)
        .await
        .unwrap()
}

async fn instance_closed(app: &TestApp) -> bool {
    sqlx::query_scalar("SELECT closed_at IS NOT NULL FROM sylva_meta.instance WHERE id = TRUE")
        .fetch_one(&app.pool)
        .await
        .unwrap()
}

/// The last user **deleting** scorches every data table (audit log included),
/// closes the instance, and serves the terminal closed page on every route
/// thereafter — while `/assets` keeps serving so the page renders styled.
#[tokio::test]
async fn solo_delete_scorches_and_closes_instance() {
    let app = TestApp::new().await;
    let owner = app
        .seed_user("last@example.com", "Last", "lastpw", InstanceRole::Owner)
        .await;
    let session = cookie_name_value(&web_login(&app, &owner.email, "lastpw").await.unwrap());
    let sid = app.session_id_for_cookie(&session).await;
    let csrf = app.csrf_for(sid);
    let critical = app.sudo_critical_cookie(&session, &csrf, "lastpw").await;
    let cookie = format!("{session}; {critical}");

    let resp = post_form_raw(&app, "/me/account/delete", &cookie, format!("csrf_token={csrf}")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get("HX-Redirect").and_then(|v| v.to_str().ok()),
        Some("/"),
        "closing the last account redirects to the closed page, not /goodbye",
    );

    assert!(instance_closed(&app).await, "instance marked closed");
    for table in [
        "identity.users",
        "auth.credentials",
        "auth.sessions",
        "audit.events",
        "pending.transitions",
        "notifications.outbox",
    ] {
        assert_eq!(table_count(&app, table).await, 0, "{table} scorched");
    }

    // The closed page is served on any route now (no auth needed)...
    let (status, body) = get_with_cookie(&app, "/me", None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("This server has been closed"), "closed page served");
    // ...and /assets is exempt so that page can load its stylesheet.
    let (asset_status, _) = get_with_cookie(&app, "/assets/css/app.css", None).await;
    assert_eq!(asset_status, StatusCode::OK, "assets stay served when closed");
}

/// The last user **anonymizing** closes the instance too — but keeps the
/// tombstone (and the audit log); it is *not* a scorch.
#[tokio::test]
async fn solo_anonymize_closes_but_keeps_tombstone() {
    let app = TestApp::new().await;
    let owner = app
        .seed_user("solo2@example.com", "Solo2", "solo2pw", InstanceRole::Owner)
        .await;
    let session = cookie_name_value(&web_login(&app, &owner.email, "solo2pw").await.unwrap());
    let sid = app.session_id_for_cookie(&session).await;
    let csrf = app.csrf_for(sid);
    let critical = app.sudo_critical_cookie(&session, &csrf, "solo2pw").await;
    let cookie = format!("{session}; {critical}");

    let resp =
        post_form_raw(&app, "/me/account/anonymize", &cookie, format!("csrf_token={csrf}")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get("HX-Redirect").and_then(|v| v.to_str().ok()),
        Some("/"),
    );

    assert!(instance_closed(&app).await, "instance closed");
    assert_eq!(
        table_count(&app, "identity.users").await,
        1,
        "anonymize keeps the tombstone row",
    );
    let lifecycle: String =
        sqlx::query_scalar("SELECT lifecycle::text FROM identity.users WHERE id = $1")
            .bind(owner.id.0)
            .fetch_one(&app.pool)
            .await
            .unwrap();
    assert_eq!(lifecycle, "anonymized");
    assert!(
        table_count(&app, "audit.events").await > 0,
        "anonymize does not scorch the audit log",
    );

    let (_, body) = get_with_cookie(&app, "/login", None).await;
    assert!(body.contains("This server has been closed"));
}

/// A close that leaves other users behind does NOT close the instance — the
/// web keeps working normally.
#[tokio::test]
async fn close_with_remaining_users_keeps_instance_open() {
    let app = TestApp::new().await;
    let owner1 = app
        .seed_user("a@example.com", "A", "apwapw", InstanceRole::Owner)
        .await;
    let _owner2 = app
        .seed_user("b@example.com", "B", "bpwbpw", InstanceRole::Owner)
        .await;
    let session = cookie_name_value(&web_login(&app, &owner1.email, "apwapw").await.unwrap());
    let sid = app.session_id_for_cookie(&session).await;
    let csrf = app.csrf_for(sid);
    let critical = app.sudo_critical_cookie(&session, &csrf, "apwapw").await;
    let cookie = format!("{session}; {critical}");

    let resp = post_form_raw(&app, "/me/account/delete", &cookie, format!("csrf_token={csrf}")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get("HX-Redirect").and_then(|v| v.to_str().ok()),
        Some("/goodbye?mode=deleted"),
        "with users remaining, it's the normal goodbye — not the closed page",
    );
    assert!(!instance_closed(&app).await, "instance stays open while users remain");
    assert_eq!(
        table_count(&app, "identity.users").await,
        1,
        "the other owner survives",
    );
    let (_, body) = get_with_cookie(&app, "/login", None).await;
    assert!(!body.contains("This server has been closed"), "web still open");
}

// ── Empty instance: closed page + scorch ──────────────────────────────────

async fn scalar_i64(app: &TestApp, sql: &str) -> i64 {
    sqlx::query_scalar(sql).fetch_one(&app.pool).await.unwrap()
}

async fn instance_closed_at(app: &TestApp) -> Option<chrono::DateTime<chrono::Utc>> {
    sqlx::query_scalar("SELECT closed_at FROM sylva_meta.instance WHERE id = TRUE")
        .fetch_one(&app.pool)
        .await
        .unwrap()
}

/// A solo Delete is a full teardown: the instance is marked closed, every data
/// table is scorched (audit included), and every web route then serves the
/// terminal closed page — while `/assets` keeps serving so it renders styled.
#[tokio::test]
async fn solo_delete_closes_and_scorches_the_instance() {
    let app = TestApp::new().await;
    let owner = app
        .seed_user("last@example.com", "Last", "lastpw1", InstanceRole::Owner)
        .await;
    let session = cookie_name_value(&web_login(&app, &owner.email, "lastpw1").await.unwrap());
    let sid = app.session_id_for_cookie(&session).await;
    let csrf = app.csrf_for(sid);
    let critical = app.sudo_critical_cookie(&session, &csrf, "lastpw1").await;
    let cookie = format!("{session}; {critical}");

    let resp = post_form_raw(&app, "/me/account/delete", &cookie, format!("csrf_token={csrf}")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    // Closed-page redirect (root), not the transient goodbye.
    assert_eq!(
        resp.headers().get("HX-Redirect").and_then(|v| v.to_str().ok()),
        Some("/"),
    );
    // Every data table is empty — audit included.
    assert_eq!(scalar_i64(&app, "SELECT count(*) FROM identity.users").await, 0, "users");
    assert_eq!(scalar_i64(&app, "SELECT count(*) FROM auth.credentials").await, 0, "credentials");
    assert_eq!(scalar_i64(&app, "SELECT count(*) FROM audit.events").await, 0, "audit scorched");
    // The closed flag is set and survived the scorch (it's in sylva_meta).
    assert!(instance_closed_at(&app).await.is_some(), "instance marked closed");
    // Any subsequent web route serves the closed page; assets still serve.
    let (status, body) = get_with_cookie(&app, "/login", None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("This server has been closed"), "closed page served: {body}");
    let (assets_status, _) = get_with_cookie(&app, "/assets/css/app.css", None).await;
    assert_eq!(assets_status, StatusCode::OK, "assets still served when closed");
}

/// A solo Anonymize closes the instance but keeps the tombstone the user chose
/// to leave — no scorch.
#[tokio::test]
async fn solo_anonymize_closes_but_keeps_the_tombstone() {
    let app = TestApp::new().await;
    let owner = app
        .seed_user("hide-last@example.com", "HideLast", "hidepw1", InstanceRole::Owner)
        .await;
    let session = cookie_name_value(&web_login(&app, &owner.email, "hidepw1").await.unwrap());
    let sid = app.session_id_for_cookie(&session).await;
    let csrf = app.csrf_for(sid);
    let critical = app.sudo_critical_cookie(&session, &csrf, "hidepw1").await;
    let cookie = format!("{session}; {critical}");

    let resp =
        post_form_raw(&app, "/me/account/anonymize", &cookie, format!("csrf_token={csrf}")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get("HX-Redirect").and_then(|v| v.to_str().ok()),
        Some("/"),
    );
    assert!(instance_closed_at(&app).await.is_some(), "closed on solo anonymize");
    // The tombstone row is kept (redacted), not scorched.
    let (email, lifecycle): (String, String) =
        sqlx::query_as("SELECT email, lifecycle::text FROM identity.users WHERE id = $1")
            .bind(owner.id.0)
            .fetch_one(&app.pool)
            .await
            .unwrap();
    assert!(email.contains("@purged.invalid"), "tombstone redacted: {email}");
    assert_eq!(lifecycle, "anonymized");
    let (status, body) = get_with_cookie(&app, "/login", None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("This server has been closed"));
}

/// A non-last user leaving (an owner remains) does NOT close the instance — it
/// gets the normal goodbye, and the login page still works.
#[tokio::test]
async fn member_close_with_owner_remaining_keeps_instance_open() {
    let app = TestApp::new().await;
    let _owner = app
        .seed_user("keep@example.com", "Keep", "keeppw1", InstanceRole::Owner)
        .await;
    let member = app
        .seed_user("leaver@example.com", "Leaver", "leavepw", InstanceRole::Member)
        .await;
    let session = cookie_name_value(&web_login(&app, &member.email, "leavepw").await.unwrap());
    let sid = app.session_id_for_cookie(&session).await;
    let csrf = app.csrf_for(sid);
    let critical = app.sudo_critical_cookie(&session, &csrf, "leavepw").await;
    let cookie = format!("{session}; {critical}");

    let resp = post_form_raw(&app, "/me/account/delete", &cookie, format!("csrf_token={csrf}")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get("HX-Redirect").and_then(|v| v.to_str().ok()),
        Some("/goodbye?mode=deleted"),
        "owner remains → normal goodbye, not the closed page",
    );
    assert!(instance_closed_at(&app).await.is_none(), "instance stays open");
    let (status, body) = get_with_cookie(&app, "/login", None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Sign in"), "login page still served");
}
