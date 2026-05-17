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
    assert!(set_cookie.starts_with("hearth_session="));
    assert!(set_cookie.contains("HttpOnly"));
    assert!(set_cookie.contains("SameSite=Lax"));
}

#[tokio::test]
async fn login_post_with_wrong_password_renders_error() {
    let app = TestApp::new().await;
    app.seed_user("u@test.local", "U", "rightpw", InstanceRole::User)
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
async fn logout_clears_cookie_and_revokes_session() {
    let app = TestApp::new().await;
    let user = app
        .seed_user("u@test.local", "U", "pw", InstanceRole::User)
        .await;
    let set_cookie = web_login(&app, "u@test.local", "pw").await.unwrap();
    let cookie = cookie_name_value(&set_cookie);

    // Logout
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri("/logout")
        .header(header::COOKIE, cookie.clone())
        .body(axum::body::Body::empty())
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

#[tokio::test]
async fn root_redirects_based_on_auth() {
    let app = TestApp::new().await;
    app.seed_user("u@test.local", "U", "pw", InstanceRole::User)
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
    // The Authorization header + `hearth_session` cookie should both
    // satisfy the AuthenticatedUser extractor. This proves the cookie
    // fallback doesn't only work on web routes — the API surface is
    // also usable from a browser session if you ever want to.
    let app = TestApp::new().await;
    app.seed_user("u@test.local", "U", "pw", InstanceRole::User)
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
    app.seed_user("u@test.local", "U", "pw", InstanceRole::User)
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
