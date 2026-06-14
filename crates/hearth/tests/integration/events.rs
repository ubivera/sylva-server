//! Events (audit log) page — admin/owner gating, rendering, cursor pagination.

use axum::http::{Method, StatusCode, header};
use identity::InstanceRole;
use uuid::Uuid;

use crate::common::TestApp;

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

async fn web_login_session(app: &TestApp, email: &str, password: &str) -> (String, Uuid) {
    let body = format!("email={}&password={}", urlencoding(email), urlencoding(password));
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
        .expect("login Set-Cookie")
        .to_string();
    let cookie = cookie_name_value(&set_cookie);
    let session_id = app.session_id_for_cookie(&cookie).await;
    (cookie, session_id)
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
    (status, String::from_utf8_lossy(&bytes).to_string())
}

#[tokio::test]
async fn events_page_requires_admin() {
    let app = TestApp::new().await;
    app.seed_user("member@test.local", "Mem", "pw", InstanceRole::Member)
        .await;
    let (cookie, _) = web_login_session(&app, "member@test.local", "pw").await;

    let (status, _) = get_with_cookie(&app, "/events", &cookie).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // A Member sees no Events entry in the sidebar.
    let (_, me) = get_with_cookie(&app, "/me", &cookie).await;
    assert!(!me.contains("href=\"/events\""));
}

#[tokio::test]
async fn events_page_shows_recent_events() {
    let app = TestApp::new().await;
    // `seed_user` emits a `test_seed_user` audit event attributed to the user.
    app.seed_user("admin@test.local", "Adminna", "pw", InstanceRole::Admin)
        .await;
    let (cookie, _) = web_login_session(&app, "admin@test.local", "pw").await;

    let (status, html) = get_with_cookie(&app, "/events", &cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("Time"));
    assert!(html.contains("Test seed user"), "humanized event type should render");
    assert!(html.contains("Adminna"), "actor display name should render");

    // Admin sees the Events nav entry.
    let (_, me) = get_with_cookie(&app, "/me", &cookie).await;
    assert!(me.contains("href=\"/events\""));
}

#[tokio::test]
async fn events_page_paginates_with_cursor() {
    let app = TestApp::new().await;
    app.seed_user("owner@test.local", "Ownie", "pw", InstanceRole::Owner)
        .await;
    let (cookie, _) = web_login_session(&app, "owner@test.local", "pw").await;

    // Append more than one page of events directly (no Argon2 cost).
    for i in 0..(audit::DEFAULT_PAGE_SIZE as usize + 3) {
        let mut tx = app.pool.begin().await.unwrap();
        audit::append(&mut tx, None, None, "test_event", serde_json::json!({ "i": i }))
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }

    // Newest page is full → offers an "Older" cursor link.
    let (status, html) = get_with_cookie(&app, "/events", &cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        html.contains("/events?before="),
        "a full newest page should offer an Older cursor"
    );

    // The tail page (low seqno) has no further history and offers "Newest".
    let (status, tail) = get_with_cookie(&app, "/events?before=5", &cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert!(tail.contains("Newest"), "a paged-back view should offer Newest");
    assert!(
        !tail.contains("/events?before="),
        "the tail page should not offer a further Older cursor"
    );
}
