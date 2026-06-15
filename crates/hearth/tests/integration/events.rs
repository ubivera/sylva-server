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

/// Count rendered data rows by their per-row modal trigger.
fn row_count(html: &str) -> usize {
    html.matches("data-open-modal=\"/events/").count()
}

/// Append a single audit event (no Argon2 cost) and return its seqno.
async fn append_event(app: &TestApp, event_type: &str, data: serde_json::Value) -> i64 {
    let mut tx = app.pool.begin().await.unwrap();
    let ev = audit::append(&mut tx, None, None, event_type, data).await.unwrap();
    tx.commit().await.unwrap();
    ev.seqno
}

#[tokio::test]
async fn events_page_offset_pagination() {
    let app = TestApp::new().await;
    app.seed_user("owner@test.local", "Ownie", "pw", InstanceRole::Owner)
        .await;
    let (cookie, _) = web_login_session(&app, "owner@test.local", "pw").await;

    // 25 appended, plus the seed + login events → ≥3 pages at 10/page.
    for i in 0..25 {
        append_event(&app, "test_event", serde_json::json!({ "i": i })).await;
    }

    // Page 1: a full page (10 rows) + the Members-style bar with page links.
    let (status, html) = get_with_cookie(&app, "/events", &cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("pagination-bar"));
    assert!(html.contains("Rows per page"));
    assert!(html.contains("/events?page=2"));
    assert!(html.contains("/events?page=3"));
    assert_eq!(row_count(&html), 10, "default page size is 10");

    // Page 2 is also full; offset paging splits the log into 10-row pages.
    let (status, p2) = get_with_cookie(&app, "/events?page=2", &cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(row_count(&p2), 10);

    // A larger page size collapses it to a single page.
    let (status, big) = get_with_cookie(&app, "/events?rows=100", &cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert!(big.contains("of 1"), "100/page fits everything on one page");
}

#[tokio::test]
async fn events_filter_by_type() {
    let app = TestApp::new().await;
    app.seed_user("owner@test.local", "Ownie", "pw", InstanceRole::Owner)
        .await;
    let (cookie, _) = web_login_session(&app, "owner@test.local", "pw").await;

    for _ in 0..3 {
        append_event(&app, "alpha_event", serde_json::json!({})).await;
    }
    for _ in 0..2 {
        append_event(&app, "beta_event", serde_json::json!({})).await;
    }

    let (status, html) = get_with_cookie(&app, "/events?type=alpha_event", &cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(row_count(&html), 3, "only alpha_event rows");
}

#[tokio::test]
async fn events_search_matches_event_data() {
    let app = TestApp::new().await;
    app.seed_user("owner@test.local", "Ownie", "pw", InstanceRole::Owner)
        .await;
    let (cookie, _) = web_login_session(&app, "owner@test.local", "pw").await;

    append_event(&app, "test_event", serde_json::json!({ "needle": "haystack" })).await;

    // Matches the value inside event_data.
    let (status, hit) = get_with_cookie(&app, "/events?q=haystack", &cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(row_count(&hit), 1);

    // No match → the filtered empty state.
    let (status, miss) = get_with_cookie(&app, "/events?q=zzzznevermatches", &cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(row_count(&miss), 0);
    assert!(miss.contains("No events match"));
}

#[tokio::test]
async fn event_detail_modal_shows_data_and_hashes() {
    let app = TestApp::new().await;
    app.seed_user("admin@test.local", "Adminna", "pw", InstanceRole::Admin)
        .await;
    let (cookie, _) = web_login_session(&app, "admin@test.local", "pw").await;

    let seqno = append_event(&app, "test_event", serde_json::json!({ "marker_value": 12345 })).await;

    let (status, html) = get_with_cookie(&app, &format!("/events/{seqno}/modal"), &cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains(&format!("Event #{seqno}")));
    assert!(html.contains("prev_hash"), "chain hashes shown");
    assert!(html.contains("Chain"));
    assert!(html.contains("marker_value"), "full event_data rendered");
    assert!(html.contains("12345"));

    // A Member can't reach the detail either.
    app.seed_user("member@test.local", "Mem", "pw", InstanceRole::Member)
        .await;
    let (mcookie, _) = web_login_session(&app, "member@test.local", "pw").await;
    let (mstatus, _) = get_with_cookie(&app, &format!("/events/{seqno}/modal"), &mcookie).await;
    assert_eq!(mstatus, StatusCode::FORBIDDEN);
}
