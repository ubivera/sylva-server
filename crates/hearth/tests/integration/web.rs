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

    // Instance name appears in title + brand line.
    assert!(
        body.contains("test-instance"),
        "instance name should be visible in chrome: {body}"
    );
    // Brand line uses the "Sylva · {name}" format.
    assert!(body.contains("Sylva"));
    // Sidebar nav present.
    assert!(body.contains(r#"class="sidebar""#));
    assert!(body.contains(r#"href="/me""#));
    // User card present with avatar + email.
    assert!(body.contains(r#"class="user-card""#));
    assert!(body.contains("Big Boss"));
    assert!(body.contains("o@test.local"));
    // Owner role badge with the right class.
    assert!(body.contains("role-owner"));
    // Search trigger placeholder.
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
    // But should be styled (CSS link present).
    assert!(body.contains("/assets/css/app.css"));
    // And the public wordmark should be there.
    assert!(body.contains("Sylva Hearth"));
}

#[tokio::test]
async fn role_badge_class_matches_user_role() {
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
    assert!(body.contains("role-member"));
    assert!(!body.contains("role-owner"));
    assert!(!body.contains("role-admin"));
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

    // Logout (with CSRF token)
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
    // The Authorization header + `hearth_session` cookie should both
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
    // Role badges rendered. Status is now communicated by a dot on the
    // avatar (see `.avatar-status` in CSS) rather than a column.
    assert!(body.contains("role-admin"));
    assert!(body.contains("role-member"));
    assert!(body.contains("avatar-status-active"));
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
    // The search input is present.
    assert!(body.contains(r#"id="users-search""#));
    assert!(body.contains("Search by name or email"));
    // Each row carries a lowercased data-search haystack of name + email.
    assert!(body.contains(r#"data-search="alice alice@test.local""#));
    assert!(body.contains(r#"data-search="adm in admin@test.local""#));
    // The inline filter script is on the page.
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

    // Joined column header should be marked `aria-sort=ascending`.
    assert!(
        body.contains(r#"aria-sort="ascending""#),
        "expected joined column to be ascending: {body}"
    );
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
    // href now also carries `&filter=all` so flipping sort doesn't drop
    // any active filter.
    let (_, body) = get_with_cookie(&app, "/members?sort=name&dir=asc", Some(&cookie)).await;
    assert!(body.contains(r#"href="/members?sort=name&amp;dir=desc&amp;filter=all""#));
    // Other columns reset to asc when clicked from a different sort.
    assert!(body.contains(r#"href="/members?sort=role&amp;dir=asc&amp;filter=all""#));
    assert!(body.contains(r#"href="/members?sort=joined&amp;dir=asc&amp;filter=all""#));
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
    assert!(body.contains(r#"aria-sort="ascending""#));
}

#[tokio::test]
async fn users_page_renders_deactivated_avatar_status_dot() {
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
    // Status is rendered as a colored dot on the avatar, not a column.
    assert!(body.contains("avatar-status-active"));
    assert!(
        body.contains("avatar-status-deactivated"),
        "expected deactivated dot in: {body}"
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
