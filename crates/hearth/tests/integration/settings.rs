//! Instance Settings (CP1) — the storage + effective-config layer.
//!
//! Covers `hearth::instance`'s override round-trips and the
//! DB-override-else-env `effective` model that seeds the hot-swappable
//! `AppState` cells. The page + handlers land in CP2.

use axum::http::{Method, StatusCode, header};
use axum::response::Response;
use hearth::config::{Config, NotificationsConfig};
use hearth::instance::{self, SmtpInput};
use identity::InstanceRole;
use uuid::Uuid;

use crate::common::TestApp;

/// Build a stand-in env `Config` without touching the process environment
/// (which is shared across parallel tests). Only the two fields `effective`
/// reads as fallbacks matter here.
fn env_config(instance_name: &str, notifications_mode: &str) -> Config {
    let instance_name = instance_name.to_string();
    let notifications_mode = notifications_mode.to_string();
    Config::from_env_lookup(move |key| match key {
        "HEARTH_INSTANCE_NAME" => Some(instance_name.clone()),
        "HEARTH_NOTIFICATIONS_MODE" => Some(notifications_mode.clone()),
        _ => None,
    })
    .expect("test config parses")
}

fn smtp_input(host: &str, password: Option<&str>) -> SmtpInput {
    SmtpInput {
        host: host.to_string(),
        port: 587,
        tls: "starttls".to_string(),
        username: "mailer@example.com".to_string(),
        from_email: "noreply@example.com".to_string(),
        from_name: Some("Example".to_string()),
        password: password.map(str::to_string),
    }
}

#[tokio::test]
async fn effective_falls_back_to_env_when_no_overrides() {
    let app = TestApp::new().await;
    let cfg = env_config("EnvName", "log");

    let eff = instance::effective(&app.pool, &cfg, &app.secret_key)
        .await
        .expect("effective");

    // Fresh DB: every override column is NULL, so env wins.
    assert_eq!(eff.instance_name, "EnvName");
    assert!(matches!(eff.notifications, NotificationsConfig::Log));
}

#[tokio::test]
async fn instance_name_override_round_trips_and_clears() {
    let app = TestApp::new().await;
    let cfg = env_config("EnvName", "disabled");

    instance::save_instance_name(&app.pool, Some("My Cool Server"))
        .await
        .expect("save name");
    let eff = instance::effective(&app.pool, &cfg, &app.secret_key)
        .await
        .expect("effective");
    assert_eq!(eff.instance_name, "My Cool Server");

    // Clearing (None / empty) reverts to the env default.
    instance::save_instance_name(&app.pool, None)
        .await
        .expect("clear name");
    let eff = instance::effective(&app.pool, &cfg, &app.secret_key)
        .await
        .expect("effective");
    assert_eq!(eff.instance_name, "EnvName");

    // An empty string is treated as "clear", not as a literal name.
    instance::save_instance_name(&app.pool, Some(""))
        .await
        .expect("empty name");
    let eff = instance::effective(&app.pool, &cfg, &app.secret_key)
        .await
        .expect("effective");
    assert_eq!(eff.instance_name, "EnvName");
}

#[tokio::test]
async fn notifications_mode_override_wins_over_env() {
    let app = TestApp::new().await;
    // Env says SMTP would be off (disabled); the DB override flips it to log.
    let cfg = env_config("EnvName", "disabled");

    instance::save_notifications(&app.pool, &app.secret_key, "log", None)
        .await
        .expect("save log mode");
    let eff = instance::effective(&app.pool, &cfg, &app.secret_key)
        .await
        .expect("effective");
    assert!(matches!(eff.notifications, NotificationsConfig::Log));

    instance::save_notifications(&app.pool, &app.secret_key, "disabled", None)
        .await
        .expect("save disabled mode");
    let eff = instance::effective(&app.pool, &cfg, &app.secret_key)
        .await
        .expect("effective");
    assert!(matches!(eff.notifications, NotificationsConfig::Disabled));
}

#[tokio::test]
async fn smtp_password_is_stored_sealed_not_plaintext() {
    let app = TestApp::new().await;
    let cfg = env_config("EnvName", "disabled");

    assert!(
        !instance::smtp_password_is_set(&app.pool)
            .await
            .expect("password set check"),
        "no password before any SMTP save"
    );

    instance::save_notifications(
        &app.pool,
        &app.secret_key,
        "smtp",
        Some(smtp_input("smtp.example.com", Some("hunter2"))),
    )
    .await
    .expect("save smtp");

    // The raw column must not contain the plaintext — it's sealed
    // (XChaCha20-Poly1305: 24-byte nonce + ciphertext + 16-byte tag).
    let enc: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT smtp_password_enc FROM hearth_meta.instance WHERE id = TRUE")
            .fetch_one(&app.pool)
            .await
            .expect("read enc column");
    let enc = enc.expect("password column populated");
    assert_ne!(enc, b"hunter2".to_vec(), "stored ciphertext equals plaintext");
    assert!(enc.len() > b"hunter2".len(), "ciphertext lacks AEAD overhead");
    assert!(
        instance::smtp_password_is_set(&app.pool)
            .await
            .expect("password set check")
    );

    // …and `effective` unseals it back to the original.
    let eff = instance::effective(&app.pool, &cfg, &app.secret_key)
        .await
        .expect("effective");
    match eff.notifications {
        NotificationsConfig::Smtp(s) => {
            assert_eq!(s.host, "smtp.example.com");
            assert_eq!(s.password, "hunter2");
            assert_eq!(s.port, 587);
            assert_eq!(s.from_email, "noreply@example.com");
        }
        other => panic!("expected SMTP config, got {other:?}"),
    }
}

#[tokio::test]
async fn blank_smtp_password_keeps_existing_secret() {
    let app = TestApp::new().await;
    let cfg = env_config("EnvName", "disabled");

    // First save sets the password.
    instance::save_notifications(
        &app.pool,
        &app.secret_key,
        "smtp",
        Some(smtp_input("smtp.one", Some("secret1"))),
    )
    .await
    .expect("first save");

    // Second save changes the host but leaves the password blank → the
    // previously-sealed secret must be retained (write-only field in the UI).
    instance::save_notifications(
        &app.pool,
        &app.secret_key,
        "smtp",
        Some(smtp_input("smtp.two", None)),
    )
    .await
    .expect("second save");

    let eff = instance::effective(&app.pool, &cfg, &app.secret_key)
        .await
        .expect("effective");
    match eff.notifications {
        NotificationsConfig::Smtp(s) => {
            assert_eq!(s.host, "smtp.two", "host should update");
            assert_eq!(s.password, "secret1", "blank save kept the old secret");
        }
        other => panic!("expected SMTP config, got {other:?}"),
    }
}

// ── Web routes (CP2): page gate, identity save, notifications + test-send ──

const OWNER_EMAIL: &str = "owner@test.local";
const OWNER_PW: &str = "ownerpw123";

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

/// Web-login via the `/login` form; returns (session cookie pair, session id).
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

/// POST a urlencoded form with `HX-Request` set (mirrors the htmx-driven
/// browser flow, including the reauth chain). `cookie_header` is the full
/// Cookie value (session, optionally plus a `hearth_sudo` grant).
async fn post_form_hx(app: &TestApp, path: &str, cookie_header: &str, body: String) -> Response {
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri(path)
        .header(header::COOKIE, cookie_header)
        .header("HX-Request", "true")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(axum::body::Body::from(body))
        .unwrap();
    tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap()
}

fn hx_redirect(resp: &Response) -> String {
    resp.headers()
        .get("hx-redirect")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string()
}

fn hx_trigger_toast(resp: &Response) -> Option<serde_json::Value> {
    let raw = resp.headers().get("hx-trigger")?.to_str().ok()?;
    let parsed: serde_json::Value = serde_json::from_str(raw).ok()?;
    parsed.get("hearth-toast").cloned()
}

#[tokio::test]
async fn settings_page_is_owner_only_and_hidden_from_others() {
    let app = TestApp::new().await;
    app.seed_user("admin@test.local", "Adm", "pw", InstanceRole::Admin)
        .await;
    let (cookie, sid) = web_login_session(&app, "admin@test.local", "pw").await;

    // GET /settings → 403 for a non-Owner.
    let (status, _) = get_with_cookie(&app, "/settings", &cookie).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // …and the sidebar shows no Settings entry on other pages.
    let (_, me_html) = get_with_cookie(&app, "/me", &cookie).await;
    assert!(
        !me_html.contains("href=\"/settings\""),
        "admin should not see a Settings nav entry"
    );

    // A non-Owner POST is rejected too (CSRF valid, role gate fails).
    let csrf = app.csrf_for(sid);
    let resp = post_form_hx(
        &app,
        "/settings/identity",
        &cookie,
        format!("csrf_token={csrf}&instance_name=Nope"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn owner_sees_settings_nav_and_page() {
    let app = TestApp::new().await;
    app.seed_user(OWNER_EMAIL, "Ownie", OWNER_PW, InstanceRole::Owner)
        .await;
    let (cookie, _) = web_login_session(&app, OWNER_EMAIL, OWNER_PW).await;

    let (_, me_html) = get_with_cookie(&app, "/me", &cookie).await;
    assert!(
        me_html.contains("href=\"/settings\""),
        "owner should see a Settings nav entry"
    );

    let (status, html) = get_with_cookie(&app, "/settings", &cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("Display name"));
    assert!(html.contains("Delivery mode"));
}

#[tokio::test]
async fn identity_save_updates_name_live() {
    let app = TestApp::new().await;
    app.seed_user(OWNER_EMAIL, "Ownie", OWNER_PW, InstanceRole::Owner)
        .await;
    let (cookie, sid) = web_login_session(&app, OWNER_EMAIL, OWNER_PW).await;
    let csrf = app.csrf_for(sid);

    let resp = post_form_hx(
        &app,
        "/settings/identity",
        &cookie,
        format!("csrf_token={csrf}&instance_name={}", urlencoding("Hearthside HQ")),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(hx_redirect(&resp), "/settings");

    // The name field reflects the new value…
    let (_, settings_html) = get_with_cookie(&app, "/settings", &cookie).await;
    assert!(settings_html.contains("value=\"Hearthside HQ\""));
    // …and the live sidebar brand (a different page) shows it without restart.
    let (_, me_html) = get_with_cookie(&app, "/me", &cookie).await;
    assert!(me_html.contains("Hearthside HQ"));
}

#[tokio::test]
async fn notifications_save_is_reauth_gated() {
    let app = TestApp::new().await;
    app.seed_user(OWNER_EMAIL, "Ownie", OWNER_PW, InstanceRole::Owner)
        .await;
    let (cookie, sid) = web_login_session(&app, OWNER_EMAIL, OWNER_PW).await;
    let csrf = app.csrf_for(sid);

    // No `hearth_sudo` grant attached → require_sudo rejects with 403.
    let resp = post_form_hx(
        &app,
        "/settings/notifications",
        &cookie,
        format!("csrf_token={csrf}&mode=log"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn notifications_save_with_sudo_persists_smtp() {
    let app = TestApp::new().await;
    app.seed_user(OWNER_EMAIL, "Ownie", OWNER_PW, InstanceRole::Owner)
        .await;
    let (cookie, sid) = web_login_session(&app, OWNER_EMAIL, OWNER_PW).await;
    let csrf = app.csrf_for(sid);
    let sudo = app.sudo_cookie(&cookie, &csrf, OWNER_PW).await;
    assert!(!sudo.is_empty(), "expected a sudo grant");
    let cookie_header = format!("{cookie}; {sudo}");

    let body = format!(
        "csrf_token={csrf}&mode=smtp&smtp_host=mail.example.com&smtp_port=587\
         &smtp_tls=starttls&smtp_username={}&smtp_password=hunter2&smtp_from_email={}",
        urlencoding("mailer@example.com"),
        urlencoding("noreply@example.com"),
    );
    let resp = post_form_hx(&app, "/settings/notifications", &cookie_header, body).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(hx_redirect(&resp), "/settings");

    // The password is stored sealed, and the page reflects SMTP mode + host.
    assert!(
        instance::smtp_password_is_set(&app.pool).await.unwrap(),
        "password should be stored"
    );
    let (_, html) = get_with_cookie(&app, "/settings", &cookie).await;
    assert!(html.contains("value=\"mail.example.com\""));
}

#[tokio::test]
async fn notifications_save_rejects_incomplete_smtp() {
    let app = TestApp::new().await;
    app.seed_user(OWNER_EMAIL, "Ownie", OWNER_PW, InstanceRole::Owner)
        .await;
    let (cookie, sid) = web_login_session(&app, OWNER_EMAIL, OWNER_PW).await;
    let csrf = app.csrf_for(sid);
    let sudo = app.sudo_cookie(&cookie, &csrf, OWNER_PW).await;
    let cookie_header = format!("{cookie}; {sudo}");

    // mode=smtp but no host/username/from → validation error toast, nothing saved.
    let resp = post_form_hx(
        &app,
        "/settings/notifications",
        &cookie_header,
        format!("csrf_token={csrf}&mode=smtp&smtp_host=&smtp_port=587&smtp_tls=starttls&smtp_username=&smtp_from_email="),
    )
    .await;
    let toast = hx_trigger_toast(&resp).expect("error toast");
    assert_eq!(toast["kind"], "error");
    assert!(
        !instance::smtp_password_is_set(&app.pool).await.unwrap(),
        "nothing should have been saved"
    );
}

#[tokio::test]
async fn test_email_in_log_mode_succeeds() {
    let app = TestApp::new().await;
    app.seed_user(OWNER_EMAIL, "Ownie", OWNER_PW, InstanceRole::Owner)
        .await;
    let (cookie, sid) = web_login_session(&app, OWNER_EMAIL, OWNER_PW).await;
    let csrf = app.csrf_for(sid);

    // The harness seeds a Log notifier, so a test-send "succeeds" with no
    // real SMTP server. No reauth required for the test-send.
    let resp = post_form_hx(
        &app,
        "/settings/notifications/test",
        &cookie,
        format!("csrf_token={csrf}"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let toast = hx_trigger_toast(&resp).expect("toast");
    assert_eq!(toast["kind"], "success");
}

#[tokio::test]
async fn shutdown_modal_is_owner_only() {
    let app = TestApp::new().await;
    app.seed_user("admin@test.local", "Adm", "pw", InstanceRole::Admin)
        .await;
    let (cookie_admin, _) = web_login_session(&app, "admin@test.local", "pw").await;
    let (status, _) = get_with_cookie(&app, "/modals/settings/shutdown", &cookie_admin).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    app.seed_user(OWNER_EMAIL, "Ownie", OWNER_PW, InstanceRole::Owner)
        .await;
    let (cookie, _) = web_login_session(&app, OWNER_EMAIL, OWNER_PW).await;
    let (status, html) = get_with_cookie(&app, "/modals/settings/shutdown", &cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("Close this server"));
}

#[tokio::test]
async fn force_close_requires_critical_reauth() {
    let app = TestApp::new().await;
    app.seed_user(OWNER_EMAIL, "Ownie", OWNER_PW, InstanceRole::Owner)
        .await;
    let (cookie, sid) = web_login_session(&app, OWNER_EMAIL, OWNER_PW).await;
    let csrf = app.csrf_for(sid);

    // A plain session (even an ordinary sudo grant) doesn't satisfy the
    // critical gate → rejected, and the instance stays open.
    let resp = post_form_hx(
        &app,
        "/settings/shutdown",
        &cookie,
        format!("csrf_token={csrf}"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert!(!instance::load_closed(&app.pool).await.unwrap());
}

#[tokio::test]
async fn owner_force_close_scorches_and_closes() {
    let app = TestApp::new().await;
    app.seed_user(OWNER_EMAIL, "Ownie", OWNER_PW, InstanceRole::Owner)
        .await;
    let (cookie, sid) = web_login_session(&app, OWNER_EMAIL, OWNER_PW).await;
    let csrf = app.csrf_for(sid);
    let critical = app.sudo_critical_cookie(&cookie, &csrf, OWNER_PW).await;
    assert!(!critical.is_empty(), "expected a critical grant");
    let cookie_header = format!("{cookie}; {critical}");

    let resp = post_form_hx(
        &app,
        "/settings/shutdown",
        &cookie_header,
        format!("csrf_token={csrf}"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(hx_redirect(&resp), "/");

    // The instance is closed and every data table was scorched.
    assert!(instance::load_closed(&app.pool).await.unwrap());
    let users: i64 = sqlx::query_scalar("SELECT count(*) FROM identity.users")
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(users, 0, "users table should be scorched");
}
