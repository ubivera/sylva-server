//! Server recovery code: rotation from Settings + force-applying a pending
//! transition (break-glass bypass of the veto window).

use axum::http::{Method, StatusCode, header};
use axum::response::Response;
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

/// POST a urlencoded form (HX-Request set) and return status + the HX-Redirect
/// header (if any) + the body.
async fn post_form(
    app: &TestApp,
    path: &str,
    cookie: &str,
    body: String,
) -> (StatusCode, Option<String>, String) {
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri(path)
        .header(header::COOKIE, cookie)
        .header("HX-Request", "true")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(axum::body::Body::from(body))
        .unwrap();
    let resp: Response = tower::ServiceExt::oneshot(app.router.clone(), req).await.unwrap();
    let status = resp.status();
    let hx_redirect = resp
        .headers()
        .get("hx-redirect")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, hx_redirect, String::from_utf8_lossy(&bytes).to_string())
}

// ── Rotation (Settings) ───────────────────────────────────────────────────

#[tokio::test]
async fn recovery_rotate_with_correct_code_invalidates_old() {
    let app = TestApp::new().await;
    let code = app.seed_recovery_code().await;
    app.seed_user("o@test.local", "Ownie", "pw", InstanceRole::Owner)
        .await;
    let (cookie, sid) = web_login_session(&app, "o@test.local", "pw").await;
    let csrf = app.csrf_for(sid);

    let (status, _hx, body) = post_form(
        &app,
        "/settings/recovery-code/rotate",
        &cookie,
        format!("csrf_token={csrf}&current_code={}", urlencoding(&code)),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Your new recovery code"), "shows the new code once");

    // Old code no longer verifies; a fresh active code now exists.
    assert!(
        auth::recovery_code::verify(&app.pool, &code).await.unwrap().is_none(),
        "old code invalidated"
    );
    assert!(
        auth::recovery_code::active_metadata(&app.pool).await.unwrap().is_some(),
        "a new active code exists"
    );
}

#[tokio::test]
async fn recovery_rotate_with_wrong_code_does_nothing() {
    let app = TestApp::new().await;
    let code = app.seed_recovery_code().await;
    app.seed_user("o@test.local", "Ownie", "pw", InstanceRole::Owner)
        .await;
    let (cookie, sid) = web_login_session(&app, "o@test.local", "pw").await;
    let csrf = app.csrf_for(sid);

    let (status, hx, body) = post_form(
        &app,
        "/settings/recovery-code/rotate",
        &cookie,
        format!("csrf_token={csrf}&current_code=WRONG-CODE-0000"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(hx.is_none(), "stays in the modal (no redirect)");
    assert!(body.contains("not valid"), "inline error");
    // The original code still works — nothing rotated.
    assert!(
        auth::recovery_code::verify(&app.pool, &code).await.unwrap().is_some(),
        "original code untouched"
    );
}

#[tokio::test]
async fn recovery_rotate_requires_owner() {
    let app = TestApp::new().await;
    let code = app.seed_recovery_code().await;
    app.seed_user("adm@test.local", "Adm", "pw", InstanceRole::Admin)
        .await;
    let (cookie, sid) = web_login_session(&app, "adm@test.local", "pw").await;
    let csrf = app.csrf_for(sid);

    let (status, _hx, _body) = post_form(
        &app,
        "/settings/recovery-code/rotate",
        &cookie,
        format!("csrf_token={csrf}&current_code={}", urlencoding(&code)),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

// ── Force-apply (bypass veto) ─────────────────────────────────────────────

/// Enqueue a pending demotion of `target` to Member, initiated by `initiator`.
async fn enqueue_demotion(app: &TestApp, initiator: identity::UserId, target: identity::UserId) -> Uuid {
    let mut tx = app.pool.begin().await.unwrap();
    let (id, _) = pending::enqueue_role_change(&mut tx, initiator, target, InstanceRole::Member)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    id
}

async fn role_of(app: &TestApp, id: identity::UserId) -> InstanceRole {
    sqlx::query_scalar("SELECT instance_role FROM identity.users WHERE id = $1")
        .bind(id.0)
        .fetch_one(&app.pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn force_apply_with_recovery_code_bypasses_veto() {
    let app = TestApp::new().await;
    let code = app.seed_recovery_code().await;
    let owner_a = app.seed_user("a@test.local", "Aowner", "pw", InstanceRole::Owner).await;
    let owner_b = app.seed_user("b@test.local", "Bowner", "pw", InstanceRole::Owner).await;
    let tid = enqueue_demotion(&app, owner_a.id, owner_b.id).await;

    let (cookie, sid) = web_login_session(&app, "a@test.local", "pw").await;
    let csrf = app.csrf_for(sid);

    let (status, hx, _body) = post_form(
        &app,
        &format!("/pending/{tid}/force-apply"),
        &cookie,
        format!("csrf_token={csrf}&recovery_code={}", urlencoding(&code)),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(hx.as_deref(), Some("/pending"));

    // Applied immediately via the recovery bypass — target demoted, the veto
    // window never had to elapse.
    let row = pending::find_by_id(&app.pool, tid).await.unwrap().unwrap();
    assert_eq!(row.state, pending::TransitionState::Applied);
    assert_eq!(row.resolution.as_deref(), Some("recovery_bypass"));
    assert_eq!(row.resolved_by_user_id, Some(owner_a.id.0));
    assert_eq!(role_of(&app, owner_b.id).await, InstanceRole::Member);
}

#[tokio::test]
async fn force_apply_with_wrong_code_leaves_it_pending() {
    let app = TestApp::new().await;
    let _code = app.seed_recovery_code().await;
    let owner_a = app.seed_user("a@test.local", "Aowner", "pw", InstanceRole::Owner).await;
    let owner_b = app.seed_user("b@test.local", "Bowner", "pw", InstanceRole::Owner).await;
    let tid = enqueue_demotion(&app, owner_a.id, owner_b.id).await;

    let (cookie, sid) = web_login_session(&app, "a@test.local", "pw").await;
    let csrf = app.csrf_for(sid);

    let (status, hx, body) = post_form(
        &app,
        &format!("/pending/{tid}/force-apply"),
        &cookie,
        format!("csrf_token={csrf}&recovery_code=WRONG-CODE-0000"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(hx.is_none(), "stays in the dialog");
    assert!(body.contains("not valid"));

    // Still pending; the target keeps Owner.
    let row = pending::find_by_id(&app.pool, tid).await.unwrap().unwrap();
    assert_eq!(row.state, pending::TransitionState::Pending);
    assert_eq!(role_of(&app, owner_b.id).await, InstanceRole::Owner);
}

#[tokio::test]
async fn force_apply_requires_owner() {
    let app = TestApp::new().await;
    let code = app.seed_recovery_code().await;
    let owner_a = app.seed_user("a@test.local", "Aowner", "pw", InstanceRole::Owner).await;
    let owner_b = app.seed_user("b@test.local", "Bowner", "pw", InstanceRole::Owner).await;
    let tid = enqueue_demotion(&app, owner_a.id, owner_b.id).await;

    // An Admin (even with the recovery code) can't reach the force-apply.
    app.seed_user("adm@test.local", "Adm", "pw", InstanceRole::Admin)
        .await;
    let (cookie, sid) = web_login_session(&app, "adm@test.local", "pw").await;
    let csrf = app.csrf_for(sid);

    let (status, _hx, _body) = post_form(
        &app,
        &format!("/pending/{tid}/force-apply"),
        &cookie,
        format!("csrf_token={csrf}&recovery_code={}", urlencoding(&code)),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(role_of(&app, owner_b.id).await, InstanceRole::Owner);
}
