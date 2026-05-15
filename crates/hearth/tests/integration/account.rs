use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use identity::InstanceRole;
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use super::common::{SeededUser, TestApp};

const PW: &str = "secret-pw";

async fn app_with_user() -> (TestApp, SeededUser, String) {
    let app = TestApp::new().await;
    let user = app
        .seed_user("u@test.local", "U Person", PW, InstanceRole::User)
        .await;
    let token = app.login(&user.email, PW).await;
    (app, user, token)
}

#[derive(Deserialize)]
struct SessionView {
    id: Uuid,
    user_id: Uuid,
    is_current: bool,
    revoked_at: Option<DateTime<Utc>>,
}

#[derive(Deserialize)]
struct ChangePasswordBody {
    sessions_revoked: u64,
}

#[derive(Deserialize)]
struct ProfileBody {
    id: Uuid,
    email: String,
    display_name: String,
    locale: Option<String>,
    #[allow(dead_code)]
    instance_role: InstanceRole,
    #[allow(dead_code)]
    updated_at: DateTime<Utc>,
}

// ---- /account/password ----

#[tokio::test]
async fn change_password_wrong_current_returns_401() {
    let (app, _user, token) = app_with_user().await;
    let resp = app
        .post(
            "/account/password",
            Some(&token),
            Some(json!({ "current_password": "wrong", "new_password": "x" })),
        )
        .await;
    resp.assert_status(StatusCode::UNAUTHORIZED)
        .assert_error("current_password_wrong");
}

#[tokio::test]
async fn change_password_empty_new_returns_400() {
    let (app, _user, token) = app_with_user().await;
    let resp = app
        .post(
            "/account/password",
            Some(&token),
            Some(json!({ "current_password": PW, "new_password": "" })),
        )
        .await;
    resp.assert_status(StatusCode::BAD_REQUEST)
        .assert_error("new_password_required");
}

#[tokio::test]
async fn change_password_revokes_other_sessions_but_keeps_caller() {
    let (app, user, token1) = app_with_user().await;
    let token2 = app.login(&user.email, PW).await; // second session

    let resp = app
        .post(
            "/account/password",
            Some(&token1),
            Some(json!({ "current_password": PW, "new_password": "new-pw" })),
        )
        .await;
    resp.assert_status(StatusCode::OK);
    let body: ChangePasswordBody = resp.json();
    assert_eq!(body.sessions_revoked, 1);

    // token2 is now dead.
    app.get("/me", Some(&token2))
        .await
        .assert_status(StatusCode::UNAUTHORIZED)
        .assert_error("invalid_session");

    // token1 (caller) still works.
    app.get("/me", Some(&token1))
        .await
        .assert_status(StatusCode::OK);

    // New password lets login through; old does not.
    app.post(
        "/auth/login",
        None,
        Some(json!({ "email": user.email, "password": "new-pw" })),
    )
    .await
    .assert_status(StatusCode::OK);
    app.post(
        "/auth/login",
        None,
        Some(json!({ "email": user.email, "password": PW })),
    )
    .await
    .assert_status(StatusCode::UNAUTHORIZED)
    .assert_error("invalid_credentials");
}

#[tokio::test]
async fn change_password_emits_audit_event() {
    let (app, user, token) = app_with_user().await;
    app.login(&user.email, PW).await; // 2nd session so revoked count > 0

    app.post(
        "/account/password",
        Some(&token),
        Some(json!({ "current_password": PW, "new_password": "new" })),
    )
    .await
    .assert_status(StatusCode::OK);

    let (event_data,): (serde_json::Value,) = sqlx::query_as(
        "SELECT event_data FROM audit.events
         WHERE actor_user_id = $1 AND event_type = 'password_changed'
         ORDER BY seqno DESC LIMIT 1",
    )
    .bind(user.id)
    .fetch_one(&app.pool)
    .await
    .unwrap();
    assert_eq!(event_data["other_sessions_revoked"].as_u64(), Some(1));
}

// ---- /account/profile ----

#[tokio::test]
async fn profile_no_changes_returns_400() {
    let (app, _user, token) = app_with_user().await;
    let resp = app.patch("/account/profile", Some(&token), Some(json!({}))).await;
    resp.assert_status(StatusCode::BAD_REQUEST)
        .assert_error("no_changes_specified");
}

#[tokio::test]
async fn profile_whitespace_display_name_returns_400() {
    let (app, _user, token) = app_with_user().await;
    let resp = app
        .patch(
            "/account/profile",
            Some(&token),
            Some(json!({ "display_name": "   " })),
        )
        .await;
    resp.assert_status(StatusCode::BAD_REQUEST)
        .assert_error("display_name_empty");
}

#[tokio::test]
async fn profile_update_display_name() {
    let (app, user, token) = app_with_user().await;
    let resp = app
        .patch(
            "/account/profile",
            Some(&token),
            Some(json!({ "display_name": "U Updated" })),
        )
        .await;
    resp.assert_status(StatusCode::OK);
    let body: ProfileBody = resp.json();
    assert_eq!(body.id, user.id.0);
    assert_eq!(body.email, user.email);
    assert_eq!(body.display_name, "U Updated");
    assert!(body.locale.is_none(), "locale untouched");
}

#[tokio::test]
async fn profile_update_locale_only() {
    let (app, _user, token) = app_with_user().await;
    let resp = app
        .patch(
            "/account/profile",
            Some(&token),
            Some(json!({ "locale": "fr-FR" })),
        )
        .await;
    resp.assert_status(StatusCode::OK);
    let body: ProfileBody = resp.json();
    assert_eq!(body.locale.as_deref(), Some("fr-FR"));
    assert_eq!(body.display_name, "U Person", "display_name untouched");
}

#[tokio::test]
async fn profile_update_both_fields_records_only_changed_in_audit() {
    let (app, user, token) = app_with_user().await;
    app.patch(
        "/account/profile",
        Some(&token),
        Some(json!({ "display_name": "U Person", "locale": "en-US" })),
    )
    .await
    .assert_status(StatusCode::OK);

    // display_name didn't actually change (same as seed), so only `locale`
    // should appear in event_data.
    let (event_data,): (serde_json::Value,) = sqlx::query_as(
        "SELECT event_data FROM audit.events
         WHERE actor_user_id = $1 AND event_type = 'profile_updated'
         ORDER BY seqno DESC LIMIT 1",
    )
    .bind(user.id)
    .fetch_one(&app.pool)
    .await
    .unwrap();
    assert!(
        event_data.get("display_name").is_none(),
        "unchanged display_name should not appear in event_data: {event_data}"
    );
    assert_eq!(
        event_data["locale"]["from"],
        serde_json::Value::Null,
        "locale 'from' should be null (was unset)"
    );
    assert_eq!(event_data["locale"]["to"].as_str(), Some("en-US"));
}

// ---- /account/sessions ----

#[tokio::test]
async fn sessions_list_flags_current_session() {
    let (app, user, token1) = app_with_user().await;
    let _token2 = app.login(&user.email, PW).await;

    let resp = app.get("/account/sessions", Some(&token1)).await;
    resp.assert_status(StatusCode::OK);
    let sessions: Vec<SessionView> = resp.json();
    assert_eq!(sessions.len(), 2);
    let current = sessions.iter().filter(|s| s.is_current).count();
    assert_eq!(current, 1, "exactly one session must be flagged current");
    for s in &sessions {
        assert_eq!(s.user_id, user.id.0);
    }
}

#[tokio::test]
async fn revoke_own_session_succeeds_and_kills_token() {
    let (app, user, token1) = app_with_user().await;
    let token2 = app.login(&user.email, PW).await;

    // From token2's perspective, the OTHER (non-current) session is token1.
    let sessions: Vec<SessionView> = app
        .get("/account/sessions", Some(&token2))
        .await
        .json();
    let other_id = sessions
        .iter()
        .find(|s| !s.is_current && s.revoked_at.is_none())
        .map(|s| s.id)
        .expect("non-current session present");

    let revoke = app
        .post(
            &format!("/account/sessions/{other_id}/revoke"),
            Some(&token2),
            None,
        )
        .await;
    revoke.assert_status(StatusCode::NO_CONTENT);

    // token1 (the revoked one) is dead.
    app.get("/me", Some(&token1))
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
    // token2 (the revoker) still works.
    app.get("/me", Some(&token2))
        .await
        .assert_status(StatusCode::OK);
}

#[tokio::test]
async fn revoke_another_users_session_returns_404() {
    let app = TestApp::new().await;
    let alice = app
        .seed_user("alice@test.local", "Alice", "alpw", InstanceRole::User)
        .await;
    let bob = app
        .seed_user("bob@test.local", "Bob", "bopw", InstanceRole::User)
        .await;
    let alice_token = app.login(&alice.email, "alpw").await;
    let bob_token = app.login(&bob.email, "bopw").await;

    // Get bob's session id.
    let bob_sessions: Vec<SessionView> = app
        .get("/account/sessions", Some(&bob_token))
        .await
        .json();
    let bob_session_id = bob_sessions[0].id;

    // Alice tries to revoke it.
    let resp = app
        .post(
            &format!("/account/sessions/{bob_session_id}/revoke"),
            Some(&alice_token),
            None,
        )
        .await;
    resp.assert_status(StatusCode::NOT_FOUND)
        .assert_error("session_not_found");

    // Bob's session is still alive.
    app.get("/me", Some(&bob_token))
        .await
        .assert_status(StatusCode::OK);
}

#[tokio::test]
async fn revoke_nonexistent_session_returns_404() {
    let (app, _user, token) = app_with_user().await;
    let fake = Uuid::new_v4();
    let resp = app
        .post(&format!("/account/sessions/{fake}/revoke"), Some(&token), None)
        .await;
    resp.assert_status(StatusCode::NOT_FOUND)
        .assert_error("session_not_found");
}

// ---- /account/activity ----

#[derive(Deserialize)]
struct PaginatedActivity {
    items: Vec<ActivityEvent>,
    next_cursor: Option<i64>,
}

#[derive(Deserialize)]
struct ActivityEvent {
    seqno: i64,
    event_type: String,
    actor_user_id: Option<Uuid>,
}

#[tokio::test]
async fn activity_scopes_to_caller() {
    let app = TestApp::new().await;
    let alice = app
        .seed_user("a@test.local", "A", "ap", InstanceRole::User)
        .await;
    let _bob = app
        .seed_user("b@test.local", "B", "bp", InstanceRole::User)
        .await;
    let a_token = app.login(&alice.email, "ap").await;

    // Bob does things too — those must NOT appear in Alice's feed.
    let _ = app.login("b@test.local", "bp").await;

    let resp = app.get("/account/activity", Some(&a_token)).await;
    resp.assert_status(StatusCode::OK);
    let body: PaginatedActivity = resp.json();
    assert!(!body.items.is_empty());
    for item in &body.items {
        assert_eq!(item.actor_user_id, Some(alice.id.0), "leaked event: {:?}", item.event_type);
    }
    // Single page should fit; cursor should be None.
    assert!(body.next_cursor.is_none());
    // seqno must be strictly decreasing (newest first).
    let seqnos: Vec<i64> = body.items.iter().map(|i| i.seqno).collect();
    for w in seqnos.windows(2) {
        assert!(w[0] > w[1], "seqno not strictly decreasing: {seqnos:?}");
    }
}
