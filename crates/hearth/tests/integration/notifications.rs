use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use identity::InstanceRole;
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use super::common::TestApp;

const OWNER_PW: &str = "ownerpw";

async fn app_with_owner_token() -> (TestApp, Uuid, String) {
    let app = TestApp::new().await;
    let owner = app
        .seed_user("owner@test.local", "Owner", OWNER_PW, InstanceRole::Owner)
        .await;
    let token = app.login(&owner.email, OWNER_PW).await;
    (app, owner.id.0, token)
}

#[derive(Deserialize, Debug)]
#[allow(dead_code)]
struct NotificationView {
    id: Uuid,
    kind: String,
    recipient_email: String,
    subject: String,
    state: String,
    attempts: i32,
    last_error: Option<String>,
    next_attempt_at: DateTime<Utc>,
    created_at: DateTime<Utc>,
    sent_at: Option<DateTime<Utc>>,
    payload: serde_json::Value,
}

#[derive(Deserialize)]
struct CreateInviteResp {
    invitation_id: Uuid,
    #[allow(dead_code)]
    token: String,
}

#[tokio::test]
async fn creating_an_invitation_enqueues_a_notification() {
    let (app, _, owner_tok) = app_with_owner_token().await;

    let inv: CreateInviteResp = app
        .post(
            "/admin/invites",
            Some(&owner_tok),
            Some(json!({ "email": "alice@test.local" })),
        )
        .await
        .json();

    let rows: Vec<NotificationView> = app
        .get("/admin/notifications", Some(&owner_tok))
        .await
        .json();
    assert_eq!(rows.len(), 1, "exactly one outbox row should exist");
    let row = &rows[0];
    assert_eq!(row.kind, "invitation");
    assert_eq!(row.recipient_email, "alice@test.local");
    assert_eq!(row.state, "pending");
    assert_eq!(row.attempts, 0);
    assert!(row.sent_at.is_none());
    assert_eq!(
        row.payload["invitation_id"].as_str(),
        Some(inv.invitation_id.to_string().as_str())
    );
}

#[tokio::test]
async fn worker_marks_pending_rows_as_sent_in_log_mode() {
    let (app, _, owner_tok) = app_with_owner_token().await;

    app.post(
        "/admin/invites",
        Some(&owner_tok),
        Some(json!({ "email": "b@test.local" })),
    )
    .await
    .assert_status(StatusCode::CREATED);

    let processed = app.run_notifications_once().await;
    assert_eq!(processed, 1);

    let rows: Vec<NotificationView> = app
        .get("/admin/notifications", Some(&owner_tok))
        .await
        .json();
    assert_eq!(rows[0].state, "sent");
    assert!(rows[0].sent_at.is_some());
}

#[tokio::test]
async fn transient_failure_schedules_retry_with_backoff() {
    let (app, _, owner_tok) = app_with_owner_token().await;
    app.set_notifier(notifications::NotifierImpl::AlwaysFail(
        "synthetic transient error".to_string(),
    ));

    app.post(
        "/admin/invites",
        Some(&owner_tok),
        Some(json!({ "email": "c@test.local" })),
    )
    .await
    .assert_status(StatusCode::CREATED);

    let processed = app.run_notifications_once().await;
    assert_eq!(processed, 1);

    let (state, attempts, last_error, next_at): (String, i32, Option<String>, DateTime<Utc>) =
        sqlx::query_as(
            "SELECT state::text, attempts, last_error, next_attempt_at
             FROM notifications.outbox ORDER BY created_at DESC LIMIT 1",
        )
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(state, "pending");
    assert_eq!(attempts, 1);
    assert_eq!(last_error.as_deref(), Some("synthetic transient error"));
    assert!(next_at > Utc::now());

    let processed_again = app.run_notifications_once().await;
    assert_eq!(processed_again, 0);
}

#[tokio::test]
async fn exhausted_retries_mark_row_dead() {
    let (app, _, owner_tok) = app_with_owner_token().await;
    app.set_notifier(notifications::NotifierImpl::AlwaysFail("perma".to_string()));

    app.post(
        "/admin/invites",
        Some(&owner_tok),
        Some(json!({ "email": "d@test.local" })),
    )
    .await
    .assert_status(StatusCode::CREATED);

    // Drive the worker enough times to burn through MAX_ATTEMPTS. Between
    // cycles we manually reset `next_attempt_at` to "now" so we don't have
    // to wait for the real backoff schedule.
    for _ in 0..notifications::MAX_ATTEMPTS {
        sqlx::query("UPDATE notifications.outbox SET next_attempt_at = now()")
            .execute(&app.pool)
            .await
            .unwrap();
        app.run_notifications_once().await;
    }

    let (state, attempts): (String, i32) = sqlx::query_as(
        "SELECT state::text, attempts FROM notifications.outbox ORDER BY created_at DESC LIMIT 1",
    )
    .fetch_one(&app.pool)
    .await
    .unwrap();
    assert_eq!(state, "dead");
    assert_eq!(attempts, notifications::MAX_ATTEMPTS);
}

#[tokio::test]
async fn disabled_notifier_marks_rows_as_skipped() {
    let (app, _, owner_tok) = app_with_owner_token().await;
    app.set_notifier(notifications::NotifierImpl::Disabled);

    app.post(
        "/admin/invites",
        Some(&owner_tok),
        Some(json!({ "email": "e@test.local" })),
    )
    .await
    .assert_status(StatusCode::CREATED);

    app.run_notifications_once().await;
    let (state,): (String,) = sqlx::query_as(
        "SELECT state::text FROM notifications.outbox ORDER BY created_at DESC LIMIT 1",
    )
    .fetch_one(&app.pool)
    .await
    .unwrap();
    assert_eq!(state, "skipped");
}

#[tokio::test]
async fn admin_notifications_supports_state_filter() {
    let (app, _, owner_tok) = app_with_owner_token().await;
    // First invite — let it succeed via log notifier.
    app.post(
        "/admin/invites",
        Some(&owner_tok),
        Some(json!({ "email": "first@test.local" })),
    )
    .await;
    app.run_notifications_once().await;
    // Second invite — leave it pending (don't run the worker for it).
    app.post(
        "/admin/invites",
        Some(&owner_tok),
        Some(json!({ "email": "second@test.local" })),
    )
    .await;

    let sent: Vec<NotificationView> = app
        .get("/admin/notifications?state=sent", Some(&owner_tok))
        .await
        .json();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].recipient_email, "first@test.local");

    let pending: Vec<NotificationView> = app
        .get("/admin/notifications?state=pending", Some(&owner_tok))
        .await
        .json();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].recipient_email, "second@test.local");
}

#[tokio::test]
async fn non_admin_cannot_list_notifications() {
    let app = TestApp::new().await;
    let user = app
        .seed_user("u@test.local", "U", "pw", InstanceRole::User)
        .await;
    let tok = app.login(&user.email, "pw").await;

    let resp = app.get("/admin/notifications", Some(&tok)).await;
    resp.assert_status(StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn outbox_subject_contains_inviter_name_and_role() {
    let app = TestApp::new().await;
    let owner = app
        .seed_user("o@test.local", "Big Boss", OWNER_PW, InstanceRole::Owner)
        .await;
    let owner_tok = app.login(&owner.email, OWNER_PW).await;

    app.post(
        "/admin/invites",
        Some(&owner_tok),
        Some(json!({ "email": "newcomer@test.local", "instance_role": "admin" })),
    )
    .await
    .assert_status(StatusCode::CREATED);

    let (subject, body_text): (String, String) = sqlx::query_as(
        "SELECT subject, body_text FROM notifications.outbox ORDER BY created_at DESC LIMIT 1",
    )
    .fetch_one(&app.pool)
    .await
    .unwrap();
    assert!(subject.contains("Big Boss"), "subject was: {subject}");
    assert!(body_text.contains("Admin"), "body was: {body_text}");
    // Accept URL embeds the base_url + token.
    assert!(
        body_text.contains("http://127.0.0.1:8443/invite/"),
        "body should contain accept URL: {body_text}"
    );
}

#[tokio::test]
async fn no_pending_rows_means_worker_does_nothing() {
    let app = TestApp::new().await;
    let processed = app.run_notifications_once().await;
    assert_eq!(processed, 0);
}
