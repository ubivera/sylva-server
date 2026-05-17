use axum::http::StatusCode;
use chrono::{DateTime, Duration, Utc};
use identity::InstanceRole;
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use super::common::TestApp;

const OWNER_PW: &str = "ownerpw";
const PEER_PW: &str = "peerpw";

#[derive(Deserialize, Debug)]
#[allow(dead_code)]
struct PendingTransitionView {
    id: Uuid,
    kind: String,
    initiator_user_id: Option<Uuid>,
    target_user_id: Option<Uuid>,
    payload: serde_json::Value,
    state: String,
    effective_at: DateTime<Utc>,
    resolved_at: Option<DateTime<Utc>>,
    resolved_by_user_id: Option<Uuid>,
    resolution: Option<String>,
    created_at: DateTime<Utc>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct LifecycleBody {
    id: Uuid,
    email: String,
    display_name: String,
    instance_role: InstanceRole,
}

/// Stand up an instance with two Owners (A and B) and return their tokens.
async fn app_with_two_owners() -> (TestApp, Uuid, String, Uuid, String) {
    let app = TestApp::new().await;
    let a = app
        .seed_user("a@test.local", "Owner A", OWNER_PW, InstanceRole::Owner)
        .await;
    let b = app
        .seed_user("b@test.local", "Owner B", PEER_PW, InstanceRole::Owner)
        .await;
    let a_tok = app.login(&a.email, OWNER_PW).await;
    let b_tok = app.login(&b.email, PEER_PW).await;
    (app, a.id.0, a_tok, b.id.0, b_tok)
}

#[tokio::test]
async fn owner_demoting_peer_owner_creates_pending_row() {
    let (app, _a_id, a_tok, b_id, _b_tok) = app_with_two_owners().await;

    let resp = app
        .post(
            &format!("/admin/users/{b_id}/role"),
            Some(&a_tok),
            Some(json!({ "role": "admin" })),
        )
        .await;
    resp.assert_status(StatusCode::ACCEPTED);
    let body: PendingTransitionView = resp.json();
    assert_eq!(body.kind, "role_change");
    assert_eq!(body.state, "pending");
    assert_eq!(body.target_user_id, Some(b_id));
    assert_eq!(body.payload["to_role"].as_str(), Some("admin"));

    // effective_at is roughly 72h out (allow some leeway).
    let now = Utc::now();
    assert!(body.effective_at > now + Duration::hours(71));
    assert!(body.effective_at < now + Duration::hours(73));

    // B's role hasn't changed yet.
    let (role,): (InstanceRole,) =
        sqlx::query_as("SELECT instance_role FROM identity.users WHERE id = $1")
            .bind(b_id)
            .fetch_one(&app.pool)
            .await
            .unwrap();
    assert_eq!(role, InstanceRole::Owner);
}

#[tokio::test]
async fn pending_transition_appears_in_list() {
    let (app, _a_id, a_tok, b_id, b_tok) = app_with_two_owners().await;
    app.post(
        &format!("/admin/users/{b_id}/role"),
        Some(&a_tok),
        Some(json!({ "role": "admin" })),
    )
    .await
    .assert_status(StatusCode::ACCEPTED);

    let rows: Vec<PendingTransitionView> = app
        .get("/admin/pending-transitions", Some(&b_tok))
        .await
        .json();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].state, "pending");
}

#[tokio::test]
async fn target_owner_can_veto_their_own_pending_demotion() {
    let (app, _a_id, a_tok, b_id, b_tok) = app_with_two_owners().await;
    let pending: PendingTransitionView = app
        .post(
            &format!("/admin/users/{b_id}/role"),
            Some(&a_tok),
            Some(json!({ "role": "admin" })),
        )
        .await
        .json();

    let resp = app
        .post(
            &format!("/admin/pending-transitions/{}/veto", pending.id),
            Some(&b_tok),
            None,
        )
        .await;
    resp.assert_status(StatusCode::OK);
    let body: PendingTransitionView = resp.json();
    assert_eq!(body.state, "vetoed");
    assert_eq!(body.resolution.as_deref(), Some("vetoed"));

    // Running the worker afterward does nothing — row is no longer pending.
    sqlx::query("UPDATE pending.transitions SET effective_at = now() - interval '1 hour'")
        .execute(&app.pool)
        .await
        .unwrap();
    let applied = app.run_pending_transitions_once().await;
    assert_eq!(applied, 0);

    let (role,): (InstanceRole,) =
        sqlx::query_as("SELECT instance_role FROM identity.users WHERE id = $1")
            .bind(b_id)
            .fetch_one(&app.pool)
            .await
            .unwrap();
    assert_eq!(role, InstanceRole::Owner, "B should still be Owner");
}

#[tokio::test]
async fn third_party_owner_can_veto_on_behalf_of_target() {
    let app = TestApp::new().await;
    let a = app
        .seed_user("a@test.local", "A", "apw", InstanceRole::Owner)
        .await;
    let b = app
        .seed_user("b@test.local", "B", "bpw", InstanceRole::Owner)
        .await;
    let c = app
        .seed_user("c@test.local", "C", "cpw", InstanceRole::Owner)
        .await;
    let a_tok = app.login(&a.email, "apw").await;
    let c_tok = app.login(&c.email, "cpw").await;

    let pending: PendingTransitionView = app
        .post(
            &format!("/admin/users/{}/role", b.id.0),
            Some(&a_tok),
            Some(json!({ "role": "admin" })),
        )
        .await
        .json();

    // C (third party Owner) vetoes B's demotion.
    let resp = app
        .post(
            &format!("/admin/pending-transitions/{}/veto", pending.id),
            Some(&c_tok),
            None,
        )
        .await;
    resp.assert_status(StatusCode::OK);
    let body: PendingTransitionView = resp.json();
    assert_eq!(body.state, "vetoed");
    assert_eq!(body.resolved_by_user_id, Some(c.id.0));
}

#[tokio::test]
async fn initiator_can_cancel_their_own_pending() {
    let (app, a_id, a_tok, b_id, _b_tok) = app_with_two_owners().await;
    let pending: PendingTransitionView = app
        .post(
            &format!("/admin/users/{b_id}/role"),
            Some(&a_tok),
            Some(json!({ "role": "admin" })),
        )
        .await
        .json();

    let resp = app
        .post(
            &format!("/admin/pending-transitions/{}/cancel", pending.id),
            Some(&a_tok),
            None,
        )
        .await;
    resp.assert_status(StatusCode::OK);
    let body: PendingTransitionView = resp.json();
    assert_eq!(body.state, "cancelled");
    assert_eq!(body.resolved_by_user_id, Some(a_id));
}

#[tokio::test]
async fn veto_after_resolution_returns_409() {
    let (app, _a_id, a_tok, b_id, b_tok) = app_with_two_owners().await;
    let pending: PendingTransitionView = app
        .post(
            &format!("/admin/users/{b_id}/role"),
            Some(&a_tok),
            Some(json!({ "role": "admin" })),
        )
        .await
        .json();

    app.post(
        &format!("/admin/pending-transitions/{}/veto", pending.id),
        Some(&b_tok),
        None,
    )
    .await
    .assert_status(StatusCode::OK);

    // Second veto returns 409.
    let resp = app
        .post(
            &format!("/admin/pending-transitions/{}/veto", pending.id),
            Some(&b_tok),
            None,
        )
        .await;
    resp.assert_status(StatusCode::CONFLICT)
        .assert_error("not_pending");
}

#[tokio::test]
async fn worker_applies_due_transitions() {
    let (app, _a_id, a_tok, b_id, _b_tok) = app_with_two_owners().await;
    app.post(
        &format!("/admin/users/{b_id}/role"),
        Some(&a_tok),
        Some(json!({ "role": "admin" })),
    )
    .await
    .assert_status(StatusCode::ACCEPTED);

    // Manually fast-forward effective_at so the worker considers it due.
    sqlx::query("UPDATE pending.transitions SET effective_at = now() - interval '1 minute'")
        .execute(&app.pool)
        .await
        .unwrap();

    let applied = app.run_pending_transitions_once().await;
    assert_eq!(applied, 1);

    let (role, state): (InstanceRole, String) = sqlx::query_as(
        "SELECT u.instance_role, t.state::text
         FROM identity.users u, pending.transitions t
         WHERE u.id = $1 AND t.target_user_id = u.id",
    )
    .bind(b_id)
    .fetch_one(&app.pool)
    .await
    .unwrap();
    assert_eq!(role, InstanceRole::Admin);
    assert_eq!(state, "applied");
}

#[tokio::test]
async fn worker_does_not_apply_future_transitions() {
    let (app, _a_id, a_tok, b_id, _b_tok) = app_with_two_owners().await;
    app.post(
        &format!("/admin/users/{b_id}/role"),
        Some(&a_tok),
        Some(json!({ "role": "admin" })),
    )
    .await
    .assert_status(StatusCode::ACCEPTED);

    let applied = app.run_pending_transitions_once().await;
    assert_eq!(applied, 0);
}

#[tokio::test]
async fn second_pending_against_same_target_is_blocked() {
    let app = TestApp::new().await;
    let a = app
        .seed_user("a@test.local", "A", "apw", InstanceRole::Owner)
        .await;
    let b = app
        .seed_user("b@test.local", "B", "bpw", InstanceRole::Owner)
        .await;
    let c = app
        .seed_user("c@test.local", "C", "cpw", InstanceRole::Owner)
        .await;
    let a_tok = app.login(&a.email, "apw").await;
    let c_tok = app.login(&c.email, "cpw").await;

    app.post(
        &format!("/admin/users/{}/role", b.id.0),
        Some(&a_tok),
        Some(json!({ "role": "admin" })),
    )
    .await
    .assert_status(StatusCode::ACCEPTED);

    // C tries to also demote B → 409.
    let resp = app
        .post(
            &format!("/admin/users/{}/role", b.id.0),
            Some(&c_tok),
            Some(json!({ "role": "user" })),
        )
        .await;
    resp.assert_status(StatusCode::CONFLICT)
        .assert_error("pending_action_exists");
}

#[tokio::test]
async fn admin_cannot_veto_or_cancel() {
    // Admins can list pending (the route is AdminUser-gated), but the
    // veto + cancel handlers require Owner.
    let app = TestApp::new().await;
    let owner = app
        .seed_user("o@test.local", "O", OWNER_PW, InstanceRole::Owner)
        .await;
    let admin = app
        .seed_user("ad@test.local", "AD", "apw", InstanceRole::Admin)
        .await;
    let other_owner = app
        .seed_user("o2@test.local", "O2", "o2pw", InstanceRole::Owner)
        .await;
    let owner_tok = app.login(&owner.email, OWNER_PW).await;
    let admin_tok = app.login(&admin.email, "apw").await;

    let pending: PendingTransitionView = app
        .post(
            &format!("/admin/users/{}/role", other_owner.id.0),
            Some(&owner_tok),
            Some(json!({ "role": "admin" })),
        )
        .await
        .json();

    let resp = app
        .post(
            &format!("/admin/pending-transitions/{}/veto", pending.id),
            Some(&admin_tok),
            None,
        )
        .await;
    resp.assert_status(StatusCode::FORBIDDEN);

    let resp = app
        .post(
            &format!("/admin/pending-transitions/{}/cancel", pending.id),
            Some(&admin_tok),
            None,
        )
        .await;
    resp.assert_status(StatusCode::FORBIDDEN);
}

// ────────────────────────────────────────────────────────────────────────
// Recovery code
// ────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn rotate_with_correct_current_code_replaces_it() {
    let (app, _a_id, a_tok, _b_id, _b_tok) = app_with_two_owners().await;
    let original = app.seed_recovery_code().await;

    let resp = app
        .post(
            "/admin/server/recovery-code/rotate",
            Some(&a_tok),
            Some(json!({ "current_code": original })),
        )
        .await;
    resp.assert_status(StatusCode::OK);
    let body: serde_json::Value = resp.json();
    let new_code = body["new_code"].as_str().unwrap().to_string();
    // Apple-style format: 8 groups of 4 chars + 7 dashes = 39 chars.
    assert_eq!(new_code.len(), 39);
    assert_ne!(new_code, original);

    // Old code no longer verifies as active; new code does.
    let old_active: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM auth.recovery_codes
         WHERE rotated_at IS NULL AND code_hash = $1",
    )
    .bind(&auth::recovery_code::hash_code(&original)[..])
    .fetch_optional(&app.pool)
    .await
    .unwrap();
    assert!(old_active.is_none(), "original code should no longer be active");

    let new_active: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM auth.recovery_codes
         WHERE rotated_at IS NULL AND code_hash = $1",
    )
    .bind(&auth::recovery_code::hash_code(&new_code)[..])
    .fetch_optional(&app.pool)
    .await
    .unwrap();
    assert!(new_active.is_some(), "new code should be active");
}

#[tokio::test]
async fn rotate_with_wrong_current_code_returns_401() {
    let (app, _a_id, a_tok, _b_id, _b_tok) = app_with_two_owners().await;
    let _original = app.seed_recovery_code().await;

    let resp = app
        .post(
            "/admin/server/recovery-code/rotate",
            Some(&a_tok),
            Some(json!({ "current_code": "wrong".repeat(13) })),
        )
        .await;
    resp.assert_status(StatusCode::UNAUTHORIZED)
        .assert_error("invalid_recovery_code");
}

#[tokio::test]
async fn bypass_with_valid_code_applies_immediately() {
    let (app, _a_id, a_tok, b_id, _b_tok) = app_with_two_owners().await;
    let recovery = app.seed_recovery_code().await;

    let resp = app
        .post(
            &format!("/admin/users/{b_id}/role"),
            Some(&a_tok),
            Some(json!({
                "role": "admin",
                "bypass_recovery_code": recovery,
            })),
        )
        .await;
    resp.assert_status(StatusCode::OK);
    let body: LifecycleBody = resp.json();
    assert_eq!(body.instance_role, InstanceRole::Admin);

    // No pending row created.
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM pending.transitions")
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(count, 0);

    // Audit captured both `recovery_code_used` and `pending_role_change_applied`.
    let (used,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM audit.events WHERE event_type = 'recovery_code_used'",
    )
    .fetch_one(&app.pool)
    .await
    .unwrap();
    assert_eq!(used, 1);
    let (applied_event_data,): (serde_json::Value,) = sqlx::query_as(
        "SELECT event_data FROM audit.events
         WHERE event_type = 'pending_role_change_applied'
         ORDER BY seqno DESC LIMIT 1",
    )
    .fetch_one(&app.pool)
    .await
    .unwrap();
    assert_eq!(applied_event_data["via"].as_str(), Some("recovery_bypass"));
}

#[tokio::test]
async fn bypass_with_wrong_code_returns_401() {
    let (app, _a_id, a_tok, b_id, _b_tok) = app_with_two_owners().await;
    let _ = app.seed_recovery_code().await;

    let resp = app
        .post(
            &format!("/admin/users/{b_id}/role"),
            Some(&a_tok),
            Some(json!({
                "role": "admin",
                "bypass_recovery_code": "feedface".repeat(8),
            })),
        )
        .await;
    resp.assert_status(StatusCode::UNAUTHORIZED)
        .assert_error("invalid_recovery_code");

    // B is still an Owner.
    let (role,): (InstanceRole,) =
        sqlx::query_as("SELECT instance_role FROM identity.users WHERE id = $1")
            .bind(b_id)
            .fetch_one(&app.pool)
            .await
            .unwrap();
    assert_eq!(role, InstanceRole::Owner);
}

#[tokio::test]
async fn notifications_disabled_does_not_block_pending_flow() {
    let (app, _a_id, a_tok, b_id, _b_tok) = app_with_two_owners().await;
    app.set_notifier(notifications::NotifierImpl::Disabled);

    let resp = app
        .post(
            &format!("/admin/users/{b_id}/role"),
            Some(&a_tok),
            Some(json!({ "role": "admin" })),
        )
        .await;
    resp.assert_status(StatusCode::ACCEPTED);

    // Notification outbox row exists; the worker (when run) will mark it skipped.
    app.run_notifications_once().await;
    let (state,): (String,) = sqlx::query_as(
        "SELECT state::text FROM notifications.outbox WHERE kind = 'pending_role_change_initiated'",
    )
    .fetch_one(&app.pool)
    .await
    .unwrap();
    assert_eq!(state, "skipped");

    // Pending row itself still pending — protection survives even without email.
    let (transition_state,): (String,) = sqlx::query_as(
        "SELECT state::text FROM pending.transitions LIMIT 1",
    )
    .fetch_one(&app.pool)
    .await
    .unwrap();
    assert_eq!(transition_state, "pending");
}
