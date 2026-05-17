use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use identity::InstanceRole;
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use super::common::{SeededUser, TestApp};

async fn app_with_owner_and_admin() -> (TestApp, SeededUser, String, SeededUser, String) {
    let app = TestApp::new().await;
    let owner = app
        .seed_user("owner@test.local", "Owner", "ownerpw", InstanceRole::Owner)
        .await;
    let admin = app
        .seed_user("admin@test.local", "Admin", "adminpw", InstanceRole::Admin)
        .await;
    let owner_tok = app.login(&owner.email, "ownerpw").await;
    let admin_tok = app.login(&admin.email, "adminpw").await;
    (app, owner, owner_tok, admin, admin_tok)
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct AdminUserView {
    id: Uuid,
    email: String,
    instance_role: InstanceRole,
    lifecycle: String,
}

#[derive(Deserialize, Debug)]
#[allow(dead_code)]
struct InvitationView {
    id: Uuid,
    email: String,
    invited_by_user_id: Uuid,
    instance_role: InstanceRole,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

#[derive(Deserialize)]
struct CreateInviteResp {
    invitation_id: Uuid,
    email: String,
    instance_role: InstanceRole,
    token: String,
    #[allow(dead_code)]
    accept_url: String,
    #[allow(dead_code)]
    expires_at: DateTime<Utc>,
}

#[derive(Deserialize)]
struct SessionView {
    id: Uuid,
    user_id: Uuid,
}

#[derive(Deserialize)]
struct PaginatedAudit {
    items: Vec<AuditItem>,
    next_cursor: Option<i64>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct AuditItem {
    seqno: i64,
    event_type: String,
    actor_user_id: Option<Uuid>,
}

// ---- non-admin gating ----

#[tokio::test]
async fn regular_user_blocked_from_admin_routes() {
    let app = TestApp::new().await;
    let u = app
        .seed_user("u@test.local", "U", "pw", InstanceRole::User)
        .await;
    let tok = app.login(&u.email, "pw").await;

    for route in [
        ("GET", "/api/admin/users"),
        ("GET", "/api/admin/invites"),
        ("POST", "/api/admin/invites"),
        ("GET", "/api/admin/audit"),
        ("GET", "/api/admin/sessions"),
    ] {
        let resp = match route.0 {
            "GET" => app.get(route.1, Some(&tok)).await,
            "POST" => app.post(route.1, Some(&tok), Some(json!({}))).await,
            _ => unreachable!(),
        };
        assert_eq!(
            resp.status,
            StatusCode::FORBIDDEN,
            "{} {} should be 403 for plain user, got {}: {}",
            route.0,
            route.1,
            resp.status,
            resp.body_as_text()
        );
        assert_eq!(resp.error_code(), "forbidden");
    }
}

#[tokio::test]
async fn unauthenticated_admin_routes_return_401() {
    let app = TestApp::new().await;
    let resp = app.get("/api/admin/users", None).await;
    resp.assert_status(StatusCode::UNAUTHORIZED);
}

// ---- /admin/users ----

#[tokio::test]
async fn list_users_shows_active_and_deactivated_hides_deleted() {
    let (app, owner, owner_tok, admin, _admin_tok) = app_with_owner_and_admin().await;
    // Deactivated user - still in the directory.
    let ghost = app
        .seed_user("ghost@test.local", "Ghost", "pw", InstanceRole::User)
        .await;
    sqlx::query("UPDATE identity.users SET lifecycle = 'deactivated' WHERE id = $1")
        .bind(ghost.id)
        .execute(&app.pool)
        .await
        .unwrap();
    // Soft-deleted user - hidden.
    let gone = app
        .seed_user("gone@test.local", "Gone", "pw", InstanceRole::User)
        .await;
    sqlx::query("UPDATE identity.users SET lifecycle = 'soft_deleted' WHERE id = $1")
        .bind(gone.id)
        .execute(&app.pool)
        .await
        .unwrap();
    // Hard-deleted user - hidden.
    let purged = app
        .seed_user("purged@test.local", "Purged", "pw", InstanceRole::User)
        .await;
    sqlx::query("UPDATE identity.users SET lifecycle = 'hard_deleted' WHERE id = $1")
        .bind(purged.id)
        .execute(&app.pool)
        .await
        .unwrap();

    let resp = app.get("/api/admin/users", Some(&owner_tok)).await;
    resp.assert_status(StatusCode::OK);
    let users: Vec<AdminUserView> = resp.json();
    let emails: Vec<&str> = users.iter().map(|u| u.email.as_str()).collect();
    assert!(emails.contains(&owner.email.as_str()));
    assert!(emails.contains(&admin.email.as_str()));
    assert!(emails.contains(&"ghost@test.local"));
    assert!(
        !emails.contains(&"gone@test.local"),
        "soft_deleted must be hidden: {emails:?}"
    );
    assert!(
        !emails.contains(&"purged@test.local"),
        "hard_deleted must be hidden: {emails:?}"
    );

    let ghost_view = users.iter().find(|u| u.email == "ghost@test.local").unwrap();
    assert_eq!(ghost_view.lifecycle, "deactivated");
}

#[tokio::test]
async fn create_invite_emits_token_and_audit() {
    let (app, owner, owner_tok, _admin, _admin_tok) = app_with_owner_and_admin().await;
    let resp = app
        .post(
            "/api/admin/invites",
            Some(&owner_tok),
            Some(json!({ "email": "alice@test.local" })),
        )
        .await;
    resp.assert_status(StatusCode::CREATED);
    let body: CreateInviteResp = resp.json();
    assert_eq!(body.email, "alice@test.local");
    assert_eq!(body.instance_role, InstanceRole::User); // default
    assert_eq!(body.token.len(), 64);

    // Audit event landed.
    let (event_data,): (serde_json::Value,) = sqlx::query_as(
        "SELECT event_data FROM audit.events
         WHERE event_type = 'invite_created' AND actor_user_id = $1
         ORDER BY seqno DESC LIMIT 1",
    )
    .bind(owner.id)
    .fetch_one(&app.pool)
    .await
    .unwrap();
    assert_eq!(event_data["invited_email"].as_str(), Some("alice@test.local"));
    assert_eq!(event_data["invitation_id"].as_str(), Some(body.invitation_id.to_string().as_str()));
}

#[tokio::test]
async fn create_invite_requires_email() {
    let (app, _owner, owner_tok, _admin, _admin_tok) = app_with_owner_and_admin().await;
    let resp = app
        .post(
            "/api/admin/invites",
            Some(&owner_tok),
            Some(json!({ "email": "   " })),
        )
        .await;
    resp.assert_status(StatusCode::BAD_REQUEST)
        .assert_error("email_required");
}

#[tokio::test]
async fn admin_cannot_invite_owner_role() {
    let (app, _owner, _owner_tok, _admin, admin_tok) = app_with_owner_and_admin().await;
    let resp = app
        .post(
            "/api/admin/invites",
            Some(&admin_tok),
            Some(json!({ "email": "x@test.local", "instance_role": "owner" })),
        )
        .await;
    resp.assert_status(StatusCode::FORBIDDEN)
        .assert_error("cannot_invite_higher_role");
}

#[tokio::test]
async fn owner_can_invite_admin() {
    let (app, _owner, owner_tok, _admin, _admin_tok) = app_with_owner_and_admin().await;
    let resp = app
        .post(
            "/api/admin/invites",
            Some(&owner_tok),
            Some(json!({ "email": "newadmin@test.local", "instance_role": "admin" })),
        )
        .await;
    resp.assert_status(StatusCode::CREATED);
    let body: CreateInviteResp = resp.json();
    assert_eq!(body.instance_role, InstanceRole::Admin);
}

#[tokio::test]
async fn create_invite_rejects_existing_email() {
    let (app, _owner, owner_tok, admin, _admin_tok) = app_with_owner_and_admin().await;
    // Admin's email is already taken by an active user.
    let resp = app
        .post(
            "/api/admin/invites",
            Some(&owner_tok),
            Some(json!({ "email": admin.email })),
        )
        .await;
    resp.assert_status(StatusCode::CONFLICT)
        .assert_error("email_already_in_use");
}

#[tokio::test]
async fn create_invite_rejects_duplicate_active_invite() {
    let (app, _owner, owner_tok, _admin, _admin_tok) = app_with_owner_and_admin().await;
    app.post(
        "/api/admin/invites",
        Some(&owner_tok),
        Some(json!({ "email": "dup@test.local" })),
    )
    .await
    .assert_status(StatusCode::CREATED);

    let dup = app
        .post(
            "/api/admin/invites",
            Some(&owner_tok),
            Some(json!({ "email": "dup@test.local" })),
        )
        .await;
    dup.assert_status(StatusCode::CONFLICT)
        .assert_error("active_invite_exists");
}

// ---- /admin/invites: list + revoke ----

#[tokio::test]
async fn list_invites_returns_pending_only_newest_first() {
    let (app, _owner, owner_tok, _admin, _admin_tok) = app_with_owner_and_admin().await;

    let first: CreateInviteResp = app
        .post(
            "/api/admin/invites",
            Some(&owner_tok),
            Some(json!({ "email": "a@test.local" })),
        )
        .await
        .json();
    // Tiny pause so created_at differs (Postgres timestamps go to microsecond).
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    let second: CreateInviteResp = app
        .post(
            "/api/admin/invites",
            Some(&owner_tok),
            Some(json!({ "email": "b@test.local" })),
        )
        .await
        .json();

    let list: Vec<InvitationView> = app
        .get("/api/admin/invites", Some(&owner_tok))
        .await
        .json();
    assert_eq!(list.len(), 2);
    assert_eq!(list[0].id, second.invitation_id, "newest first");
    assert_eq!(list[1].id, first.invitation_id);
    for inv in &list {
        assert_eq!(inv.invited_by_user_id, list[0].invited_by_user_id);
    }
}

#[tokio::test]
async fn revoke_invite_drops_from_pending() {
    let (app, _owner, owner_tok, _admin, _admin_tok) = app_with_owner_and_admin().await;
    let inv: CreateInviteResp = app
        .post(
            "/api/admin/invites",
            Some(&owner_tok),
            Some(json!({ "email": "rev@test.local" })),
        )
        .await
        .json();

    let revoke = app
        .post(
            &format!("/api/admin/invites/{}/revoke", inv.invitation_id),
            Some(&owner_tok),
            None,
        )
        .await;
    revoke.assert_status(StatusCode::NO_CONTENT);

    let list: Vec<InvitationView> = app
        .get("/api/admin/invites", Some(&owner_tok))
        .await
        .json();
    assert!(list.is_empty());
}

#[tokio::test]
async fn revoke_invite_idempotent_second_call_404() {
    let (app, _owner, owner_tok, _admin, _admin_tok) = app_with_owner_and_admin().await;
    let inv: CreateInviteResp = app
        .post(
            "/api/admin/invites",
            Some(&owner_tok),
            Some(json!({ "email": "id@test.local" })),
        )
        .await
        .json();

    app.post(
        &format!("/api/admin/invites/{}/revoke", inv.invitation_id),
        Some(&owner_tok),
        None,
    )
    .await
    .assert_status(StatusCode::NO_CONTENT);

    let second = app
        .post(
            &format!("/api/admin/invites/{}/revoke", inv.invitation_id),
            Some(&owner_tok),
            None,
        )
        .await;
    second
        .assert_status(StatusCode::NOT_FOUND)
        .assert_error("invite_not_found");
}

#[tokio::test]
async fn revoke_unknown_invite_returns_404() {
    let (app, _owner, owner_tok, _admin, _admin_tok) = app_with_owner_and_admin().await;
    let bogus = Uuid::new_v4();
    let resp = app
        .post(
            &format!("/api/admin/invites/{bogus}/revoke"),
            Some(&owner_tok),
            None,
        )
        .await;
    resp.assert_status(StatusCode::NOT_FOUND)
        .assert_error("invite_not_found");
}

#[tokio::test]
async fn revoke_accepted_invite_returns_409() {
    let (app, _owner, owner_tok, _admin, _admin_tok) = app_with_owner_and_admin().await;
    let inv: CreateInviteResp = app
        .post(
            "/api/admin/invites",
            Some(&owner_tok),
            Some(json!({ "email": "acc@test.local" })),
        )
        .await
        .json();

    // Accept the invite.
    app.post(
        "/api/auth/accept-invite",
        None,
        Some(json!({
            "token": inv.token,
            "display_name": "Accepted",
            "password": "accpw",
        })),
    )
    .await
    .assert_status(StatusCode::CREATED);

    let resp = app
        .post(
            &format!("/api/admin/invites/{}/revoke", inv.invitation_id),
            Some(&owner_tok),
            None,
        )
        .await;
    resp.assert_status(StatusCode::CONFLICT)
        .assert_error("invite_already_accepted");
}

// ---- /admin/audit ----

#[tokio::test]
async fn audit_pagination_cursor_walks_the_chain() {
    let (app, _owner, owner_tok, _admin, _admin_tok) = app_with_owner_and_admin().await;
    // Generate enough events: each create-invite adds one. Mix with logins
    // that already happened in setup.
    for i in 0..6 {
        app.post(
            "/api/admin/invites",
            Some(&owner_tok),
            Some(json!({ "email": format!("p{i}@test.local") })),
        )
        .await
        .assert_status(StatusCode::CREATED);
    }

    let page1: PaginatedAudit = app
        .get("/api/admin/audit?limit=3", Some(&owner_tok))
        .await
        .json();
    assert_eq!(page1.items.len(), 3);
    let cursor = page1
        .next_cursor
        .expect("next_cursor present when page is full");

    let page2: PaginatedAudit = app
        .get(&format!("/api/admin/audit?limit=3&cursor={cursor}"), Some(&owner_tok))
        .await
        .json();
    assert_eq!(page2.items.len(), 3);
    let first_page2 = page2.items[0].seqno;
    assert!(first_page2 < page1.items.last().unwrap().seqno);

    // Eventually we reach the end.
    let mut next = page2.next_cursor;
    let mut total = page1.items.len() + page2.items.len();
    while let Some(c) = next {
        let page: PaginatedAudit = app
            .get(&format!("/api/admin/audit?limit=10&cursor={c}"), Some(&owner_tok))
            .await
            .json();
        total += page.items.len();
        next = page.next_cursor;
    }
    // We seeded 2 users (each emits an audit row) + 2 logins + 6 invite creates = 10 events.
    assert_eq!(total, 10, "expected 10 audit events, got {total}");
}

#[tokio::test]
async fn audit_filter_actor_scopes_correctly() {
    let (app, owner, owner_tok, admin, _admin_tok) = app_with_owner_and_admin().await;
    // owner creates an invite (actor = owner)
    app.post(
        "/api/admin/invites",
        Some(&owner_tok),
        Some(json!({ "email": "f@test.local" })),
    )
    .await
    .assert_status(StatusCode::CREATED);

    let resp = app
        .get(
            &format!("/api/admin/audit?actor={}", owner.id.0),
            Some(&owner_tok),
        )
        .await;
    resp.assert_status(StatusCode::OK);
    let body: PaginatedAudit = resp.json();
    assert!(!body.items.is_empty());
    for ev in &body.items {
        assert_eq!(ev.actor_user_id, Some(owner.id.0));
    }
    // Admin's events should NOT appear in this filtered view.
    assert!(
        !body.items.iter().any(|e| e.actor_user_id == Some(admin.id.0)),
        "admin's events leaked into owner-filtered list"
    );
}

// ---- /admin/sessions ----

#[tokio::test]
async fn admin_sessions_lists_all_active_users() {
    let (app, owner, _owner_tok, admin, admin_tok) = app_with_owner_and_admin().await;
    let resp = app.get("/api/admin/sessions", Some(&admin_tok)).await;
    resp.assert_status(StatusCode::OK);
    let sessions: Vec<SessionView> = resp.json();
    let user_ids: Vec<Uuid> = sessions.iter().map(|s| s.user_id).collect();
    assert!(user_ids.contains(&owner.id.0));
    assert!(user_ids.contains(&admin.id.0));
}

#[tokio::test]
async fn admin_revoke_session_kills_target_token() {
    let (app, owner, owner_tok, _admin, admin_tok) = app_with_owner_and_admin().await;

    // Find owner's session id via admin's session list.
    let sessions: Vec<SessionView> = app
        .get("/api/admin/sessions", Some(&admin_tok))
        .await
        .json();
    let target = sessions
        .iter()
        .find(|s| s.user_id == owner.id.0)
        .map(|s| s.id)
        .expect("owner has an active session");

    app.post(
        &format!("/api/admin/sessions/{target}/revoke"),
        Some(&admin_tok),
        None,
    )
    .await
    .assert_status(StatusCode::NO_CONTENT);

    app.get("/api/me", Some(&owner_tok))
        .await
        .assert_status(StatusCode::UNAUTHORIZED);

    let (event_data,): (serde_json::Value,) = sqlx::query_as(
        "SELECT event_data FROM audit.events
         WHERE event_type = 'session_revoked_by_admin'
         ORDER BY seqno DESC LIMIT 1",
    )
    .fetch_one(&app.pool)
    .await
    .unwrap();
    assert_eq!(
        event_data["session_id"].as_str(),
        Some(target.to_string().as_str())
    );
    assert_eq!(
        event_data["target_user_id"].as_str(),
        Some(owner.id.0.to_string().as_str())
    );
}

#[tokio::test]
async fn admin_revoke_nonexistent_session_returns_404() {
    let (app, _owner, _owner_tok, _admin, admin_tok) = app_with_owner_and_admin().await;
    let bogus = Uuid::new_v4();
    let resp = app
        .post(
            &format!("/api/admin/sessions/{bogus}/revoke"),
            Some(&admin_tok),
            None,
        )
        .await;
    resp.assert_status(StatusCode::NOT_FOUND)
        .assert_error("session_not_found");
}

// ────────────────────────────────────────────────────────────────────────
// /admin/users/{id}/lifecycle tests
// ────────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
#[allow(dead_code)]
struct LifecycleBody {
    id: Uuid,
    email: String,
    display_name: String,
    lifecycle: String,
    instance_role: InstanceRole,
    updated_at: DateTime<Utc>,
}

async fn seed_user_token(
    app: &TestApp,
    email: &str,
    name: &str,
    pw: &str,
    role: InstanceRole,
) -> (Uuid, String) {
    let user = app.seed_user(email, name, pw, role).await;
    let token = app.login(email, pw).await;
    (user.id.0, token)
}

#[tokio::test]
async fn deactivate_then_reactivate_cycle() {
    let (app, _owner, owner_tok, _admin, _admin_tok) = app_with_owner_and_admin().await;
    let (user_id, user_tok) =
        seed_user_token(&app, "u@test.local", "U", "upw", InstanceRole::User).await;

    // Deactivate.
    let resp = app
        .post(
            &format!("/api/admin/users/{user_id}/deactivate"),
            Some(&owner_tok),
            None,
        )
        .await;
    resp.assert_status(StatusCode::OK);
    let body: LifecycleBody = resp.json();
    assert_eq!(body.lifecycle, "deactivated");

    // User's session is dead.
    app.get("/api/me", Some(&user_tok))
        .await
        .assert_status(StatusCode::UNAUTHORIZED);

    // Login attempt: invalid_credentials (deactivated reads as unknown).
    app.post(
        "/api/auth/login",
        None,
        Some(json!({ "email": "u@test.local", "password": "upw" })),
    )
    .await
    .assert_status(StatusCode::UNAUTHORIZED)
    .assert_error("invalid_credentials");

    // Reactivate.
    let resp = app
        .post(
            &format!("/api/admin/users/{user_id}/reactivate"),
            Some(&owner_tok),
            None,
        )
        .await;
    resp.assert_status(StatusCode::OK);
    let body: LifecycleBody = resp.json();
    assert_eq!(body.lifecycle, "active");

    // Same password works again — credentials were preserved.
    app.post(
        "/api/auth/login",
        None,
        Some(json!({ "email": "u@test.local", "password": "upw" })),
    )
    .await
    .assert_status(StatusCode::OK);
}

#[tokio::test]
async fn deactivate_already_deactivated_returns_409() {
    let (app, _owner, owner_tok, _admin, _admin_tok) = app_with_owner_and_admin().await;
    let (user_id, _tok) =
        seed_user_token(&app, "u@test.local", "U", "upw", InstanceRole::User).await;

    app.post(
        &format!("/api/admin/users/{user_id}/deactivate"),
        Some(&owner_tok),
        None,
    )
    .await
    .assert_status(StatusCode::OK);

    let again = app
        .post(
            &format!("/api/admin/users/{user_id}/deactivate"),
            Some(&owner_tok),
            None,
        )
        .await;
    again
        .assert_status(StatusCode::CONFLICT)
        .assert_error("already_deactivated");
}

#[tokio::test]
async fn reactivate_already_active_returns_409() {
    let (app, _owner, owner_tok, _admin, _admin_tok) = app_with_owner_and_admin().await;
    let (user_id, _tok) =
        seed_user_token(&app, "u@test.local", "U", "upw", InstanceRole::User).await;

    let resp = app
        .post(
            &format!("/api/admin/users/{user_id}/reactivate"),
            Some(&owner_tok),
            None,
        )
        .await;
    resp.assert_status(StatusCode::CONFLICT)
        .assert_error("already_active");
}

#[tokio::test]
async fn cannot_target_self_for_any_lifecycle_action() {
    let (app, owner, owner_tok, _admin, _admin_tok) = app_with_owner_and_admin().await;
    for action in ["deactivate", "reactivate", "delete", "purge"] {
        let resp = app
            .post(
                &format!("/api/admin/users/{}/{action}", owner.id.0),
                Some(&owner_tok),
                None,
            )
            .await;
        assert_eq!(
            resp.status,
            StatusCode::FORBIDDEN,
            "self-{action} should be 403, got {}: {}",
            resp.status,
            resp.body_as_text()
        );
        assert_eq!(resp.error_code(), "cannot_target_self");
    }
}

#[tokio::test]
async fn admin_cannot_act_on_peer_admin() {
    // Admin1 cannot deactivate Admin2 (peer-on-peer). Only Owner can.
    let app = TestApp::new().await;
    let admin1 = app
        .seed_user("a1@test.local", "A1", "pw1", InstanceRole::Admin)
        .await;
    let admin2 = app
        .seed_user("a2@test.local", "A2", "pw2", InstanceRole::Admin)
        .await;
    let tok1 = app.login(&admin1.email, "pw1").await;

    let resp = app
        .post(
            &format!("/api/admin/users/{}/deactivate", admin2.id.0),
            Some(&tok1),
            None,
        )
        .await;
    resp.assert_status(StatusCode::FORBIDDEN)
        .assert_error("cannot_target_peer_or_higher");
}

#[tokio::test]
async fn admin_cannot_act_on_owner() {
    let (app, owner, _owner_tok, _admin, admin_tok) = app_with_owner_and_admin().await;
    let resp = app
        .post(
            &format!("/api/admin/users/{}/deactivate", owner.id.0),
            Some(&admin_tok),
            None,
        )
        .await;
    resp.assert_status(StatusCode::FORBIDDEN)
        .assert_error("cannot_target_peer_or_higher");
}

#[tokio::test]
async fn owner_can_deactivate_admin() {
    let (app, _owner, owner_tok, admin, _admin_tok) = app_with_owner_and_admin().await;
    let resp = app
        .post(
            &format!("/api/admin/users/{}/deactivate", admin.id.0),
            Some(&owner_tok),
            None,
        )
        .await;
    resp.assert_status(StatusCode::OK);
}

#[tokio::test]
async fn lifecycle_action_on_unknown_user_returns_404() {
    let (app, _owner, owner_tok, _admin, _admin_tok) = app_with_owner_and_admin().await;
    let bogus = Uuid::new_v4();
    for action in ["deactivate", "reactivate", "delete", "purge"] {
        let resp = app
            .post(
                &format!("/api/admin/users/{bogus}/{action}"),
                Some(&owner_tok),
                None,
            )
            .await;
        assert_eq!(
            resp.status,
            StatusCode::NOT_FOUND,
            "{action} on unknown id should be 404"
        );
        assert_eq!(resp.error_code(), "user_not_found");
    }
}

#[tokio::test]
async fn delete_redacts_pii_and_frees_email() {
    let (app, _owner, owner_tok, _admin, _admin_tok) = app_with_owner_and_admin().await;
    let (user_id, user_tok) =
        seed_user_token(&app, "victim@test.local", "Victim", "pw", InstanceRole::User).await;

    let resp = app
        .post(
            &format!("/api/admin/users/{user_id}/delete"),
            Some(&owner_tok),
            None,
        )
        .await;
    resp.assert_status(StatusCode::NO_CONTENT);

    // Session is dead.
    app.get("/api/me", Some(&user_tok))
        .await
        .assert_status(StatusCode::UNAUTHORIZED);

    // Row exists with redacted PII + soft_deleted lifecycle.
    let (email, display, lifecycle): (String, String, String) = sqlx::query_as(
        "SELECT email, display_name, lifecycle::text FROM identity.users WHERE id = $1",
    )
    .bind(user_id)
    .fetch_one(&app.pool)
    .await
    .unwrap();
    assert_eq!(lifecycle, "soft_deleted");
    assert_eq!(display, "[deleted user]");
    assert!(
        email.starts_with("deleted+") && email.ends_with("@purged.invalid"),
        "email should be redacted, got: {email}"
    );

    // Credentials row gone.
    let creds_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM auth.credentials WHERE user_id = $1")
            .bind(user_id)
            .fetch_one(&app.pool)
            .await
            .unwrap();
    assert_eq!(creds_count, 0, "credentials should be wiped");

    // Original email is freed for re-invitation.
    let invite_resp = app
        .post(
            "/api/admin/invites",
            Some(&owner_tok),
            Some(json!({ "email": "victim@test.local" })),
        )
        .await;
    invite_resp.assert_status(StatusCode::CREATED);

    // Audit event recorded the original email.
    let (event_data,): (serde_json::Value,) = sqlx::query_as(
        "SELECT event_data FROM audit.events
         WHERE event_type = 'user_deleted'
         ORDER BY seqno DESC LIMIT 1",
    )
    .fetch_one(&app.pool)
    .await
    .unwrap();
    assert_eq!(
        event_data["redacted_from_email"].as_str(),
        Some("victim@test.local")
    );
}

#[tokio::test]
async fn purge_can_target_already_soft_deleted_user() {
    let (app, _owner, owner_tok, _admin, _admin_tok) = app_with_owner_and_admin().await;
    let (user_id, _tok) =
        seed_user_token(&app, "victim@test.local", "Victim", "pw", InstanceRole::User).await;

    // Soft-delete first.
    app.post(
        &format!("/api/admin/users/{user_id}/delete"),
        Some(&owner_tok),
        None,
    )
    .await
    .assert_status(StatusCode::NO_CONTENT);

    // Purge a soft-deleted user.
    let resp = app
        .post(
            &format!("/api/admin/users/{user_id}/purge"),
            Some(&owner_tok),
            None,
        )
        .await;
    resp.assert_status(StatusCode::NO_CONTENT);

    let lifecycle: String =
        sqlx::query_scalar("SELECT lifecycle::text FROM identity.users WHERE id = $1")
            .bind(user_id)
            .fetch_one(&app.pool)
            .await
            .unwrap();
    assert_eq!(lifecycle, "hard_deleted");

    // Audit recorded the prior lifecycle.
    let (event_data,): (serde_json::Value,) = sqlx::query_as(
        "SELECT event_data FROM audit.events
         WHERE event_type = 'user_purged'
         ORDER BY seqno DESC LIMIT 1",
    )
    .fetch_one(&app.pool)
    .await
    .unwrap();
    assert_eq!(event_data["prior_lifecycle"].as_str(), Some("soft_deleted"));
}

#[tokio::test]
async fn purge_directly_from_active_works() {
    let (app, _owner, owner_tok, _admin, _admin_tok) = app_with_owner_and_admin().await;
    let (user_id, _tok) =
        seed_user_token(&app, "v@test.local", "V", "pw", InstanceRole::User).await;

    let resp = app
        .post(
            &format!("/api/admin/users/{user_id}/purge"),
            Some(&owner_tok),
            None,
        )
        .await;
    resp.assert_status(StatusCode::NO_CONTENT);

    let lifecycle: String =
        sqlx::query_scalar("SELECT lifecycle::text FROM identity.users WHERE id = $1")
            .bind(user_id)
            .fetch_one(&app.pool)
            .await
            .unwrap();
    assert_eq!(lifecycle, "hard_deleted");
}

#[tokio::test]
async fn deleted_user_is_invisible_to_admin_list() {
    let (app, _owner, owner_tok, _admin, _admin_tok) = app_with_owner_and_admin().await;
    let (user_id, _tok) =
        seed_user_token(&app, "vanish@test.local", "Vanish", "pw", InstanceRole::User).await;

    app.post(
        &format!("/api/admin/users/{user_id}/delete"),
        Some(&owner_tok),
        None,
    )
    .await
    .assert_status(StatusCode::NO_CONTENT);

    let list: Vec<AdminUserView> = app
        .get("/api/admin/users", Some(&owner_tok))
        .await
        .json();
    assert!(
        list.iter().all(|u| u.email != "vanish@test.local"),
        "soft-deleted user should be hidden from /admin/users"
    );
}

#[tokio::test]
async fn reactivate_only_works_from_deactivated_state() {
    let (app, _owner, owner_tok, _admin, _admin_tok) = app_with_owner_and_admin().await;
    let (user_id, _tok) =
        seed_user_token(&app, "u@test.local", "U", "pw", InstanceRole::User).await;

    // Soft-delete then attempt reactivate → 404 (account is gone).
    app.post(
        &format!("/api/admin/users/{user_id}/delete"),
        Some(&owner_tok),
        None,
    )
    .await
    .assert_status(StatusCode::NO_CONTENT);

    let resp = app
        .post(
            &format!("/api/admin/users/{user_id}/reactivate"),
            Some(&owner_tok),
            None,
        )
        .await;
    resp.assert_status(StatusCode::NOT_FOUND)
        .assert_error("user_not_found");
}

#[tokio::test]
async fn deactivate_revokes_all_sessions() {
    let (app, _owner, owner_tok, _admin, _admin_tok) = app_with_owner_and_admin().await;
    let user = app
        .seed_user("multi@test.local", "Multi", "pw", InstanceRole::User)
        .await;
    let t1 = app.login(&user.email, "pw").await;
    let t2 = app.login(&user.email, "pw").await;
    let t3 = app.login(&user.email, "pw").await;

    app.post(
        &format!("/api/admin/users/{}/deactivate", user.id.0),
        Some(&owner_tok),
        None,
    )
    .await
    .assert_status(StatusCode::OK);

    for tok in [&t1, &t2, &t3] {
        app.get("/api/me", Some(tok))
            .await
            .assert_status(StatusCode::UNAUTHORIZED);
    }

    let (event_data,): (serde_json::Value,) = sqlx::query_as(
        "SELECT event_data FROM audit.events
         WHERE event_type = 'user_deactivated'
         ORDER BY seqno DESC LIMIT 1",
    )
    .fetch_one(&app.pool)
    .await
    .unwrap();
    assert_eq!(event_data["sessions_revoked"].as_u64(), Some(3));
}

// ────────────────────────────────────────────────────────────────────────
// /admin/users/{id}/role tests
// ────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn owner_promotes_user_to_admin() {
    let (app, _owner, owner_tok, _admin, _admin_tok) = app_with_owner_and_admin().await;
    let target = app
        .seed_user("u@test.local", "U", "pw", InstanceRole::User)
        .await;

    let resp = app
        .post(
            &format!("/api/admin/users/{}/role", target.id.0),
            Some(&owner_tok),
            Some(json!({ "role": "admin" })),
        )
        .await;
    resp.assert_status(StatusCode::OK);
    let body: LifecycleBody = resp.json();
    assert_eq!(body.instance_role, InstanceRole::Admin);

    // /me as that user now reflects the new role.
    let user_tok = app.login(&target.email, "pw").await;
    let me: serde_json::Value = app.get("/api/me", Some(&user_tok)).await.json();
    assert_eq!(me["instance_role"].as_str(), Some("admin"));
}

#[tokio::test]
async fn owner_demotes_admin_to_user() {
    let (app, _owner, owner_tok, admin, _admin_tok) = app_with_owner_and_admin().await;

    let resp = app
        .post(
            &format!("/api/admin/users/{}/role", admin.id.0),
            Some(&owner_tok),
            Some(json!({ "role": "user" })),
        )
        .await;
    resp.assert_status(StatusCode::OK);
    let body: LifecycleBody = resp.json();
    assert_eq!(body.instance_role, InstanceRole::User);

    // Audit recorded both ends.
    let (event_data,): (serde_json::Value,) = sqlx::query_as(
        "SELECT event_data FROM audit.events
         WHERE event_type = 'user_role_changed'
         ORDER BY seqno DESC LIMIT 1",
    )
    .fetch_one(&app.pool)
    .await
    .unwrap();
    assert_eq!(event_data["from_role"].as_str(), Some("admin"));
    assert_eq!(event_data["to_role"].as_str(), Some("user"));
}

#[tokio::test]
async fn owner_can_promote_admin_to_owner_multi_owner() {
    let (app, _owner, owner_tok, admin, _admin_tok) = app_with_owner_and_admin().await;

    let resp = app
        .post(
            &format!("/api/admin/users/{}/role", admin.id.0),
            Some(&owner_tok),
            Some(json!({ "role": "owner" })),
        )
        .await;
    resp.assert_status(StatusCode::OK);
    let body: LifecycleBody = resp.json();
    assert_eq!(body.instance_role, InstanceRole::Owner);

    let owner_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM identity.users WHERE instance_role = 'owner'",
    )
    .fetch_one(&app.pool)
    .await
    .unwrap();
    assert_eq!(owner_count, 2, "multi-owner should be allowed");
}

#[tokio::test]
async fn owner_can_demote_another_owner_via_recovery_bypass() {
    // Multi-Owner setup: O1 (original) promotes A → O2 (immediate, target
    // wasn't Owner yet), then O1 demotes O2. The demote is Owner-on-Owner
    // and goes through the pending flow by default, so we use the recovery
    // code bypass to keep this test's instant semantics. The pending-flow
    // tests live in tests/integration/pending_transitions.rs.
    let (app, _owner, owner_tok, admin, _admin_tok) = app_with_owner_and_admin().await;
    let recovery = app.seed_recovery_code().await;

    app.post(
        &format!("/api/admin/users/{}/role", admin.id.0),
        Some(&owner_tok),
        Some(json!({ "role": "owner" })),
    )
    .await
    .assert_status(StatusCode::OK);

    let resp = app
        .post(
            &format!("/api/admin/users/{}/role", admin.id.0),
            Some(&owner_tok),
            Some(json!({ "role": "admin", "bypass_recovery_code": recovery })),
        )
        .await;
    resp.assert_status(StatusCode::OK);
    let body: LifecycleBody = resp.json();
    assert_eq!(body.instance_role, InstanceRole::Admin);
}

#[tokio::test]
async fn admin_cannot_change_roles() {
    let (app, _owner, _owner_tok, _admin, admin_tok) = app_with_owner_and_admin().await;
    let target = app
        .seed_user("u@test.local", "U", "pw", InstanceRole::User)
        .await;

    let resp = app
        .post(
            &format!("/api/admin/users/{}/role", target.id.0),
            Some(&admin_tok),
            Some(json!({ "role": "admin" })),
        )
        .await;
    resp.assert_status(StatusCode::FORBIDDEN)
        .assert_error("forbidden");
}

#[tokio::test]
async fn regular_user_cannot_change_roles() {
    let app = TestApp::new().await;
    let owner = app
        .seed_user("owner@test.local", "Owner", "ownerpw", InstanceRole::Owner)
        .await;
    let user = app
        .seed_user("u@test.local", "U", "upw", InstanceRole::User)
        .await;
    let user_tok = app.login(&user.email, "upw").await;

    // The AdminUser extractor itself returns 403 here.
    let resp = app
        .post(
            &format!("/api/admin/users/{}/role", owner.id.0),
            Some(&user_tok),
            Some(json!({ "role": "admin" })),
        )
        .await;
    resp.assert_status(StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn change_role_blocks_self_target() {
    let (app, owner, owner_tok, _admin, _admin_tok) = app_with_owner_and_admin().await;
    let resp = app
        .post(
            &format!("/api/admin/users/{}/role", owner.id.0),
            Some(&owner_tok),
            Some(json!({ "role": "admin" })),
        )
        .await;
    resp.assert_status(StatusCode::FORBIDDEN)
        .assert_error("cannot_target_self");
}

#[tokio::test]
async fn change_role_same_role_returns_409() {
    let (app, _owner, owner_tok, _admin, _admin_tok) = app_with_owner_and_admin().await;
    let target = app
        .seed_user("u@test.local", "U", "pw", InstanceRole::User)
        .await;

    let resp = app
        .post(
            &format!("/api/admin/users/{}/role", target.id.0),
            Some(&owner_tok),
            Some(json!({ "role": "user" })),
        )
        .await;
    resp.assert_status(StatusCode::CONFLICT)
        .assert_error("already_in_role");
}

#[tokio::test]
async fn change_role_on_deleted_user_returns_404() {
    let (app, _owner, owner_tok, _admin, _admin_tok) = app_with_owner_and_admin().await;
    let target = app
        .seed_user("ghost@test.local", "Ghost", "pw", InstanceRole::User)
        .await;

    // Soft-delete first.
    app.post(
        &format!("/api/admin/users/{}/delete", target.id.0),
        Some(&owner_tok),
        None,
    )
    .await
    .assert_status(StatusCode::NO_CONTENT);

    let resp = app
        .post(
            &format!("/api/admin/users/{}/role", target.id.0),
            Some(&owner_tok),
            Some(json!({ "role": "admin" })),
        )
        .await;
    resp.assert_status(StatusCode::NOT_FOUND)
        .assert_error("user_not_found");
}

#[tokio::test]
async fn demoted_owner_loses_powers_on_next_request() {
    // Owner1 promotes Admin to Owner2, Owner2 makes an admin-level call
    // successfully, then Owner1 demotes Owner2 to User and Owner2's next
    // admin call fails with 403. Uses recovery-code bypass for the
    // Owner→User demotion since that's Owner-on-Owner.
    let (app, _owner1, owner1_tok, admin, _admin_tok) = app_with_owner_and_admin().await;
    let recovery = app.seed_recovery_code().await;

    app.post(
        &format!("/api/admin/users/{}/role", admin.id.0),
        Some(&owner1_tok),
        Some(json!({ "role": "owner" })),
    )
    .await
    .assert_status(StatusCode::OK);

    let owner2_tok = app.login(&admin.email, "adminpw").await;

    app.get("/api/admin/users", Some(&owner2_tok))
        .await
        .assert_status(StatusCode::OK);

    app.post(
        &format!("/api/admin/users/{}/role", admin.id.0),
        Some(&owner1_tok),
        Some(json!({ "role": "user", "bypass_recovery_code": recovery })),
    )
    .await
    .assert_status(StatusCode::OK);

    let me = app.get("/api/me", Some(&owner2_tok)).await;
    me.assert_status(StatusCode::OK);
    let me_body: serde_json::Value = me.json();
    assert_eq!(me_body["instance_role"].as_str(), Some("user"));

    app.get("/api/admin/users", Some(&owner2_tok))
        .await
        .assert_status(StatusCode::FORBIDDEN);
}
