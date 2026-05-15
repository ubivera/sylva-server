use axum::http::StatusCode;
use chrono::{Duration, Utc};
use identity::{DEFAULT_INVITATION_TTL, InstanceRole, UserId, hash_invite_token};
use serde::Deserialize;
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

use super::common::{LoginBody, SeededUser, TestApp};

const OWNER_PW: &str = "ownerpw";

async fn app_with_owner() -> (TestApp, SeededUser) {
    let app = TestApp::new().await;
    let owner = app
        .seed_user("owner@test.local", "Owner", OWNER_PW, InstanceRole::Owner)
        .await;
    (app, owner)
}

#[derive(Deserialize)]
struct MeBody {
    id: Uuid,
    email: String,
    display_name: String,
    instance_role: InstanceRole,
}

#[tokio::test]
async fn login_success_returns_token_and_user_id() {
    let (app, owner) = app_with_owner().await;
    let resp = app
        .post(
            "/auth/login",
            None,
            Some(json!({ "email": owner.email, "password": OWNER_PW })),
        )
        .await;
    resp.assert_status(StatusCode::OK);
    let body: LoginBody = resp.json();
    assert_eq!(body.user_id, owner.id.0);
    assert!(!body.token.is_empty(), "token should be non-empty");
}

#[tokio::test]
async fn login_wrong_password_returns_generic_401() {
    let (app, owner) = app_with_owner().await;
    let resp = app
        .post(
            "/auth/login",
            None,
            Some(json!({ "email": owner.email, "password": "wrong" })),
        )
        .await;
    resp.assert_status(StatusCode::UNAUTHORIZED)
        .assert_error("invalid_credentials");
}

#[tokio::test]
async fn login_unknown_email_returns_same_generic_401() {
    let app = TestApp::new().await;
    let resp = app
        .post(
            "/auth/login",
            None,
            Some(json!({ "email": "nope@test.local", "password": "whatever" })),
        )
        .await;
    resp.assert_status(StatusCode::UNAUTHORIZED)
        .assert_error("invalid_credentials");
}

#[tokio::test]
async fn login_deactivated_user_treated_as_unknown() {
    let app = TestApp::new().await;
    let user = app
        .seed_user("ghost@test.local", "Ghost", "pw", InstanceRole::User)
        .await;
    sqlx::query("UPDATE identity.users SET lifecycle = 'deactivated' WHERE id = $1")
        .bind(user.id)
        .execute(&app.pool)
        .await
        .unwrap();

    let resp = app
        .post(
            "/auth/login",
            None,
            Some(json!({ "email": user.email, "password": user.password })),
        )
        .await;
    resp.assert_status(StatusCode::UNAUTHORIZED)
        .assert_error("invalid_credentials");
}

#[tokio::test]
async fn me_returns_caller_identity() {
    let (app, owner) = app_with_owner().await;
    let token = app.login(&owner.email, OWNER_PW).await;
    let resp = app.get("/me", Some(&token)).await;
    resp.assert_status(StatusCode::OK);
    let body: MeBody = resp.json();
    assert_eq!(body.id, owner.id.0);
    assert_eq!(body.email, owner.email);
    assert_eq!(body.display_name, "Owner");
    assert_eq!(body.instance_role, InstanceRole::Owner);
}

#[tokio::test]
async fn me_without_token_is_unauthorized() {
    let app = TestApp::new().await;
    let resp = app.get("/me", None).await;
    resp.assert_status(StatusCode::UNAUTHORIZED)
        .assert_error("missing_authorization");
}

#[tokio::test]
async fn me_with_garbage_token_is_unauthorized() {
    let app = TestApp::new().await;
    let resp = app.get("/me", Some("not-a-real-token")).await;
    resp.assert_status(StatusCode::UNAUTHORIZED)
        .assert_error("invalid_session");
}

#[tokio::test]
async fn me_with_non_bearer_scheme_is_unauthorized() {
    use axum::http::header::AUTHORIZATION;
    let app = TestApp::new().await;
    let req = axum::http::Request::builder()
        .method(axum::http::Method::GET)
        .uri("/me")
        .header(AUTHORIZATION, "Basic abc123")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.router.clone(), req)
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn logout_revokes_the_session() {
    let (app, owner) = app_with_owner().await;
    let token = app.login(&owner.email, OWNER_PW).await;

    let logout = app.post("/auth/logout", Some(&token), None).await;
    logout.assert_status(StatusCode::NO_CONTENT);

    // Same token must no longer work.
    let me = app.get("/me", Some(&token)).await;
    me.assert_status(StatusCode::UNAUTHORIZED)
        .assert_error("invalid_session");
}

async fn seed_pending_invite(
    pool: &PgPool,
    inviter: UserId,
    email: &str,
    role: InstanceRole,
) -> (Uuid, String) {
    let mut tx = pool.begin().await.unwrap();
    let (inv, token) = identity::InvitationRepository::create(
        &mut tx,
        inviter,
        email,
        role,
        DEFAULT_INVITATION_TTL,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    (inv.id.0, token)
}

#[tokio::test]
async fn accept_invite_creates_user_and_issues_session() {
    let (app, owner) = app_with_owner().await;
    let (_inv_id, token) =
        seed_pending_invite(&app.pool, owner.id, "alice@test.local", InstanceRole::User).await;

    let resp = app
        .post(
            "/auth/accept-invite",
            None,
            Some(json!({
                "token": token,
                "display_name": "Alice",
                "password": "alicepw",
            })),
        )
        .await;
    resp.assert_status(StatusCode::CREATED);
    let body: LoginBody = resp.json();
    assert!(!body.token.is_empty());

    // The returned session should authenticate.
    let me: MeBody = app.get("/me", Some(&body.token)).await.json();
    assert_eq!(me.email, "alice@test.local");
    assert_eq!(me.instance_role, InstanceRole::User);
}

#[tokio::test]
async fn accept_invite_rejects_invalid_token() {
    let app = TestApp::new().await;
    let resp = app
        .post(
            "/auth/accept-invite",
            None,
            Some(json!({
                "token": "deadbeef".repeat(8),
                "display_name": "X",
                "password": "y",
            })),
        )
        .await;
    resp.assert_status(StatusCode::UNAUTHORIZED)
        .assert_error("invalid_or_expired_token");
}

#[tokio::test]
async fn accept_invite_rejects_expired_token() {
    let (app, owner) = app_with_owner().await;
    let (inv_id, token) =
        seed_pending_invite(&app.pool, owner.id, "exp@test.local", InstanceRole::User).await;

    // Forcibly expire it.
    sqlx::query("UPDATE identity.invitations SET expires_at = now() - interval '1 hour' WHERE id = $1")
        .bind(inv_id)
        .execute(&app.pool)
        .await
        .unwrap();

    let resp = app
        .post(
            "/auth/accept-invite",
            None,
            Some(json!({
                "token": token,
                "display_name": "Exp",
                "password": "pw",
            })),
        )
        .await;
    resp.assert_status(StatusCode::UNAUTHORIZED)
        .assert_error("invalid_or_expired_token");
}

#[tokio::test]
async fn accept_invite_rejects_revoked_token() {
    let (app, owner) = app_with_owner().await;
    let (inv_id, token) =
        seed_pending_invite(&app.pool, owner.id, "rev@test.local", InstanceRole::User).await;

    sqlx::query("UPDATE identity.invitations SET revoked_at = now() WHERE id = $1")
        .bind(inv_id)
        .execute(&app.pool)
        .await
        .unwrap();

    let resp = app
        .post(
            "/auth/accept-invite",
            None,
            Some(json!({
                "token": token,
                "display_name": "Rev",
                "password": "pw",
            })),
        )
        .await;
    resp.assert_status(StatusCode::UNAUTHORIZED)
        .assert_error("invalid_or_expired_token");
}

#[tokio::test]
async fn accept_invite_rejects_already_accepted_token() {
    let (app, owner) = app_with_owner().await;
    let (_inv_id, token) =
        seed_pending_invite(&app.pool, owner.id, "twice@test.local", InstanceRole::User).await;

    // First accept succeeds.
    let first = app
        .post(
            "/auth/accept-invite",
            None,
            Some(json!({
                "token": token,
                "display_name": "T1",
                "password": "pw",
            })),
        )
        .await;
    first.assert_status(StatusCode::CREATED);

    // Second accept with the same token must fail.
    let second = app
        .post(
            "/auth/accept-invite",
            None,
            Some(json!({
                "token": token,
                "display_name": "T2",
                "password": "pw",
            })),
        )
        .await;
    second
        .assert_status(StatusCode::UNAUTHORIZED)
        .assert_error("invalid_or_expired_token");
}

#[tokio::test]
async fn accept_invite_validates_display_name_and_password() {
    let (app, owner) = app_with_owner().await;
    let (_inv_id, token) =
        seed_pending_invite(&app.pool, owner.id, "v@test.local", InstanceRole::User).await;

    let r1 = app
        .post(
            "/auth/accept-invite",
            None,
            Some(json!({
                "token": token,
                "display_name": "   ",
                "password": "pw",
            })),
        )
        .await;
    r1.assert_status(StatusCode::BAD_REQUEST)
        .assert_error("display_name_required");

    let r2 = app
        .post(
            "/auth/accept-invite",
            None,
            Some(json!({
                "token": token,
                "display_name": "Valid",
                "password": "",
            })),
        )
        .await;
    r2.assert_status(StatusCode::BAD_REQUEST)
        .assert_error("password_required");
}

#[tokio::test]
async fn accept_invite_assigns_role_from_invitation() {
    let (app, owner) = app_with_owner().await;
    let (_inv_id, token) = seed_pending_invite(
        &app.pool,
        owner.id,
        "newadmin@test.local",
        InstanceRole::Admin,
    )
    .await;

    let resp = app
        .post(
            "/auth/accept-invite",
            None,
            Some(json!({
                "token": token,
                "display_name": "New Admin",
                "password": "pw",
            })),
        )
        .await;
    resp.assert_status(StatusCode::CREATED);
    let body: LoginBody = resp.json();

    let me: MeBody = app.get("/me", Some(&body.token)).await.json();
    assert_eq!(me.instance_role, InstanceRole::Admin);
}

#[tokio::test]
async fn token_hash_is_what_lives_in_the_db_not_raw() {
    // Defense-in-depth: the raw token must never appear in identity.invitations.
    let (app, owner) = app_with_owner().await;
    let (inv_id, token) =
        seed_pending_invite(&app.pool, owner.id, "h@test.local", InstanceRole::User).await;
    let expected_hash = hash_invite_token(&token);

    let stored: Vec<u8> =
        sqlx::query_scalar("SELECT token_hash FROM identity.invitations WHERE id = $1")
            .bind(inv_id)
            .fetch_one(&app.pool)
            .await
            .unwrap();
    assert_eq!(stored, expected_hash.to_vec());

    // And the raw token does not appear in any column textually.
    let row: Option<String> = sqlx::query_scalar(
        "SELECT email FROM identity.invitations WHERE email LIKE $1 OR email_lower LIKE $1",
    )
    .bind(format!("%{token}%"))
    .fetch_optional(&app.pool)
    .await
    .unwrap();
    assert!(row.is_none(), "raw token leaked into email columns");

    // Future-proofing: also tolerates the (currently-zero) DEFAULT_INVITATION_TTL
    // changing — the row should always be created with a future expires_at.
    let exp: chrono::DateTime<Utc> =
        sqlx::query_scalar("SELECT expires_at FROM identity.invitations WHERE id = $1")
            .bind(inv_id)
            .fetch_one(&app.pool)
            .await
            .unwrap();
    assert!(exp > Utc::now() + Duration::minutes(1));
}
