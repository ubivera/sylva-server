//! gRPC `Account` service (Hub Phase 2b) — bootstrap, login, key material, and
//! device enroll/list/revoke. Binds the gRPC server on an ephemeral port against
//! the bundled-postgres test pool, then drives it with the generated client.
//! Multi-thread runtime: an in-process client+server round-trip deadlocks on a
//! current-thread runtime.

use identity::InstanceRole;
use proto::account::v1::{
    BootstrapRequest, ChangePasswordRequest, DeviceEnrollment, DeviceId, Empty, KeyMaterial,
    LoginRequest, RegisterDeviceRequest, UpdateDisplayNameRequest, UpdateEmailRequest,
    account_client::AccountClient, login_response::Outcome,
};

use crate::common::TestApp;

const PW: &str = "correct-horse-battery";

/// Wrap a message in a request carrying a `Bearer` token.
fn authed<T>(token: &str, msg: T) -> tonic::Request<T> {
    let mut req = tonic::Request::new(msg);
    req.metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    req
}

fn sample_key_material() -> KeyMaterial {
    KeyMaterial {
        x25519_public: vec![1u8; 32],
        ed25519_public: vec![2u8; 32],
        x25519_private_wrapped: vec![3u8; 48],
        ed25519_private_wrapped: vec![4u8; 48],
        master_key_wrapped: vec![5u8; 48],
        kdf_salt: vec![6u8; 16],
        kdf_params: r#"{"m":65536,"t":3,"p":4}"#.to_string(),
    }
}

fn sample_device(label: &str) -> DeviceEnrollment {
    DeviceEnrollment {
        device_label: label.to_string(),
        platform: "windows".to_string(),
        device_public_key: vec![7u8; 32],
        machine_label: "Family-PC".to_string(),
    }
}

fn bootstrap_request() -> BootstrapRequest {
    BootstrapRequest {
        email: "owner@test.local".to_string(),
        display_name: "Olivia".to_string(),
        password: PW.to_string(),
        key_material: Some(sample_key_material()),
        device: Some(sample_device("Olivia's PC")),
    }
}

/// Spin up the gRPC server on `127.0.0.1:0` against the test pool with a
/// generous (default) auth limiter; returns the bound address + a shutdown
/// sender.
async fn spawn_grpc(app: &TestApp) -> (std::net::SocketAddr, tokio::sync::watch::Sender<bool>) {
    spawn_grpc_with_limiter(
        app,
        std::sync::Arc::new(auth::ratelimit::RateLimiter::auth_default()),
    )
    .await
}

/// As [`spawn_grpc`], but with a caller-supplied auth limiter so a test can use
/// a tiny burst to exercise throttling deterministically.
async fn spawn_grpc_with_limiter(
    app: &TestApp,
    auth_rate_limiter: std::sync::Arc<auth::ratelimit::RateLimiter>,
) -> (std::net::SocketAddr, tokio::sync::watch::Sender<bool>) {
    let ctx = platform::PlatformContext {
        sessions: auth::SessionRepository::new(app.pool.clone()),
        users: identity::UserRepository::new(app.pool.clone()),
        resources: platform::resources::ResourceRepository::new(app.pool.clone()),
        user_keys: identity::UserKeyRepository::new(app.pool.clone()),
        devices: identity::DeviceRepository::new(app.pool.clone()),
        pool: app.pool.clone(),
        secret_key: std::sync::Arc::new([0u8; 32]),
        auth_rate_limiter,
        trust_proxy: false,
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, mut rx) = tokio::sync::watch::channel(false);
    tokio::spawn(platform::serve_grpc(ctx, listener, async move {
        let _ = rx.changed().await;
    }));
    (addr, tx)
}

async fn connect(addr: std::net::SocketAddr) -> AccountClient<tonic::transport::Channel> {
    AccountClient::connect(format!("http://{addr}")).await.unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn bootstrap_creates_owner_session_devices_and_keys() {
    let app = TestApp::new().await;
    let (addr, shutdown) = spawn_grpc(&app).await;
    let mut client = connect(addr).await;

    let session = client
        .bootstrap(tonic::Request::new(bootstrap_request()))
        .await
        .unwrap()
        .into_inner();
    assert!(!session.token.is_empty());
    let user_id = uuid::Uuid::parse_str(&session.user_id).expect("user_id is a UUID");

    // The first account is the Owner, with a key bundle persisted.
    let (role,): (String,) =
        sqlx::query_as("SELECT instance_role::text FROM identity.users WHERE id = $1")
            .bind(user_id)
            .fetch_one(&app.pool)
            .await
            .unwrap();
    assert_eq!(role, "owner");
    let (key_rows,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM identity.user_keys")
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(key_rows, 1);

    // The session token works: the bootstrap device is the one enrolled device.
    let devices = client
        .list_my_devices(authed(&session.token, Empty {}))
        .await
        .unwrap()
        .into_inner()
        .devices;
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].device_label, "Olivia's PC");
    assert_eq!(devices[0].platform, "windows");
    assert!(!devices[0].machine_id.is_empty(), "device linked to a machine");
    assert!(devices[0].revoked_at.is_empty(), "active device");

    // GetKeyMaterial returns exactly the ciphertext + public keys we handed in.
    let km = client
        .get_key_material(authed(&session.token, Empty {}))
        .await
        .unwrap()
        .into_inner()
        .key_material
        .expect("key material present");
    assert_eq!(km.master_key_wrapped, vec![5u8; 48]);
    assert_eq!(km.x25519_public, vec![1u8; 32]);
    assert_eq!(km.kdf_params, r#"{"m":65536,"t":3,"p":4}"#);

    // The bootstrap emitted an `owner_bootstrapped` audit event.
    let (events,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM audit.events WHERE event_type = 'owner_bootstrapped'")
            .fetch_one(&app.pool)
            .await
            .unwrap();
    assert_eq!(events, 1);

    let _ = shutdown.send(true);
}

#[tokio::test(flavor = "multi_thread")]
async fn bootstrap_rejected_when_a_user_exists() {
    let app = TestApp::new().await;
    app.seed_user("someone@test.local", "Sam", "pw", InstanceRole::Member)
        .await;
    let (addr, shutdown) = spawn_grpc(&app).await;
    let mut client = connect(addr).await;

    let err = client
        .bootstrap(tonic::Request::new(bootstrap_request()))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);

    let _ = shutdown.send(true);
}

#[tokio::test(flavor = "multi_thread")]
async fn bootstrap_validates_required_fields() {
    let app = TestApp::new().await;
    let (addr, shutdown) = spawn_grpc(&app).await;
    let mut client = connect(addr).await;

    // Missing key material.
    let mut req = bootstrap_request();
    req.key_material = None;
    let err = client.bootstrap(tonic::Request::new(req)).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);

    // Missing device.
    let mut req = bootstrap_request();
    req.device = None;
    let err = client.bootstrap(tonic::Request::new(req)).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);

    // Blank email.
    let mut req = bootstrap_request();
    req.email = "   ".to_string();
    let err = client.bootstrap(tonic::Request::new(req)).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);

    // A failed bootstrap left no user behind.
    let (users,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM identity.users")
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(users, 0);

    let _ = shutdown.send(true);
}

#[tokio::test(flavor = "multi_thread")]
async fn login_succeeds_and_rejects_bad_credentials() {
    let app = TestApp::new().await;
    let (addr, shutdown) = spawn_grpc(&app).await;
    let mut client = connect(addr).await;

    client
        .bootstrap(tonic::Request::new(bootstrap_request()))
        .await
        .unwrap();

    // Correct credentials → a session.
    let resp = client
        .login(tonic::Request::new(LoginRequest {
            email: "owner@test.local".to_string(),
            password: PW.to_string(),
            mfa_challenge_token: String::new(),
            mfa_response: Vec::new(),
        }))
        .await
        .unwrap()
        .into_inner();
    let session = match resp.outcome {
        Some(Outcome::Session(s)) => s,
        other => panic!("expected a session, got {other:?}"),
    };
    assert!(!session.token.is_empty());
    // The minted token authenticates a real RPC.
    client
        .list_my_devices(authed(&session.token, Empty {}))
        .await
        .unwrap();

    // Wrong password → unauthenticated.
    let err = client
        .login(tonic::Request::new(LoginRequest {
            email: "owner@test.local".to_string(),
            password: "wrong".to_string(),
            mfa_challenge_token: String::new(),
            mfa_response: Vec::new(),
        }))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated);

    // Unknown email → unauthenticated (no account enumeration over the wire).
    let err = client
        .login(tonic::Request::new(LoginRequest {
            email: "nobody@test.local".to_string(),
            password: PW.to_string(),
            mfa_challenge_token: String::new(),
            mfa_response: Vec::new(),
        }))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated);

    // Blank email → invalid argument.
    let err = client
        .login(tonic::Request::new(LoginRequest {
            email: "  ".to_string(),
            password: PW.to_string(),
            mfa_challenge_token: String::new(),
            mfa_response: Vec::new(),
        }))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);

    let _ = shutdown.send(true);
}

#[tokio::test(flavor = "multi_thread")]
async fn register_list_revoke_device_flow() {
    let app = TestApp::new().await;
    let (addr, shutdown) = spawn_grpc(&app).await;
    let mut client = connect(addr).await;

    let session = client
        .bootstrap(tonic::Request::new(bootstrap_request()))
        .await
        .unwrap()
        .into_inner();
    let token = session.token;

    // Enroll a second device.
    let second = client
        .register_device(authed(
            &token,
            RegisterDeviceRequest {
                device: Some(sample_device("Olivia's Laptop")),
            },
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(second.device_label, "Olivia's Laptop");

    // Both devices list (active), oldest first.
    let listed = client
        .list_my_devices(authed(&token, Empty {}))
        .await
        .unwrap()
        .into_inner()
        .devices;
    assert_eq!(listed.len(), 2);
    assert_eq!(listed[0].device_label, "Olivia's PC");
    assert_eq!(listed[1].device_label, "Olivia's Laptop");

    // Revoke the laptop → it drops out of the active list.
    client
        .revoke_device(authed(
            &token,
            DeviceId {
                device_id: second.device_id.clone(),
            },
        ))
        .await
        .unwrap();
    let after = client
        .list_my_devices(authed(&token, Empty {}))
        .await
        .unwrap()
        .into_inner()
        .devices;
    assert_eq!(after.len(), 1);
    assert_eq!(after[0].device_label, "Olivia's PC");

    // Revoking again → not found (already revoked).
    let err = client
        .revoke_device(authed(
            &token,
            DeviceId {
                device_id: second.device_id.clone(),
            },
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::NotFound);

    // An unknown device id → not found; a non-UUID → invalid argument.
    let err = client
        .revoke_device(authed(
            &token,
            DeviceId {
                device_id: uuid::Uuid::new_v4().to_string(),
            },
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::NotFound);
    let err = client
        .revoke_device(authed(
            &token,
            DeviceId {
                device_id: "not-a-uuid".to_string(),
            },
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);

    let _ = shutdown.send(true);
}

#[tokio::test(flavor = "multi_thread")]
async fn account_rpcs_require_auth() {
    let app = TestApp::new().await;
    let (addr, shutdown) = spawn_grpc(&app).await;
    let mut client = connect(addr).await;

    let codes = [
        client
            .get_key_material(tonic::Request::new(Empty {}))
            .await
            .unwrap_err()
            .code(),
        client
            .list_my_devices(tonic::Request::new(Empty {}))
            .await
            .unwrap_err()
            .code(),
        client
            .register_device(tonic::Request::new(RegisterDeviceRequest {
                device: Some(sample_device("X")),
            }))
            .await
            .unwrap_err()
            .code(),
        client
            .revoke_device(tonic::Request::new(DeviceId {
                device_id: uuid::Uuid::new_v4().to_string(),
            }))
            .await
            .unwrap_err()
            .code(),
    ];
    for code in codes {
        assert_eq!(code, tonic::Code::Unauthenticated);
    }

    let _ = shutdown.send(true);
}

#[tokio::test(flavor = "multi_thread")]
async fn login_is_rate_limited_per_ip() {
    let app = TestApp::new().await;
    // A tiny burst (3) with no refill makes throttling deterministic.
    let limiter = std::sync::Arc::new(auth::ratelimit::RateLimiter::new(3, 0.0));
    let (addr, shutdown) = spawn_grpc_with_limiter(&app, limiter).await;
    let mut client = connect(addr).await;

    // Bootstrap succeeds (success doesn't consume the bucket).
    client
        .bootstrap(tonic::Request::new(bootstrap_request()))
        .await
        .unwrap();

    let wrong = || LoginRequest {
        email: "owner@test.local".to_string(),
        password: "wrong".to_string(),
        mfa_challenge_token: String::new(),
        mfa_response: Vec::new(),
    };

    // The burst of wrong-password attempts is rejected as unauthenticated.
    for _ in 0..3 {
        let err = client.login(tonic::Request::new(wrong())).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    // Once the bucket is drained, further attempts are throttled *before* the
    // password is checked — so even the correct password is refused.
    let err = client.login(tonic::Request::new(wrong())).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::ResourceExhausted);
    let err = client
        .login(tonic::Request::new(LoginRequest {
            email: "owner@test.local".to_string(),
            password: PW.to_string(),
            mfa_challenge_token: String::new(),
            mfa_response: Vec::new(),
        }))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::ResourceExhausted);

    let _ = shutdown.send(true);
}

// ── Account self-service ───────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn get_and_update_profile_round_trips() {
    let app = TestApp::new().await;
    let (addr, shutdown) = spawn_grpc(&app).await;
    let mut client = connect(addr).await;

    let session = client
        .bootstrap(tonic::Request::new(bootstrap_request()))
        .await
        .unwrap()
        .into_inner();
    let token = session.token;

    // GetProfile reflects the bootstrapped owner.
    let profile = client
        .get_profile(authed(&token, Empty {}))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(profile.user_id, session.user_id);
    assert_eq!(profile.email, "owner@test.local");
    assert_eq!(profile.display_name, "Olivia");
    assert_eq!(profile.instance_role, "owner");

    // UpdateDisplayName changes it and returns the updated profile…
    let updated = client
        .update_display_name(authed(
            &token,
            UpdateDisplayNameRequest {
                display_name: "Liv".to_string(),
            },
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(updated.display_name, "Liv");
    // …and a re-GetProfile confirms it persisted.
    let after = client
        .get_profile(authed(&token, Empty {}))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(after.display_name, "Liv");

    // A blank display name is rejected.
    let err = client
        .update_display_name(authed(
            &token,
            UpdateDisplayNameRequest {
                display_name: "   ".to_string(),
            },
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);

    // An `display_name_changed` audit event was recorded.
    let (events,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM audit.events WHERE event_type = 'display_name_changed'",
    )
    .fetch_one(&app.pool)
    .await
    .unwrap();
    assert_eq!(events, 1);

    let _ = shutdown.send(true);
}

#[tokio::test(flavor = "multi_thread")]
async fn update_email_requires_the_current_password() {
    let app = TestApp::new().await;
    let (addr, shutdown) = spawn_grpc(&app).await;
    let mut client = connect(addr).await;

    let session = client
        .bootstrap(tonic::Request::new(bootstrap_request()))
        .await
        .unwrap()
        .into_inner();
    let token = session.token;

    // Wrong current password → unauthenticated (and the email is unchanged).
    let err = client
        .update_email(authed(
            &token,
            UpdateEmailRequest {
                new_email: "new@test.local".to_string(),
                current_password: "wrong".to_string(),
            },
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated);

    // Right password → the email changes.
    let updated = client
        .update_email(authed(
            &token,
            UpdateEmailRequest {
                new_email: "new@test.local".to_string(),
                current_password: PW.to_string(),
            },
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(updated.email, "new@test.local");
    let (email,): (String,) =
        sqlx::query_as("SELECT email FROM identity.users WHERE id = $1")
            .bind(uuid::Uuid::parse_str(&session.user_id).unwrap())
            .fetch_one(&app.pool)
            .await
            .unwrap();
    assert_eq!(email, "new@test.local");

    // An email already in use by another account → already_exists.
    app.seed_user("taken@test.local", "Sam", "pw", InstanceRole::Member)
        .await;
    let err = client
        .update_email(authed(
            &token,
            UpdateEmailRequest {
                new_email: "taken@test.local".to_string(),
                current_password: PW.to_string(),
            },
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::AlreadyExists);

    let _ = shutdown.send(true);
}

#[tokio::test(flavor = "multi_thread")]
async fn change_password_updates_verifier_and_key_wrap() {
    let app = TestApp::new().await;
    let (addr, shutdown) = spawn_grpc(&app).await;
    let mut client = connect(addr).await;

    let session = client
        .bootstrap(tonic::Request::new(bootstrap_request()))
        .await
        .unwrap()
        .into_inner();
    let token = session.token;
    let user_id = uuid::Uuid::parse_str(&session.user_id).unwrap();

    // Wrong current password → unauthenticated.
    let err = client
        .change_password(authed(
            &token,
            ChangePasswordRequest {
                current_password: "wrong".to_string(),
                new_password: "new-secret".to_string(),
                new_master_key_wrapped: vec![9u8; 72],
                new_kdf_salt: vec![8u8; 16],
                new_kdf_params: r#"{"m":65536,"t":3,"p":4}"#.to_string(),
            },
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated);

    // The original verifier still verifies the old password (the failed attempt
    // changed nothing).
    let (hash_before,): (String,) =
        sqlx::query_as("SELECT password_hash FROM auth.credentials WHERE user_id = $1")
            .bind(user_id)
            .fetch_one(&app.pool)
            .await
            .unwrap();
    assert!(auth::verify_user_password(&app.pool, identity::UserId::new(user_id), PW)
        .await
        .unwrap());

    // Right current password → the verifier is recomputed and the key wrap rotates.
    client
        .change_password(authed(
            &token,
            ChangePasswordRequest {
                current_password: PW.to_string(),
                new_password: "new-secret".to_string(),
                new_master_key_wrapped: vec![9u8; 72],
                new_kdf_salt: vec![8u8; 16],
                new_kdf_params: r#"{"m":1,"t":1,"p":1}"#.to_string(),
            },
        ))
        .await
        .unwrap();

    // The server-side verifier now accepts the new password, not the old one.
    assert!(auth::verify_user_password(&app.pool, identity::UserId::new(user_id), "new-secret")
        .await
        .unwrap());
    assert!(!auth::verify_user_password(&app.pool, identity::UserId::new(user_id), PW)
        .await
        .unwrap());
    let (hash_after,): (String,) =
        sqlx::query_as("SELECT password_hash FROM auth.credentials WHERE user_id = $1")
            .bind(user_id)
            .fetch_one(&app.pool)
            .await
            .unwrap();
    assert_ne!(hash_before, hash_after, "the verifier was recomputed");

    // The re-wrapped master key + salt + params landed in user_keys.
    let (wrapped, salt, params): (Vec<u8>, Vec<u8>, String) = sqlx::query_as(
        "SELECT master_key_wrapped, kdf_salt, kdf_params FROM identity.user_keys WHERE user_id = $1",
    )
    .bind(user_id)
    .fetch_one(&app.pool)
    .await
    .unwrap();
    assert_eq!(wrapped, vec![9u8; 72]);
    assert_eq!(salt, vec![8u8; 16]);
    assert_eq!(params, r#"{"m":1,"t":1,"p":1}"#);
    // The private-key wraps are untouched (only the master-key wrap rotates).
    let (x_priv,): (Vec<u8>,) =
        sqlx::query_as("SELECT x25519_private_wrapped FROM identity.user_keys WHERE user_id = $1")
            .bind(user_id)
            .fetch_one(&app.pool)
            .await
            .unwrap();
    assert_eq!(x_priv, vec![3u8; 48], "private-key wrap unchanged");

    // The new password now logs in (end-to-end verifier swap).
    let resp = client
        .login(tonic::Request::new(LoginRequest {
            email: "owner@test.local".to_string(),
            password: "new-secret".to_string(),
            mfa_challenge_token: String::new(),
            mfa_response: Vec::new(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(matches!(resp.outcome, Some(Outcome::Session(_))));

    let _ = shutdown.send(true);
}

#[tokio::test(flavor = "multi_thread")]
async fn self_service_rpcs_require_auth() {
    let app = TestApp::new().await;
    let (addr, shutdown) = spawn_grpc(&app).await;
    let mut client = connect(addr).await;

    let codes = [
        client
            .get_profile(tonic::Request::new(Empty {}))
            .await
            .unwrap_err()
            .code(),
        client
            .update_display_name(tonic::Request::new(UpdateDisplayNameRequest {
                display_name: "X".to_string(),
            }))
            .await
            .unwrap_err()
            .code(),
        client
            .update_email(tonic::Request::new(UpdateEmailRequest {
                new_email: "x@test.local".to_string(),
                current_password: PW.to_string(),
            }))
            .await
            .unwrap_err()
            .code(),
        client
            .change_password(tonic::Request::new(ChangePasswordRequest {
                current_password: PW.to_string(),
                new_password: "y".to_string(),
                new_master_key_wrapped: vec![1u8; 8],
                new_kdf_salt: vec![2u8; 8],
                new_kdf_params: "{}".to_string(),
            }))
            .await
            .unwrap_err()
            .code(),
    ];
    for code in codes {
        assert_eq!(code, tonic::Code::Unauthenticated);
    }

    let _ = shutdown.send(true);
}
