//! Cross-stack end-to-end test (Hub build spec Phase 3.7): the **real**
//! `sylva-sdk` client driven against a **real**, live Hearth — discovery over
//! actual HTTP, the enrollment flows over actual gRPC, real server-side crypto
//! storage. Proves the full client crypto + wire path before any UI.
//!
//! Gated behind the `e2e` feature so the standard suite never pulls the SDK:
//!   cargo test -p hearth --features e2e --test integration sdk_e2e

use sylva_sdk::crypto::KdfParams;
use sylva_sdk::flows::{self, NewOwner};
use sylva_sdk::proto::account::v1 as pb;
use sylva_sdk::transport::{client, discovery};

use super::common::TestApp;

/// Cheap KDF for the test (the round-trip, not the cost factor, is under test).
fn fast() -> KdfParams {
    KdfParams {
        m_cost_kib: 64,
        t_cost: 1,
        p_cost: 1,
    }
}

/// Serve Hearth's real gRPC services on an ephemeral port against the test pool;
/// returns `host:port` + a shutdown sender.
async fn spawn_grpc(app: &TestApp) -> (String, tokio::sync::watch::Sender<bool>) {
    let ctx = platform::PlatformContext {
        sessions: auth::SessionRepository::new(app.pool.clone()),
        users: identity::UserRepository::new(app.pool.clone()),
        resources: platform::resources::ResourceRepository::new(app.pool.clone()),
        user_keys: identity::UserKeyRepository::new(app.pool.clone()),
        devices: identity::DeviceRepository::new(app.pool.clone()),
        pool: app.pool.clone(),
        secret_key: std::sync::Arc::new([0u8; 32]),
        auth_rate_limiter: std::sync::Arc::new(auth::ratelimit::RateLimiter::auth_default()),
        trust_proxy: false,
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, mut rx) = tokio::sync::watch::channel(false);
    tokio::spawn(platform::serve_grpc(ctx, listener, async move {
        let _ = rx.changed().await;
    }));
    (addr.to_string(), tx)
}

/// Serve Hearth's real HTTP router (which carries `/.well-known/hearth-discovery`)
/// on an ephemeral port; returns the base URL + the server task handle.
async fn spawn_http(app: &TestApp) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = app.router.clone();
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, router.into_make_service()).await;
    });
    (format!("http://{addr}"), handle)
}

#[tokio::test(flavor = "multi_thread")]
async fn sdk_discovers_and_verifies_the_real_server() {
    let app = TestApp::new().await;
    let (base_url, server) = spawn_http(&app).await;

    // The SDK fetches + verifies the real signed discovery response.
    let verified = discovery::fetch_and_verify(&base_url).await.unwrap();

    // It recovered the server's actual identity key (the one TestApp generated).
    let (stored,): (Option<Vec<u8>>, ) = sqlx::query_as(
        "SELECT server_identity_public FROM hearth_meta.instance WHERE id = TRUE",
    )
    .fetch_one(&app.pool)
    .await
    .unwrap();
    let stored = stored.expect("server identity generated at startup");
    assert_eq!(verified.identity_public.to_vec(), stored);

    // TOFU: first contact pins; the matching pin verifies; a wrong pin doesn't.
    assert_eq!(
        discovery::check_pin(&verified, None),
        discovery::TrustDecision::FirstContact
    );
    let pinned: [u8; 32] = stored.try_into().unwrap();
    assert_eq!(
        discovery::check_pin(&verified, Some(&pinned)),
        discovery::TrustDecision::Matches
    );
    assert_eq!(
        discovery::check_pin(&verified, Some(&[0u8; 32])),
        discovery::TrustDecision::Mismatch
    );

    server.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn sdk_enrolls_logs_in_and_manages_devices_end_to_end() {
    let app = TestApp::new().await;
    let (grpc_addr, shutdown) = spawn_grpc(&app).await;
    let channel = client::connect(&[grpc_addr]).await.unwrap();

    // ── Enroll the first owner: real client-side 2SKD → real server storage ──
    let enrolled = flows::enroll_new_owner_with_params(
        channel.clone(),
        NewOwner {
            email: "owner@e2e.local",
            display_name: "Olivia",
            password: "pw-e2e",
            device_label: "Olivia's PC",
            platform: "windows",
            machine_label: "Family-PC",
        },
        fast(),
    )
    .await
    .unwrap();
    assert!(!enrolled.user_id.is_empty());
    // The Secret Key was generated for write-down (8 Crockford groups).
    assert_eq!(enrolled.secret_key.display().split('-').count(), 8);

    // The server actually persisted the owner + the wrapped key bundle.
    let (owners,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM identity.users WHERE instance_role = 'owner'")
            .fetch_one(&app.pool)
            .await
            .unwrap();
    assert_eq!(owners, 1);
    let (key_rows,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM identity.user_keys")
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(key_rows, 1);

    // ── Log in fresh: fetch the wrapped material + unlock with password + Secret Key ──
    let mut session = flows::login(channel.clone(), "owner@e2e.local", "pw-e2e", &enrolled.secret_key)
        .await
        .unwrap();
    // THE round-trip proof: the master key unlocked from the server's stored
    // ciphertext is byte-identical to the one generated client-side at enroll.
    assert_eq!(
        session.identity.master_key.as_bytes(),
        enrolled.identity.master_key.as_bytes()
    );

    // ── Devices: bootstrap enrolled one; enroll a second; revoke it ──
    let devices = session.account.list_devices().await.unwrap();
    assert_eq!(devices.len(), 1, "the bootstrap device");
    assert_eq!(devices[0].device_label, "Olivia's PC");

    let second = session
        .account
        .register_device(pb::DeviceEnrollment {
            device_label: "Laptop".to_string(),
            platform: "windows".to_string(),
            device_public_key: vec![8u8; 32],
            machine_label: "Family-PC".to_string(),
        })
        .await
        .unwrap();
    assert_eq!(session.account.list_devices().await.unwrap().len(), 2);

    session.account.revoke_device(second.device_id).await.unwrap();
    assert_eq!(session.account.list_devices().await.unwrap().len(), 1);

    let _ = shutdown.send(true);
}

#[tokio::test(flavor = "multi_thread")]
async fn sdk_login_with_wrong_secret_key_is_rejected_locally() {
    let app = TestApp::new().await;
    let (grpc_addr, shutdown) = spawn_grpc(&app).await;
    let channel = client::connect(&[grpc_addr]).await.unwrap();

    flows::enroll_new_owner_with_params(
        channel.clone(),
        NewOwner {
            email: "owner@e2e.local",
            display_name: "Olivia",
            password: "pw-e2e",
            device_label: "PC",
            platform: "windows",
            machine_label: "M",
        },
        fast(),
    )
    .await
    .unwrap();

    // Correct password (server auth passes) but a wrong Secret Key → the local
    // unlock fails. Demonstrates the server alone can't grant data access.
    let result = flows::login(
        channel,
        "owner@e2e.local",
        "pw-e2e",
        &sylva_sdk::crypto::SecretKey::generate(),
    )
    .await;
    assert!(matches!(result, Err(flows::EnrollError::Crypto(_))));

    let _ = shutdown.send(true);
}
