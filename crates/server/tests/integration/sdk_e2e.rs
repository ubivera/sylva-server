//! Cross-stack end-to-end test (Hub build spec Phase 3.7): the **real**
//! `sylva-sdk` client driven against a **real**, live server — discovery over
//! actual HTTP, the enrollment flows over actual gRPC, real server-side crypto
//! storage. Proves the full client crypto + wire path before any UI.
//!
//! Gated behind the `e2e` feature so the standard suite never pulls the SDK:
//!   cargo test -p server --features e2e --test integration sdk_e2e

use ed25519_dalek::{Signer, SigningKey};
use sylva_sdk::crypto::KdfParams;
use sylva_sdk::flows::{self, NewOwner};
use sylva_sdk::proto::account::v1 as pb;
use sylva_sdk::proto::machine::v1 as mb;
use sylva_sdk::proto::machine::v1::machine_client::MachineClient;
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

/// Serve server's real gRPC services on an ephemeral port against the test pool;
/// returns `host:port` + a shutdown sender.
async fn spawn_grpc(app: &TestApp) -> (String, tokio::sync::watch::Sender<bool>) {
    let ctx = platform::PlatformContext {
        sessions: auth::SessionRepository::new(app.pool.clone()),
        users: identity::UserRepository::new(app.pool.clone()),
        resources: platform::resources::ResourceRepository::new(app.pool.clone()),
        user_keys: identity::UserKeyRepository::new(app.pool.clone()),
        devices: identity::DeviceRepository::new(app.pool.clone()),
        user_avatars: identity::UserAvatarRepository::new(app.pool.clone()),
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

/// Serve server's real HTTP router (which carries `/.well-known/sylva-discovery`)
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
        "SELECT server_identity_public FROM sylva_meta.instance WHERE id = TRUE",
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

// ── Machine agent (slice 2, CP1 spine) ──────────────────────────────────────

/// The bytes the agent signs at registration (must match the server's
/// `canonical_machine_bytes`).
fn canonical_machine_bytes(public: &[u8], platform: &str, label: &str) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(b"sylva-machine-registration:v1\n");
    v.extend_from_slice(public);
    v.push(b'\n');
    v.extend_from_slice(platform.as_bytes());
    v.push(b'\n');
    v.extend_from_slice(label.as_bytes());
    v
}

fn machine_authed<T>(token: &str, msg: T) -> tonic::Request<T> {
    let mut req = tonic::Request::new(msg);
    req.metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    req
}

/// The full agent spine against a real server: discover + TOFU-pin over real
/// HTTP, then register (with Ed25519 proof-of-possession) + check in + consume
/// the push stream over real gRPC — driving the **SDK's** Machine client + the
/// SDK's discovery, the exact code paths `sylva-agent` runs.
#[tokio::test(flavor = "multi_thread")]
async fn machine_agent_registers_checks_in_and_subscribes_end_to_end() {
    let app = TestApp::new().await;
    let (base_url, http) = spawn_http(&app).await;
    let (grpc_addr, shutdown) = spawn_grpc(&app).await;

    // 1. Discovery + TOFU (the agent's first step): the SDK fetches + verifies the
    //    real signed discovery response, and first contact pins / a match verifies.
    let verified = discovery::fetch_and_verify(&base_url).await.unwrap();
    assert_eq!(
        discovery::check_pin(&verified, None),
        discovery::TrustDecision::FirstContact
    );
    assert_eq!(
        discovery::check_pin(&verified, Some(&verified.identity_public)),
        discovery::TrustDecision::Matches
    );

    // 2. Register the machine over gRPC with a real Ed25519 proof-of-possession.
    let channel = client::connect(&[grpc_addr]).await.unwrap();
    let mut machine = MachineClient::new(channel);
    let signing_key = SigningKey::from_bytes(&[5u8; 32]);
    let public = signing_key.verifying_key().to_bytes();
    let signature = signing_key
        .sign(&canonical_machine_bytes(&public, "windows", "Family-PC"))
        .to_bytes()
        .to_vec();
    let session = machine
        .register_machine(tonic::Request::new(mb::RegisterMachineRequest {
            machine_identity_public: public.to_vec(),
            platform: "windows".to_string(),
            label: "Family-PC".to_string(),
            signature,
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(!session.token.is_empty());

    // 3. Check in (authed) + 4. subscribe (authed) — the first push is the config.
    machine
        .check_in(machine_authed(
            &session.token,
            mb::CheckInRequest {
                agent_version: "0.0.1".to_string(),
            },
        ))
        .await
        .unwrap();
    let mut stream = machine
        .subscribe(machine_authed(&session.token, mb::Empty {}))
        .await
        .unwrap()
        .into_inner();
    let first = stream.message().await.unwrap().expect("a server push");
    assert!(matches!(
        first.payload,
        Some(mb::server_push::Payload::Config(_))
    ));

    // The server persisted the machine (identity key + a recorded check-in).
    let (machines,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM identity.machines \
         WHERE machine_identity_public IS NOT NULL AND last_seen_at IS NOT NULL",
    )
    .fetch_one(&app.pool)
    .await
    .unwrap();
    assert_eq!(machines, 1);

    let _ = shutdown.send(true);
    http.abort();
}

/// The full telemetry path (CP3): an admin enables location + provisions a
/// device-admin group key; the agent reads that from `Subscribe`, seals a
/// location fix to the group key, and reports it; the server stores only
/// ciphertext; an admin holding the group secret decrypts it. Exercises the
/// SDK's sealed-box crypto + the server's zero-knowledge storage end to end.
#[tokio::test(flavor = "multi_thread")]
async fn machine_telemetry_seals_to_group_and_admin_decrypts_end_to_end() {
    let app = TestApp::new().await;
    let (grpc_addr, shutdown) = spawn_grpc(&app).await;
    let channel = client::connect(&[grpc_addr]).await.unwrap();
    let mut machine = MachineClient::new(channel);

    // Register the machine.
    let signing_key = SigningKey::from_bytes(&[6u8; 32]);
    let public = signing_key.verifying_key().to_bytes();
    let signature = signing_key
        .sign(&canonical_machine_bytes(&public, "windows", "Family-PC"))
        .to_bytes()
        .to_vec();
    let session = machine
        .register_machine(tonic::Request::new(mb::RegisterMachineRequest {
            machine_identity_public: public.to_vec(),
            platform: "windows".to_string(),
            label: "Family-PC".to_string(),
            signature,
        }))
        .await
        .unwrap()
        .into_inner();
    let machine_id = uuid::Uuid::parse_str(&session.machine_id).unwrap();

    // Admin policy (dev SQL until the client-app panel exists): provision a
    // device-admin group key + enable location for this machine.
    let group = sylva_sdk::crypto::generate_group_keypair();
    sqlx::query("INSERT INTO identity.device_admin_group (group_public) VALUES ($1)")
        .bind(group.public.as_slice())
        .execute(&app.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE identity.machines SET location_enabled = true WHERE id = $1")
        .bind(machine_id)
        .execute(&app.pool)
        .await
        .unwrap();

    // The agent reads its effective config from the push stream.
    let mut stream = machine
        .subscribe(machine_authed(&session.token, mb::Empty {}))
        .await
        .unwrap()
        .into_inner();
    let config = loop {
        match stream.message().await.unwrap().expect("a push").payload {
            Some(mb::server_push::Payload::Config(cfg)) => break cfg,
            _ => continue,
        }
    };
    assert!(config.location_enabled);
    let group_public: [u8; 32] = config.device_admin_group_public.as_slice().try_into().unwrap();
    assert_eq!(group_public, group.public);

    // The agent seals a location fix to the group key and reports it.
    let location = br#"{"lat":35.594566,"lon":-77.408395,"accuracy_m":27.0}"#;
    let ciphertext = sylva_sdk::crypto::seal_to(&group_public, location).unwrap();
    machine
        .report_telemetry(machine_authed(
            &session.token,
            mb::ReportTelemetryRequest {
                blobs: vec![mb::TelemetryBlob {
                    kind: "location".to_string(),
                    recipient_key_id: config.group_key_id.clone(),
                    seq: 1,
                    ciphertext,
                    signature: Vec::new(),
                }],
            },
        ))
        .await
        .unwrap();

    // The server stored only ciphertext; an admin with the group secret decrypts it.
    let (kind, stored): (String, Vec<u8>) = sqlx::query_as(
        "SELECT kind, ciphertext FROM identity.machine_telemetry WHERE machine_id = $1",
    )
    .bind(machine_id)
    .fetch_one(&app.pool)
    .await
    .unwrap();
    assert_eq!(kind, "location");
    assert_ne!(stored, location, "server stores ciphertext, not plaintext");
    let decrypted = sylva_sdk::crypto::open_sealed(&group.secret, &stored).unwrap();
    assert_eq!(decrypted, location);

    let _ = shutdown.send(true);
}
