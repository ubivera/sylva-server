//! gRPC `Machine` service (Hub slice 2, CP1 spine) — machine registration with
//! Ed25519 proof-of-possession, liveness check-in, and the keep-alive subscribe
//! stream. Binds the gRPC server on an ephemeral port against bundled-postgres,
//! then drives it with the generated client. Multi-thread runtime: an in-process
//! client+server round-trip deadlocks on a current-thread runtime.

use ed25519_dalek::{Signer, SigningKey};
use proto::machine::v1::{
    CheckInRequest, Empty, RegisterMachineRequest, ReportTelemetryRequest, TelemetryBlob,
    machine_client::MachineClient, server_push,
};

use crate::common::TestApp;

/// Wrap a message in a request carrying a `Bearer` token.
fn authed<T>(token: &str, msg: T) -> tonic::Request<T> {
    let mut req = tonic::Request::new(msg);
    req.metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    req
}

/// A deterministic machine keypair (seed → Ed25519); returns the key + its
/// 32-byte public bytes.
fn machine_keypair(seed: u8) -> (SigningKey, Vec<u8>) {
    let sk = SigningKey::from_bytes(&[seed; 32]);
    let pk = sk.verifying_key().to_bytes().to_vec();
    (sk, pk)
}

/// The bytes the server expects a machine to sign (must match the server's
/// `canonical_machine_bytes`).
fn canonical(public: &[u8], platform: &str, label: &str) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(b"sylva-machine-registration:v1\n");
    v.extend_from_slice(public);
    v.push(b'\n');
    v.extend_from_slice(platform.as_bytes());
    v.push(b'\n');
    v.extend_from_slice(label.as_bytes());
    v
}

fn register_request(
    sk: &SigningKey,
    public: &[u8],
    platform: &str,
    label: &str,
) -> RegisterMachineRequest {
    let signature = sk
        .sign(&canonical(public, platform, label))
        .to_bytes()
        .to_vec();
    RegisterMachineRequest {
        machine_identity_public: public.to_vec(),
        platform: platform.to_string(),
        label: label.to_string(),
        signature,
    }
}

async fn spawn_grpc(app: &TestApp) -> (std::net::SocketAddr, tokio::sync::watch::Sender<bool>) {
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
    (addr, tx)
}

async fn connect(addr: std::net::SocketAddr) -> MachineClient<tonic::transport::Channel> {
    MachineClient::connect(format!("http://{addr}"))
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn register_check_in_and_subscribe() {
    let app = TestApp::new().await;
    let (addr, shutdown) = spawn_grpc(&app).await;
    let mut client = connect(addr).await;

    let (sk, pk) = machine_keypair(7);

    // Register → a machine id + session token.
    let session = client
        .register_machine(tonic::Request::new(register_request(
            &sk, &pk, "windows", "Family-PC",
        )))
        .await
        .unwrap()
        .into_inner();
    assert!(!session.token.is_empty());
    let machine_id = uuid::Uuid::parse_str(&session.machine_id).expect("machine_id is a UUID");

    // The machine row carries the identity key.
    let (count,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM identity.machines \
         WHERE id = $1 AND machine_identity_public IS NOT NULL",
    )
    .bind(machine_id)
    .fetch_one(&app.pool)
    .await
    .unwrap();
    assert_eq!(count, 1);

    // Re-register (same key) is idempotent — still one row, same id.
    let again = client
        .register_machine(tonic::Request::new(register_request(
            &sk,
            &pk,
            "windows",
            "Family-PC-renamed",
        )))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(again.machine_id, session.machine_id);
    let (machines,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM identity.machines")
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(machines, 1);

    // Check-in (authed) bumps last_seen_at + records the agent version.
    client
        .check_in(authed(
            &session.token,
            CheckInRequest {
                agent_version: "0.1.0".to_string(),
            },
        ))
        .await
        .unwrap();
    let (has_seen, agent_version): (bool, Option<String>) = sqlx::query_as(
        "SELECT last_seen_at IS NOT NULL, agent_version FROM identity.machines WHERE id = $1",
    )
    .bind(machine_id)
    .fetch_one(&app.pool)
    .await
    .unwrap();
    assert!(has_seen);
    assert_eq!(agent_version.as_deref(), Some("0.1.0"));

    // Registration emitted a `machine_registered` audit event.
    let (events,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM audit.events WHERE event_type = 'machine_registered'",
    )
    .fetch_one(&app.pool)
    .await
    .unwrap();
    assert!(events >= 1);

    // Subscribe (authed) → the first push is the config.
    let mut stream = client
        .subscribe(authed(&session.token, Empty {}))
        .await
        .unwrap()
        .into_inner();
    let first = stream
        .message()
        .await
        .unwrap()
        .expect("a server push");
    match first.payload {
        Some(server_push::Payload::Config(cfg)) => assert!(!cfg.location_enabled),
        other => panic!("expected a config push, got {other:?}"),
    }

    let _ = shutdown.send(true);
}

#[tokio::test(flavor = "multi_thread")]
async fn register_rejects_bad_signature() {
    let app = TestApp::new().await;
    let (addr, shutdown) = spawn_grpc(&app).await;
    let mut client = connect(addr).await;

    let (_sk, pk) = machine_keypair(9);
    let (wrong_key, _) = machine_keypair(11);

    // Signed by the wrong key → the signature won't verify against `pk`.
    let bad = register_request(&wrong_key, &pk, "windows", "PC");
    let err = client
        .register_machine(tonic::Request::new(bad))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);

    // Garbage signature → also rejected.
    let mut garbage = register_request(&wrong_key, &pk, "windows", "PC");
    garbage.signature = vec![0u8; 64];
    let err = client
        .register_machine(tonic::Request::new(garbage))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);

    // No machine row was created.
    let (machines,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM identity.machines")
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(machines, 0);

    let _ = shutdown.send(true);
}

#[tokio::test(flavor = "multi_thread")]
async fn machine_rpcs_require_auth() {
    let app = TestApp::new().await;
    let (addr, shutdown) = spawn_grpc(&app).await;
    let mut client = connect(addr).await;

    let checkin = client
        .check_in(tonic::Request::new(CheckInRequest {
            agent_version: "x".to_string(),
        }))
        .await
        .unwrap_err()
        .code();
    assert_eq!(checkin, tonic::Code::Unauthenticated);

    let subscribe = client
        .subscribe(tonic::Request::new(Empty {}))
        .await
        .unwrap_err()
        .code();
    assert_eq!(subscribe, tonic::Code::Unauthenticated);

    let _ = shutdown.send(true);
}

#[tokio::test(flavor = "multi_thread")]
async fn report_telemetry_stores_an_opaque_blob() {
    let app = TestApp::new().await;
    let (addr, shutdown) = spawn_grpc(&app).await;
    let mut client = connect(addr).await;

    let (sk, pk) = machine_keypair(13);
    let session = client
        .register_machine(tonic::Request::new(register_request(&sk, &pk, "windows", "PC")))
        .await
        .unwrap()
        .into_inner();
    let machine_id = uuid::Uuid::parse_str(&session.machine_id).unwrap();

    client
        .report_telemetry(authed(
            &session.token,
            ReportTelemetryRequest {
                blobs: vec![TelemetryBlob {
                    kind: "location".to_string(),
                    recipient_key_id: vec![1u8; 16],
                    seq: 1,
                    ciphertext: b"sealed-location-blob".to_vec(),
                    signature: Vec::new(),
                }],
            },
        ))
        .await
        .unwrap();

    // Stored verbatim — the server never decrypts it.
    let (kind, ciphertext): (String, Vec<u8>) = sqlx::query_as(
        "SELECT kind, ciphertext FROM identity.machine_telemetry WHERE machine_id = $1",
    )
    .bind(machine_id)
    .fetch_one(&app.pool)
    .await
    .unwrap();
    assert_eq!(kind, "location");
    assert_eq!(ciphertext, b"sealed-location-blob");

    let _ = shutdown.send(true);
}

#[tokio::test(flavor = "multi_thread")]
async fn subscribe_reflects_location_toggle_and_group() {
    let app = TestApp::new().await;
    let (addr, shutdown) = spawn_grpc(&app).await;
    let mut client = connect(addr).await;

    let (sk, pk) = machine_keypair(17);
    let session = client
        .register_machine(tonic::Request::new(register_request(&sk, &pk, "windows", "PC")))
        .await
        .unwrap()
        .into_inner();
    let machine_id = uuid::Uuid::parse_str(&session.machine_id).unwrap();

    // Admin policy (dev SQL until the client-app panel exists): enable location +
    // provision a device-admin group key.
    sqlx::query("UPDATE identity.machines SET location_enabled = true WHERE id = $1")
        .bind(machine_id)
        .execute(&app.pool)
        .await
        .unwrap();
    let group_public = vec![9u8; 32];
    sqlx::query("INSERT INTO identity.device_admin_group (group_public) VALUES ($1)")
        .bind(&group_public)
        .execute(&app.pool)
        .await
        .unwrap();

    let mut stream = client
        .subscribe(authed(&session.token, Empty {}))
        .await
        .unwrap()
        .into_inner();
    let first = stream.message().await.unwrap().expect("a server push");
    match first.payload {
        Some(server_push::Payload::Config(cfg)) => {
            assert!(cfg.location_enabled, "toggle reflected");
            assert_eq!(cfg.device_admin_group_public, group_public, "group pubkey pushed");
            assert!(!cfg.group_key_id.is_empty(), "group key id pushed");
        }
        other => panic!("expected a config push, got {other:?}"),
    }

    let _ = shutdown.send(true);
}
