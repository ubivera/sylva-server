//! gRPC platform API (CP1) — transport + auth via the existing session token.
//!
//! Binds the platform gRPC server on an ephemeral port against the bundled-
//! postgres test pool, then drives it with a generated client. Uses the
//! multi-thread runtime: an in-process client+server round-trip deadlocks on a
//! current-thread runtime.

use ed25519_dalek::{Signer, SigningKey};
use identity::InstanceRole;
use platform::registry::{self, AppDeclaration};
use proto::platform::v1::{
    AppIdentifier, CreateResourceRequest, Empty, ListResourcesRequest, RegisterAppRequest,
    ResourceId, UpdateResourceRequest, platform_client::PlatformClient,
    resources_client::ResourcesClient,
};

use crate::common::TestApp;

/// Wrap a message in a request carrying a `Bearer` token.
fn authed<T>(token: &str, msg: T) -> tonic::Request<T> {
    let mut req = tonic::Request::new(msg);
    req.metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    req
}

fn sample_decl() -> AppDeclaration {
    AppDeclaration {
        app_identifier: "garden.ubivera.tasks".to_string(),
        display_name: "Tasks".to_string(),
        publisher: "Ubivera, LLC".to_string(),
        app_public_key: vec![9u8; 32],
        schema_version: 1,
        resource_types: vec!["task".to_string(), "project".to_string()],
    }
}

fn register_request(decl: &AppDeclaration, signature: Vec<u8>) -> RegisterAppRequest {
    RegisterAppRequest {
        app_identifier: decl.app_identifier.clone(),
        display_name: decl.display_name.clone(),
        publisher: decl.publisher.clone(),
        app_public_key: decl.app_public_key.clone(),
        schema_version: decl.schema_version,
        resource_types: decl.resource_types.clone(),
        signature,
    }
}

/// Register the sample app directly in the DB (the signed gRPC registration
/// flow is exercised by the registration tests) and return its server-assigned
/// id for use as a resource's `app_id`. Declares resource_types `task`/`project`.
async fn seed_app(app: &TestApp) -> String {
    registry::upsert_app(&app.pool, &sample_decl(), None)
        .await
        .unwrap()
        .id
        .to_string()
}

/// Spin up the platform gRPC server on `127.0.0.1:0` against the test pool;
/// returns the bound address + a shutdown sender.
async fn spawn_grpc(app: &TestApp) -> (std::net::SocketAddr, tokio::sync::watch::Sender<bool>) {
    let ctx = platform::PlatformContext {
        sessions: auth::SessionRepository::new(app.pool.clone()),
        users: identity::UserRepository::new(app.pool.clone()),
        resources: platform::resources::ResourceRepository::new(app.pool.clone()),
        pool: app.pool.clone(),
        secret_key: std::sync::Arc::new([0u8; 32]),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, mut rx) = tokio::sync::watch::channel(false);
    tokio::spawn(platform::serve_grpc(ctx, listener, async move {
        let _ = rx.changed().await;
    }));
    (addr, tx)
}

#[tokio::test(flavor = "multi_thread")]
async fn whoami_returns_authenticated_user() {
    let app = TestApp::new().await;
    let seeded = app
        .seed_user("grpc@test.local", "Grace", "pw", InstanceRole::Member)
        .await;
    let token = app.login("grpc@test.local", "pw").await;
    let (addr, shutdown) = spawn_grpc(&app).await;

    let mut client = PlatformClient::connect(format!("http://{addr}")).await.unwrap();
    let mut req = tonic::Request::new(Empty {});
    req.metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    let resp = client.who_am_i(req).await.unwrap().into_inner();

    assert_eq!(resp.user_id, seeded.id.0.to_string());
    assert_eq!(resp.display_name, "Grace");
    assert_eq!(resp.instance_role, "member");

    let _ = shutdown.send(true);
}

#[tokio::test(flavor = "multi_thread")]
async fn whoami_rejects_missing_and_bad_tokens() {
    let app = TestApp::new().await;
    let (addr, shutdown) = spawn_grpc(&app).await;
    let mut client = PlatformClient::connect(format!("http://{addr}")).await.unwrap();

    // No authorization metadata at all.
    let err = client
        .who_am_i(tonic::Request::new(Empty {}))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated);

    // A well-formed header carrying a token that matches no session.
    let mut bad = tonic::Request::new(Empty {});
    bad.metadata_mut()
        .insert("authorization", "Bearer not-a-real-token".parse().unwrap());
    let err = client.who_am_i(bad).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated);

    let _ = shutdown.send(true);
}

#[tokio::test(flavor = "multi_thread")]
async fn resource_crud_round_trip() {
    let app = TestApp::new().await;
    let seeded = app
        .seed_user("owner@test.local", "Olive", "pw", InstanceRole::Member)
        .await;
    let token = app.login("owner@test.local", "pw").await;
    let (addr, shutdown) = spawn_grpc(&app).await;
    let mut client = ResourcesClient::connect(format!("http://{addr}")).await.unwrap();

    let app_id = seed_app(&app).await;
    let app_resource_id = uuid::Uuid::new_v4().to_string();

    // Create.
    let created = client
        .create_resource(authed(
            &token,
            CreateResourceRequest {
                app_id: app_id.clone(),
                resource_type: "task".into(),
                app_resource_id: app_resource_id.clone(),
                parent_resource_id: None,
                content_blob: b"ciphertext-v1".to_vec(),
                content_signature: b"sig".to_vec(),
                schema_version: 1,
            },
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(created.app_resource_id, app_resource_id);
    assert_eq!(created.owner_user_id, seeded.id.0.to_string());
    assert_eq!(created.content_blob, b"ciphertext-v1".to_vec());
    let id = created.id.clone();

    // Read it back.
    let read = client
        .read_resource(authed(&token, ResourceId { id: id.clone() }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(read.id, id);
    assert_eq!(read.content_blob, b"ciphertext-v1".to_vec());

    // Update the blob.
    let updated = client
        .update_resource(authed(
            &token,
            UpdateResourceRequest {
                id: id.clone(),
                parent_resource_id: None,
                content_blob: b"ciphertext-v2".to_vec(),
                content_signature: b"sig2".to_vec(),
                schema_version: 2,
            },
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(updated.content_blob, b"ciphertext-v2".to_vec());
    assert_eq!(updated.schema_version, 2);

    // List finds it.
    let listed = client
        .list_resources(authed(
            &token,
            ListResourcesRequest {
                app_id: app_id.clone(),
                resource_type: "task".into(),
                limit: 0,
                offset: 0,
                include_deleted: false,
            },
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(listed.total, 1);
    assert_eq!(listed.resources.len(), 1);
    assert_eq!(listed.resources[0].id, id);

    // Delete (tombstone).
    client
        .delete_resource(authed(&token, ResourceId { id: id.clone() }))
        .await
        .unwrap();

    // Gone from reads + listing.
    let err = client
        .read_resource(authed(&token, ResourceId { id: id.clone() }))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::NotFound);
    let after = client
        .list_resources(authed(
            &token,
            ListResourcesRequest {
                app_id,
                resource_type: "task".into(),
                limit: 0,
                offset: 0,
                include_deleted: false,
            },
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(after.total, 0);

    let _ = shutdown.send(true);
}

#[tokio::test(flavor = "multi_thread")]
async fn resources_are_owner_scoped() {
    let app = TestApp::new().await;
    app.seed_user("a@test.local", "Alice", "pw", InstanceRole::Member)
        .await;
    app.seed_user("b@test.local", "Bob", "pw", InstanceRole::Member)
        .await;
    let tok_a = app.login("a@test.local", "pw").await;
    let tok_b = app.login("b@test.local", "pw").await;
    let (addr, shutdown) = spawn_grpc(&app).await;
    let mut client = ResourcesClient::connect(format!("http://{addr}")).await.unwrap();

    let app_id = seed_app(&app).await;
    let created = client
        .create_resource(authed(
            &tok_a,
            CreateResourceRequest {
                app_id: app_id.clone(),
                resource_type: "task".into(),
                app_resource_id: uuid::Uuid::new_v4().to_string(),
                parent_resource_id: None,
                content_blob: b"a-secret".to_vec(),
                content_signature: b"s".to_vec(),
                schema_version: 1,
            },
        ))
        .await
        .unwrap()
        .into_inner();
    let id = created.id;

    // B can't see A's resource at all — read / update / delete all NotFound.
    assert_eq!(
        client
            .read_resource(authed(&tok_b, ResourceId { id: id.clone() }))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::NotFound
    );
    assert_eq!(
        client
            .update_resource(authed(
                &tok_b,
                UpdateResourceRequest {
                    id: id.clone(),
                    parent_resource_id: None,
                    content_blob: b"hijack".to_vec(),
                    content_signature: b"x".to_vec(),
                    schema_version: 9,
                },
            ))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::NotFound
    );
    assert_eq!(
        client
            .delete_resource(authed(&tok_b, ResourceId { id: id.clone() }))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::NotFound
    );

    // B's listing of the same app/type is empty.
    let b_list = client
        .list_resources(authed(
            &tok_b,
            ListResourcesRequest {
                app_id,
                resource_type: "task".into(),
                limit: 0,
                offset: 0,
                include_deleted: false,
            },
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(b_list.total, 0);

    // A's resource is untouched.
    let a_read = client
        .read_resource(authed(&tok_a, ResourceId { id }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(a_read.content_blob, b"a-secret".to_vec());

    let _ = shutdown.send(true);
}

#[tokio::test(flavor = "multi_thread")]
async fn duplicate_app_resource_id_conflicts_and_auth_required() {
    let app = TestApp::new().await;
    app.seed_user("o@test.local", "O", "pw", InstanceRole::Member)
        .await;
    let token = app.login("o@test.local", "pw").await;
    let (addr, shutdown) = spawn_grpc(&app).await;
    let mut client = ResourcesClient::connect(format!("http://{addr}")).await.unwrap();

    let app_id = seed_app(&app).await;
    let app_resource_id = uuid::Uuid::new_v4().to_string();
    let make = || CreateResourceRequest {
        app_id: app_id.clone(),
        resource_type: "task".into(),
        app_resource_id: app_resource_id.clone(),
        parent_resource_id: None,
        content_blob: b"x".to_vec(),
        content_signature: b"s".to_vec(),
        schema_version: 1,
    };

    // No token → unauthenticated (the Resources service is gated too).
    let err = client
        .create_resource(tonic::Request::new(make()))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated);

    // First create succeeds; a second with the same app_resource_id conflicts.
    client.create_resource(authed(&token, make())).await.unwrap();
    let err = client.create_resource(authed(&token, make())).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::AlreadyExists);

    let _ = shutdown.send(true);
}

#[tokio::test(flavor = "multi_thread")]
async fn register_app_with_trusted_publisher_round_trip() {
    let app = TestApp::new().await;
    app.seed_user("dev@test.local", "Dev", "pw", InstanceRole::Member)
        .await;
    let token = app.login("dev@test.local", "pw").await;

    // Trust a publisher, then sign the declaration with its key.
    let publisher_key = SigningKey::from_bytes(&[7u8; 32]);
    let decl = sample_decl();
    registry::add_trusted_publisher(&app.pool, &decl.publisher, publisher_key.verifying_key().as_bytes(), None)
        .await
        .unwrap();
    let sig = publisher_key
        .sign(&registry::canonical_declaration_bytes(&decl))
        .to_bytes()
        .to_vec();

    let (addr, shutdown) = spawn_grpc(&app).await;
    let mut client = PlatformClient::connect(format!("http://{addr}")).await.unwrap();

    let reg = client
        .register_app(authed(&token, register_request(&decl, sig)))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(reg.app_identifier, "garden.ubivera.tasks");
    assert_eq!(reg.status, "enabled");
    assert_eq!(reg.resource_types, vec!["task".to_string(), "project".to_string()]);
    assert!(!reg.id.is_empty());

    // GetAppRegistration returns the same registration.
    let fetched = client
        .get_app_registration(authed(
            &token,
            AppIdentifier { app_identifier: "garden.ubivera.tasks".into() },
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(fetched.id, reg.id);

    let _ = shutdown.send(true);
}

#[tokio::test(flavor = "multi_thread")]
async fn register_app_untrusted_publisher_is_denied() {
    let app = TestApp::new().await;
    app.seed_user("dev@test.local", "Dev", "pw", InstanceRole::Member)
        .await;
    let token = app.login("dev@test.local", "pw").await;

    // No publisher trusted; a perfectly valid self-signature still fails.
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let decl = sample_decl();
    let sig = key
        .sign(&registry::canonical_declaration_bytes(&decl))
        .to_bytes()
        .to_vec();

    let (addr, shutdown) = spawn_grpc(&app).await;
    let mut client = PlatformClient::connect(format!("http://{addr}")).await.unwrap();
    let err = client
        .register_app(authed(&token, register_request(&decl, sig)))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);

    let _ = shutdown.send(true);
}

#[tokio::test(flavor = "multi_thread")]
async fn register_app_bad_signature_is_denied() {
    let app = TestApp::new().await;
    app.seed_user("dev@test.local", "Dev", "pw", InstanceRole::Member)
        .await;
    let token = app.login("dev@test.local", "pw").await;

    let decl = sample_decl();
    // Trust the real publisher key, but sign with an attacker's key.
    let publisher_key = SigningKey::from_bytes(&[7u8; 32]);
    registry::add_trusted_publisher(&app.pool, &decl.publisher, publisher_key.verifying_key().as_bytes(), None)
        .await
        .unwrap();
    let attacker = SigningKey::from_bytes(&[1u8; 32]);
    let sig = attacker
        .sign(&registry::canonical_declaration_bytes(&decl))
        .to_bytes()
        .to_vec();

    let (addr, shutdown) = spawn_grpc(&app).await;
    let mut client = PlatformClient::connect(format!("http://{addr}")).await.unwrap();
    let err = client
        .register_app(authed(&token, register_request(&decl, sig)))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);

    let _ = shutdown.send(true);
}

#[tokio::test(flavor = "multi_thread")]
async fn register_requires_auth_and_get_missing_is_not_found() {
    let app = TestApp::new().await;
    app.seed_user("dev@test.local", "Dev", "pw", InstanceRole::Member)
        .await;
    let token = app.login("dev@test.local", "pw").await;
    let (addr, shutdown) = spawn_grpc(&app).await;
    let mut client = PlatformClient::connect(format!("http://{addr}")).await.unwrap();

    // No token → unauthenticated (registration is gated like every RPC).
    let decl = sample_decl();
    let err = client
        .register_app(tonic::Request::new(register_request(&decl, vec![0u8; 64])))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated);

    // Unregistered identifier → not_found.
    let err = client
        .get_app_registration(authed(
            &token,
            AppIdentifier { app_identifier: "nope.absent.app".into() },
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::NotFound);

    let _ = shutdown.send(true);
}

#[tokio::test(flavor = "multi_thread")]
async fn create_resource_requires_registered_enabled_app_and_declared_type() {
    let app = TestApp::new().await;
    app.seed_user("owner@test.local", "Olive", "pw", InstanceRole::Member)
        .await;
    let token = app.login("owner@test.local", "pw").await;
    let app_id = seed_app(&app).await; // enabled; declares "task" + "project"
    let (addr, shutdown) = spawn_grpc(&app).await;
    let mut client = ResourcesClient::connect(format!("http://{addr}")).await.unwrap();

    let make = |app_id: &str, rtype: &str| CreateResourceRequest {
        app_id: app_id.to_string(),
        resource_type: rtype.to_string(),
        app_resource_id: uuid::Uuid::new_v4().to_string(),
        parent_resource_id: None,
        content_blob: b"x".to_vec(),
        content_signature: b"s".to_vec(),
        schema_version: 1,
    };

    // Unknown app_id → the app isn't registered.
    let err = client
        .create_resource(authed(&token, make(&uuid::Uuid::new_v4().to_string(), "task")))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);

    // Registered app, but a resource_type it never declared.
    let err = client
        .create_resource(authed(&token, make(&app_id, "widget")))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);

    // A declared type on the live app succeeds (here the second declared type).
    client
        .create_resource(authed(&token, make(&app_id, "project")))
        .await
        .unwrap();

    // Disabling the app refuses further creates even for a declared type.
    sqlx::query("UPDATE platform.registered_apps SET status = 'disabled' WHERE id = $1")
        .bind(uuid::Uuid::parse_str(&app_id).unwrap())
        .execute(&app.pool)
        .await
        .unwrap();
    let err = client
        .create_resource(authed(&token, make(&app_id, "task")))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);

    let _ = shutdown.send(true);
}
