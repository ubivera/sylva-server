//! Public server discovery (Hub Phase 2c) — `GET /.well-known/sylva-discovery`.
//! Verifies the response is signed by the server identity key over the exact
//! fields returned, that the identity is stable + nonce-bound, and that the
//! nonce is length-bounded.

use axum::http::StatusCode;
use ed25519_dalek::{Signature, VerifyingKey};

use super::common::TestApp;

#[derive(serde::Deserialize)]
struct Discovery {
    name: String,
    #[allow(dead_code)]
    server_version: String,
    grpc_port: u16,
    server_identity_public: String,
    nonce: String,
    signature: String,
    payload_version: u32,
}

fn hex_decode(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "hex must be even length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex digit"))
        .collect()
}

#[tokio::test]
async fn discovery_is_signed_stable_and_nonce_bound() {
    let app = TestApp::new().await;

    let nonce = "client-nonce-123";
    let resp = app
        .get(&format!("/.well-known/sylva-discovery?nonce={nonce}"), None)
        .await;
    resp.assert_status(StatusCode::OK);
    let d: Discovery = resp.json();

    assert_eq!(d.nonce, nonce, "nonce echoed");
    assert_eq!(d.payload_version, 1);
    assert_eq!(d.name, "test-instance");
    assert!(d.grpc_port > 0, "advertises a gRPC port");

    let pk: [u8; 32] = hex_decode(&d.server_identity_public)
        .try_into()
        .expect("32-byte public key");
    let sig: [u8; 64] = hex_decode(&d.signature).try_into().expect("64-byte signature");
    let vk = VerifyingKey::from_bytes(&pk).expect("valid public key");
    let signature = Signature::from_bytes(&sig);

    // The signature verifies over the exact fields the server returned.
    let msg = server::discovery::canonical_bytes(&d.nonce, &pk, d.grpc_port, &d.name);
    vk.verify_strict(&msg, &signature)
        .expect("discovery signature verifies");

    // Tampering with any covered field breaks verification.
    let tampered = server::discovery::canonical_bytes(&d.nonce, &pk, d.grpc_port, "evil-server");
    assert!(
        vk.verify_strict(&tampered, &signature).is_err(),
        "signature must not verify over altered fields"
    );

    // The identity is stable across calls, and the signature is freshly bound
    // to the supplied nonce (so a recorded response can't be replayed).
    let resp2 = app
        .get("/.well-known/sylva-discovery?nonce=a-different-nonce", None)
        .await;
    resp2.assert_status(StatusCode::OK);
    let d2: Discovery = resp2.json();
    assert_eq!(
        d2.server_identity_public, d.server_identity_public,
        "server identity is stable"
    );
    assert_eq!(d2.nonce, "a-different-nonce");
    assert_ne!(d2.signature, d.signature, "signature is bound to the nonce");
}

#[tokio::test]
async fn discovery_without_a_nonce_is_ok() {
    let app = TestApp::new().await;
    let resp = app.get("/.well-known/sylva-discovery", None).await;
    resp.assert_status(StatusCode::OK);
    let d: Discovery = resp.json();
    assert_eq!(d.nonce, "", "missing nonce defaults to empty");

    let pk: [u8; 32] = hex_decode(&d.server_identity_public).try_into().unwrap();
    let sig: [u8; 64] = hex_decode(&d.signature).try_into().unwrap();
    let vk = VerifyingKey::from_bytes(&pk).unwrap();
    let msg = server::discovery::canonical_bytes(&d.nonce, &pk, d.grpc_port, &d.name);
    vk.verify_strict(&msg, &Signature::from_bytes(&sig))
        .expect("empty-nonce response still verifies");
}

#[tokio::test]
async fn discovery_rejects_an_overlong_nonce() {
    let app = TestApp::new().await;
    let long = "a".repeat(257);
    let resp = app
        .get(&format!("/.well-known/sylva-discovery?nonce={long}"), None)
        .await;
    resp.assert_status(StatusCode::BAD_REQUEST);
}
