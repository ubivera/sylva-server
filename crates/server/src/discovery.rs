//! Public server discovery: `GET /.well-known/sylva-discovery`.
//!
//! Unauthenticated and always available (no session, not gated by the
//! closed-instance page) — it's the first call a native client (Sylva Hub)
//! makes against a server it's pointed at. It returns the server's name, the
//! gRPC port, and the **server identity public key**, plus an Ed25519
//! **signature** over a canonical, domain-separated payload that includes a
//! caller-supplied **nonce**. The client pins the public key on first contact
//! (TOFU) and verifies the signature on every subsequent discovery; the nonce
//! proves the server holds the private key *now* (anti-replay), so a passive
//! MITM can't pass off a recorded response.
//!
//! Channel binding: the design (docs/design/hub.md) also binds the signature to
//! the TLS certificate SPKI. server doesn't terminate TLS at this layer (a
//! reverse proxy does, in production), so the SPKI isn't available here yet;
//! that field is added to the signed payload when TLS termination moves in. The
//! durable anchor — the pinned identity key — and the nonce are in place now.

use axum::{
    Json, Router,
    extract::{Query, State},
    http::StatusCode,
    routing::get,
};
use ed25519_dalek::Signer;
use serde::{Deserialize, Serialize};

use crate::app::AppState;

/// Bumped whenever the signed-payload layout changes, so clients can refuse a
/// layout they don't understand rather than silently mis-verify.
const PAYLOAD_VERSION: u32 = 1;

/// Domain-separation tag — keeps a discovery signature from ever being valid in
/// another context that happens to sign similar bytes.
const DOMAIN: &[u8] = b"sylva.discovery.v1";

/// Cap the echoed nonce so a caller can't make us sign an unbounded blob.
const MAX_NONCE_LEN: usize = 256;

#[derive(Deserialize)]
pub struct DiscoveryQuery {
    /// Caller-supplied freshness challenge, echoed and covered by the signature.
    #[serde(default)]
    nonce: String,
}

#[derive(Serialize)]
struct DiscoveryResponse {
    name: String,
    server_version: &'static str,
    grpc_port: u16,
    /// Hex-encoded Ed25519 public key (32 bytes → 64 hex chars).
    server_identity_public: String,
    /// The caller's nonce, echoed back.
    nonce: String,
    /// Hex-encoded Ed25519 signature over [`canonical_bytes`] (64 → 128 hex).
    signature: String,
    payload_version: u32,
}

/// The discovery sub-router, mounted at the server root (alongside `/health`)
/// so it bypasses the API prefix, auth, and the closed-instance page.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/.well-known/sylva-discovery", get(handler))
        .with_state(state)
}

async fn handler(
    State(state): State<AppState>,
    Query(query): Query<DiscoveryQuery>,
) -> Result<Json<DiscoveryResponse>, StatusCode> {
    if query.nonce.len() > MAX_NONCE_LEN {
        return Err(StatusCode::BAD_REQUEST);
    }
    let name = state.instance_name.load_full().as_ref().clone();
    let grpc_port = state.env_config.grpc_listen_addr.port();
    let identity = &state.server_identity;

    let payload = canonical_bytes(&query.nonce, &identity.public, grpc_port, &name);
    let signature = identity.signing_key.sign(&payload);

    Ok(Json(DiscoveryResponse {
        name,
        server_version: env!("CARGO_PKG_VERSION"),
        grpc_port,
        server_identity_public: hex_encode(&identity.public),
        nonce: query.nonce,
        signature: hex_encode(&signature.to_bytes()),
        payload_version: PAYLOAD_VERSION,
    }))
}

/// The exact bytes the server signs and the client reconstructs to verify.
/// Domain-separated and **length-prefixed** per field, so no combination of
/// field values can be confused for another (e.g. a name ending in digits vs.
/// the port). Order + framing are part of the contract: clients MUST rebuild it
/// identically. Exposed so the client core (and tests) share one definition.
pub fn canonical_bytes(nonce: &str, public: &[u8; 32], grpc_port: u16, name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    push_field(&mut out, DOMAIN);
    push_field(&mut out, &PAYLOAD_VERSION.to_be_bytes());
    push_field(&mut out, nonce.as_bytes());
    push_field(&mut out, public);
    push_field(&mut out, &grpc_port.to_be_bytes());
    push_field(&mut out, name.as_bytes());
    out
}

fn push_field(out: &mut Vec<u8>, field: &[u8]) {
    out.extend_from_slice(&(field.len() as u32).to_be_bytes());
    out.extend_from_slice(field);
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}
