//! Client-IP resolution + the [`ClientIp`] extractor for rate-limiting the
//! brute-forceable auth endpoints (`/login`, `/recover`, the JSON
//! `/api/auth/login`).
//!
//! The token-bucket limiter itself now lives in [`auth::ratelimit`] — shared
//! with the gRPC `Account` service (`Bootstrap` / `Login`), which can't depend
//! on `server`. It's re-exported here so existing `rate_limit::RateLimiter`
//! call-sites keep working unchanged.
//!
//! Keying is by client IP. **By default the socket peer IP is used and
//! forwarding headers are ignored** — a client could otherwise spoof
//! `X-Forwarded-For` to mint a fresh bucket per request and defeat the limit
//! entirely. Operators behind a reverse proxy (the standard https topology) set
//! `SYLVA_TRUST_PROXY=1`, which switches keying to the first `X-Forwarded-For`
//! / `X-Real-IP` hop the proxy sets. See `server-recovery.md`.

use std::net::{IpAddr, SocketAddr};

use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::request::Parts;

pub use auth::ratelimit::{DEFAULT_AUTH_BURST, DEFAULT_AUTH_REFILL_PER_SEC, RateLimiter};

use crate::app::AppState;

/// Resolve the effective client IP for rate-limit keying.
///
/// - `trust_proxy = false` (default): use the **socket peer** IP and ignore
///   forwarding headers (a client could spoof them to evade the limit). Falls
///   back to `"direct"` when no peer is known (e.g. unit tests with no live
///   connection).
/// - `trust_proxy = true`: the instance is behind a reverse proxy that sets
///   `X-Forwarded-For` / `X-Real-IP`; trust the first hop.
pub fn resolve_client_ip(
    peer: Option<IpAddr>,
    headers: &axum::http::HeaderMap,
    trust_proxy: bool,
) -> String {
    if trust_proxy && let Some(ip) = forwarded_ip(headers) {
        return ip;
    }
    peer.map(|ip| ip.to_string())
        .unwrap_or_else(|| "direct".to_string())
}

/// Max stored `User-Agent` length — enough to identify a browser/OS, short
/// enough to bound the session row.
const MAX_USER_AGENT_LEN: usize = 400;

/// Extract + bound the request's `User-Agent` for storage on the session row
/// (the web layer renders it into a friendly device label). `None` when the
/// header is absent, non-text, or empty.
pub fn user_agent(headers: &axum::http::HeaderMap) -> Option<String> {
    let raw = headers.get(axum::http::header::USER_AGENT)?.to_str().ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed.chars().take(MAX_USER_AGENT_LEN).collect())
}

/// First `X-Forwarded-For` hop, else `X-Real-IP`. Only consulted when the
/// operator has opted into trusting a proxy.
fn forwarded_ip(headers: &axum::http::HeaderMap) -> Option<String> {
    if let Some(v) = headers.get("x-forwarded-for")
        && let Ok(s) = v.to_str()
        && let Some(first) = s.split(',').next()
        && !first.trim().is_empty()
    {
        return Some(first.trim().to_string());
    }
    if let Some(v) = headers.get("x-real-ip")
        && let Ok(s) = v.to_str()
        && !s.trim().is_empty()
    {
        return Some(s.trim().to_string());
    }
    None
}

/// Extractor yielding the rate-limit client key (the effective client IP).
/// Reads the socket peer from `ConnectInfo` (wired at serve time via
/// `into_make_service_with_connect_info`) and the instance's `trust_proxy`
/// policy from [`AppState`]. Infallible — degrades to `"direct"`.
pub struct ClientIp(pub String);

impl FromRequestParts<AppState> for ClientIp {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let peer = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ci| ci.0.ip());
        Ok(ClientIp(resolve_client_ip(
            peer,
            &parts.headers,
            state.trust_proxy,
        )))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn peer(s: &str) -> Option<IpAddr> {
        Some(s.parse().unwrap())
    }

    #[test]
    fn untrusted_proxy_uses_peer_and_ignores_forwarding_headers() {
        // The spoofable headers must NOT influence the key when the proxy
        // isn't trusted — otherwise an attacker mints a bucket per request.
        let mut h = axum::http::HeaderMap::new();
        h.insert("x-forwarded-for", "203.0.113.7".parse().unwrap());
        h.insert("x-real-ip", "203.0.113.8".parse().unwrap());
        assert_eq!(resolve_client_ip(peer("10.0.0.5"), &h, false), "10.0.0.5");
    }

    #[test]
    fn untrusted_proxy_without_peer_falls_back_to_direct() {
        let h = axum::http::HeaderMap::new();
        assert_eq!(resolve_client_ip(None, &h, false), "direct");
    }

    #[test]
    fn trusted_proxy_prefers_first_forwarded_hop() {
        let mut h = axum::http::HeaderMap::new();
        h.insert("x-forwarded-for", "203.0.113.7, 10.0.0.1".parse().unwrap());
        assert_eq!(resolve_client_ip(peer("10.0.0.9"), &h, true), "203.0.113.7");
    }

    #[test]
    fn trusted_proxy_falls_back_to_real_ip_then_peer() {
        let mut h = axum::http::HeaderMap::new();
        h.insert("x-real-ip", "198.51.100.4".parse().unwrap());
        assert_eq!(resolve_client_ip(peer("10.0.0.9"), &h, true), "198.51.100.4");
        // No forwarding header → even a trusting proxy uses the peer.
        let empty = axum::http::HeaderMap::new();
        assert_eq!(resolve_client_ip(peer("10.0.0.9"), &empty, true), "10.0.0.9");
    }
}
