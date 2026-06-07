//! In-memory, per-client token-bucket rate limiting for the
//! brute-forceable auth endpoints (`/login`, `/recover`, and the JSON
//! `/api/auth/login`).
//!
//! Model: each key starts with a full bucket of `capacity` tokens.
//! Every *failed* attempt removes one token; tokens refill linearly
//! over time. A handler checks [`RateLimiter::allowed`] **before** doing
//! any credential work and returns 429 when the bucket is empty, so a
//! flood of guesses from one client is cut off cheaply. Successful
//! requests never consume tokens, so a legitimate user typing their
//! password correctly is never throttled.
//!
//! Keyed by best-effort client IP via [`client_key`] (first
//! `X-Forwarded-For` hop, else `X-Real-IP`, else the shared literal
//! `"direct"`). This assumes a **trusted reverse proxy** sets that
//! header — the standard self-hosted topology. Without one, the header
//! is client-controlled and keying degrades to the shared `"direct"`
//! bucket; see `hearth-recovery.md` for the deployment note.
//!
//! State is process-local (a `Mutex<HashMap>`); a multi-process
//! deployment would need a shared store. Single-instance is the design
//! target today.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

/// Burst size for the auth limiter: how many failed attempts a single
/// client can make before being throttled.
pub const DEFAULT_AUTH_BURST: u32 = 10;

/// Steady-state refill for the auth limiter, in tokens per second.
/// `0.1` → one fresh attempt every 10 seconds once the burst is spent.
pub const DEFAULT_AUTH_REFILL_PER_SEC: f64 = 0.1;

struct Bucket {
    tokens: f64,
    last_ms: u64,
}

/// A per-key token-bucket limiter. Cheap to share behind an `Arc`.
pub struct RateLimiter {
    capacity: f64,
    refill_per_ms: f64,
    origin: Instant,
    buckets: Mutex<HashMap<String, Bucket>>,
}

impl RateLimiter {
    pub fn new(capacity: u32, refill_per_sec: f64) -> Self {
        Self {
            capacity: f64::from(capacity),
            refill_per_ms: refill_per_sec / 1000.0,
            origin: Instant::now(),
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// The auth-endpoint limiter with the crate defaults.
    pub fn auth_default() -> Self {
        Self::new(DEFAULT_AUTH_BURST, DEFAULT_AUTH_REFILL_PER_SEC)
    }

    /// Whether `key` currently has capacity for another attempt. Does
    /// not consume a token — call [`RateLimiter::record_failure`] after
    /// an attempt actually fails.
    pub fn allowed(&self, key: &str) -> bool {
        self.allowed_at(key, self.now_ms())
    }

    /// Charge one failed attempt against `key`.
    pub fn record_failure(&self, key: &str) {
        self.record_failure_at(key, self.now_ms());
    }

    fn now_ms(&self) -> u64 {
        self.origin.elapsed().as_millis() as u64
    }

    fn allowed_at(&self, key: &str, now_ms: u64) -> bool {
        let mut buckets = self.lock();
        let bucket = Self::refilled(&mut buckets, key, now_ms, self.capacity, self.refill_per_ms);
        bucket.tokens >= 1.0
    }

    fn record_failure_at(&self, key: &str, now_ms: u64) {
        let mut buckets = self.lock();
        let bucket = Self::refilled(&mut buckets, key, now_ms, self.capacity, self.refill_per_ms);
        bucket.tokens = (bucket.tokens - 1.0).max(0.0);
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Bucket>> {
        // A poisoned lock just means some other thread panicked mid-update;
        // the bucket map is still coherent enough to keep limiting on.
        self.buckets.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn refilled<'a>(
        buckets: &'a mut HashMap<String, Bucket>,
        key: &str,
        now_ms: u64,
        capacity: f64,
        refill_per_ms: f64,
    ) -> &'a mut Bucket {
        let bucket = buckets.entry(key.to_string()).or_insert(Bucket {
            tokens: capacity,
            last_ms: now_ms,
        });
        let elapsed = now_ms.saturating_sub(bucket.last_ms);
        if elapsed > 0 {
            bucket.tokens = (bucket.tokens + elapsed as f64 * refill_per_ms).min(capacity);
            bucket.last_ms = now_ms;
        }
        bucket
    }
}

/// Best-effort client identifier for rate-limit keying. See the module
/// docs for the trusted-proxy assumption.
pub fn client_key(headers: &axum::http::HeaderMap) -> String {
    if let Some(v) = headers.get("x-forwarded-for")
        && let Ok(s) = v.to_str()
        && let Some(first) = s.split(',').next()
        && !first.trim().is_empty()
    {
        return first.trim().to_string();
    }
    if let Some(v) = headers.get("x-real-ip")
        && let Ok(s) = v.to_str()
        && !s.trim().is_empty()
    {
        return s.trim().to_string();
    }
    "direct".to_string()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn fresh_key_is_allowed() {
        let rl = RateLimiter::new(3, 0.0);
        assert!(rl.allowed_at("a", 0));
    }

    #[test]
    fn drains_after_capacity_failures() {
        let rl = RateLimiter::new(3, 0.0);
        for _ in 0..3 {
            assert!(rl.allowed_at("a", 0));
            rl.record_failure_at("a", 0);
        }
        // Bucket empty → blocked, and stays blocked with no refill.
        assert!(!rl.allowed_at("a", 0));
    }

    #[test]
    fn refills_over_time() {
        // 1 token/sec refill.
        let rl = RateLimiter::new(2, 1.0);
        rl.record_failure_at("a", 0);
        rl.record_failure_at("a", 0);
        assert!(!rl.allowed_at("a", 0), "drained");
        // 1100ms later ≈ 1.1 tokens regenerated.
        assert!(rl.allowed_at("a", 1_100));
    }

    #[test]
    fn refill_caps_at_capacity() {
        let rl = RateLimiter::new(2, 1.0);
        rl.record_failure_at("a", 0);
        // A long gap can't push tokens above capacity.
        assert!(rl.allowed_at("a", 10_000_000));
        rl.record_failure_at("a", 10_000_000);
        rl.record_failure_at("a", 10_000_000);
        assert!(!rl.allowed_at("a", 10_000_000));
    }

    #[test]
    fn keys_are_independent() {
        let rl = RateLimiter::new(1, 0.0);
        rl.record_failure_at("a", 0);
        assert!(!rl.allowed_at("a", 0));
        assert!(rl.allowed_at("b", 0), "other key unaffected");
    }

    #[test]
    fn client_key_prefers_first_forwarded_hop() {
        let mut h = axum::http::HeaderMap::new();
        h.insert("x-forwarded-for", "203.0.113.7, 10.0.0.1".parse().unwrap());
        assert_eq!(client_key(&h), "203.0.113.7");
    }

    #[test]
    fn client_key_falls_back_to_real_ip_then_direct() {
        let mut h = axum::http::HeaderMap::new();
        h.insert("x-real-ip", "198.51.100.4".parse().unwrap());
        assert_eq!(client_key(&h), "198.51.100.4");
        assert_eq!(client_key(&axum::http::HeaderMap::new()), "direct");
    }
}
