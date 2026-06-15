//! Stateless, single-purpose signed tokens binding a user id to an
//! expiry. For short-lived "you proved X, now you may do Y" handoffs
//! that must NOT grant a real session. Two uses today:
//!
//! - [`PURPOSE_RECOVERY_RESET`] — proved email + recovery code, may set a
//!   new password (`/recover/reset`).
//! - [`PURPOSE_MFA_PENDING`] — proved password, must still pass a second
//!   factor (`/login/verify`).
//!
//! The `purpose` is folded into the MAC input, so a token minted for one
//! handoff can never be replayed against the other. Stateless: the
//! signature + embedded expiry are the gate (no DB row). Signed under
//! the per-process CSRF secret — a restart invalidates in-flight tokens,
//! which only forces the user to restart that short flow.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::csrf::SECRET_LEN;

/// Purpose tag for the forgot-password reset handoff.
pub const PURPOSE_RECOVERY_RESET: &str = "recovery-reset";
/// Purpose tag for the "password ok, awaiting second factor" handoff.
pub const PURPOSE_MFA_PENDING: &str = "mfa-pending";
/// Purpose tag for the step-up "recently reauthenticated" sudo grant that
/// unlocks sensitive actions for a short window.
pub const PURPOSE_REAUTH: &str = "reauth";
/// Purpose tag for a *critical* step-up grant that gates irreversible
/// account actions (self anonymize / delete). Distinct from
/// [`PURPOSE_REAUTH`] so an ordinary fresh sudo grant can never satisfy
/// these actions — they must always re-prove a factor, ignoring the
/// 5-minute sudo window. Minted only by a forced re-auth and carried in a
/// separate, short-lived cookie.
pub const PURPOSE_REAUTH_CRITICAL: &str = "reauth-critical";

/// Sign a token binding `user_id` to `expires_at` (unix seconds) under
/// `purpose`. Format: `{user_id}.{expires_at}.{hex(mac)}`.
pub fn sign(secret: &[u8; SECRET_LEN], purpose: &str, user_id: Uuid, expires_at: i64) -> String {
    let mac = mac_hex(secret, purpose, user_id, expires_at);
    format!("{user_id}.{expires_at}.{mac}")
}

/// Verify a token for `purpose` against `now`. Returns the `user_id` iff
/// the signature checks out (constant-time) AND it hasn't expired AND it
/// was minted for this exact purpose.
pub fn verify(secret: &[u8; SECRET_LEN], purpose: &str, token: &str, now: i64) -> Option<Uuid> {
    let mut parts = token.splitn(3, '.');
    let user_id = Uuid::parse_str(parts.next()?).ok()?;
    let expires_at: i64 = parts.next()?.parse().ok()?;
    let presented_sig = parts.next()?;
    if parts.next().is_some() {
        return None;
    }

    let expected_sig = mac_hex(secret, purpose, user_id, expires_at);
    if !bool::from(expected_sig.as_bytes().ct_eq(presented_sig.as_bytes())) {
        return None;
    }
    if now >= expires_at {
        return None;
    }
    Some(user_id)
}

fn mac_hex(secret: &[u8; SECRET_LEN], purpose: &str, user_id: Uuid, expires_at: i64) -> String {
    #[allow(clippy::expect_used)]
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret)
        .expect("HMAC-SHA256 accepts keys of any length");
    mac.update(format!("{purpose}:{user_id}:{expires_at}").as_bytes());
    let tag = mac.finalize().into_bytes();
    hex_encode(&tag)
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    const SECRET: [u8; SECRET_LEN] = [9u8; SECRET_LEN];

    #[test]
    fn sign_then_verify_roundtrips() {
        let uid = Uuid::new_v4();
        let token = sign(&SECRET, PURPOSE_MFA_PENDING, uid, 10_000);
        assert_eq!(verify(&SECRET, PURPOSE_MFA_PENDING, &token, 9_999), Some(uid));
    }

    #[test]
    fn purpose_is_isolated() {
        // A token minted for one purpose must not verify under another —
        // the core reason this is generalized rather than duplicated.
        let uid = Uuid::new_v4();
        let token = sign(&SECRET, PURPOSE_RECOVERY_RESET, uid, 10_000);
        assert_eq!(verify(&SECRET, PURPOSE_MFA_PENDING, &token, 9_999), None);
        assert_eq!(verify(&SECRET, PURPOSE_REAUTH, &token, 9_999), None);
        assert_eq!(verify(&SECRET, PURPOSE_RECOVERY_RESET, &token, 9_999), Some(uid));
    }

    #[test]
    fn reauth_purpose_is_isolated() {
        // A sudo grant must not be usable as a login/recovery handoff, and
        // neither of those must unlock a sensitive action as a sudo grant.
        let uid = Uuid::new_v4();
        let grant = sign(&SECRET, PURPOSE_REAUTH, uid, 10_000);
        assert_eq!(verify(&SECRET, PURPOSE_REAUTH, &grant, 9_999), Some(uid));
        assert_eq!(verify(&SECRET, PURPOSE_MFA_PENDING, &grant, 9_999), None);
        assert_eq!(verify(&SECRET, PURPOSE_RECOVERY_RESET, &grant, 9_999), None);
    }

    #[test]
    fn critical_reauth_purpose_is_isolated() {
        // A normal sudo grant must NOT satisfy a critical-reauth gate, and
        // vice versa — this is what makes irreversible actions always
        // re-prompt regardless of the ordinary 5-minute sudo window.
        let uid = Uuid::new_v4();
        let normal = sign(&SECRET, PURPOSE_REAUTH, uid, 10_000);
        let critical = sign(&SECRET, PURPOSE_REAUTH_CRITICAL, uid, 10_000);
        assert_eq!(verify(&SECRET, PURPOSE_REAUTH_CRITICAL, &normal, 9_999), None);
        assert_eq!(verify(&SECRET, PURPOSE_REAUTH, &critical, 9_999), None);
        assert_eq!(
            verify(&SECRET, PURPOSE_REAUTH_CRITICAL, &critical, 9_999),
            Some(uid)
        );
    }

    #[test]
    fn expired_token_is_rejected() {
        let uid = Uuid::new_v4();
        let token = sign(&SECRET, PURPOSE_MFA_PENDING, uid, 10_000);
        assert_eq!(verify(&SECRET, PURPOSE_MFA_PENDING, &token, 10_000), None);
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let uid = Uuid::new_v4();
        let token = sign(&SECRET, PURPOSE_MFA_PENDING, uid, 10_000);
        let mut chars: Vec<char> = token.chars().collect();
        let last = chars.len() - 1;
        chars[last] = if chars[last] == '0' { '1' } else { '0' };
        let tampered: String = chars.into_iter().collect();
        assert_eq!(verify(&SECRET, PURPOSE_MFA_PENDING, &tampered, 9_999), None);
    }

    #[test]
    fn different_secret_is_rejected() {
        let uid = Uuid::new_v4();
        let token = sign(&SECRET, PURPOSE_MFA_PENDING, uid, 10_000);
        assert_eq!(verify(&[1u8; SECRET_LEN], PURPOSE_MFA_PENDING, &token, 9_999), None);
    }

    #[test]
    fn malformed_tokens_are_rejected() {
        assert_eq!(verify(&SECRET, PURPOSE_MFA_PENDING, "", 0), None);
        assert_eq!(verify(&SECRET, PURPOSE_MFA_PENDING, "garbage", 0), None);
        assert_eq!(verify(&SECRET, PURPOSE_MFA_PENDING, "not-a-uuid.10000.ab", 0), None);
        assert_eq!(verify(&SECRET, PURPOSE_MFA_PENDING, "a.b.c.d", 0), None);
    }
}
