//! Single-purpose, stateless token gating the forgot-password reset
//! form. Minted once the user proves possession of their email +
//! recovery code (`POST /recover`), it authorizes the new-password
//! step (`/recover/reset`) without granting a real session — the user
//! has no working password yet.
//!
//! Stateless by design: the token binds a `user_id` to an absolute
//! expiry, HMAC-signed under the server secret. No DB row to create,
//! look up, or clean up. The signature + embedded expiry are the gate;
//! tampering with either invalidates the token.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::csrf::SECRET_LEN;

/// Sign a reset token binding `user_id` to `expires_at` (unix
/// seconds). Format: `{user_id}.{expires_at}.{hex(mac)}`, where the MAC
/// covers `recovery-reset:{user_id}:{expires_at}` under `secret`.
pub fn sign(secret: &[u8; SECRET_LEN], user_id: Uuid, expires_at: i64) -> String {
    let mac = mac_hex(secret, user_id, expires_at);
    format!("{user_id}.{expires_at}.{mac}")
}

/// Verify a reset token against `now` (unix seconds). Returns the
/// `user_id` it was minted for iff the signature checks out AND it
/// hasn't expired. Constant-time MAC comparison; any structural,
/// signature, or expiry problem returns `None` (the caller maps that
/// to "start the recovery flow over").
pub fn verify(secret: &[u8; SECRET_LEN], token: &str, now: i64) -> Option<Uuid> {
    let mut parts = token.splitn(3, '.');
    let user_id = Uuid::parse_str(parts.next()?).ok()?;
    let expires_at: i64 = parts.next()?.parse().ok()?;
    let presented_sig = parts.next()?;
    if parts.next().is_some() {
        return None;
    }

    let expected_sig = mac_hex(secret, user_id, expires_at);
    if !bool::from(expected_sig.as_bytes().ct_eq(presented_sig.as_bytes())) {
        return None;
    }
    if now >= expires_at {
        return None;
    }
    Some(user_id)
}

fn mac_hex(secret: &[u8; SECRET_LEN], user_id: Uuid, expires_at: i64) -> String {
    #[allow(clippy::expect_used)]
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret)
        .expect("HMAC-SHA256 accepts keys of any length");
    mac.update(format!("recovery-reset:{user_id}:{expires_at}").as_bytes());
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
        let exp = 10_000;
        let token = sign(&SECRET, uid, exp);
        assert_eq!(verify(&SECRET, &token, 9_999), Some(uid));
    }

    #[test]
    fn expired_token_is_rejected() {
        let uid = Uuid::new_v4();
        let token = sign(&SECRET, uid, 10_000);
        assert_eq!(verify(&SECRET, &token, 10_000), None);
        assert_eq!(verify(&SECRET, &token, 10_001), None);
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let uid = Uuid::new_v4();
        let token = sign(&SECRET, uid, 10_000);
        let mut bytes: Vec<char> = token.chars().collect();
        // Flip the last hex char of the signature.
        let last = bytes.len() - 1;
        bytes[last] = if bytes[last] == '0' { '1' } else { '0' };
        let tampered: String = bytes.into_iter().collect();
        assert_eq!(verify(&SECRET, &tampered, 9_999), None);
    }

    #[test]
    fn swapped_user_id_is_rejected() {
        // Re-using a valid signature with a different user id must fail
        // (the user id is part of the MAC input).
        let uid = Uuid::from_u128(1);
        let token = sign(&SECRET, uid, 10_000);
        let other = Uuid::from_u128(2);
        let (_, rest) = token.split_once('.').unwrap();
        let forged = format!("{other}.{rest}");
        assert_eq!(verify(&SECRET, &forged, 9_999), None);
    }

    #[test]
    fn different_secret_is_rejected() {
        let uid = Uuid::new_v4();
        let token = sign(&SECRET, uid, 10_000);
        assert_eq!(verify(&[1u8; SECRET_LEN], &token, 9_999), None);
    }

    #[test]
    fn malformed_tokens_are_rejected() {
        assert_eq!(verify(&SECRET, "", 0), None);
        assert_eq!(verify(&SECRET, "garbage", 0), None);
        assert_eq!(verify(&SECRET, "not-a-uuid.10000.abcd", 0), None);
        assert_eq!(verify(&SECRET, "extra.parts.here.nope", 0), None);
    }
}
