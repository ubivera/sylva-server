use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use uuid::Uuid;

/// Size of the server-side CSRF secret. 32 bytes / 256 bits is overkill
/// for a per-process secret but cheap.
pub const SECRET_LEN: usize = 32;

/// Number of bytes of MAC to embed in the token. 16 bytes → 32 hex
/// chars; 128 bits of randomness, sufficient for CSRF (no oracle).
const TOKEN_BYTES: usize = 16;

/// The string length consumers see (`TOKEN_BYTES` * 2 hex chars).
pub const TOKEN_LEN: usize = TOKEN_BYTES * 2;

/// Derive a CSRF token for the given session id. Deterministic for a
/// fixed `(secret, session_id)`; render this directly into the form's
/// `csrf_token` hidden input.
pub fn compute_token(secret: &[u8; SECRET_LEN], session_id: Uuid) -> String {
    // `new_from_slice` only fails on length mismatch; HMAC-SHA256 accepts
    // keys of any length so this branch is genuinely unreachable.
    #[allow(clippy::expect_used)]
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret)
        .expect("HMAC-SHA256 accepts keys of any length");
    mac.update(session_id.as_bytes());
    let tag = mac.finalize().into_bytes();
    hex_encode(&tag[..TOKEN_BYTES])
}

/// Constant-time check that `presented` matches the expected token for
/// `(secret, session_id)`.
pub fn verify_token(presented: &str, secret: &[u8; SECRET_LEN], session_id: Uuid) -> bool {
    if presented.len() != TOKEN_LEN {
        return false;
    }
    let expected = compute_token(secret, session_id);
    expected.as_bytes().ct_eq(presented.as_bytes()).into()
}

/// Generate a fresh secret. Called once per server startup.
pub fn generate_secret() -> [u8; SECRET_LEN] {
    use rand::RngCore;
    let mut out = [0u8; SECRET_LEN];
    rand::thread_rng().fill_bytes(&mut out);
    out
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

    #[test]
    fn token_is_deterministic_for_same_input() {
        let secret = [7u8; SECRET_LEN];
        let session = Uuid::nil();
        assert_eq!(compute_token(&secret, session), compute_token(&secret, session));
    }

    #[test]
    fn token_changes_with_session() {
        let secret = [7u8; SECRET_LEN];
        let a = compute_token(&secret, Uuid::from_u128(1));
        let b = compute_token(&secret, Uuid::from_u128(2));
        assert_ne!(a, b);
    }

    #[test]
    fn token_changes_with_secret() {
        let session = Uuid::from_u128(42);
        let a = compute_token(&[1u8; SECRET_LEN], session);
        let b = compute_token(&[2u8; SECRET_LEN], session);
        assert_ne!(a, b);
    }

    #[test]
    fn verify_accepts_matching_token() {
        let secret = generate_secret();
        let session = Uuid::new_v4();
        let token = compute_token(&secret, session);
        assert!(verify_token(&token, &secret, session));
    }

    #[test]
    fn verify_rejects_wrong_token() {
        let secret = generate_secret();
        let session = Uuid::new_v4();
        assert!(!verify_token("00000000000000000000000000000000", &secret, session));
    }

    #[test]
    fn verify_rejects_token_for_different_session() {
        let secret = generate_secret();
        let token = compute_token(&secret, Uuid::from_u128(1));
        assert!(!verify_token(&token, &secret, Uuid::from_u128(2)));
    }

    #[test]
    fn verify_rejects_wrong_length() {
        let secret = generate_secret();
        let session = Uuid::new_v4();
        assert!(!verify_token("tooshort", &secret, session));
        assert!(!verify_token(
            "way_too_long_for_a_csrf_token_more_than_thirty_two_chars",
            &secret,
            session,
        ));
    }

    #[test]
    fn token_length_matches_constant() {
        let token = compute_token(&[0u8; SECRET_LEN], Uuid::nil());
        assert_eq!(token.len(), TOKEN_LEN);
    }
}
