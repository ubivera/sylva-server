//! RFC 6238 TOTP (time-based one-time passwords) for authenticator-app
//! second factors. Standard parameters: 20-byte secret, HMAC-SHA1,
//! 6 digits, 30-second step, ±1 step accepted to tolerate clock skew.
//! These match what Google Authenticator / 1Password / Aegis default to.
//!
//! The raw secret is generated here and stored encrypted at rest (see
//! [`crate::secretbox`] / [`crate::user_totp`]); only the base32 form is
//! ever shown to the user (in the QR code / manual-entry key).

use hmac::{Hmac, Mac};
use sha1::Sha1;
use subtle::ConstantTimeEq;

/// Secret length in bytes (160 bits) — the RFC 6238 reference size.
pub const SECRET_BYTES: usize = 20;
const DIGITS: u32 = 6;
const TIME_STEP_SECS: i64 = 30;

/// Generate a fresh random TOTP secret.
pub fn generate_secret() -> [u8; SECRET_BYTES] {
    use rand::RngCore;
    let mut secret = [0u8; SECRET_BYTES];
    rand::thread_rng().fill_bytes(&mut secret);
    secret
}

/// Base32 (RFC 4648, unpadded, uppercase) encoding of a secret — the
/// form entered into an authenticator app manually or via QR.
pub fn base32_encode(secret: &[u8]) -> String {
    base32::encode(base32::Alphabet::Rfc4648 { padding: false }, secret)
}

/// Build the `otpauth://totp/...` provisioning URI an authenticator app
/// consumes (rendered as a QR code). `issuer` labels the account in the
/// app; `account` is the user's email.
pub fn otpauth_uri(issuer: &str, account: &str, secret_b32: &str) -> String {
    let iss = percent_encode(issuer);
    let acc = percent_encode(account);
    format!(
        "otpauth://totp/{iss}:{acc}?secret={secret_b32}&issuer={iss}&algorithm=SHA1&digits=6&period=30"
    )
}

/// Verify a presented 6-digit `code` against `secret` at `unix_time`,
/// accepting the current 30s step and its immediate neighbours.
/// Constant-time digit comparison; rejects anything not exactly 6 ASCII
/// digits.
pub fn verify_code(secret: &[u8], code: &str, unix_time: i64) -> bool {
    let code = code.trim();
    if code.len() != DIGITS as usize || !code.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let base = (unix_time / TIME_STEP_SECS).max(0);
    for delta in [-1i64, 0, 1] {
        let counter = base + delta;
        if counter < 0 {
            continue;
        }
        let expected = format_code(hotp(secret, counter as u64));
        if bool::from(expected.as_bytes().ct_eq(code.as_bytes())) {
            return true;
        }
    }
    false
}

/// The code for `secret` at `unix_time`. Production only ever *verifies*
/// (via [`verify_code`]); this generator exists for tests and tooling
/// that need to produce a valid code for a known secret.
pub fn code_at(secret: &[u8], unix_time: i64) -> String {
    let counter = (unix_time / TIME_STEP_SECS).max(0) as u64;
    format_code(hotp(secret, counter))
}

/// RFC 4226 HOTP truncation → an N-digit value.
fn hotp(secret: &[u8], counter: u64) -> u32 {
    // HMAC-SHA1 accepts a key of any length, so `new_from_slice` cannot
    // fail here — the only error variant is InvalidLength.
    #[allow(clippy::expect_used)]
    let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(secret)
        .expect("HMAC accepts keys of any length");
    mac.update(&counter.to_be_bytes());
    let hash = mac.finalize().into_bytes();

    let offset = (hash[hash.len() - 1] & 0x0f) as usize;
    let bin = (u32::from(hash[offset] & 0x7f) << 24)
        | (u32::from(hash[offset + 1]) << 16)
        | (u32::from(hash[offset + 2]) << 8)
        | u32::from(hash[offset + 3]);
    bin % 10u32.pow(DIGITS)
}

fn format_code(value: u32) -> String {
    format!("{value:0width$}", width = DIGITS as usize)
}

/// Percent-encode a string for use in the otpauth label/query
/// (unreserved set per RFC 3986).
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    // RFC 6238 Appendix B reference secret (ASCII "12345678901234567890").
    const RFC_SECRET: &[u8] = b"12345678901234567890";

    #[test]
    fn matches_rfc6238_vectors() {
        // (unix time, full 8-digit TOTP from the RFC → last 6 digits).
        let cases = [
            (59i64, "287082"),
            (1_111_111_109, "081804"),
            (1_111_111_111, "050471"),
            (1_234_567_890, "005924"),
            (2_000_000_000, "279037"),
        ];
        for (t, expected) in cases {
            assert_eq!(code_at(RFC_SECRET, t), expected, "T={t}");
        }
    }

    #[test]
    fn verify_accepts_current_step() {
        let t = 1_234_567_890;
        assert!(verify_code(RFC_SECRET, "005924", t));
    }

    #[test]
    fn verify_accepts_adjacent_steps() {
        // A code generated one step earlier still verifies (skew window).
        let t = 1_234_567_890;
        let prev = code_at(RFC_SECRET, t - TIME_STEP_SECS);
        assert!(verify_code(RFC_SECRET, &prev, t));
        let next = code_at(RFC_SECRET, t + TIME_STEP_SECS);
        assert!(verify_code(RFC_SECRET, &next, t));
    }

    #[test]
    fn verify_rejects_two_steps_away() {
        let t = 1_234_567_890;
        let far = code_at(RFC_SECRET, t - 3 * TIME_STEP_SECS);
        assert!(!verify_code(RFC_SECRET, &far, t));
    }

    #[test]
    fn verify_rejects_malformed() {
        let t = 1_234_567_890;
        assert!(!verify_code(RFC_SECRET, "12345", t));
        assert!(!verify_code(RFC_SECRET, "1234567", t));
        assert!(!verify_code(RFC_SECRET, "abcdef", t));
        assert!(!verify_code(RFC_SECRET, "", t));
    }

    #[test]
    fn base32_roundtrips_into_decodable_form() {
        let secret = generate_secret();
        let encoded = base32_encode(&secret);
        let decoded =
            base32::decode(base32::Alphabet::Rfc4648 { padding: false }, &encoded).unwrap();
        assert_eq!(decoded, secret);
    }

    #[test]
    fn otpauth_uri_encodes_email_and_issuer() {
        let uri = otpauth_uri("Sylva Hearth", "a@b.test", "ABCD");
        assert!(uri.starts_with("otpauth://totp/Sylva%20Hearth:a%40b.test?"));
        assert!(uri.contains("secret=ABCD"));
        assert!(uri.contains("issuer=Sylva%20Hearth"));
        assert!(uri.contains("algorithm=SHA1"));
        assert!(uri.contains("digits=6"));
        assert!(uri.contains("period=30"));
    }
}
