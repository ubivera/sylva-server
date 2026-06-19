//! Authenticated encryption for secrets the server must be able to read
//! back later — unlike passwords and recovery codes, which are one-way
//! hashed. Today the sole user is the TOTP shared secret (the server
//! needs the plaintext secret to compute the expected code at sign-in).
//!
//! XChaCha20-Poly1305 with a random 192-bit nonce prepended to the
//! ciphertext: `nonce(24) || ciphertext+tag`. The key is the persistent
//! per-instance server key (server's `secret_key`), which — unlike the
//! per-process CSRF secret — survives restarts so sealed data stays
//! readable.

use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};

use crate::{AuthError, Result};

const NONCE_LEN: usize = 24;

/// Encrypt `plaintext` under `key`. The returned blob is opaque and
/// self-contained (it carries its own nonce) — store it as-is and hand
/// it back to [`open`].
pub fn seal(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| AuthError::Crypto)?;
    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(nonce.as_slice());
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt a blob produced by [`seal`]. Returns `Err(Crypto)` if the
/// blob is truncated, tampered with, or was sealed under a different
/// key (the AEAD tag fails) — callers must not distinguish these.
pub fn open(key: &[u8; 32], blob: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < NONCE_LEN {
        return Err(AuthError::Crypto);
    }
    let (nonce_bytes, ciphertext) = blob.split_at(NONCE_LEN);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = XNonce::from_slice(nonce_bytes);
    cipher.decrypt(nonce, ciphertext).map_err(|_| AuthError::Crypto)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    const KEY: [u8; 32] = [7u8; 32];

    #[test]
    fn round_trips() {
        let blob = seal(&KEY, b"hello totp secret").unwrap();
        assert_eq!(open(&KEY, &blob).unwrap(), b"hello totp secret");
    }

    #[test]
    fn distinct_nonces_per_seal() {
        // Same plaintext + key should not produce identical ciphertext.
        let a = seal(&KEY, b"same").unwrap();
        let b = seal(&KEY, b"same").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn wrong_key_fails() {
        let blob = seal(&KEY, b"secret").unwrap();
        assert!(open(&[9u8; 32], &blob).is_err());
    }

    #[test]
    fn tamper_fails() {
        let mut blob = seal(&KEY, b"secret").unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0x01;
        assert!(open(&KEY, &blob).is_err());
    }

    #[test]
    fn truncated_blob_fails() {
        assert!(open(&KEY, b"short").is_err());
    }
}
