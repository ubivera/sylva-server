use chrono::{DateTime, Utc};
use identity::UserId;
use rand::{RngCore, rngs::OsRng};
use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

use crate::Result;

/// 20 random bytes → 32 base32 chars × 5 bits = 160 bits of entropy. Well
/// above the 128-bit floor for "infeasible to brute-force"; chosen because
/// 160 bits maps cleanly to 8 groups of 4 base32 chars without padding.
const CODE_ENTROPY_BYTES: usize = 20;

/// Crockford base32 alphabet: digits + uppercase letters with `I`, `L`,
/// `O`, `U` removed. Eliminates the 0/O, 1/I/L look-alike traps that
/// plague hex when a human is reading a code off paper.
const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Produce a fresh recovery code formatted for human handling: 8 groups
/// of 4 Crockford base32 characters separated by hyphens. Example:
/// `7HZK-9R4M-NXBP-V2T8-3JDQ-6KWS-MGYF-PE5X` (35 chars including dashes).
///
/// The format is designed for paper/password-manager storage and
/// over-the-phone read-back; an operator typing it later can use any
/// casing, drop the hyphens, or accept `I`/`L` for `1` and `O` for `0`
/// — see [`canonicalize`] for the normalisation rules.
pub fn generate_code() -> String {
    let mut bytes = [0u8; CODE_ENTROPY_BYTES];
    OsRng.fill_bytes(&mut bytes);
    encode_grouped(&bytes)
}

fn encode_grouped(bytes: &[u8; CODE_ENTROPY_BYTES]) -> String {
    // 20 bytes = 4 chunks × 5 bytes = 4 chunks × 8 base32 chars = 32 chars.
    let mut chars = [0u8; 32];
    for chunk in 0..4 {
        let o = chunk * 5;
        let c = chunk * 8;
        let b = [bytes[o], bytes[o + 1], bytes[o + 2], bytes[o + 3], bytes[o + 4]];
        chars[c] = CROCKFORD[(b[0] >> 3) as usize];
        chars[c + 1] = CROCKFORD[(((b[0] & 0x07) << 2) | (b[1] >> 6)) as usize];
        chars[c + 2] = CROCKFORD[((b[1] >> 1) & 0x1f) as usize];
        chars[c + 3] = CROCKFORD[(((b[1] & 0x01) << 4) | (b[2] >> 4)) as usize];
        chars[c + 4] = CROCKFORD[(((b[2] & 0x0f) << 1) | (b[3] >> 7)) as usize];
        chars[c + 5] = CROCKFORD[((b[3] >> 2) & 0x1f) as usize];
        chars[c + 6] = CROCKFORD[(((b[3] & 0x03) << 3) | (b[4] >> 5)) as usize];
        chars[c + 7] = CROCKFORD[(b[4] & 0x1f) as usize];
    }

    let mut out = String::with_capacity(32 + 7);
    for (i, &c) in chars.iter().enumerate() {
        if i > 0 && i % 4 == 0 {
            out.push('-');
        }
        out.push(c as char);
    }
    out
}

/// Hash a recovery code for storage / comparison. The input is
/// [`canonicalize`]d first so any reasonable form the operator types back
/// — with or without dashes, any casing, `I`/`L`→`1`, `O`→`0` — maps to
/// the same hash.
pub fn hash_code(raw: &str) -> [u8; 32] {
    let canonical = canonicalize(raw);
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    hasher.finalize().into()
}

/// Normalise a recovery code for hashing: strip dashes + whitespace,
/// uppercase, map Crockford look-alikes (`I`/`L`→`1`, `O`→`0`). Any
/// other character passes through unchanged — the resulting hash will
/// simply not match the stored hash, which is the intended failure mode
/// for genuinely-wrong input.
fn canonicalize(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch.to_ascii_uppercase() {
            '-' | ' ' | '\t' | '\n' | '\r' => {}
            'I' | 'L' => out.push('1'),
            'O' => out.push('0'),
            other => out.push(other),
        }
    }
    out
}

/// Metadata about a recovery code. The raw code never appears here — the
/// `GET /admin/server/recovery-code` endpoint returns this view so the
/// operator can confirm a code exists and when it was last touched.
#[derive(Debug, Clone, sqlx::FromRow, Serialize)]
pub struct RecoveryCodeRow {
    pub id: Uuid,
    pub created_at: DateTime<Utc>,
    pub created_by_user_id: Option<Uuid>,
    pub rotated_at: Option<DateTime<Utc>>,
    pub rotated_by_user_id: Option<Uuid>,
}

/// Insert the very first recovery code at provision time. Fails if an
/// active code already exists (the singleton unique index will reject the
/// second row). Returns the row id so the caller can audit it.
pub async fn bootstrap(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    raw_code: &str,
    by_user_id: Option<UserId>,
) -> Result<Uuid> {
    let hash = hash_code(raw_code);
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO auth.recovery_codes (code_hash, created_by_user_id)
         VALUES ($1, $2)
         RETURNING id",
    )
    .bind(&hash[..])
    .bind(by_user_id)
    .fetch_one(&mut **tx)
    .await?;
    Ok(id)
}

/// Look up the currently active recovery code's metadata (no raw, no hash).
pub async fn active_metadata(pool: &PgPool) -> Result<Option<RecoveryCodeRow>> {
    let row: Option<RecoveryCodeRow> = sqlx::query_as(
        "SELECT id, created_at, created_by_user_id, rotated_at, rotated_by_user_id
         FROM auth.recovery_codes
         WHERE rotated_at IS NULL",
    )
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// Verify that `presented` matches the currently-active code. Returns the
/// row's id on match (useful for audit), `None` on mismatch or when no
/// active code exists. Constant-time comparison is unnecessary at the SHA-
/// 256 layer: the hash space is 256 bits, so no observable timing channel
/// is actionable.
pub async fn verify(pool: &PgPool, presented: &str) -> Result<Option<Uuid>> {
    let hash = hash_code(presented);
    let id: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM auth.recovery_codes
         WHERE rotated_at IS NULL AND code_hash = $1",
    )
    .bind(&hash[..])
    .fetch_optional(pool)
    .await?;
    Ok(id)
}

/// Atomically rotate the active recovery code: verify possession of the
/// current code and replace it in one UPDATE so a concurrent rotation
/// can't slip between a verify and a write.
///
/// Returns `Ok(Some((new_id, previous_id)))` on success or `Ok(None)`
/// when `current_raw` doesn't hash to the active code (the operator
/// supplied the wrong current code — handler should map to 401).
pub async fn rotate(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    current_raw: &str,
    new_raw: &str,
    by_user_id: UserId,
) -> Result<Option<(Uuid, Uuid)>> {
    let current_hash = hash_code(current_raw);

    // Mark current active row rotated only if its hash matches what the
    // caller supplied. If another rotation happened first, the WHERE
    // clause fails and we return None — the operator has to retry with
    // the genuinely-active code.
    let previous_id: Option<Uuid> = sqlx::query_scalar(
        "UPDATE auth.recovery_codes
         SET rotated_at = now(), rotated_by_user_id = $1
         WHERE rotated_at IS NULL AND code_hash = $2
         RETURNING id",
    )
    .bind(by_user_id)
    .bind(&current_hash[..])
    .fetch_optional(&mut **tx)
    .await?;

    let Some(previous_id) = previous_id else {
        return Ok(None);
    };

    let new_hash = hash_code(new_raw);
    let new_id: Uuid = sqlx::query_scalar(
        "INSERT INTO auth.recovery_codes (code_hash, created_by_user_id)
         VALUES ($1, $2)
         RETURNING id",
    )
    .bind(&new_hash[..])
    .bind(by_user_id)
    .fetch_one(&mut **tx)
    .await?;

    Ok(Some((new_id, previous_id)))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn generate_code_has_apple_style_format() {
        let code = generate_code();
        // 8 groups of 4 chars (32) + 7 separators = 39 chars total.
        assert_eq!(code.len(), 39);

        let groups: Vec<&str> = code.split('-').collect();
        assert_eq!(groups.len(), 8, "expected 8 groups: {code}");
        for g in &groups {
            assert_eq!(g.len(), 4, "group {g:?} should be 4 chars: {code}");
        }

        // Every character must belong to the Crockford alphabet.
        for c in code.chars() {
            if c == '-' {
                continue;
            }
            assert!(
                CROCKFORD.contains(&(c as u8)),
                "char {c:?} not in Crockford alphabet: {code}"
            );
        }
    }

    #[test]
    fn generate_code_is_unpredictable() {
        let a = generate_code();
        let b = generate_code();
        assert_ne!(a, b);
    }

    #[test]
    fn canonicalize_strips_dashes_and_uppercases() {
        assert_eq!(canonicalize("ab-cd"), "ABCD");
        assert_eq!(canonicalize("  AB CD\t"), "ABCD");
    }

    #[test]
    fn canonicalize_maps_crockford_lookalikes() {
        // I → 1, L → 1, O → 0. Digits pass through unchanged.
        assert_eq!(canonicalize("IL10"), "1110"); // I→1, L→1, 1→1, 0→0
        assert_eq!(canonicalize("iLoO"), "1100"); // i→1, L→1, o→0, O→0
        assert_eq!(canonicalize("ABCD"), "ABCD"); // unaffected chars pass through
    }

    #[test]
    fn hash_code_invariant_under_format_quirks() {
        let canonical = generate_code();
        let h = hash_code(&canonical);

        // Same code without dashes hashes identically.
        let stripped = canonical.replace('-', "");
        assert_eq!(hash_code(&stripped), h);

        // Lowercased hashes identically.
        assert_eq!(hash_code(&canonical.to_ascii_lowercase()), h);

        // Substituting `1` → `I` (and `0` → `O`) hashes identically iff
        // the original had any such chars. Build a stress variant by
        // taking the canonical form and swapping any `1`s for `I`s and
        // `0`s for `O`s; that's exactly what a sloppy operator would type.
        let look_alike: String = canonical
            .chars()
            .map(|c| match c {
                '1' => 'I',
                '0' => 'O',
                other => other,
            })
            .collect();
        assert_eq!(hash_code(&look_alike), h);
    }

    #[test]
    fn hash_code_differs_for_actually_wrong_input() {
        let a = hash_code("ABCD-EFGH-JKMN-PQRS-TVWX-YZ23-4567-89AB");
        let b = hash_code("ABCD-EFGH-JKMN-PQRS-TVWX-YZ23-4567-89AC");
        assert_ne!(a, b);
    }
}
