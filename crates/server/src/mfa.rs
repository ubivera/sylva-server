//! Cross-factor MFA helpers — questions that span every enrolled factor
//! type (TOTP authenticators, WebAuthn passkeys) rather than a single
//! one. The post-password sign-in branch uses this to decide whether a
//! second factor is owed at all.

use identity::UserId;
use sqlx::PgPool;

/// Whether the user has at least one active second factor of *any* kind.
/// Security-critical: this is the single gate deciding if `/login` may
/// issue a session directly or must hand off to the challenge. Keep it
/// the one source of truth as new factor types are added.
pub async fn has_second_factor(db: &PgPool, user_id: UserId) -> anyhow::Result<bool> {
    if auth::user_totp::is_enrolled(db, user_id).await? {
        return Ok(true);
    }
    crate::webauthn::has_any(db, user_id).await
}
