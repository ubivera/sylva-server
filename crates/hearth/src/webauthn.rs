//! WebAuthn / passkey ceremonies and credential storage, built on
//! `webauthn-rs`. The web layer talks to this module in JSON (it never
//! touches `webauthn-rs` types directly): start functions return the
//! browser ceremony options as `serde_json::Value`; finish functions
//! take the browser's credential response as a JSON string.
//!
//! Passkeys store only a **public** key, so credentials are persisted as
//! plain JSONB (no encryption needed, unlike TOTP secrets). The short-
//! lived ceremony *state* (registration/authentication) is persisted in
//! `auth.webauthn_challenges` between the start and finish requests
//! (serde-enabled via the `danger-allow-state-serialisation` feature).
//!
//! **RP requirement:** WebAuthn needs the public base URL to have a
//! hostname (`localhost` in dev, an https domain in prod) — a bare IP
//! has no RP ID, so [`build`] errors and the passkey feature degrades to
//! "unavailable".

use anyhow::{Context, anyhow};
use identity::{User, UserId};
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;
use webauthn_rs::prelude::*;

use crate::app::AppState;

const PURPOSE_REGISTER: &str = "register";
const PURPOSE_AUTH: &str = "authenticate";

/// Upper bound on passkeys per user (parallels the authenticator cap).
pub const MAX_PASSKEYS: i64 = 50;

/// A stored passkey as shown in the Security tab (no key material).
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct WebauthnCredentialRow {
    pub id: Uuid,
    pub label: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub last_used_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Build the relying-party handle from the instance's public base URL.
/// Errors when the URL has no hostname (bare IP) — passkeys then surface
/// as unavailable rather than crashing.
pub fn build(public_base_url: &str, rp_name: &str) -> anyhow::Result<Webauthn> {
    let origin = Url::parse(public_base_url)
        .with_context(|| format!("invalid public_base_url: {public_base_url}"))?;
    let rp_id = origin
        .domain()
        .ok_or_else(|| {
            anyhow!("public_base_url must have a hostname for WebAuthn (not a bare IP)")
        })?
        .to_string();
    let webauthn = WebauthnBuilder::new(&rp_id, &origin)?.rp_name(rp_name).build()?;
    Ok(webauthn)
}

/// Whether passkeys are configurable on this instance (RP can be built).
pub fn available(state: &AppState) -> bool {
    build(&state.public_base_url, &state.instance_name).is_ok()
}

// ── Public read API (used by the Security-tab UI + login branch) ──────────

pub async fn list(pool: &PgPool, user_id: UserId) -> anyhow::Result<Vec<WebauthnCredentialRow>> {
    let rows = sqlx::query_as::<_, WebauthnCredentialRow>(
        "SELECT id, label, created_at, last_used_at
         FROM auth.webauthn_credentials
         WHERE user_id = $1
         ORDER BY created_at",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

pub async fn count(pool: &PgPool, user_id: UserId) -> anyhow::Result<i64> {
    let (n,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM auth.webauthn_credentials WHERE user_id = $1")
            .bind(user_id)
            .fetch_one(pool)
            .await?;
    Ok(n)
}

pub async fn has_any(pool: &PgPool, user_id: UserId) -> anyhow::Result<bool> {
    Ok(count(pool, user_id).await? > 0)
}

pub async fn rename(pool: &PgPool, user_id: UserId, id: Uuid, label: &str) -> anyhow::Result<bool> {
    let r = sqlx::query(
        "UPDATE auth.webauthn_credentials SET label = $3 WHERE id = $1 AND user_id = $2",
    )
    .bind(id)
    .bind(user_id)
    .bind(label)
    .execute(pool)
    .await?;
    Ok(r.rows_affected() > 0)
}

pub async fn delete(pool: &PgPool, user_id: UserId, id: Uuid) -> anyhow::Result<bool> {
    let r = sqlx::query("DELETE FROM auth.webauthn_credentials WHERE id = $1 AND user_id = $2")
        .bind(id)
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(r.rows_affected() > 0)
}

// ── Registration ceremony ─────────────────────────────────────────────────

/// Start enrolling a new passkey. Returns `(challenge_id, options)` —
/// `options` is the `navigator.credentials.create` argument (JSON),
/// `challenge_id` ties the browser's eventual response to the stored
/// ceremony state.
pub async fn start_registration(
    state: &AppState,
    user: &User,
) -> anyhow::Result<(Uuid, Value)> {
    let webauthn = build(&state.public_base_url, &state.instance_name)?;
    let exclude = existing_cred_ids(&state.db, user.id).await?;
    let exclude = if exclude.is_empty() { None } else { Some(exclude) };
    let (ccr, reg_state) =
        webauthn.start_passkey_registration(user.id.0, &user.email, &user.display_name, exclude)?;
    let challenge_id =
        insert_challenge(&state.db, user.id, PURPOSE_REGISTER, &serde_json::to_value(&reg_state)?)
            .await?;
    Ok((challenge_id, serde_json::to_value(&ccr)?))
}

/// Finish passkey enrollment: validate the browser's response against the
/// stored ceremony state and persist the credential under `label`.
pub async fn finish_registration(
    state: &AppState,
    user: &User,
    challenge_id: Uuid,
    label: &str,
    credential_json: &str,
) -> anyhow::Result<()> {
    let webauthn = build(&state.public_base_url, &state.instance_name)?;
    let reg: RegisterPublicKeyCredential = serde_json::from_str(credential_json)
        .context("malformed passkey registration response")?;
    let state_json = take_challenge(&state.db, user.id, challenge_id, PURPOSE_REGISTER)
        .await?
        .ok_or_else(|| anyhow!("registration challenge expired"))?;
    let reg_state: PasskeyRegistration = serde_json::from_value(state_json)?;
    let passkey = webauthn.finish_passkey_registration(&reg, &reg_state)?;
    sqlx::query(
        "INSERT INTO auth.webauthn_credentials (user_id, label, credential)
         VALUES ($1, $2, $3)",
    )
    .bind(user.id)
    .bind(label)
    .bind(serde_json::to_value(&passkey)?)
    .execute(&state.db)
    .await?;
    Ok(())
}

// ── Authentication ceremony (second factor) ───────────────────────────────

/// Start a passkey authentication for a known user. Returns `None` if the
/// user has no passkeys.
pub async fn start_authentication(
    state: &AppState,
    user_id: UserId,
) -> anyhow::Result<Option<(Uuid, Value)>> {
    let passkeys = all_passkeys(&state.db, user_id).await?;
    if passkeys.is_empty() {
        return Ok(None);
    }
    let webauthn = build(&state.public_base_url, &state.instance_name)?;
    let creds: Vec<Passkey> = passkeys.into_iter().map(|(_, pk)| pk).collect();
    let (rcr, auth_state) = webauthn.start_passkey_authentication(&creds)?;
    let challenge_id =
        insert_challenge(&state.db, user_id, PURPOSE_AUTH, &serde_json::to_value(&auth_state)?)
            .await?;
    Ok(Some((challenge_id, serde_json::to_value(&rcr)?)))
}

/// Finish passkey authentication. Returns `true` on a valid assertion,
/// stamping the matched credential's `last_used_at` (and counter).
pub async fn finish_authentication(
    state: &AppState,
    user_id: UserId,
    challenge_id: Uuid,
    credential_json: &str,
) -> anyhow::Result<bool> {
    let webauthn = build(&state.public_base_url, &state.instance_name)?;
    let pkc: PublicKeyCredential = match serde_json::from_str(credential_json) {
        Ok(c) => c,
        Err(err) => {
            tracing::warn!(?err, "malformed passkey auth response");
            return Ok(false);
        }
    };
    let state_json = match take_challenge(&state.db, user_id, challenge_id, PURPOSE_AUTH).await? {
        Some(s) => s,
        None => return Ok(false),
    };
    let auth_state: PasskeyAuthentication = serde_json::from_value(state_json)?;
    let result = match webauthn.finish_passkey_authentication(&pkc, &auth_state) {
        Ok(r) => r,
        Err(err) => {
            tracing::warn!(?err, "passkey authentication rejected");
            return Ok(false);
        }
    };

    // Update the matched credential (counter / backup flags) + last-used.
    let mut passkeys = all_passkeys(&state.db, user_id).await?;
    for (row_id, passkey) in passkeys.iter_mut() {
        if passkey.cred_id() == result.cred_id() {
            if passkey.update_credential(&result) == Some(true) {
                sqlx::query("UPDATE auth.webauthn_credentials SET credential = $2 WHERE id = $1")
                    .bind(*row_id)
                    .bind(serde_json::to_value(&*passkey)?)
                    .execute(&state.db)
                    .await?;
            }
            sqlx::query("UPDATE auth.webauthn_credentials SET last_used_at = now() WHERE id = $1")
                .bind(*row_id)
                .execute(&state.db)
                .await?;
            break;
        }
    }
    Ok(true)
}

// ── Internal helpers ──────────────────────────────────────────────────────

async fn existing_cred_ids(pool: &PgPool, user_id: UserId) -> anyhow::Result<Vec<CredentialID>> {
    Ok(all_passkeys(pool, user_id)
        .await?
        .into_iter()
        .map(|(_, pk)| pk.cred_id().clone())
        .collect())
}

async fn all_passkeys(pool: &PgPool, user_id: UserId) -> anyhow::Result<Vec<(Uuid, Passkey)>> {
    let rows: Vec<(Uuid, Value)> = sqlx::query_as(
        "SELECT id, credential FROM auth.webauthn_credentials WHERE user_id = $1",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    let mut out = Vec::with_capacity(rows.len());
    for (id, json) in rows {
        out.push((id, serde_json::from_value(json)?));
    }
    Ok(out)
}

/// Insert a ceremony state, clearing any prior in-flight ceremony of the
/// same purpose for this user (one at a time). Returns the challenge id.
async fn insert_challenge(
    pool: &PgPool,
    user_id: UserId,
    purpose: &str,
    state_json: &Value,
) -> anyhow::Result<Uuid> {
    sqlx::query("DELETE FROM auth.webauthn_challenges WHERE user_id = $1 AND purpose = $2")
        .bind(user_id)
        .bind(purpose)
        .execute(pool)
        .await?;
    let (id,): (Uuid,) = sqlx::query_as(
        "INSERT INTO auth.webauthn_challenges (user_id, purpose, state)
         VALUES ($1, $2, $3) RETURNING id",
    )
    .bind(user_id)
    .bind(purpose)
    .bind(state_json)
    .fetch_one(pool)
    .await?;
    Ok(id)
}

/// Consume a ceremony state (delete + return) scoped to user + purpose.
async fn take_challenge(
    pool: &PgPool,
    user_id: UserId,
    id: Uuid,
    purpose: &str,
) -> anyhow::Result<Option<Value>> {
    let row: Option<(Value,)> = sqlx::query_as(
        "DELETE FROM auth.webauthn_challenges
         WHERE id = $1 AND user_id = $2 AND purpose = $3
         RETURNING state",
    )
    .bind(id)
    .bind(user_id)
    .bind(purpose)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|(v,)| v))
}
