//! Instance-level state read at startup: the server identity keypair (the
//! trust anchor native clients pin) and the operator-chosen display name
//! advertised in discovery. Both live on the `sylva_meta.instance` singleton.

use sqlx::PgPool;

use crate::config;

// ── Server identity key ────────────────────────────────────────────────────
//
// The Ed25519 keypair native clients (Sylva Hub) TOFU-pin as the server's
// durable trust anchor — stable across cert rotation and multiple endpoints
// (see docs/design/hub.md). It lives on the `sylva_meta` singleton so the
// server keeps its identity across restarts; the private key is sealed with the
// instance `secret_key` (XChaCha20-Poly1305). The server signs discovery
// responses with it.

/// The loaded server identity: the Ed25519 signing key (for signing discovery
/// responses) + its public key (advertised + pinned by clients).
pub struct ServerIdentity {
    pub signing_key: ed25519_dalek::SigningKey,
    pub public: [u8; 32],
}

/// The two persisted identity columns: `(public, sealed_seed)`, each NULL until
/// first generation.
type StoredServerIdentity = (Option<Vec<u8>>, Option<Vec<u8>>);

/// Load the server identity, generating + persisting one on first call. Called
/// once at startup. The 32-byte signing seed is the sealed secret; the public
/// key is stored in the clear. Idempotent after the first generation.
pub async fn ensure_server_identity(
    db: &PgPool,
    secret_key: &[u8; 32],
) -> anyhow::Result<ServerIdentity> {
    let row: Option<StoredServerIdentity> = sqlx::query_as(
        "SELECT server_identity_public, server_identity_priv_enc \
         FROM sylva_meta.instance WHERE id = TRUE",
    )
    .fetch_optional(db)
    .await?;

    if let Some((Some(public), Some(priv_enc))) = row {
        let seed = auth::secretbox::open(secret_key, &priv_enc)
            .map_err(|_| anyhow::anyhow!("decrypting server identity key"))?;
        let seed: [u8; 32] = seed
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("stored server identity key has the wrong length"))?;
        let public: [u8; 32] = public
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("stored server identity public key has the wrong length"))?;
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        return Ok(ServerIdentity { signing_key, public });
    }

    // First run: generate a fresh keypair from OS entropy, seal the seed, and
    // persist both. (We seed `from_bytes` rather than `generate` to avoid
    // coupling to a specific `rand_core` version across crates.)
    let mut seed = [0u8; 32];
    let mut rng = rand::rngs::OsRng;
    rand::RngCore::fill_bytes(&mut rng, &mut seed);
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let public = signing_key.verifying_key().to_bytes();
    let priv_enc = auth::secretbox::seal(secret_key, &seed)
        .map_err(|_| anyhow::anyhow!("sealing server identity key"))?;
    sqlx::query(
        "UPDATE sylva_meta.instance \
         SET server_identity_public = $1, server_identity_priv_enc = $2 \
         WHERE id = TRUE",
    )
    .bind(&public[..])
    .bind(&priv_enc[..])
    .execute(db)
    .await?;
    Ok(ServerIdentity { signing_key, public })
}

// ── Instance display name ──────────────────────────────────────────────────

/// The instance display name advertised in discovery: the DB override on the
/// `sylva_meta.instance` singleton if set, else the env/startup default
/// (`SYLVA_INSTANCE_NAME`). A missing row falls back to the env default.
pub async fn server_name(db: &PgPool, env: &config::Config) -> anyhow::Result<String> {
    let stored: Option<Option<String>> =
        sqlx::query_scalar("SELECT instance_name FROM sylva_meta.instance WHERE id = TRUE")
            .fetch_optional(db)
            .await?;
    Ok(stored
        .flatten()
        .unwrap_or_else(|| env.instance_name.clone()))
}
