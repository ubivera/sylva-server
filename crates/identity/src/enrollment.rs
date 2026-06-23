//! Sylva Hub device-enrollment + E2E key material (see `docs/design/hub.md`).
//!
//! Three identity-plane tables behind the `Account` gRPC service:
//! - `identity.user_keys` — per-user crypto bundle (public keys + ciphertext).
//! - `identity.machines`  — the thin machine plane (the full plane is slice 2).
//! - `identity.devices`   — per-user device enrollments.
//!
//! Creates are **transaction-static** (so `Account.Bootstrap` writes the user,
//! keys, machine, and device atomically); reads + revoke are pool-based,
//! mirroring [`crate::UserRepository`].

use chrono::{DateTime, Duration, Utc};
use rand::{RngCore, rngs::OsRng};
use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

use crate::{Result, UserId};

/// Strongly-typed device identifier (a device enrollment).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, sqlx::Type, Serialize)]
#[sqlx(transparent)]
pub struct DeviceId(pub Uuid);

impl DeviceId {
    pub fn new(uuid: Uuid) -> Self {
        Self(uuid)
    }
    pub fn into_inner(self) -> Uuid {
        self.0
    }
}

impl std::fmt::Display for DeviceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// Strongly-typed machine identifier (a physical machine; thin in slice 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, sqlx::Type, Serialize)]
#[sqlx(transparent)]
pub struct MachineId(pub Uuid);

impl MachineId {
    pub fn new(uuid: Uuid) -> Self {
        Self(uuid)
    }
    pub fn into_inner(self) -> Uuid {
        self.0
    }
}

impl std::fmt::Display for MachineId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

// ── user_keys ────────────────────────────────────────────────────────────────

/// A user's wrapped key bundle. Public keys + ciphertext only — the server
/// never holds plaintext keys, the master key, or the Secret Key. `user_id` is
/// the query key, so it isn't a field here.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct UserKeyMaterial {
    pub x25519_public: Vec<u8>,
    pub ed25519_public: Vec<u8>,
    pub x25519_private_wrapped: Vec<u8>,
    pub ed25519_private_wrapped: Vec<u8>,
    /// Master key wrapped by `KEK = Argon2id(password, secret_key)` (the 2SKD).
    pub master_key_wrapped: Vec<u8>,
    pub kdf_salt: Vec<u8>,
    pub kdf_params: String,
}

const USER_KEY_COLS: &str = "x25519_public, ed25519_public, x25519_private_wrapped, \
     ed25519_private_wrapped, master_key_wrapped, kdf_salt, kdf_params";

#[derive(Clone)]
pub struct UserKeyRepository {
    pool: PgPool,
}

impl UserKeyRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Insert a user's key bundle within the caller's transaction (account
    /// creation). 1:1 with the user; a duplicate is a `23505` unique violation.
    pub async fn create(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        user_id: UserId,
        km: &UserKeyMaterial,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO identity.user_keys
                 (user_id, x25519_public, ed25519_public, x25519_private_wrapped,
                  ed25519_private_wrapped, master_key_wrapped, kdf_salt, kdf_params)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(user_id)
        .bind(&km.x25519_public)
        .bind(&km.ed25519_public)
        .bind(&km.x25519_private_wrapped)
        .bind(&km.ed25519_private_wrapped)
        .bind(&km.master_key_wrapped)
        .bind(&km.kdf_salt)
        .bind(&km.kdf_params)
        .execute(&mut **tx)
        .await?;
        Ok(())
    }

    /// Re-wrap a user's master key within the caller's transaction (password
    /// change): the client re-derives `KEK = KDF(new_password, secret_key)` over
    /// a fresh salt and hands back the new `master_key_wrapped` + salt + params.
    /// The master-key-wrapped *private* keys don't change (the master key is
    /// unchanged), so only these three columns rotate.
    pub async fn update(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        user_id: UserId,
        master_key_wrapped: &[u8],
        kdf_salt: &[u8],
        kdf_params: &str,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE identity.user_keys
             SET master_key_wrapped = $2, kdf_salt = $3, kdf_params = $4
             WHERE user_id = $1",
        )
        .bind(user_id)
        .bind(master_key_wrapped)
        .bind(kdf_salt)
        .bind(kdf_params)
        .execute(&mut **tx)
        .await?;
        Ok(())
    }

    /// Fetch a user's key bundle (for `GetKeyMaterial`). `None` if the user has
    /// no provisioned crypto yet.
    pub async fn get(&self, user_id: UserId) -> Result<Option<UserKeyMaterial>> {
        let sql = format!("SELECT {USER_KEY_COLS} FROM identity.user_keys WHERE user_id = $1");
        let km = sqlx::query_as::<_, UserKeyMaterial>(&sql)
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(km)
    }
}

// ── machines (thin; full plane is slice 2) ─────────────────────────────────────

#[derive(Debug, Clone, sqlx::FromRow, Serialize)]
pub struct Machine {
    pub id: MachineId,
    pub label: String,
    pub platform: String,
    pub claimed_by_user_id: Option<UserId>,
    pub created_at: DateTime<Utc>,
    pub last_seen_at: Option<DateTime<Utc>>,
}

/// Machine-plane writes + reads. Slice-1 device enrollment uses the
/// transaction-static [`create`](Self::create) (one machine per enrollment);
/// slice-2's agent uses the pool-based methods to register by machine identity
/// key and record liveness check-ins (see `docs/design/agent.md`).
#[derive(Clone)]
pub struct MachineRepository {
    pool: PgPool,
}

impl MachineRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Create a machine row within the caller's transaction (claimed by the
    /// enrolling user). Slice-1 device enrollment.
    pub async fn create(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        label: &str,
        platform: &str,
        claimed_by: Option<UserId>,
    ) -> Result<Machine> {
        let machine: Machine = sqlx::query_as(
            "INSERT INTO identity.machines (label, platform, claimed_by_user_id)
             VALUES ($1, $2, $3)
             RETURNING id, label, platform, claimed_by_user_id, created_at, last_seen_at",
        )
        .bind(label)
        .bind(platform)
        .bind(claimed_by)
        .fetch_one(&mut **tx)
        .await?;
        Ok(machine)
    }

    /// Register (or re-register) a machine by its Ed25519 identity key, within
    /// the caller's transaction. Idempotent on the key: re-registering updates
    /// the label/platform and bumps `last_seen_at`. Returns the machine id.
    pub async fn register_or_update(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        identity_public: &[u8],
        platform: &str,
        label: &str,
    ) -> Result<MachineId> {
        let (id,): (Uuid,) = sqlx::query_as(
            "INSERT INTO identity.machines (label, platform, machine_identity_public, last_seen_at)
             VALUES ($1, $2, $3, now())
             ON CONFLICT (machine_identity_public) DO UPDATE
                 SET label = EXCLUDED.label,
                     platform = EXCLUDED.platform,
                     last_seen_at = now()
             RETURNING id",
        )
        .bind(label)
        .bind(platform)
        .bind(identity_public)
        .fetch_one(&mut **tx)
        .await?;
        Ok(MachineId(id))
    }

    /// Record a liveness check-in: bump `last_seen_at` and the reported agent
    /// version. Pool-based (single statement).
    pub async fn touch_checkin(&self, machine_id: MachineId, agent_version: &str) -> Result<()> {
        sqlx::query(
            "UPDATE identity.machines
             SET last_seen_at = now(), agent_version = $2
             WHERE id = $1",
        )
        .bind(machine_id)
        .bind(agent_version)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Whether location reporting is enabled for this machine (admin policy,
    /// pushed to the agent in `MachineConfig`).
    pub async fn location_enabled(&self, machine_id: MachineId) -> Result<bool> {
        let (enabled,): (bool,) =
            sqlx::query_as("SELECT location_enabled FROM identity.machines WHERE id = $1")
                .bind(machine_id)
                .fetch_one(&self.pool)
                .await?;
        Ok(enabled)
    }

    /// Set the per-machine location toggle. The real surface is the client-app
    /// devices panel; dev/test uses this directly until that exists.
    pub async fn set_location_enabled(&self, machine_id: MachineId, enabled: bool) -> Result<()> {
        sqlx::query("UPDATE identity.machines SET location_enabled = $2 WHERE id = $1")
            .bind(machine_id)
            .bind(enabled)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

// ── machine sessions (slice 2 — the agent's bearer credential) ──────────────────

/// An issued machine session — the agent's bearer credential, carried on
/// CheckIn/Subscribe. Only the token hash is stored; the raw token lives on the
/// device's machine-scoped store.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct MachineSession {
    pub id: Uuid,
    pub machine_id: MachineId,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

/// Generate a 32-byte random machine session token (64-char hex). Mirrors the
/// user-session + invite-token approach; `sha256(token)` is what's stored.
pub fn generate_machine_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// SHA-256 of a machine session token — what goes into `token_hash`.
pub fn hash_machine_token(token: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hasher.finalize().into()
}

#[derive(Clone)]
pub struct MachineSessionRepository {
    pool: PgPool,
}

impl MachineSessionRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Issue a machine session within the caller's transaction. Returns the row
    /// + the raw token (handed to the agent; only its hash is persisted).
    pub async fn create(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        machine_id: MachineId,
        ttl: Duration,
    ) -> Result<(MachineSession, String)> {
        let token = generate_machine_token();
        let token_hash = hash_machine_token(&token);
        let expires_at = Utc::now() + ttl;
        let session: MachineSession = sqlx::query_as(
            "INSERT INTO identity.machine_sessions (machine_id, token_hash, expires_at)
             VALUES ($1, $2, $3)
             RETURNING id, machine_id, created_at, expires_at, revoked_at",
        )
        .bind(machine_id)
        .bind(&token_hash[..])
        .bind(expires_at)
        .fetch_one(&mut **tx)
        .await?;
        Ok((session, token))
    }

    /// Resolve a raw token to its active (non-revoked, non-expired) machine
    /// session. `None` if no match.
    pub async fn find_active(&self, token: &str) -> Result<Option<MachineSession>> {
        let token_hash = hash_machine_token(token);
        let session: Option<MachineSession> = sqlx::query_as(
            "SELECT id, machine_id, created_at, expires_at, revoked_at
             FROM identity.machine_sessions
             WHERE token_hash = $1
               AND revoked_at IS NULL
               AND expires_at > now()",
        )
        .bind(&token_hash[..])
        .fetch_optional(&self.pool)
        .await?;
        Ok(session)
    }
}

// ── devices ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, sqlx::FromRow, Serialize)]
pub struct Device {
    pub id: DeviceId,
    pub user_id: UserId,
    pub machine_id: Option<MachineId>,
    pub device_label: String,
    pub platform: String,
    pub device_public_key: Vec<u8>,
    pub created_at: DateTime<Utc>,
    pub last_seen_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

/// Fields for enrolling a device. The OS keychain holds the private key for
/// `device_public_key`; the server only ever stores the public key.
pub struct NewDevice {
    pub user_id: UserId,
    pub machine_id: Option<MachineId>,
    pub device_label: String,
    pub platform: String,
    pub device_public_key: Vec<u8>,
}

const DEVICE_COLS: &str = "id, user_id, machine_id, device_label, platform, \
     device_public_key, created_at, last_seen_at, revoked_at";

#[derive(Clone)]
pub struct DeviceRepository {
    pool: PgPool,
}

impl DeviceRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Enroll a device within the caller's transaction.
    pub async fn register(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        new: &NewDevice,
    ) -> Result<Device> {
        let sql = format!(
            "INSERT INTO identity.devices
                 (user_id, machine_id, device_label, platform, device_public_key)
             VALUES ($1, $2, $3, $4, $5)
             RETURNING {DEVICE_COLS}"
        );
        let device = sqlx::query_as::<_, Device>(&sql)
            .bind(new.user_id)
            .bind(new.machine_id)
            .bind(&new.device_label)
            .bind(&new.platform)
            .bind(&new.device_public_key)
            .fetch_one(&mut **tx)
            .await?;
        Ok(device)
    }

    /// A user's active (non-revoked) device enrollments, oldest first.
    pub async fn list_for_user(&self, user_id: UserId) -> Result<Vec<Device>> {
        let sql = format!(
            "SELECT {DEVICE_COLS} FROM identity.devices
             WHERE user_id = $1 AND revoked_at IS NULL
             ORDER BY created_at"
        );
        let devices = sqlx::query_as::<_, Device>(&sql)
            .bind(user_id)
            .fetch_all(&self.pool)
            .await?;
        Ok(devices)
    }

    /// Owner-scoped fetch of one device (any state).
    pub async fn get_owned(&self, device_id: DeviceId, user_id: UserId) -> Result<Option<Device>> {
        let sql = format!("SELECT {DEVICE_COLS} FROM identity.devices WHERE id = $1 AND user_id = $2");
        let device = sqlx::query_as::<_, Device>(&sql)
            .bind(device_id)
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(device)
    }

    /// Owner-scoped revoke (sets `revoked_at`). Returns whether a row was
    /// affected (false = not found / not owned / already revoked).
    pub async fn revoke_owned(&self, device_id: DeviceId, user_id: UserId) -> Result<bool> {
        let result = sqlx::query(
            "UPDATE identity.devices SET revoked_at = now()
             WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL",
        )
        .bind(device_id)
        .bind(user_id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }
}
