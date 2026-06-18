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

use chrono::{DateTime, Utc};
use serde::Serialize;
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

/// Machine-plane writes. Slice 1 is create-only (one machine per enrollment);
/// reads + the full management plane (dedup, claim lifecycle, location,
/// app-push) land in slice 2, at which point this gains a pool + read methods.
pub struct MachineRepository;

impl MachineRepository {
    /// Create a machine row within the caller's transaction (claimed by the
    /// enrolling user).
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
