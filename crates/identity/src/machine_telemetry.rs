//! Slice-2 machine telemetry (E2E) + the device-admin group key.
//!
//! The server is zero-knowledge here: it stores telemetry *ciphertext* sealed to
//! the device-admin group key and never reads it. The group **public** key is
//! what agents seal to (pushed to them in `MachineConfig`); the group secret is
//! held by admins (wrapping it per-admin is a client-app concern). See
//! `docs/design/agent.md`.

use sqlx::PgPool;
use uuid::Uuid;

use crate::{MachineId, Result};

/// The active device-admin group key — agents seal telemetry to `public`.
#[derive(Debug, Clone)]
pub struct DeviceAdminGroup {
    pub id: Uuid,
    pub public: Vec<u8>,
}

#[derive(Clone)]
pub struct DeviceAdminGroupRepository {
    pool: PgPool,
}

impl DeviceAdminGroupRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// The current group key (most recent), or `None` if none is provisioned yet.
    pub async fn active(&self) -> Result<Option<DeviceAdminGroup>> {
        let row: Option<(Uuid, Vec<u8>)> = sqlx::query_as(
            "SELECT id, group_public FROM identity.device_admin_group \
             ORDER BY created_at DESC LIMIT 1",
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|(id, public)| DeviceAdminGroup { id, public }))
    }

    /// Provision a group key. The client app does this for real (generating the
    /// keypair + wrapping the secret to each admin); dev/test uses this directly.
    pub async fn create(&self, public: &[u8]) -> Result<Uuid> {
        let (id,): (Uuid,) = sqlx::query_as(
            "INSERT INTO identity.device_admin_group (group_public) VALUES ($1) RETURNING id",
        )
        .bind(public)
        .fetch_one(&self.pool)
        .await?;
        Ok(id)
    }
}

/// One encrypted telemetry blob to store. The envelope is plaintext; `ciphertext`
/// is sealed to the device-admin group key — the server never reads it.
pub struct NewTelemetry {
    pub kind: String,
    pub recipient_key_id: Vec<u8>,
    pub seq: i64,
    pub ciphertext: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Clone)]
pub struct MachineTelemetryRepository {
    pool: PgPool,
}

impl MachineTelemetryRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Store a batch of telemetry blobs for a machine. Ciphertext is opaque to
    /// the server. ponytail: row-per-blob loop — batches are small; a single
    /// UNNEST insert can come if volume ever warrants it.
    pub async fn insert(&self, machine_id: MachineId, blobs: &[NewTelemetry]) -> Result<()> {
        for blob in blobs {
            sqlx::query(
                "INSERT INTO identity.machine_telemetry
                     (machine_id, kind, recipient_key_id, seq, ciphertext, signature)
                 VALUES ($1, $2, $3, $4, $5, $6)",
            )
            .bind(machine_id)
            .bind(&blob.kind)
            .bind(&blob.recipient_key_id)
            .bind(blob.seq)
            .bind(&blob.ciphertext)
            .bind(&blob.signature)
            .execute(&self.pool)
            .await?;
        }
        Ok(())
    }
}
