use chrono::{DateTime, Duration, Utc};
use identity::{InstanceRole, UserId};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum PendingError {
    #[error("database error")]
    Database(#[from] sqlx::Error),

    #[error("identity error")]
    Identity(#[from] identity::IdentityError),

    #[error("auth error")]
    Auth(#[from] auth::AuthError),

    #[error("audit error")]
    Audit(#[from] audit::AuditError),

    #[error("notifications error")]
    Notifications(#[from] notifications::NotificationsError),

    #[error("a pending action already exists for this target")]
    PendingActionExists,

    #[error("transition is not in pending state")]
    NotPending,

    #[error("transition not found")]
    NotFound,

    #[error("payload was malformed: {0}")]
    BadPayload(String),
}

pub type Result<T> = std::result::Result<T, PendingError>;

/// How long a pending Owner-on-Owner action waits before auto-applying.
/// 72 hours is long enough to span a weekend and let a target on holiday
/// notice; short enough that legitimate revocations land within a workweek.
pub const VETO_WINDOW: Duration = Duration::hours(72);

/// Mirrors the SQL enum. Each kind has its own apply-side semantics in
/// [`Worker::apply_one`].
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, sqlx::Type, Serialize, Deserialize,
)]
#[sqlx(type_name = "pending.transition_kind", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum TransitionKind {
    RoleChange,
    Deactivate,
    Anonymize,
    Delete,
}

/// Convenience: which kinds correspond to lifecycle actions (everything
/// except role_change). Re-exports the notifications crate's enum so
/// both layers agree on the same type without crate-cycle gymnastics.
pub use notifications::LifecycleAction;

pub fn lifecycle_to_kind(action: LifecycleAction) -> TransitionKind {
    match action {
        LifecycleAction::Deactivate => TransitionKind::Deactivate,
        LifecycleAction::Anonymize => TransitionKind::Anonymize,
        LifecycleAction::Delete => TransitionKind::Delete,
    }
}

pub fn lifecycle_from_kind(kind: TransitionKind) -> Option<LifecycleAction> {
    match kind {
        TransitionKind::Deactivate => Some(LifecycleAction::Deactivate),
        TransitionKind::Anonymize => Some(LifecycleAction::Anonymize),
        TransitionKind::Delete => Some(LifecycleAction::Delete),
        TransitionKind::RoleChange => None,
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, sqlx::Type, Serialize, Deserialize,
)]
#[sqlx(type_name = "pending.transition_state", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum TransitionState {
    Pending,
    Applied,
    Vetoed,
    Cancelled,
}

#[derive(Debug, Clone, sqlx::FromRow, Serialize)]
pub struct TransitionRow {
    pub id: Uuid,
    pub kind: TransitionKind,
    pub initiator_user_id: Option<Uuid>,
    pub target_user_id: Option<Uuid>,
    pub payload: serde_json::Value,
    pub state: TransitionState,
    pub effective_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub resolved_by_user_id: Option<Uuid>,
    pub resolution: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Convenience accessor for the role payload.
impl TransitionRow {
    pub fn role_payload(&self) -> Result<RolePayload> {
        if self.kind != TransitionKind::RoleChange {
            return Err(PendingError::BadPayload(format!(
                "expected role_change kind, got {:?}",
                self.kind
            )));
        }
        serde_json::from_value::<RolePayload>(self.payload.clone())
            .map_err(|e| PendingError::BadPayload(e.to_string()))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RolePayload {
    pub to_role: InstanceRole,
}

/// Insert a pending role-change row inside the caller's transaction.
///
/// The caller is responsible for:
///   1. Confirming the action is Owner-on-Owner (and not self).
///   2. Emitting the `pending_role_change_initiated` audit event.
///   3. Enqueuing the `PendingRoleChangeInitiated` notification.
///
/// Caller-driven so all the cross-cutting concerns commit together.
///
/// Returns the new row's id and `effective_at` for downstream use.
/// Fails with `PendingActionExists` if a pending row already exists for
/// the target (the DB-level partial unique index also enforces this).
pub async fn enqueue_role_change(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    initiator: UserId,
    target: UserId,
    to_role: InstanceRole,
) -> Result<(Uuid, DateTime<Utc>)> {
    enqueue_raw(
        tx,
        TransitionKind::RoleChange,
        initiator,
        target,
        serde_json::json!({ "to_role": to_role }),
    )
    .await
}

/// Insert a pending lifecycle-action row (deactivate / anonymize /
/// delete). Same caller responsibilities as
/// [`enqueue_role_change`]. Payload is empty `{}` — the kind itself
/// fully describes the action.
pub async fn enqueue_lifecycle(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    initiator: UserId,
    target: UserId,
    action: LifecycleAction,
) -> Result<(Uuid, DateTime<Utc>)> {
    enqueue_raw(
        tx,
        lifecycle_to_kind(action),
        initiator,
        target,
        serde_json::json!({}),
    )
    .await
}

async fn enqueue_raw(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    kind: TransitionKind,
    initiator: UserId,
    target: UserId,
    payload: serde_json::Value,
) -> Result<(Uuid, DateTime<Utc>)> {
    let effective_at = Utc::now() + VETO_WINDOW;
    let row: std::result::Result<(Uuid, DateTime<Utc>), sqlx::Error> = sqlx::query_as(
        "INSERT INTO pending.transitions
             (kind, initiator_user_id, target_user_id, payload, effective_at)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING id, effective_at",
    )
    .bind(kind)
    .bind(initiator)
    .bind(target)
    .bind(&payload)
    .bind(effective_at)
    .fetch_one(&mut **tx)
    .await;

    match row {
        Ok(r) => Ok(r),
        Err(sqlx::Error::Database(dbe)) if dbe.code().as_deref() == Some("23505") => {
            Err(PendingError::PendingActionExists)
        }
        Err(e) => Err(PendingError::Database(e)),
    }
}

pub async fn find_by_id(pool: &PgPool, id: Uuid) -> Result<Option<TransitionRow>> {
    let row: Option<TransitionRow> = sqlx::query_as(
        "SELECT id, kind, initiator_user_id, target_user_id, payload, state,
                effective_at, resolved_at, resolved_by_user_id, resolution,
                created_at
         FROM pending.transitions WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

pub async fn list_all(pool: &PgPool) -> Result<Vec<TransitionRow>> {
    let rows: Vec<TransitionRow> = sqlx::query_as(
        "SELECT id, kind, initiator_user_id, target_user_id, payload, state,
                effective_at, resolved_at, resolved_by_user_id, resolution,
                created_at
         FROM pending.transitions
         ORDER BY created_at DESC",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Currently-pending transitions only, oldest-expiry first. Used by
/// the `/pending` admin page's "Active" section — the resolved rows
/// (vetoed / cancelled / applied) belong to a separate history view.
/// Ordering by `effective_at ASC` puts the most-urgent rows first so
/// the operator sees the imminent ones at the top of the table.
pub async fn list_active(pool: &PgPool) -> Result<Vec<TransitionRow>> {
    let rows: Vec<TransitionRow> = sqlx::query_as(
        "SELECT id, kind, initiator_user_id, target_user_id, payload, state,
                effective_at, resolved_at, resolved_by_user_id, resolution,
                created_at
         FROM pending.transitions
         WHERE state = 'pending'
         ORDER BY effective_at ASC",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Count of currently-pending transitions. Used by the sidebar's
/// "Pending review" badge so Owners see at-a-glance how many actions
/// are awaiting them. Cheap — the `transitions_due_idx` partial index
/// covers `state = 'pending'`, so the count is essentially an index
/// scan even with many resolved rows.
pub async fn count_active(pool: &PgPool) -> Result<u32> {
    let (count,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM pending.transitions WHERE state = 'pending'",
    )
    .fetch_one(pool)
    .await?;
    Ok(count.max(0) as u32)
}

/// Most-recently-resolved transitions, newest first. Used by the
/// History section on `/pending` so Owners can audit what actually
/// went through (or got cancelled) without bouncing to the full audit
/// log. `limit` clamps the result set so very busy instances don't
/// drown the page — the active table is the urgent view; older
/// resolved rows live in the audit log proper.
pub async fn list_recent_resolved(pool: &PgPool, limit: i64) -> Result<Vec<TransitionRow>> {
    let rows: Vec<TransitionRow> = sqlx::query_as(
        "SELECT id, kind, initiator_user_id, target_user_id, payload, state,
                effective_at, resolved_at, resolved_by_user_id, resolution,
                created_at
         FROM pending.transitions
         WHERE state <> 'pending'
         ORDER BY resolved_at DESC NULLS LAST
         LIMIT $1",
    )
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Active pending transitions whose `target_user_id` is in `target_ids`.
/// Used by the `/members` page to decorate rows with a "Pending …"
/// pill — fetched in a single round-trip rather than one query per
/// row. Returns the raw rows; the caller is expected to bucket them
/// by `target_user_id` for rendering.
pub async fn active_by_target_ids(
    pool: &PgPool,
    target_ids: &[Uuid],
) -> Result<Vec<TransitionRow>> {
    if target_ids.is_empty() {
        return Ok(Vec::new());
    }
    let rows: Vec<TransitionRow> = sqlx::query_as(
        "SELECT id, kind, initiator_user_id, target_user_id, payload, state,
                effective_at, resolved_at, resolved_by_user_id, resolution,
                created_at
         FROM pending.transitions
         WHERE state = 'pending'
           AND target_user_id = ANY($1)
         ORDER BY effective_at ASC",
    )
    .bind(target_ids)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Veto a pending transition. The caller is responsible for the authz
/// check (Owner role) and for emitting the audit + notification side
/// effects in the same transaction. Returns the row in its post-update
/// shape. Fails `NotPending` if the row has already been resolved.
pub async fn veto(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    id: Uuid,
    vetoed_by: UserId,
) -> Result<TransitionRow> {
    resolve(tx, id, vetoed_by, TransitionState::Vetoed, "vetoed").await
}

/// Cancel a pending transition. Same shape as veto but a different state
/// + resolution string. Authz is caller-side: initiator or any Owner.
pub async fn cancel(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    id: Uuid,
    cancelled_by: UserId,
) -> Result<TransitionRow> {
    resolve(tx, id, cancelled_by, TransitionState::Cancelled, "cancelled").await
}

async fn resolve(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    id: Uuid,
    by: UserId,
    new_state: TransitionState,
    resolution: &str,
) -> Result<TransitionRow> {
    let row: Option<TransitionRow> = sqlx::query_as(
        "UPDATE pending.transitions
         SET state = $2, resolved_at = now(),
             resolved_by_user_id = $3, resolution = $4
         WHERE id = $1 AND state = 'pending'
         RETURNING id, kind, initiator_user_id, target_user_id, payload, state,
                   effective_at, resolved_at, resolved_by_user_id, resolution,
                   created_at",
    )
    .bind(id)
    .bind(new_state)
    .bind(by)
    .bind(resolution)
    .fetch_optional(&mut **tx)
    .await?;

    match row {
        Some(r) => Ok(r),
        None => {
            // Distinguish "not found" from "not pending" so the handler can
            // produce a specific error.
            let exists: Option<i32> =
                sqlx::query_scalar("SELECT 1 FROM pending.transitions WHERE id = $1")
                    .bind(id)
                    .fetch_optional(&mut **tx)
                    .await?;
            if exists.is_some() {
                Err(PendingError::NotPending)
            } else {
                Err(PendingError::NotFound)
            }
        }
    }
}

/// How a transition reached `applied` — drives the stored `resolution`, the
/// audit `via`, and the `via_recovery_bypass` notification flag.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ApplyVia {
    /// The 72h veto window elapsed and the worker applied it on schedule.
    Timer,
    /// An Owner forced it through early with the server recovery code,
    /// bypassing the veto window ("break glass" — force out a rogue Owner).
    RecoveryBypass,
}

impl ApplyVia {
    fn resolution(self) -> &'static str {
        match self {
            ApplyVia::Timer => "timer",
            ApplyVia::RecoveryBypass => "recovery_bypass",
        }
    }
    fn is_recovery_bypass(self) -> bool {
        matches!(self, ApplyVia::RecoveryBypass)
    }
}

/// Result of [`Worker::force_apply`].
pub enum ForceApplyOutcome {
    /// Applied immediately; carries the row in its post-update shape.
    Applied(TransitionRow),
    /// No transition with that id.
    NotFound,
    /// The transition was already resolved (applied / vetoed / cancelled) —
    /// e.g. the timer or a veto won the race.
    NotPending,
}

// ────────────────────────────────────────────────────────────────────────
// Worker — applies due transitions
// ────────────────────────────────────────────────────────────────────────

/// Pending-transition worker. It only writes — applies due transitions
/// and enqueues follow-up notifications into the outbox. The actual
/// email sending is the notifications crate's worker's job.
#[derive(Clone)]
pub struct Worker {
    pool: PgPool,
}

impl Worker {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Apply a **specific** pending transition immediately, bypassing the veto
    /// timer — the server-recovery-code "break glass" path. The caller has
    /// already verified the recovery code + Owner authz; `by` is the Owner who
    /// forced it (recorded as the resolver + in the audit). Race-safe: if the
    /// row was resolved (timer/veto) between the lookup and the claim, returns
    /// [`ForceApplyOutcome::NotPending`].
    pub async fn force_apply(&self, id: Uuid, by: UserId) -> Result<ForceApplyOutcome> {
        let Some(row) = find_by_id(&self.pool, id).await? else {
            return Ok(ForceApplyOutcome::NotFound);
        };
        if row.state != TransitionState::Pending {
            return Ok(ForceApplyOutcome::NotPending);
        }
        match self
            .apply_one(&row, ApplyVia::RecoveryBypass, Some(by))
            .await?
        {
            Some(applied) => Ok(ForceApplyOutcome::Applied(applied)),
            None => Ok(ForceApplyOutcome::NotPending),
        }
    }

    /// Apply every pending transition whose `effective_at` has come due.
    /// Returns the number of rows applied. Each row is processed in its
    /// own transaction so a single-row failure doesn't block the rest.
    pub async fn process_due(&self) -> Result<usize> {
        // Look at due rows. The real *claim* is the per-row UPDATE inside
        // `apply_one` (gated on `state = 'pending'`), which is atomic at the
        // SQL layer — two workers racing on the same row, only one's UPDATE
        // finds the row still pending. We deliberately don't try `FOR UPDATE
        // SKIP LOCKED` on this bare SELECT: outside a transaction the lock
        // would be released the instant the SELECT auto-commits, providing
        // no real concurrency protection. If we ever add a second worker,
        // the inner UPDATE keeps us correct without help here.
        let due: Vec<TransitionRow> = sqlx::query_as(
            "SELECT id, kind, initiator_user_id, target_user_id, payload, state,
                    effective_at, resolved_at, resolved_by_user_id, resolution,
                    created_at
             FROM pending.transitions
             WHERE state = 'pending' AND effective_at <= now()
             ORDER BY effective_at
             LIMIT 32",
        )
        .fetch_all(&self.pool)
        .await?;

        let mut applied = 0usize;
        for row in due {
            match self.apply_one(&row, ApplyVia::Timer, None).await {
                Ok(Some(_)) => applied += 1,
                // Raced — vetoed/cancelled/applied between SELECT and claim.
                Ok(None) => {}
                Err(err) => {
                    tracing::error!(
                        ?err,
                        transition_id = %row.id,
                        kind = ?row.kind,
                        "pending transition apply failed; will retry on next cycle"
                    );
                    // Row stays in `pending` state; next cycle picks it up.
                }
            }
        }
        Ok(applied)
    }

    /// Apply one transition. Returns `Some(applied_row)` if this call claimed
    /// and applied it, `None` if it was already resolved (lost the race).
    async fn apply_one(
        &self,
        row: &TransitionRow,
        via: ApplyVia,
        resolved_by: Option<UserId>,
    ) -> Result<Option<TransitionRow>> {
        match row.kind {
            TransitionKind::RoleChange => self.apply_role_change(row, via, resolved_by).await,
            TransitionKind::Deactivate
            | TransitionKind::Anonymize
            | TransitionKind::Delete => self.apply_lifecycle(row, via, resolved_by).await,
        }
    }

    async fn apply_role_change(
        &self,
        row: &TransitionRow,
        via: ApplyVia,
        resolved_by: Option<UserId>,
    ) -> Result<Option<TransitionRow>> {
        let payload = row.role_payload()?;
        let target_id = row
            .target_user_id
            .ok_or_else(|| PendingError::BadPayload("target_user_id is null".into()))?;
        let initiator_id = row
            .initiator_user_id
            .ok_or_else(|| PendingError::BadPayload("initiator_user_id is null".into()))?;

        let mut tx = self.pool.begin().await?;

        // Update transition state + apply role change + audit + notify, all
        // in one transaction. If anything fails the whole thing rolls back
        // and the row stays `pending` for the next cycle to retry.
        let claimed: Option<TransitionRow> = sqlx::query_as(
            "UPDATE pending.transitions
             SET state = 'applied', resolved_at = now(), resolution = $2,
                 resolved_by_user_id = $3
             WHERE id = $1 AND state = 'pending'
             RETURNING id, kind, initiator_user_id, target_user_id, payload, state,
                       effective_at, resolved_at, resolved_by_user_id, resolution,
                       created_at",
        )
        .bind(row.id)
        .bind(via.resolution())
        .bind(resolved_by)
        .fetch_optional(&mut *tx)
        .await?;

        let Some(claimed) = claimed else {
            // Vetoed / cancelled (or the timer beat us) between SELECT + UPDATE.
            tx.rollback().await?;
            return Ok(None);
        };

        // Look up target's current display fields for audit + notification.
        let (target_email, target_display_name, initiator_display_name): (String, String, String) =
            sqlx::query_as(
                "SELECT
                    (SELECT email FROM identity.users WHERE id = $1),
                    (SELECT display_name FROM identity.users WHERE id = $1),
                    (SELECT display_name FROM identity.users WHERE id = $2)",
            )
            .bind(target_id)
            .bind(initiator_id)
            .fetch_one(&mut *tx)
            .await?;

        let updated = identity::UserRepository::set_instance_role(
            &mut tx,
            identity::UserId::new(target_id),
            payload.to_role,
        )
        .await?;

        // Audit the apply.
        let actor = audit::Actor {
            user_id: identity::UserId::new(initiator_id),
            display_name: initiator_display_name.clone(),
        };
        let mut event_data = serde_json::json!({
            "transition_id": row.id,
            "via": via.resolution(),
            "initiator_user_id": initiator_id,
            "target_user_id": target_id,
            "applied_role": payload.to_role,
        });
        if let Some(by) = resolved_by {
            event_data["forced_by_user_id"] = serde_json::json!(by.0);
        }
        audit::append(&mut tx, Some(&actor), None, "pending_role_change_applied", event_data)
            .await?;

        // Notify the target that the change has landed.
        notifications::enqueue(
            &mut tx,
            notifications::Notification::PendingRoleChangeApplied {
                recipient_email: target_email,
                target_display_name,
                initiator_display_name,
                applied_role: payload.to_role,
                via_recovery_bypass: via.is_recovery_bypass(),
                transition_id: Some(row.id),
            },
        )
        .await?;

        tx.commit().await?;
        let _ = &updated;
        Ok(Some(claimed))
    }

    /// Apply a lifecycle transition (deactivate / anonymize / delete).
    /// All three follow the same transactional shape as role-change: claim
    /// the row, apply the lifecycle change, revoke sessions, audit, enqueue
    /// the applied-notification.
    async fn apply_lifecycle(
        &self,
        row: &TransitionRow,
        via: ApplyVia,
        resolved_by: Option<UserId>,
    ) -> Result<Option<TransitionRow>> {
        let action = lifecycle_from_kind(row.kind)
            .ok_or_else(|| PendingError::BadPayload(format!("not a lifecycle kind: {:?}", row.kind)))?;
        let target_id = row
            .target_user_id
            .ok_or_else(|| PendingError::BadPayload("target_user_id is null".into()))?;
        let initiator_id = row
            .initiator_user_id
            .ok_or_else(|| PendingError::BadPayload("initiator_user_id is null".into()))?;

        let mut tx = self.pool.begin().await?;

        let claimed: Option<TransitionRow> = sqlx::query_as(
            "UPDATE pending.transitions
             SET state = 'applied', resolved_at = now(), resolution = $2,
                 resolved_by_user_id = $3
             WHERE id = $1 AND state = 'pending'
             RETURNING id, kind, initiator_user_id, target_user_id, payload, state,
                       effective_at, resolved_at, resolved_by_user_id, resolution,
                       created_at",
        )
        .bind(row.id)
        .bind(via.resolution())
        .bind(resolved_by)
        .fetch_optional(&mut *tx)
        .await?;

        let Some(claimed) = claimed else {
            tx.rollback().await?;
            return Ok(None);
        };

        // Capture display fields for audit + notification BEFORE any
        // redaction (delete/purge wipe the email + display_name).
        let (target_email, target_display_name, initiator_display_name): (String, String, String) =
            sqlx::query_as(
                "SELECT
                    (SELECT email FROM identity.users WHERE id = $1),
                    (SELECT display_name FROM identity.users WHERE id = $1),
                    (SELECT display_name FROM identity.users WHERE id = $2)",
            )
            .bind(target_id)
            .bind(initiator_id)
            .fetch_one(&mut *tx)
            .await?;

        let target_user_id = identity::UserId::new(target_id);
        let (sessions_revoked, original_email) = match action {
            LifecycleAction::Deactivate => {
                let _ = identity::UserRepository::deactivate(&mut tx, target_user_id).await?;
                let n = auth::SessionRepository::revoke_all_for_user(&mut tx, target_user_id).await?;
                (n, None::<String>)
            }
            LifecycleAction::Anonymize => {
                let (_, original) =
                    identity::UserRepository::anonymize(&mut tx, target_user_id).await?;
                let n = auth::SessionRepository::revoke_all_for_user(&mut tx, target_user_id).await?;
                auth::delete_credentials(&mut tx, target_user_id).await?;
                (n, Some(original))
            }
            LifecycleAction::Delete => {
                // True removal: the row goes, and every `auth.*` row cascades
                // with it — so there's no separate session-revoke/credential
                // delete and no redacted-from email to record.
                identity::UserRepository::hard_remove(&mut tx, target_user_id).await?;
                (0, None::<String>)
            }
        };

        let actor = audit::Actor {
            user_id: identity::UserId::new(initiator_id),
            display_name: initiator_display_name.clone(),
        };
        let event_type = match action {
            LifecycleAction::Deactivate => "user_deactivated",
            LifecycleAction::Anonymize => "account_anonymized",
            LifecycleAction::Delete => "account_deleted",
        };
        let mut event_data = serde_json::json!({
            "transition_id": row.id,
            "via": via.resolution(),
            "initiator_user_id": initiator_id,
            "target_user_id": target_id,
            "sessions_revoked": sessions_revoked,
        });
        if let Some(orig) = &original_email {
            event_data["redacted_from_email"] = serde_json::Value::String(orig.clone());
        }
        if let Some(by) = resolved_by {
            event_data["forced_by_user_id"] = serde_json::json!(by.0);
        }
        audit::append(&mut tx, Some(&actor), None, event_type, event_data).await?;

        notifications::enqueue(
            &mut tx,
            notifications::Notification::PendingLifecycleApplied {
                recipient_email: target_email,
                target_display_name,
                initiator_display_name,
                action,
                via_recovery_bypass: via.is_recovery_bypass(),
                transition_id: Some(row.id),
            },
        )
        .await?;

        tx.commit().await?;
        Ok(Some(claimed))
    }

    /// Long-running poll loop. Polls every `interval`. Exits when `shutdown`
    /// signals `true`.
    pub async fn run_forever(
        self,
        interval: std::time::Duration,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) {
        loop {
            tokio::select! {
                _ = tokio::time::sleep(interval) => {
                    if let Err(err) = self.process_due().await {
                        tracing::error!(?err, "pending-transition worker cycle failed");
                    }
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        tracing::info!("pending-transition worker shutting down");
                        return;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn role_payload_roundtrips_via_json() {
        let p = RolePayload {
            to_role: InstanceRole::Admin,
        };
        let v = serde_json::to_value(&p).unwrap();
        let back: RolePayload = serde_json::from_value(v).unwrap();
        assert_eq!(back.to_role, InstanceRole::Admin);
    }

    #[test]
    fn veto_window_is_72_hours() {
        assert_eq!(VETO_WINDOW, Duration::hours(72));
    }
}
