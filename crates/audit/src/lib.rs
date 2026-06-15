use chrono::{DateTime, Timelike, Utc};
use identity::UserId;
use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("database error")]
    Database(#[from] sqlx::Error),

    #[error("canonical serialization failed")]
    Serialize(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, AuditError>;

/// Postgres advisory lock key reserved for the audit appender. Acquired
/// for the lifetime of each append transaction so the (seqno, hash) chain
/// stays race-free without needing SERIALIZABLE isolation.
const AUDIT_ADVISORY_LOCK_KEY: i64 = 0x1234_5678_9abc_def0_u64 as i64;

/// Returns `sha256(b"hearth-audit-genesis")` - the `prev_hash` for the
/// first row in the chain.
pub fn genesis_hash() -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"hearth-audit-genesis");
    hasher.finalize().into()
}

/// Who performed the audited action. Both `display_name` and the stored
/// `actor_user_id` are frozen snapshots (the column carries no foreign
/// key), so audit entries survive later renames or a physical account
/// deletion with their hashes intact — the id simply dangles once the
/// user is gone.
#[derive(Debug, Clone)]
pub struct Actor {
    pub user_id: UserId,
    pub display_name: String,
}

#[derive(Debug, Clone, sqlx::FromRow, Serialize)]
pub struct AuditEvent {
    pub seqno: i64,
    pub occurred_at: DateTime<Utc>,
    pub actor_user_id: Option<Uuid>,
    pub actor_display_name: Option<String>,
    pub app_id: Option<String>,
    pub event_type: String,
    pub event_data: serde_json::Value,
    pub prev_hash: Vec<u8>,
    pub hash: Vec<u8>,
}

/// Same fields that go into the hash, in alphabetical order. This is
/// what we serialize to compute `canonical_bytes`. Hash and redaction
/// columns are intentionally excluded (they're derived/mutable).
#[derive(Serialize)]
struct Canonical<'a> {
    actor_display_name: &'a Option<String>,
    actor_user_id: &'a Option<Uuid>,
    app_id: &'a Option<String>,
    event_data: &'a serde_json::Value,
    event_type: &'a str,
    occurred_at: &'a DateTime<Utc>,
    seqno: i64,
}

/// `sha256(prev_hash || canonical_bytes)`. Pure function - tested
/// without a DB.
/// Drop the sub-microsecond fraction of `ts` so the value matches what
/// Postgres will round-trip back to us. See the call site in [`append`].
fn truncate_to_micros(ts: DateTime<Utc>) -> DateTime<Utc> {
    let micros = ts.nanosecond() / 1_000;
    ts.with_nanosecond(micros * 1_000).unwrap_or(ts)
}

pub fn compute_hash(prev_hash: &[u8], canonical_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(prev_hash);
    hasher.update(canonical_bytes);
    hasher.finalize().into()
}

/// Count events in the chain. Pool-only - no transaction needed.
pub async fn count(pool: &PgPool) -> Result<i64> {
    let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM audit.events")
        .fetch_one(pool)
        .await?;
    Ok(count)
}

/// Filter / pagination knobs for `list`. All fields are optional.
/// `limit` is clamped by `list` to [1, MAX_PAGE_SIZE].
#[derive(Debug, Clone, Default)]
pub struct ListFilter {
    /// Only events whose actor matches this user_id. `None` = no actor filter.
    pub actor: Option<Uuid>,
    /// Only events with `occurred_at > since`. `None` = no time filter.
    pub since: Option<DateTime<Utc>>,
    /// Cursor: only events with `seqno < before_seqno`. `None` = start from
    /// the newest event. Returned as `next_cursor` for the following page.
    pub before_seqno: Option<i64>,
    /// Max rows. Defaults to `DEFAULT_PAGE_SIZE` if `None`, clamped to
    /// `MAX_PAGE_SIZE`.
    pub limit: Option<u32>,
    /// Exact `event_type` match. `None` = no type filter.
    pub event_type: Option<String>,
    /// Free-text search (`ILIKE`) over `event_type`, `actor_display_name`, and
    /// the `event_data` text. `None` = no search.
    pub search: Option<String>,
    /// Row offset for page-number pagination. `None` = 0. Callers pick either
    /// `offset` (page-number) or `before_seqno` (cursor), not both.
    pub offset: Option<i64>,
}

pub const DEFAULT_PAGE_SIZE: u32 = 50;
pub const MAX_PAGE_SIZE: u32 = 200;

/// Paginated list of audit events, newest first. Use the returned slice's
/// last item's `seqno` as `before_seqno` on the next call to walk further
/// back.
pub async fn list(pool: &PgPool, filter: &ListFilter) -> Result<Vec<AuditEvent>> {
    let limit = filter
        .limit
        .unwrap_or(DEFAULT_PAGE_SIZE)
        .clamp(1, MAX_PAGE_SIZE);

    let events: Vec<AuditEvent> = sqlx::query_as(
        "SELECT seqno, occurred_at, actor_user_id, actor_display_name, app_id,
                event_type, event_data, prev_hash, hash
         FROM audit.events
         WHERE ($1::uuid IS NULL OR actor_user_id = $1)
           AND ($2::timestamptz IS NULL OR occurred_at > $2)
           AND ($3::bigint IS NULL OR seqno < $3)
           AND ($5::text IS NULL OR event_type = $5)
           AND ($6::text IS NULL OR event_type ILIKE '%' || $6 || '%'
                                 OR actor_display_name ILIKE '%' || $6 || '%'
                                 OR event_data::text ILIKE '%' || $6 || '%')
         ORDER BY seqno DESC
         LIMIT $4 OFFSET $7",
    )
    .bind(filter.actor)
    .bind(filter.since)
    .bind(filter.before_seqno)
    .bind(i64::from(limit))
    .bind(&filter.event_type)
    .bind(&filter.search)
    .bind(filter.offset.unwrap_or(0))
    .fetch_all(pool)
    .await?;
    Ok(events)
}

/// Count events matching `filter`'s content predicates (actor / since /
/// event_type / search). Pagination knobs (limit / offset / before_seqno) are
/// ignored — this is the total for "Page X of N".
pub async fn count_filtered(pool: &PgPool, filter: &ListFilter) -> Result<i64> {
    let (count,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM audit.events
         WHERE ($1::uuid IS NULL OR actor_user_id = $1)
           AND ($2::timestamptz IS NULL OR occurred_at > $2)
           AND ($3::text IS NULL OR event_type = $3)
           AND ($4::text IS NULL OR event_type ILIKE '%' || $4 || '%'
                                 OR actor_display_name ILIKE '%' || $4 || '%'
                                 OR event_data::text ILIKE '%' || $4 || '%')",
    )
    .bind(filter.actor)
    .bind(filter.since)
    .bind(&filter.event_type)
    .bind(&filter.search)
    .fetch_one(pool)
    .await?;
    Ok(count)
}

/// Distinct event types present in the log, sorted — populates the type-filter
/// dropdown in the UI.
pub async fn distinct_event_types(pool: &PgPool) -> Result<Vec<String>> {
    let types: Vec<String> =
        sqlx::query_scalar("SELECT DISTINCT event_type FROM audit.events ORDER BY event_type")
            .fetch_all(pool)
            .await?;
    Ok(types)
}

/// Fetch a single event by `seqno` — backs the detail view (full event_data +
/// chain hashes).
pub async fn get(pool: &PgPool, seqno: i64) -> Result<Option<AuditEvent>> {
    let event: Option<AuditEvent> = sqlx::query_as(
        "SELECT seqno, occurred_at, actor_user_id, actor_display_name, app_id,
                event_type, event_data, prev_hash, hash
         FROM audit.events WHERE seqno = $1",
    )
    .bind(seqno)
    .fetch_optional(pool)
    .await?;
    Ok(event)
}

/// Append a new event to the chain within the caller's transaction.
///
/// The caller controls the transaction lifecycle - this lets the audit
/// emission be atomic with the action that prompted it (e.g., a user
/// insert and its `user_created` audit row commit together, satisfying
/// the design's "audit emission is synchronous; if audit fails, the
/// originating action fails" requirement).
///
/// Internally acquires `pg_advisory_xact_lock(AUDIT_ADVISORY_LOCK_KEY)`
/// so concurrent appenders are serialized and the hash chain stays
/// linearizable. The lock is released when the caller's transaction
/// commits or rolls back.
pub async fn append(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    actor: Option<&Actor>,
    app_id: Option<&str>,
    event_type: &str,
    event_data: serde_json::Value,
) -> Result<AuditEvent> {
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(AUDIT_ADVISORY_LOCK_KEY)
        .execute(&mut **tx)
        .await?;

    let seqno: i64 = sqlx::query_scalar("SELECT nextval('audit.events_seqno_seq')")
        .fetch_one(&mut **tx)
        .await?;

    let prev_hash: Vec<u8> =
        sqlx::query_scalar("SELECT hash FROM audit.events ORDER BY seqno DESC LIMIT 1")
            .fetch_optional(&mut **tx)
            .await?
            .unwrap_or_else(|| genesis_hash().to_vec());

    // Postgres `timestamptz` has microsecond precision; chrono's `Utc::now()`
    // captures nanoseconds. We hash over what we store, so truncate the
    // sub-microsecond bits here — otherwise a verifier reading the row back
    // and re-canonicalising it would compute a different hash than the one
    // committed alongside it.
    let occurred_at = truncate_to_micros(Utc::now());
    let actor_user_id = actor.map(|a| a.user_id.0);
    let actor_display_name = actor.map(|a| a.display_name.clone());
    let app_id_owned = app_id.map(str::to_string);

    let canonical_bytes = serde_json::to_vec(&Canonical {
        actor_display_name: &actor_display_name,
        actor_user_id: &actor_user_id,
        app_id: &app_id_owned,
        event_data: &event_data,
        event_type,
        occurred_at: &occurred_at,
        seqno,
    })?;

    let hash = compute_hash(&prev_hash, &canonical_bytes);

    let inserted: AuditEvent = sqlx::query_as(
        "INSERT INTO audit.events
             (seqno, occurred_at, actor_user_id, actor_display_name, app_id,
              event_type, event_data, prev_hash, hash)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
         RETURNING seqno, occurred_at, actor_user_id, actor_display_name, app_id,
                   event_type, event_data, prev_hash, hash",
    )
    .bind(seqno)
    .bind(occurred_at)
    .bind(actor_user_id)
    .bind(&actor_display_name)
    .bind(&app_id_owned)
    .bind(event_type)
    .bind(&event_data)
    .bind(&prev_hash)
    .bind(&hash[..])
    .fetch_one(&mut **tx)
    .await?;

    Ok(inserted)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn genesis_hash_is_sha256_of_literal() {
        let mut h = Sha256::new();
        h.update(b"hearth-audit-genesis");
        let expected: [u8; 32] = h.finalize().into();
        assert_eq!(genesis_hash(), expected);
    }

    #[test]
    fn truncate_to_micros_drops_sub_microsecond_bits() {
        let with_nanos = DateTime::<Utc>::from_timestamp_micros(1_700_000_000_123_456)
            .unwrap()
            .with_nanosecond(123_456_789)
            .unwrap();
        let truncated = super::truncate_to_micros(with_nanos);
        assert_eq!(truncated.nanosecond() % 1_000, 0);
        assert_eq!(truncated.nanosecond(), 123_456_000);
        // Idempotent.
        assert_eq!(super::truncate_to_micros(truncated), truncated);
    }

    #[test]
    fn compute_hash_matches_manual_sha256() {
        let prev = [0u8; 32];
        let bytes = b"some canonical bytes";
        let got = compute_hash(&prev, bytes);

        let mut h = Sha256::new();
        h.update(prev);
        h.update(bytes);
        let want: [u8; 32] = h.finalize().into();
        assert_eq!(got, want);
    }

    #[test]
    fn canonical_serialization_is_deterministic() {
        let occurred_at = DateTime::<Utc>::from_naive_utc_and_offset(
            chrono::DateTime::from_timestamp(1_700_000_000, 0)
                .unwrap()
                .naive_utc(),
            Utc,
        );
        let event_data = serde_json::json!({"z": 1, "a": 2, "m": 3});
        let event = Canonical {
            actor_display_name: &Some("Joe".to_string()),
            actor_user_id: &Some(Uuid::nil()),
            app_id: &None,
            event_data: &event_data,
            event_type: "test",
            occurred_at: &occurred_at,
            seqno: 1,
        };
        let a = serde_json::to_vec(&event).unwrap();
        let b = serde_json::to_vec(&event).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn canonical_struct_fields_serialize_in_alphabetical_order() {
        let event = Canonical {
            actor_display_name: &Some("J".to_string()),
            actor_user_id: &None,
            app_id: &None,
            event_data: &serde_json::json!({}),
            event_type: "test",
            occurred_at: &DateTime::<Utc>::from_timestamp(0, 0).unwrap(),
            seqno: 1,
        };
        let s = serde_json::to_string(&event).unwrap();
        let order = ["actor_display_name", "actor_user_id", "app_id", "event_data", "event_type", "occurred_at", "seqno"];
        let mut last = 0;
        for key in order {
            let pos = s.find(&format!("\"{key}\":")).unwrap_or_else(|| {
                panic!("missing key {key} in {s}")
            });
            assert!(pos >= last, "key {key} out of order");
            last = pos;
        }
    }

    #[test]
    fn nested_event_data_object_keys_serialize_sorted() {
        let event_data = serde_json::json!({"z": 1, "a": 2, "m": 3});
        let s = serde_json::to_string(&event_data).unwrap();
        assert_eq!(s, r#"{"a":2,"m":3,"z":1}"#);
    }

    #[test]
    fn two_events_chain_correctly() {
        let occurred_at = DateTime::<Utc>::from_timestamp(1_700_000_000, 0).unwrap();

        let canon1 = serde_json::to_vec(&Canonical {
            actor_display_name: &None,
            actor_user_id: &None,
            app_id: &None,
            event_data: &serde_json::json!({}),
            event_type: "first",
            occurred_at: &occurred_at,
            seqno: 1,
        })
        .unwrap();
        let hash1 = compute_hash(&genesis_hash(), &canon1);

        let canon2 = serde_json::to_vec(&Canonical {
            actor_display_name: &None,
            actor_user_id: &None,
            app_id: &None,
            event_data: &serde_json::json!({}),
            event_type: "second",
            occurred_at: &occurred_at,
            seqno: 2,
        })
        .unwrap();
        let hash2 = compute_hash(&hash1, &canon2);

        assert_ne!(hex(&hash1), hex(&genesis_hash()));
        assert_ne!(hex(&hash2), hex(&hash1));

        let hash1_again = compute_hash(&genesis_hash(), &canon1);
        assert_eq!(hash1, hash1_again);
    }
}
