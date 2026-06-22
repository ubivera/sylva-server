use audit::{Actor, compute_hash, genesis_hash};
use chrono::{DateTime, Utc};
use identity::InstanceRole;
use serde::Serialize;
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

use super::common::TestApp;

#[derive(sqlx::FromRow)]
struct Row {
    seqno: i64,
    occurred_at: DateTime<Utc>,
    actor_user_id: Option<Uuid>,
    actor_display_name: Option<String>,
    app_id: Option<String>,
    event_type: String,
    event_data: serde_json::Value,
    prev_hash: Vec<u8>,
    hash: Vec<u8>,
}

/// Mirror of `audit::Canonical`. Kept private to the crate; we duplicate the
/// shape so this test catches any change to the canonical encoding (which
/// would break externally-archived chains).
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

async fn fetch_chain(pool: &PgPool) -> Vec<Row> {
    sqlx::query_as::<_, Row>(
        "SELECT seqno, occurred_at, actor_user_id, actor_display_name, app_id,
                event_type, event_data, prev_hash, hash
         FROM audit.events
         ORDER BY seqno ASC",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

#[tokio::test]
async fn fresh_db_starts_empty() {
    let app = TestApp::new().await;
    let rows = fetch_chain(&app.pool).await;
    assert!(rows.is_empty(), "fresh DB should have no audit events");
}

#[tokio::test]
async fn chain_is_intact_after_a_busy_session() {
    let app = TestApp::new().await;

    // Seed an owner (emits one `test_seed_user` event), then append a realistic
    // mix of heterogeneous events through the same `audit::append` path the
    // services use. The chain's integrity is what's under test, independent of
    // which surface produced the events.
    let owner = app
        .seed_user("owner@test.local", "Owner", "pw", InstanceRole::Owner)
        .await;
    let actor = Actor {
        user_id: owner.id,
        display_name: owner.display_name.clone(),
    };

    let events: &[(&str, serde_json::Value)] = &[
        ("invite_created", json!({ "email": "alice@test.local" })),
        ("account_accepted_invite", json!({ "display_name": "Alice" })),
        ("profile_updated", json!({ "display_name": "Alice Q" })),
        ("password_changed", json!({})),
        ("signin_failed_password", json!({ "email": owner.email })),
        ("signin_success", json!({ "email": owner.email })),
    ];
    for (event_type, data) in events {
        let mut tx = app.pool.begin().await.unwrap();
        audit::append(&mut tx, Some(&actor), None, event_type, data.clone())
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }

    let rows = fetch_chain(&app.pool).await;
    assert!(
        rows.len() >= 6,
        "expected several events, got {}: {:?}",
        rows.len(),
        rows.iter().map(|r| &r.event_type).collect::<Vec<_>>()
    );

    // 1. seqno is monotonic and starts at 1.
    for (i, row) in rows.iter().enumerate() {
        assert_eq!(row.seqno, (i + 1) as i64, "seqno at index {i}");
    }

    // 2. First row's prev_hash is the genesis hash.
    assert_eq!(rows[0].prev_hash, genesis_hash().to_vec());

    // 3. Each subsequent row's prev_hash matches the previous row's hash.
    for w in rows.windows(2) {
        assert_eq!(
            w[1].prev_hash, w[0].hash,
            "chain break between seqno {} and {}",
            w[0].seqno, w[1].seqno
        );
    }

    // 4. Each row's hash equals sha256(prev_hash || canonical_bytes).
    for row in &rows {
        let canonical = Canonical {
            actor_display_name: &row.actor_display_name,
            actor_user_id: &row.actor_user_id,
            app_id: &row.app_id,
            event_data: &row.event_data,
            event_type: &row.event_type,
            occurred_at: &row.occurred_at,
            seqno: row.seqno,
        };
        let bytes = serde_json::to_vec(&canonical).unwrap();
        let recomputed = compute_hash(&row.prev_hash, &bytes);
        assert_eq!(
            row.hash,
            recomputed.to_vec(),
            "hash mismatch at seqno {}: event_type={}",
            row.seqno,
            row.event_type
        );
    }
}

#[tokio::test]
async fn tampering_with_event_data_is_detectable() {
    // If somebody mutates a stored event_data row, recomputing the hash from
    // the (mutated) canonical bytes must NOT match the stored hash.
    let app = TestApp::new().await;
    // `seed_user` emits one `test_seed_user` audit event — the row we tamper with.
    app.seed_user("o@test.local", "O", "pw", InstanceRole::Owner)
        .await;

    sqlx::query(
        "UPDATE audit.events SET event_data = $1 WHERE seqno = (SELECT MIN(seqno) FROM audit.events)",
    )
    .bind(serde_json::json!({ "tampered": true }))
    .execute(&app.pool)
    .await
    .unwrap();

    let rows = fetch_chain(&app.pool).await;
    let row = &rows[0];
    let canonical = Canonical {
        actor_display_name: &row.actor_display_name,
        actor_user_id: &row.actor_user_id,
        app_id: &row.app_id,
        event_data: &row.event_data,
        event_type: &row.event_type,
        occurred_at: &row.occurred_at,
        seqno: row.seqno,
    };
    let bytes = serde_json::to_vec(&canonical).unwrap();
    let recomputed = compute_hash(&row.prev_hash, &bytes);
    assert_ne!(
        row.hash,
        recomputed.to_vec(),
        "tampered event_data should produce a different hash"
    );
}
