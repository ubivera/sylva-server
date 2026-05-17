use audit::{compute_hash, genesis_hash};
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

    // Drive a realistic mix of operations so we get heterogeneous event types.
    let owner = app
        .seed_user("owner@test.local", "Owner", "pw", InstanceRole::Owner)
        .await;
    let owner_tok = app.login(&owner.email, "pw").await;

    let inv: serde_json::Value = app
        .post(
            "/api/admin/invites",
            Some(&owner_tok),
            Some(json!({ "email": "alice@test.local" })),
        )
        .await
        .json();
    let alice_tok: String = app
        .post(
            "/api/auth/accept-invite",
            None,
            Some(json!({
                "token": inv["token"],
                "display_name": "Alice",
                "password": "alicepw",
            })),
        )
        .await
        .json::<serde_json::Value>()["token"]
        .as_str()
        .unwrap()
        .to_string();

    app.patch(
        "/api/account/profile",
        Some(&alice_tok),
        Some(json!({ "display_name": "Alice Q" })),
    )
    .await;
    app.post(
        "/api/account/password",
        Some(&alice_tok),
        Some(json!({ "current_password": "alicepw", "new_password": "alicepw2" })),
    )
    .await;
    // Failed login → audits signin_failed_password.
    app.post(
        "/api/auth/login",
        None,
        Some(json!({ "email": owner.email, "password": "wrong" })),
    )
    .await;

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
    let owner = app
        .seed_user("o@test.local", "O", "pw", InstanceRole::Owner)
        .await;
    let _ = app.login(&owner.email, "pw").await; // adds a signin_success event

    // Mutate one row's event_data.
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
