use audit::AuditEvent;
use auth::Session;
use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

#[derive(Serialize)]
pub struct AuditEventView {
    pub seqno: i64,
    pub occurred_at: DateTime<Utc>,
    pub actor_user_id: Option<Uuid>,
    pub actor_display_name: Option<String>,
    pub app_id: Option<String>,
    pub event_type: String,
    pub event_data: serde_json::Value,
    /// SHA-256 of the previous row's hash (lowercase hex). Together with
    /// `hash` lets a client verify the chain.
    pub prev_hash: String,
    pub hash: String,
}

impl From<AuditEvent> for AuditEventView {
    fn from(e: AuditEvent) -> Self {
        Self {
            seqno: e.seqno,
            occurred_at: e.occurred_at,
            actor_user_id: e.actor_user_id,
            actor_display_name: e.actor_display_name,
            app_id: e.app_id,
            event_type: e.event_type,
            event_data: e.event_data,
            prev_hash: hex(&e.prev_hash),
            hash: hex(&e.hash),
        }
    }
}

#[derive(Serialize)]
pub struct SessionView {
    pub id: Uuid,
    pub user_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    /// True when this session is the one making the current request — lets
    /// the client highlight "this device" in a sessions list.
    pub is_current: bool,
    /// Device metadata captured at sign-in (raw User-Agent + resolved client
    /// IP), and the throttled last-active timestamp. Any may be `null` for a
    /// session created on a path that didn't record them (e.g. the JSON API).
    pub user_agent: Option<String>,
    pub ip_address: Option<String>,
    pub last_seen_at: Option<DateTime<Utc>>,
    /// User-chosen device nickname, shown in place of the auto-detected label.
    pub label: Option<String>,
}

impl SessionView {
    pub fn from_with_current(s: Session, current_session_id: Uuid) -> Self {
        Self {
            id: s.id,
            user_id: s.user_id,
            created_at: s.created_at,
            expires_at: s.expires_at,
            revoked_at: s.revoked_at,
            is_current: s.id == current_session_id,
            user_agent: s.user_agent,
            ip_address: s.ip_address,
            last_seen_at: s.last_seen_at,
            label: s.label,
        }
    }
}

/// Envelope for paginated list endpoints. `next_cursor` is `Some(seqno)`
/// when the caller should pass it as `?cursor=` to get the next page,
/// `None` when this is the last page.
#[derive(Serialize)]
pub struct PaginatedAudit {
    pub items: Vec<AuditEventView>,
    pub next_cursor: Option<i64>,
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}
