use audit::ListFilter;
use auth::SessionRepository;
use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Utc};
use identity::{InstanceRole, InvitationId, User, UserLifecycle};
use notifications::{OutboxRow, OutboxState};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    admin_logic::{self, Outcome},
    app::AppState,
    auth_routes::AdminUser,
    views::{AuditEventView, PaginatedAudit, SessionView},
};

#[derive(Serialize)]
pub struct AdminMemberView {
    pub id: Uuid,
    pub email: String,
    pub display_name: String,
    pub lifecycle: UserLifecycle,
    pub instance_role: InstanceRole,
    pub locale: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: &'static str,
}

fn err(code: StatusCode, error: &'static str) -> (StatusCode, Json<ErrorResponse>) {
    (code, Json(ErrorResponse { error }))
}

/// `GET /admin/users` - list every non-purged user. Admin or Owner only.
pub async fn list_members(
    State(state): State<AppState>,
    _admin: AdminUser,
) -> impl IntoResponse {
    match state.users.list_all().await {
        Ok(users) => {
            let views: Vec<AdminMemberView> = users
                .into_iter()
                .map(|u| AdminMemberView {
                    id: u.id.0,
                    email: u.email,
                    display_name: u.display_name,
                    lifecycle: u.lifecycle,
                    instance_role: u.instance_role,
                    locale: u.locale,
                    created_at: u.created_at,
                    updated_at: u.updated_at,
                })
                .collect();
            (StatusCode::OK, Json(views)).into_response()
        }
        Err(err) => {
            tracing::error!(?err, "listing users");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: "internal" }),
            )
                .into_response()
        }
    }
}

#[derive(Deserialize)]
pub struct CreateInviteRequest {
    pub email: String,
    /// Optional. Defaults to `Member` if omitted.
    pub instance_role: Option<InstanceRole>,
}

#[derive(Serialize)]
pub struct CreateInviteResponse {
    pub invitation_id: Uuid,
    pub email: String,
    pub instance_role: InstanceRole,
    pub token: String,
    pub accept_url: String,
    pub expires_at: DateTime<Utc>,
}

/// `POST /admin/invites` - create a new invitation. Admin or Owner only.
///
/// Returns the one-time acceptance token + URL. The token is shown ONCE in
/// this response; the client is responsible for delivering it to the
/// invitee. The DB only stores `sha256(token)`.
///
/// Role-escalation guard: the inviter's role must satisfy the target role
/// - an Admin cannot invite an Owner.
pub async fn create_invite(
    State(state): State<AppState>,
    admin: AdminUser,
    Json(req): Json<CreateInviteRequest>,
) -> Response {
    let target_role = req.instance_role.unwrap_or(InstanceRole::Member);
    match admin_logic::perform_create_invite(&state, &admin, &req.email, target_role).await {
        Ok(outcome) => {
            let accept_url = format!("/invite/{}", outcome.raw_token);
            let resp = CreateInviteResponse {
                invitation_id: outcome.invitation.id.0,
                email: outcome.invitation.email,
                instance_role: outcome.invitation.instance_role,
                accept_url,
                token: outcome.raw_token,
                expires_at: outcome.invitation.expires_at,
            };
            (StatusCode::CREATED, Json(resp)).into_response()
        }
        Err(e) => invite_error_to_response(e),
    }
}

fn invite_error_to_response(e: admin_logic::CreateInviteError) -> Response {
    use admin_logic::CreateInviteError as C;
    match e {
        C::EmailRequired => err(StatusCode::BAD_REQUEST, "email_required").into_response(),
        C::CannotInviteHigherRole => {
            err(StatusCode::FORBIDDEN, "cannot_invite_higher_role").into_response()
        }
        C::EmailAlreadyInUse => err(StatusCode::CONFLICT, "email_already_in_use").into_response(),
        C::ActiveInviteExists => err(StatusCode::CONFLICT, "active_invite_exists").into_response(),
        C::Internal(inner) => {
            tracing::error!(?inner, "create invite internal error");
            err(StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response()
        }
    }
}

#[derive(Deserialize)]
pub struct AuditQuery {
    pub limit: Option<u32>,
    pub cursor: Option<i64>,
    pub since: Option<DateTime<Utc>>,
    pub actor: Option<Uuid>,
}

/// `GET /admin/audit` — paginated audit log across all users.
/// Newest first. Optional `?actor=<uuid>` / `?since=<rfc3339>` filters.
pub async fn list_audit(
    State(state): State<AppState>,
    _admin: AdminUser,
    Query(q): Query<AuditQuery>,
) -> impl IntoResponse {
    let filter = ListFilter {
        actor: q.actor,
        since: q.since,
        before_seqno: q.cursor,
        limit: q.limit,
    };

    match audit::list(&state.db, &filter).await {
        Ok(events) => {
            let next_cursor = next_audit_cursor(&events, q.limit);
            let items: Vec<AuditEventView> = events.into_iter().map(Into::into).collect();
            (StatusCode::OK, Json(PaginatedAudit { items, next_cursor })).into_response()
        }
        Err(e) => {
            tracing::error!(?e, "listing audit");
            err(StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response()
        }
    }
}

/// `GET /admin/sessions` — every active session across all users.
pub async fn list_sessions(
    State(state): State<AppState>,
    admin: AdminUser,
) -> impl IntoResponse {
    match state.sessions.list_all_active().await {
        Ok(sessions) => {
            let current = admin.0.session_id;
            let views: Vec<SessionView> = sessions
                .into_iter()
                .map(|s| SessionView::from_with_current(s, current))
                .collect();
            (StatusCode::OK, Json(views)).into_response()
        }
        Err(e) => {
            tracing::error!(?e, "listing all sessions");
            err(StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response()
        }
    }
}

/// `POST /admin/sessions/{id}/revoke` — admin revokes any session. Emits
/// a `session_revoked_by_admin` audit event with both the admin (as
/// actor) and the affected user_id in `event_data`.
pub async fn revoke_session(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(session_id): Path<Uuid>,
) -> impl IntoResponse {
    let session = match state.sessions.find_by_id(session_id).await {
        Ok(Some(s)) => s,
        Ok(None) => return err(StatusCode::NOT_FOUND, "session_not_found").into_response(),
        Err(e) => {
            tracing::error!(?e, "lookup session");
            return err(StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response();
        }
    };

    let actor = admin.actor();
    let target_user_id = session.user_id;

    let result: anyhow::Result<()> = async {
        let mut tx = state.db.begin().await?;
        SessionRepository::revoke(&mut tx, session_id).await?;
        audit::append(
            &mut tx,
            Some(&actor),
            None,
            "session_revoked_by_admin",
            serde_json::json!({
                "session_id": session_id,
                "target_user_id": target_user_id,
            }),
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }
    .await;

    match result {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => {
            tracing::error!(?e, "revoking session as admin");
            err(StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response()
        }
    }
}

fn next_audit_cursor(events: &[audit::AuditEvent], requested_limit: Option<u32>) -> Option<i64> {
    let limit = requested_limit
        .unwrap_or(audit::DEFAULT_PAGE_SIZE)
        .clamp(1, audit::MAX_PAGE_SIZE) as usize;
    if events.len() < limit {
        None
    } else {
        events.last().map(|e| e.seqno)
    }
}

#[derive(Serialize)]
pub struct InvitationView {
    pub id: Uuid,
    pub email: String,
    pub invited_by_user_id: Uuid,
    pub instance_role: InstanceRole,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// `GET /admin/invites` — pending invitations (not accepted, not revoked,
/// not expired), newest first.
pub async fn list_invites(
    State(state): State<AppState>,
    _admin: AdminUser,
) -> impl IntoResponse {
    match state.invitations.list_pending().await {
        Ok(invites) => {
            let views: Vec<InvitationView> = invites
                .into_iter()
                .map(|i| InvitationView {
                    id: i.id.0,
                    email: i.email,
                    invited_by_user_id: i.invited_by_user_id.0,
                    instance_role: i.instance_role,
                    created_at: i.created_at,
                    expires_at: i.expires_at,
                })
                .collect();
            (StatusCode::OK, Json(views)).into_response()
        }
        Err(e) => {
            tracing::error!(?e, "listing pending invites");
            err(StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response()
        }
    }
}

/// `POST /admin/invites/{id}/revoke` — revoke a pending invitation.
/// Already-revoked or already-accepted invitations return 404 to avoid
/// leaking which IDs ever existed.
pub async fn revoke_invite(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(id): Path<Uuid>,
) -> Response {
    let invitation_id = InvitationId::new(id);
    match admin_logic::perform_revoke_invite(&state, &admin, invitation_id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(admin_logic::RevokeInviteError::NotFound) => {
            err(StatusCode::NOT_FOUND, "invite_not_found").into_response()
        }
        Err(admin_logic::RevokeInviteError::AlreadyAccepted) => {
            err(StatusCode::CONFLICT, "invite_already_accepted").into_response()
        }
        Err(admin_logic::RevokeInviteError::Internal(e)) => {
            tracing::error!(?e, "revoking invitation");
            err(StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response()
        }
    }
}

#[derive(Serialize)]
pub struct LifecycleResponse {
    pub id: Uuid,
    pub email: String,
    pub display_name: String,
    pub lifecycle: UserLifecycle,
    pub instance_role: InstanceRole,
    pub updated_at: DateTime<Utc>,
}

impl From<User> for LifecycleResponse {
    fn from(u: User) -> Self {
        Self {
            id: u.id.0,
            email: u.email,
            display_name: u.display_name,
            lifecycle: u.lifecycle,
            instance_role: u.instance_role,
            updated_at: u.updated_at,
        }
    }
}

/// Shared body shape for lifecycle endpoints that support recovery-code
/// bypass (deactivate / delete / purge). Optional — callers that aren't
/// trying to bypass send no body.
#[derive(Deserialize, Default)]
pub struct LifecycleActionRequest {
    pub bypass_recovery_code: Option<String>,
}

/// Translate an `admin_logic::LifecycleError` to the JSON-API error
/// response shape used across this module.
fn lifecycle_error_to_response(e: admin_logic::LifecycleError) -> Response {
    use admin_logic::LifecycleError as L;
    match e {
        L::NotFound => err(StatusCode::NOT_FOUND, "user_not_found").into_response(),
        L::SelfTarget => err(StatusCode::FORBIDDEN, "cannot_target_self").into_response(),
        L::PeerOrHigher => err(StatusCode::FORBIDDEN, "cannot_target_peer_or_higher").into_response(),
        L::Conflict(code) => err(StatusCode::CONFLICT, code).into_response(),
        L::InvalidRecoveryCode => err(StatusCode::UNAUTHORIZED, "invalid_recovery_code").into_response(),
        L::PendingActionExists => err(StatusCode::CONFLICT, "pending_action_exists").into_response(),
        L::Internal(inner) => {
            tracing::error!(?inner, "lifecycle action internal error");
            err(StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response()
        }
    }
}

/// Translate an `admin_logic::RoleError` to the JSON-API error response.
fn role_error_to_response(e: admin_logic::RoleError) -> Response {
    use admin_logic::RoleError as R;
    match e {
        R::Forbidden => err(StatusCode::FORBIDDEN, "forbidden").into_response(),
        R::NotFound => err(StatusCode::NOT_FOUND, "user_not_found").into_response(),
        R::SelfTarget => err(StatusCode::FORBIDDEN, "cannot_target_self").into_response(),
        R::NotActive => err(StatusCode::CONFLICT, "not_active").into_response(),
        R::AlreadyInRole => err(StatusCode::CONFLICT, "already_in_role").into_response(),
        R::InvalidRecoveryCode => err(StatusCode::UNAUTHORIZED, "invalid_recovery_code").into_response(),
        R::PendingActionExists => err(StatusCode::CONFLICT, "pending_action_exists").into_response(),
        R::Internal(inner) => {
            tracing::error!(?inner, "role change internal error");
            err(StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response()
        }
    }
}

/// `POST /admin/users/{id}/deactivate` — Active → Deactivated. Revokes
/// every active session; credentials stay so reactivation works without a
/// password reset. For Owner-on-Owner: routes through the 72h pending
/// veto flow unless `bypass_recovery_code` is supplied and valid.
pub async fn deactivate_member(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(target_id): Path<Uuid>,
    body: Option<Json<LifecycleActionRequest>>,
) -> Response {
    let bypass_code = body.and_then(|Json(r)| r.bypass_recovery_code);
    match admin_logic::perform_deactivate(&state, &admin, target_id, bypass_code.as_deref()).await {
        Ok(Outcome::Applied { target }) => {
            (StatusCode::OK, Json(LifecycleResponse::from(target))).into_response()
        }
        Ok(Outcome::Pending(row)) => {
            (StatusCode::ACCEPTED, Json(PendingTransitionView::from(row))).into_response()
        }
        Err(e) => lifecycle_error_to_response(e),
    }
}

/// `POST /admin/users/{id}/reactivate` — Deactivated → Active. The user
/// must sign in again to obtain a new session; their existing password
/// hash is still valid.
pub async fn reactivate_member(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(target_id): Path<Uuid>,
) -> Response {
    match admin_logic::perform_reactivate(&state, &admin, target_id).await {
        Ok(user) => (StatusCode::OK, Json(LifecycleResponse::from(user))).into_response(),
        Err(e) => lifecycle_error_to_response(e),
    }
}

/// `POST /admin/members/{id}/anonymize` — terminal "account closed" state.
/// Active/Deactivated → Anonymized. Revokes sessions, deletes the
/// credentials row, redacts PII; the tombstone row stays so anything
/// attributed to the account survives under `[deleted user]`.
pub async fn anonymize_member(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(target_id): Path<Uuid>,
    body: Option<Json<LifecycleActionRequest>>,
) -> Response {
    let bypass_code = body.and_then(|Json(r)| r.bypass_recovery_code);
    match admin_logic::perform_anonymize(&state, &admin, target_id, bypass_code.as_deref()).await {
        Ok(Outcome::Applied { .. }) => StatusCode::NO_CONTENT.into_response(),
        Ok(Outcome::Pending(row)) => {
            (StatusCode::ACCEPTED, Json(PendingTransitionView::from(row))).into_response()
        }
        Err(e) => lifecycle_error_to_response(e),
    }
}

/// `POST /admin/members/{id}/delete` — full removal. Physically deletes the
/// user row; every `auth.*` row + any invitations they created cascade away.
/// Only the append-only audit log retains a record that the account existed.
pub async fn delete_member(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(target_id): Path<Uuid>,
    body: Option<Json<LifecycleActionRequest>>,
) -> Response {
    let bypass_code = body.and_then(|Json(r)| r.bypass_recovery_code);
    match admin_logic::perform_delete(&state, &admin, target_id, bypass_code.as_deref()).await {
        Ok(Outcome::Applied { .. }) => StatusCode::NO_CONTENT.into_response(),
        Ok(Outcome::Pending(row)) => {
            (StatusCode::ACCEPTED, Json(PendingTransitionView::from(row))).into_response()
        }
        Err(e) => lifecycle_error_to_response(e),
    }
}

#[derive(Deserialize)]
pub struct ChangeRoleRequest {
    pub role: InstanceRole,
    /// Optional: if supplied and valid, bypasses the Owner-on-Owner veto
    /// window and applies the role change immediately. Verified against
    /// the server's active recovery code.
    pub bypass_recovery_code: Option<String>,
}

/// Response shape covering both immediate and pending outcomes.
#[derive(Serialize)]
#[serde(untagged)]
pub enum ChangeRoleResponse {
    Applied(LifecycleResponse),
    Pending(PendingTransitionView),
}

/// `POST /admin/users/{id}/role` — change a user's instance role.
///
/// Owner-only. Admins get `403 forbidden`.
///
/// Behaviour by case:
/// - Target is **not** an Owner: applies immediately. Returns 200.
/// - Target is an Owner, no `bypass_recovery_code`: creates a pending
///   transition with a 72-hour veto window. Returns 202.
/// - Target is an Owner, `bypass_recovery_code` matches the active code:
///   applies immediately, audit-marked `via: "recovery_bypass"`. Returns 200.
/// - Target is an Owner, `bypass_recovery_code` wrong: 401.
pub async fn change_member_role(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(target_id): Path<Uuid>,
    Json(req): Json<ChangeRoleRequest>,
) -> Response {
    match admin_logic::perform_change_role(
        &state,
        &admin,
        target_id,
        req.role,
        req.bypass_recovery_code.as_deref(),
    )
    .await
    {
        Ok(Outcome::Applied { target }) => (
            StatusCode::OK,
            Json(ChangeRoleResponse::Applied(LifecycleResponse::from(target))),
        )
            .into_response(),
        Ok(Outcome::Pending(row)) => (
            StatusCode::ACCEPTED,
            Json(ChangeRoleResponse::Pending(PendingTransitionView::from(row))),
        )
            .into_response(),
        Err(e) => role_error_to_response(e),
    }
}

#[derive(Deserialize)]
pub struct NotificationsQuery {
    pub state: Option<OutboxState>,
    pub limit: Option<u32>,
}

#[derive(Serialize)]
pub struct NotificationView {
    pub id: Uuid,
    pub kind: notifications::OutboxKind,
    pub recipient_email: String,
    pub subject: String,
    pub state: OutboxState,
    pub attempts: i32,
    pub last_error: Option<String>,
    pub next_attempt_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub sent_at: Option<DateTime<Utc>>,
    pub payload: serde_json::Value,
}

impl From<OutboxRow> for NotificationView {
    fn from(r: OutboxRow) -> Self {
        Self {
            id: r.id,
            kind: r.kind,
            recipient_email: r.recipient_email,
            subject: r.subject,
            state: r.state,
            attempts: r.attempts,
            last_error: r.last_error,
            next_attempt_at: r.next_attempt_at,
            created_at: r.created_at,
            sent_at: r.sent_at,
            payload: r.payload,
        }
    }
}

const NOTIFICATIONS_DEFAULT_LIMIT: u32 = 50;
const NOTIFICATIONS_MAX_LIMIT: u32 = 200;

/// `GET /admin/notifications` — recent outbox rows, newest first.
/// Optional `?state=pending|sending|sent|failed|dead|skipped` filter and
/// `?limit=N` (clamped to [1, 200], default 50). Body and HTML are
/// intentionally excluded from this view to keep responses small; the
/// subject and recipient give an admin enough to debug delivery.
pub async fn list_notifications(
    State(state): State<AppState>,
    _admin: AdminUser,
    Query(q): Query<NotificationsQuery>,
) -> impl IntoResponse {
    let limit = q
        .limit
        .unwrap_or(NOTIFICATIONS_DEFAULT_LIMIT)
        .clamp(1, NOTIFICATIONS_MAX_LIMIT);
    match notifications::list(&state.db, q.state, limit).await {
        Ok(rows) => {
            let views: Vec<NotificationView> = rows.into_iter().map(Into::into).collect();
            (StatusCode::OK, Json(views)).into_response()
        }
        Err(e) => {
            tracing::error!(?e, "listing notifications");
            err(StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response()
        }
    }
}

#[derive(Serialize)]
pub struct PendingTransitionView {
    pub id: Uuid,
    pub kind: pending::TransitionKind,
    pub initiator_user_id: Option<Uuid>,
    pub target_user_id: Option<Uuid>,
    pub payload: serde_json::Value,
    pub state: pending::TransitionState,
    pub effective_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub resolved_by_user_id: Option<Uuid>,
    pub resolution: Option<String>,
    pub created_at: DateTime<Utc>,
}

impl From<pending::TransitionRow> for PendingTransitionView {
    fn from(r: pending::TransitionRow) -> Self {
        Self {
            id: r.id,
            kind: r.kind,
            initiator_user_id: r.initiator_user_id,
            target_user_id: r.target_user_id,
            payload: r.payload,
            state: r.state,
            effective_at: r.effective_at,
            resolved_at: r.resolved_at,
            resolved_by_user_id: r.resolved_by_user_id,
            resolution: r.resolution,
            created_at: r.created_at,
        }
    }
}

/// `GET /admin/pending-transitions` — every transition row, newest first.
/// Owner or Admin can read; the actions themselves are Owner-only.
pub async fn list_pending_transitions(
    State(state): State<AppState>,
    _admin: AdminUser,
) -> impl IntoResponse {
    match pending::list_all(&state.db).await {
        Ok(rows) => {
            let views: Vec<PendingTransitionView> =
                rows.into_iter().map(Into::into).collect();
            (StatusCode::OK, Json(views)).into_response()
        }
        Err(e) => {
            tracing::error!(?e, "listing pending transitions");
            err(StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response()
        }
    }
}

/// `POST /admin/pending-transitions/{id}/veto` — any Owner can veto.
/// Delegates to [`admin_logic::perform_veto_pending`] so the policy
/// (Owner-only authz, audit, notification fanout) lives in one place
/// and is shared with the web `/pending/{id}/veto` route.
pub async fn veto_pending_transition(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    match admin_logic::perform_veto_pending(&state, &admin, id).await {
        Ok(row) => (StatusCode::OK, Json(PendingTransitionView::from(row))).into_response(),
        Err(admin_logic::VetoError::NotOwner) => {
            err(StatusCode::FORBIDDEN, "forbidden").into_response()
        }
        Err(admin_logic::VetoError::NotFound) => {
            err(StatusCode::NOT_FOUND, "transition_not_found").into_response()
        }
        Err(admin_logic::VetoError::NotPending) => {
            err(StatusCode::CONFLICT, "not_pending").into_response()
        }
        Err(admin_logic::VetoError::Internal(e)) => {
            tracing::error!(?e, "vetoing pending transition");
            err(StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response()
        }
    }
}

/// `POST /admin/pending-transitions/{id}/cancel` — initiator or any Owner.
///
/// Cancel keeps its inline authz here (Owner OR initiator) because the
/// rule is route-specific; the shared [`admin_logic::resolve_pending_inner`]
/// only enforces the row-state transition, leaving authz to the caller.
pub async fn cancel_pending_transition(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    // Anyone with Admin or higher can read pending state; cancellation is
    // restricted to Owner OR the initiator themselves (any role).
    let row = match pending::find_by_id(&state.db, id).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            return err(StatusCode::NOT_FOUND, "transition_not_found").into_response();
        }
        Err(e) => {
            tracing::error!(?e, "lookup pending transition");
            return err(StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response();
        }
    };

    let is_owner = admin.0.user.instance_role == InstanceRole::Owner;
    let is_initiator = row.initiator_user_id == Some(admin.0.user.id.0);
    if !is_owner && !is_initiator {
        return err(StatusCode::FORBIDDEN, "forbidden").into_response();
    }

    match admin_logic::resolve_pending_inner(
        &state,
        &admin,
        id,
        admin_logic::ResolveKind::Cancel,
    )
    .await
    {
        Ok(row) => (StatusCode::OK, Json(PendingTransitionView::from(row))).into_response(),
        Err(admin_logic::ResolveError::NotFound) => {
            err(StatusCode::NOT_FOUND, "transition_not_found").into_response()
        }
        Err(admin_logic::ResolveError::NotPending) => {
            err(StatusCode::CONFLICT, "not_pending").into_response()
        }
        Err(admin_logic::ResolveError::Internal(e)) => {
            tracing::error!(?e, "cancelling pending transition");
            err(StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response()
        }
    }
}

// ────────────────────────────────────────────────────────────────────────
// /admin/server/recovery-code
// ────────────────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct RecoveryCodeMetadata {
    pub id: Uuid,
    pub created_at: DateTime<Utc>,
    pub created_by_user_id: Option<Uuid>,
}

#[derive(Deserialize)]
pub struct RotateRecoveryCodeRequest {
    pub current_code: String,
}

#[derive(Serialize)]
pub struct RotateRecoveryCodeResponse {
    pub id: Uuid,
    pub created_at: DateTime<Utc>,
    pub new_code: String,
    pub warning: &'static str,
}

/// `GET /admin/server/recovery-code` — Owner-only. Returns metadata only;
/// the raw code is never exposed via this endpoint. Lets the operator
/// confirm a code exists and was generated as expected.
pub async fn get_recovery_code_metadata(
    State(state): State<AppState>,
    admin: AdminUser,
) -> impl IntoResponse {
    if admin.0.user.instance_role != InstanceRole::Owner {
        return err(StatusCode::FORBIDDEN, "forbidden").into_response();
    }
    match auth::recovery_code::active_metadata(&state.db).await {
        Ok(Some(row)) => (
            StatusCode::OK,
            Json(RecoveryCodeMetadata {
                id: row.id,
                created_at: row.created_at,
                created_by_user_id: row.created_by_user_id,
            }),
        )
            .into_response(),
        Ok(None) => err(StatusCode::NOT_FOUND, "no_active_recovery_code").into_response(),
        Err(e) => {
            tracing::error!(?e, "looking up recovery code");
            err(StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response()
        }
    }
}

/// `POST /admin/server/recovery-code/rotate` — Owner-only. Requires the
/// current code in the body. Generates a fresh code, returns it **once**,
/// invalidates the old one. The operator must save the returned value.
pub async fn rotate_recovery_code(
    State(state): State<AppState>,
    admin: AdminUser,
    Json(req): Json<RotateRecoveryCodeRequest>,
) -> impl IntoResponse {
    if admin.0.user.instance_role != InstanceRole::Owner {
        return err(StatusCode::FORBIDDEN, "forbidden").into_response();
    }

    let by = admin.0.user.id;
    let actor = admin.actor();

    let new_raw = auth::recovery_code::generate_code();

    // Verify-and-rotate happens atomically inside `auth::recovery_code::rotate`
    // via a single conditional UPDATE — no TOCTOU window between checking the
    // current code and replacing it.
    let result: anyhow::Result<Option<(Uuid, DateTime<Utc>)>> = async {
        let mut tx = state.db.begin().await?;
        let rotated =
            auth::recovery_code::rotate(&mut tx, &req.current_code, &new_raw, by).await?;
        let Some((new_id, previous_id)) = rotated else {
            // Wrong current code — no rows changed; commit-or-rollback is moot.
            return Ok(None);
        };
        audit::append(
            &mut tx,
            Some(&actor),
            None,
            "recovery_code_rotated",
            serde_json::json!({
                "new_code_id": new_id,
                "previous_code_id": previous_id,
                "rotated_by": by.0,
            }),
        )
        .await?;
        let created_at: DateTime<Utc> = sqlx::query_scalar(
            "SELECT created_at FROM auth.recovery_codes WHERE id = $1",
        )
        .bind(new_id)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(Some((new_id, created_at)))
    }
    .await;

    match result {
        Ok(Some((id, created_at))) => (
            StatusCode::OK,
            Json(RotateRecoveryCodeResponse {
                id,
                created_at,
                new_code: new_raw,
                warning: "SAVE THIS CODE NOW. It will not be shown again. \
                          The previous code is invalidated.",
            }),
        )
            .into_response(),
        Ok(None) => err(StatusCode::UNAUTHORIZED, "invalid_recovery_code").into_response(),
        Err(e) => {
            tracing::error!(?e, "rotating recovery code");
            err(StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response()
        }
    }
}
