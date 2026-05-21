use audit::ListFilter;
use auth::SessionRepository;
use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Utc};
use identity::{
    DEFAULT_INVITATION_TTL, InstanceRole, InvitationId, InvitationRepository, User, UserLifecycle,
};
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
pub struct AdminUserView {
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
pub async fn list_users(
    State(state): State<AppState>,
    _admin: AdminUser,
) -> impl IntoResponse {
    match state.users.list_all().await {
        Ok(users) => {
            let views: Vec<AdminUserView> = users
                .into_iter()
                .map(|u| AdminUserView {
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
    /// Optional. Defaults to `User` if omitted.
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
/// this response; the client (eventually email + web wizard) is responsible
/// for delivering it to the invitee. The DB only stores `sha256(token)`.
///
/// Role-escalation guard: the inviter's role must satisfy the target role
/// - an Admin cannot invite an Owner.
pub async fn create_invite(
    State(state): State<AppState>,
    admin: AdminUser,
    Json(req): Json<CreateInviteRequest>,
) -> impl IntoResponse {
    let target_role = req.instance_role.unwrap_or(InstanceRole::User);

    if req.email.trim().is_empty() {
        return err(StatusCode::BAD_REQUEST, "email_required").into_response();
    }

    if !authz::satisfies(admin.0.user.instance_role, target_role) {
        return err(StatusCode::FORBIDDEN, "cannot_invite_higher_role").into_response();
    }

    match state.users.email_in_use(&req.email).await {
        Ok(true) => {
            return err(StatusCode::CONFLICT, "email_already_in_use").into_response();
        }
        Err(err_) => {
            tracing::error!(?err_, "checking email_in_use");
            return err(StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response();
        }
        Ok(false) => {}
    }

    match state.invitations.email_has_active_invite(&req.email).await {
        Ok(true) => {
            return err(StatusCode::CONFLICT, "active_invite_exists").into_response();
        }
        Err(err_) => {
            tracing::error!(?err_, "checking active invite");
            return err(StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response();
        }
        Ok(false) => {}
    }

    let actor = admin.actor();
    let inviter_display_name = admin.0.user.display_name.clone();
    let base = state.public_base_url.clone();
    let result: anyhow::Result<CreateInviteResponse> = async {
        let mut tx = state.db.begin().await?;
        let (invitation, token) = InvitationRepository::create(
            &mut tx,
            admin.0.user.id,
            &req.email,
            target_role,
            DEFAULT_INVITATION_TTL,
        )
        .await?;

        audit::append(
            &mut tx,
            Some(&actor),
            None,
            "invite_created",
            serde_json::json!({
                "invitation_id": invitation.id.0,
                "invited_email": invitation.email,
                "instance_role": invitation.instance_role,
            }),
        )
        .await?;

        // Enqueue the delivery email in the same transaction so we never
        // create an invitation without queuing its email (or vice versa).
        let full_accept_url = format!("{base}/invite/{token}");
        notifications::enqueue(
            &mut tx,
            notifications::Notification::Invitation {
                recipient_email: invitation.email.clone(),
                inviter_display_name: inviter_display_name.clone(),
                accept_url: full_accept_url.clone(),
                expires_at: invitation.expires_at,
                instance_role: invitation.instance_role,
                invitation_id: invitation.id.0,
            },
        )
        .await?;

        tx.commit().await?;

        Ok(CreateInviteResponse {
            invitation_id: invitation.id.0,
            email: invitation.email,
            instance_role: invitation.instance_role,
            // The relative path is kept for back-compat in case any caller
            // depends on it; the email contains the full URL via base_url.
            accept_url: format!("/invite/{token}"),
            token,
            expires_at: invitation.expires_at,
        })
    }
    .await;

    match result {
        Ok(resp) => (StatusCode::CREATED, Json(resp)).into_response(),
        Err(err_) => {
            tracing::error!(?err_, "creating invite");
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
) -> impl IntoResponse {
    let invitation_id = InvitationId::new(id);
    let invitation = match state.invitations.find_by_id(invitation_id).await {
        Ok(Some(inv)) => inv,
        Ok(None) => return err(StatusCode::NOT_FOUND, "invite_not_found").into_response(),
        Err(e) => {
            tracing::error!(?e, "lookup invitation");
            return err(StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response();
        }
    };

    if invitation.accepted_at.is_some() {
        return err(StatusCode::CONFLICT, "invite_already_accepted").into_response();
    }
    if invitation.revoked_at.is_some() {
        return err(StatusCode::NOT_FOUND, "invite_not_found").into_response();
    }

    let actor = admin.actor();
    let result: anyhow::Result<()> = async {
        let mut tx = state.db.begin().await?;
        InvitationRepository::revoke(&mut tx, invitation_id).await?;
        audit::append(
            &mut tx,
            Some(&actor),
            None,
            "invite_revoked",
            serde_json::json!({
                "invitation_id": id,
                "invited_email": invitation.email,
                "instance_role": invitation.instance_role,
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
pub async fn deactivate_user(
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
pub async fn reactivate_user(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(target_id): Path<Uuid>,
) -> Response {
    match admin_logic::perform_reactivate(&state, &admin, target_id).await {
        Ok(user) => (StatusCode::OK, Json(LifecycleResponse::from(user))).into_response(),
        Err(e) => lifecycle_error_to_response(e),
    }
}

/// `POST /admin/users/{id}/delete` — terminal "account removed" state.
/// Active/Deactivated → SoftDeleted. Revokes sessions, deletes the
/// credentials row, redacts PII. Content the user authored that other
/// users have access to is preserved (future content-cleanup hook drops
/// orphans once the apps platform lands).
pub async fn delete_user(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(target_id): Path<Uuid>,
    body: Option<Json<LifecycleActionRequest>>,
) -> Response {
    let bypass_code = body.and_then(|Json(r)| r.bypass_recovery_code);
    match admin_logic::perform_soft_delete(&state, &admin, target_id, bypass_code.as_deref()).await {
        Ok(Outcome::Applied { .. }) => StatusCode::NO_CONTENT.into_response(),
        Ok(Outcome::Pending(row)) => {
            (StatusCode::ACCEPTED, Json(PendingTransitionView::from(row))).into_response()
        }
        Err(e) => lifecycle_error_to_response(e),
    }
}

/// `POST /admin/users/{id}/purge` — terminal "full purge" state.
/// Active/Deactivated/SoftDeleted → HardDeleted. Today the row-level
/// effect matches `delete_user`; once content lives in the apps
/// platform, the content-cleanup hook here drops *all* their content
/// regardless of collaborators.
pub async fn purge_user(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(target_id): Path<Uuid>,
    body: Option<Json<LifecycleActionRequest>>,
) -> Response {
    let bypass_code = body.and_then(|Json(r)| r.bypass_recovery_code);
    match admin_logic::perform_hard_delete(&state, &admin, target_id, bypass_code.as_deref()).await {
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
pub async fn change_user_role(
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
pub async fn veto_pending_transition(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    if admin.0.user.instance_role != InstanceRole::Owner {
        return err(StatusCode::FORBIDDEN, "forbidden").into_response();
    }
    resolve_pending(&state, &admin, id, ResolveKind::Veto).await
}

/// `POST /admin/pending-transitions/{id}/cancel` — initiator or any Owner.
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

    resolve_pending(&state, &admin, id, ResolveKind::Cancel).await
}

#[derive(Clone, Copy)]
enum ResolveKind {
    Veto,
    Cancel,
}

async fn resolve_pending(
    state: &AppState,
    admin: &AdminUser,
    transition_id: Uuid,
    kind: ResolveKind,
) -> axum::response::Response {
    let actor = admin.actor();
    let by_user_id = admin.0.user.id;
    let admin_display_name = admin.0.user.display_name.clone();

    let result: anyhow::Result<pending::TransitionRow> = async {
        let mut tx = state.db.begin().await?;
        let row = match kind {
            ResolveKind::Veto => pending::veto(&mut tx, transition_id, by_user_id).await?,
            ResolveKind::Cancel => pending::cancel(&mut tx, transition_id, by_user_id).await?,
        };

        // Look up initiator + target display info for audit + notification.
        let initiator_id = row
            .initiator_user_id
            .ok_or_else(|| anyhow::anyhow!("initiator_user_id is null"))?;
        let target_id = row
            .target_user_id
            .ok_or_else(|| anyhow::anyhow!("target_user_id is null"))?;
        let (initiator_email, initiator_display_name, target_display_name): (
            String,
            String,
            String,
        ) = sqlx::query_as(
            "SELECT
                (SELECT email FROM identity.users WHERE id = $1),
                (SELECT display_name FROM identity.users WHERE id = $1),
                (SELECT display_name FROM identity.users WHERE id = $2)",
        )
        .bind(initiator_id)
        .bind(target_id)
        .fetch_one(&mut *tx)
        .await?;

        // Audit + notification details differ by kind. For role_change we
        // include the to_role; for lifecycle kinds we include the action.
        let is_lifecycle = pending::lifecycle_from_kind(row.kind).is_some();
        let event_type = match (kind, is_lifecycle) {
            (ResolveKind::Veto, false) => "pending_role_change_vetoed",
            (ResolveKind::Cancel, false) => "pending_role_change_cancelled",
            (ResolveKind::Veto, true) => "pending_lifecycle_vetoed",
            (ResolveKind::Cancel, true) => "pending_lifecycle_cancelled",
        };

        let mut event_data = serde_json::json!({
            "transition_id": transition_id,
            "initiator_user_id": initiator_id,
            "target_user_id": target_id,
            "resolved_by": by_user_id.0,
        });
        if let Some(action) = pending::lifecycle_from_kind(row.kind) {
            event_data["action"] = serde_json::to_value(action)?;
        } else {
            let payload = row.role_payload()?;
            event_data["to_role"] = serde_json::to_value(payload.to_role)?;
        }
        audit::append(&mut tx, Some(&actor), None, event_type, event_data).await?;

        // Notify the initiator on veto. (Skip notification for cancel —
        // the initiator is usually the cancel-er themselves.)
        if matches!(kind, ResolveKind::Veto) {
            if let Some(action) = pending::lifecycle_from_kind(row.kind) {
                notifications::enqueue(
                    &mut tx,
                    notifications::Notification::PendingLifecycleVetoed {
                        recipient_email: initiator_email,
                        initiator_display_name,
                        target_display_name,
                        vetoed_by_display_name: admin_display_name.clone(),
                        action,
                        transition_id,
                    },
                )
                .await?;
            } else {
                let payload = row.role_payload()?;
                let from_role: InstanceRole = sqlx::query_scalar(
                    "SELECT instance_role FROM identity.users WHERE id = $1",
                )
                .bind(target_id)
                .fetch_one(&mut *tx)
                .await?;
                notifications::enqueue(
                    &mut tx,
                    notifications::Notification::PendingRoleChangeVetoed {
                        recipient_email: initiator_email,
                        initiator_display_name,
                        target_display_name,
                        vetoed_by_display_name: admin_display_name.clone(),
                        from_role,
                        to_role: payload.to_role,
                        transition_id,
                    },
                )
                .await?;
            }
        }

        tx.commit().await?;
        Ok(row)
    }
    .await;

    match result {
        Ok(row) => (StatusCode::OK, Json(PendingTransitionView::from(row))).into_response(),
        Err(e) => {
            if let Some(pe) = e.downcast_ref::<pending::PendingError>() {
                match pe {
                    pending::PendingError::NotFound => {
                        return err(StatusCode::NOT_FOUND, "transition_not_found").into_response();
                    }
                    pending::PendingError::NotPending => {
                        return err(StatusCode::CONFLICT, "not_pending").into_response();
                    }
                    _ => {}
                }
            }
            tracing::error!(?e, "resolving pending transition");
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
