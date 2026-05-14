use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use chrono::{DateTime, Utc};
use identity::{
    DEFAULT_INVITATION_TTL, InstanceRole, InvitationRepository, UserLifecycle,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{app::AppState, auth_routes::AdminUser};

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
        tx.commit().await?;

        Ok(CreateInviteResponse {
            invitation_id: invitation.id.0,
            email: invitation.email,
            instance_role: invitation.instance_role,
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

