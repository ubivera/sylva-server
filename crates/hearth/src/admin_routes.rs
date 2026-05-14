use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use chrono::{DateTime, Utc};
use identity::{InstanceRole, UserLifecycle};
use serde::Serialize;
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

/// `GET /admin/users` — list every non-purged user. Admin or Owner only.
///
/// Returns a JSON array sorted by `created_at` ascending. Password hashes
/// and other auth-only fields are not exposed.
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
