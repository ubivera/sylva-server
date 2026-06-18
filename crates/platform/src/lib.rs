//! Sylva Hearth **platform** gRPC services — the app-facing API.
//!
//! Two services: `Platform` (`WhoAmI` + app registration) and `Resources`
//! (owner-scoped generic content storage). Every RPC authenticates the caller
//! by the opaque session token (from the REST `/api/auth/login`) presented in
//! `authorization: Bearer <token>` metadata. Resources are tied to a registered,
//! enabled app via `app_id`. Sharing/ReBAC + a sync stream are later checkpoints.
//!
//! Deliberately depends only on `proto`, `auth`, and `identity` — never on the
//! `hearth` crate — so the dependency graph stays `hearth → platform → proto`
//! with no cycle. The gRPC server is handed a [`PlatformContext`] built from the
//! same repositories the REST layer uses.

use std::sync::Arc;

use proto::platform::v1::{
    AppIdentifier, AppRegistration, CreateResourceRequest, Empty, ListResourcesRequest,
    ListResourcesResponse, RegisterAppRequest, Resource, ResourceId, StreamChangesRequest,
    UpdateResourceRequest, WhoAmIResponse,
    platform_server::{Platform, PlatformServer},
    resources_server::{Resources, ResourcesServer},
};
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{Request, Response, Status};

pub mod account;
pub mod registry;
pub mod resources;

/// Shared context for the gRPC services (Platform, Resources, Account). Each
/// repository wraps the `PgPool`, so cloning is cheap. `secret_key` is threaded
/// for app-key verification at registration; `user_keys`/`devices` back the
/// Account service's enrollment flow.
#[derive(Clone)]
pub struct PlatformContext {
    pub sessions: auth::SessionRepository,
    pub users: identity::UserRepository,
    pub resources: resources::ResourceRepository,
    pub user_keys: identity::UserKeyRepository,
    pub devices: identity::DeviceRepository,
    /// Pool for registry queries + audit transactions (app registration, enrollment).
    pub pool: sqlx::PgPool,
    pub secret_key: Arc<[u8; 32]>,
}

/// The caller resolved from a request's bearer token.
pub struct AuthedUser {
    pub user: identity::User,
}

/// Resolve `authorization: Bearer <token>` metadata into an authenticated user,
/// mirroring the REST `AuthenticatedUser` extractor (bearer → `find_active` →
/// `find_by_id` → best-effort `touch_last_seen`). Any failure maps to
/// `unauthenticated` with a coarse reason; specifics go to `tracing` so we don't
/// leak which check failed over the wire.
///
/// This is an `async` helper called per-RPC rather than a `tonic::Interceptor`
/// (those are synchronous and can't `.await` the DB lookups). Once there are
/// several RPCs it can graduate to a shared tower layer.
pub async fn authenticate(
    ctx: &PlatformContext,
    metadata: &tonic::metadata::MetadataMap,
) -> Result<AuthedUser, Status> {
    let raw = metadata
        .get("authorization")
        .ok_or_else(|| Status::unauthenticated("missing_authorization"))?;
    // Non-ASCII header → reject rather than panic (deny-`panic` posture).
    let value = raw
        .to_str()
        .map_err(|_| Status::unauthenticated("invalid_authorization"))?;
    let token = value
        .strip_prefix("Bearer ")
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .ok_or_else(|| Status::unauthenticated("invalid_authorization"))?;

    // `find_active` already filters revoked / expired sessions + inactive users.
    let session = ctx
        .sessions
        .find_active(token)
        .await
        .map_err(|err| {
            tracing::error!(?err, "grpc auth: session lookup failed");
            Status::unauthenticated("invalid_session")
        })?
        .ok_or_else(|| Status::unauthenticated("invalid_session"))?;

    let user = ctx
        .users
        .find_by_id(identity::UserId::new(session.user_id))
        .await
        .map_err(|err| {
            tracing::error!(?err, "grpc auth: user lookup failed");
            Status::unauthenticated("invalid_session")
        })?
        .ok_or_else(|| Status::unauthenticated("invalid_session"))?;

    // Best-effort activity bump (matches the REST extractor); never fatal.
    if let Err(err) = ctx.sessions.touch_last_seen(session.id).await {
        tracing::warn!(?err, "grpc auth: touch_last_seen failed");
    }

    Ok(AuthedUser { user })
}

/// The `Platform` gRPC service implementation.
pub struct PlatformService {
    ctx: PlatformContext,
}

#[tonic::async_trait]
impl Platform for PlatformService {
    async fn who_am_i(
        &self,
        request: Request<Empty>,
    ) -> Result<Response<WhoAmIResponse>, Status> {
        let authed = authenticate(&self.ctx, request.metadata()).await?;
        // Map the role to the wire token explicitly so the contract doesn't
        // ride on serde's representation of `InstanceRole`.
        let instance_role = match authed.user.instance_role {
            identity::InstanceRole::Owner => "owner",
            identity::InstanceRole::Admin => "admin",
            identity::InstanceRole::Member => "member",
        };
        Ok(Response::new(WhoAmIResponse {
            user_id: authed.user.id.0.to_string(),
            display_name: authed.user.display_name,
            instance_role: instance_role.to_string(),
        }))
    }

    async fn register_app(
        &self,
        request: Request<RegisterAppRequest>,
    ) -> Result<Response<AppRegistration>, Status> {
        let authed = authenticate(&self.ctx, request.metadata()).await?;
        let actor = audit::Actor {
            user_id: authed.user.id,
            display_name: authed.user.display_name.clone(),
        };
        let req = request.into_inner();
        if req.app_identifier.trim().is_empty()
            || req.display_name.trim().is_empty()
            || req.publisher.trim().is_empty()
        {
            return Err(Status::invalid_argument(
                "app_identifier, display_name, and publisher are required",
            ));
        }
        let decl = registry::AppDeclaration {
            app_identifier: req.app_identifier,
            display_name: req.display_name,
            publisher: req.publisher,
            app_public_key: req.app_public_key,
            schema_version: req.schema_version,
            resource_types: req.resource_types,
        };

        // The publisher must be trusted, and the declaration must carry that
        // publisher's valid signature.
        let publisher = registry::get_trusted_publisher(&self.ctx.pool, &decl.publisher)
            .await
            .map_err(|err| internal(&err, "register_app:get_publisher"))?
            .ok_or_else(|| Status::permission_denied("publisher is not trusted on this server"))?;
        if !registry::verify_declaration_signature(&publisher.public_key, &decl, &req.signature) {
            return Err(Status::permission_denied("invalid publisher signature"));
        }

        // Upsert the registration + audit it atomically.
        let mut tx = self
            .ctx
            .pool
            .begin()
            .await
            .map_err(|err| internal(&err, "register_app:begin"))?;
        let row = registry::upsert_app(&mut *tx, &decl, Some(authed.user.id.0))
            .await
            .map_err(|err| internal(&err, "register_app:upsert"))?;
        audit::append(
            &mut tx,
            Some(&actor),
            None,
            "app_registered",
            serde_json::json!({
                "app_id": row.id,
                "app_identifier": row.app_identifier,
                "publisher": row.publisher,
                "schema_version": row.schema_version,
            }),
        )
        .await
        .map_err(|err| internal(&err, "register_app:audit"))?;
        tx.commit()
            .await
            .map_err(|err| internal(&err, "register_app:commit"))?;

        Ok(Response::new(app_to_proto(row)))
    }

    async fn get_app_registration(
        &self,
        request: Request<AppIdentifier>,
    ) -> Result<Response<AppRegistration>, Status> {
        // Any authenticated user can look up a registration.
        authenticate(&self.ctx, request.metadata()).await?;
        let identifier = request.into_inner().app_identifier;
        match registry::get_app_by_identifier(&self.ctx.pool, &identifier).await {
            Ok(Some(row)) => Ok(Response::new(app_to_proto(row))),
            Ok(None) => Err(Status::not_found("app not registered")),
            Err(err) => Err(internal(&err, "get_app_registration")),
        }
    }
}

/// Build the tonic service wrapper for the `Platform` service.
pub fn platform_server(ctx: PlatformContext) -> PlatformServer<PlatformService> {
    PlatformServer::new(PlatformService { ctx })
}

// ── Resources service (CP2, owner-scoped) ──────────────────────────────────

const DEFAULT_LIST_LIMIT: u32 = 50;
const MAX_LIST_LIMIT: u32 = 200;
const DEFAULT_CHANGES_LIMIT: u32 = 500;
const MAX_CHANGES_LIMIT: u32 = 2000;

/// The `Resources` gRPC service. Every RPC authenticates the caller (the
/// owner), then scopes the storage op to that owner — a resource owned by
/// someone else is reported `not_found`.
pub struct ResourcesService {
    ctx: PlatformContext,
}

#[tonic::async_trait]
impl Resources for ResourcesService {
    async fn create_resource(
        &self,
        request: Request<CreateResourceRequest>,
    ) -> Result<Response<Resource>, Status> {
        let owner = authenticate(&self.ctx, request.metadata()).await?.user.id.0;
        let req = request.into_inner();
        if req.resource_type.trim().is_empty() {
            return Err(Status::invalid_argument("resource_type is required"));
        }
        let app_id = parse_uuid(&req.app_id, "app_id")?;

        // CP3b: a resource must belong to a registered, enabled app and carry one
        // of that app's declared resource_types. App registration is instance-
        // global; the resource's owner is still the caller. The FK on
        // `resources.app_id` backstops a concurrent app-delete race (23503).
        let app = registry::get_app(&self.ctx.pool, app_id)
            .await
            .map_err(|err| internal(&err, "create_resource:get_app"))?
            .ok_or_else(|| Status::failed_precondition("app is not registered"))?;
        if app.status != "enabled" {
            return Err(Status::failed_precondition("app is disabled"));
        }
        if !app.resource_types.iter().any(|t| t == &req.resource_type) {
            return Err(Status::invalid_argument(format!(
                "resource_type '{}' is not declared by app '{}'",
                req.resource_type, app.app_identifier
            )));
        }

        let new = resources::NewResource {
            app_id,
            resource_type: req.resource_type,
            app_resource_id: parse_uuid(&req.app_resource_id, "app_resource_id")?,
            parent_resource_id: parse_opt_uuid(
                req.parent_resource_id.as_deref(),
                "parent_resource_id",
            )?,
            owner_user_id: owner,
            content_blob: req.content_blob,
            content_signature: req.content_signature,
            schema_version: req.schema_version,
        };
        match self.ctx.resources.create(&new).await {
            Ok(row) => Ok(Response::new(to_proto(row))),
            Err(sqlx::Error::Database(dbe)) if dbe.code().as_deref() == Some("23505") => Err(
                Status::already_exists("a resource with that app_resource_id already exists"),
            ),
            Err(sqlx::Error::Database(dbe)) if dbe.code().as_deref() == Some("23503") => {
                Err(Status::failed_precondition("app is not registered"))
            }
            Err(err) => Err(internal(&err, "create_resource")),
        }
    }

    async fn read_resource(
        &self,
        request: Request<ResourceId>,
    ) -> Result<Response<Resource>, Status> {
        let owner = authenticate(&self.ctx, request.metadata()).await?.user.id.0;
        let id = parse_uuid(&request.into_inner().id, "id")?;
        match self.ctx.resources.get_owned(id, owner).await {
            Ok(Some(row)) => Ok(Response::new(to_proto(row))),
            Ok(None) => Err(Status::not_found("resource not found")),
            Err(err) => Err(internal(&err, "read_resource")),
        }
    }

    async fn update_resource(
        &self,
        request: Request<UpdateResourceRequest>,
    ) -> Result<Response<Resource>, Status> {
        let owner = authenticate(&self.ctx, request.metadata()).await?.user.id.0;
        let req = request.into_inner();
        let id = parse_uuid(&req.id, "id")?;
        let parent = parse_opt_uuid(req.parent_resource_id.as_deref(), "parent_resource_id")?;
        match self
            .ctx
            .resources
            .update_owned(
                id,
                owner,
                &req.content_blob,
                &req.content_signature,
                req.schema_version,
                parent,
            )
            .await
        {
            Ok(Some(row)) => Ok(Response::new(to_proto(row))),
            Ok(None) => Err(Status::not_found("resource not found")),
            Err(err) => Err(internal(&err, "update_resource")),
        }
    }

    async fn delete_resource(
        &self,
        request: Request<ResourceId>,
    ) -> Result<Response<Empty>, Status> {
        let owner = authenticate(&self.ctx, request.metadata()).await?.user.id.0;
        let id = parse_uuid(&request.into_inner().id, "id")?;
        match self.ctx.resources.soft_delete_owned(id, owner).await {
            Ok(true) => Ok(Response::new(Empty {})),
            Ok(false) => Err(Status::not_found("resource not found")),
            Err(err) => Err(internal(&err, "delete_resource")),
        }
    }

    async fn list_resources(
        &self,
        request: Request<ListResourcesRequest>,
    ) -> Result<Response<ListResourcesResponse>, Status> {
        let owner = authenticate(&self.ctx, request.metadata()).await?.user.id.0;
        let req = request.into_inner();
        if req.resource_type.trim().is_empty() {
            return Err(Status::invalid_argument("resource_type is required"));
        }
        let app_id = parse_uuid(&req.app_id, "app_id")?;
        let limit = clamp_limit(req.limit);
        let offset = i64::from(req.offset);
        match self
            .ctx
            .resources
            .list_owned(app_id, &req.resource_type, owner, limit, offset, req.include_deleted)
            .await
        {
            Ok((rows, total)) => Ok(Response::new(ListResourcesResponse {
                resources: rows.into_iter().map(to_proto).collect(),
                total: total.max(0) as u32,
            })),
            Err(err) => Err(internal(&err, "list_resources")),
        }
    }

    type StreamChangesStream =
        std::pin::Pin<Box<dyn tokio_stream::Stream<Item = Result<Resource, Status>> + Send>>;

    /// Owner-scoped incremental sync. Streams every resource (including
    /// tombstones) whose `change_seq` exceeds `since_cursor`, oldest first, then
    /// completes — a bounded catch-up batch. The client persists the max
    /// `change_seq` it sees and re-calls with it until a call yields nothing.
    async fn stream_changes(
        &self,
        request: Request<StreamChangesRequest>,
    ) -> Result<Response<Self::StreamChangesStream>, Status> {
        let owner = authenticate(&self.ctx, request.metadata()).await?.user.id.0;
        let req = request.into_inner();
        let app_id = parse_uuid(&req.app_id, "app_id")?;
        let resource_type = if req.resource_type.trim().is_empty() {
            None
        } else {
            Some(req.resource_type)
        };
        // u64 cursor → i64 column; a value past i64::MAX just means "nothing newer".
        let since = i64::try_from(req.since_cursor).unwrap_or(i64::MAX);
        let limit = clamp_changes_limit(req.limit);
        let rows = self
            .ctx
            .resources
            .list_changes(app_id, resource_type.as_deref(), owner, since, limit)
            .await
            .map_err(|err| internal(&err, "stream_changes"))?;
        let items: Vec<Result<Resource, Status>> =
            rows.into_iter().map(|row| Ok(to_proto(row))).collect();
        Ok(Response::new(Box::pin(tokio_stream::iter(items))))
    }
}

fn clamp_changes_limit(requested: u32) -> i64 {
    let n = if requested == 0 {
        DEFAULT_CHANGES_LIMIT
    } else {
        requested.min(MAX_CHANGES_LIMIT)
    };
    i64::from(n)
}

/// Build the tonic service wrapper for the `Resources` service.
pub fn resources_server(ctx: PlatformContext) -> ResourcesServer<ResourcesService> {
    ResourcesServer::new(ResourcesService { ctx })
}

fn clamp_limit(requested: u32) -> i64 {
    let n = if requested == 0 {
        DEFAULT_LIST_LIMIT
    } else {
        requested.min(MAX_LIST_LIMIT)
    };
    i64::from(n)
}

fn parse_uuid(value: &str, field: &str) -> Result<uuid::Uuid, Status> {
    uuid::Uuid::parse_str(value.trim())
        .map_err(|_| Status::invalid_argument(format!("{field} must be a UUID")))
}

fn parse_opt_uuid(value: Option<&str>, field: &str) -> Result<Option<uuid::Uuid>, Status> {
    match value.map(str::trim).filter(|v| !v.is_empty()) {
        Some(v) => Ok(Some(parse_uuid(v, field)?)),
        None => Ok(None),
    }
}

fn internal<E: std::fmt::Debug>(err: &E, op: &str) -> Status {
    tracing::error!(?err, op, "grpc platform operation failed");
    Status::internal("internal error")
}

/// Map a stored row to its wire form (timestamps as RFC 3339).
fn to_proto(row: resources::ResourceRow) -> Resource {
    Resource {
        id: row.id.to_string(),
        app_id: row.app_id.to_string(),
        resource_type: row.resource_type,
        app_resource_id: row.app_resource_id.to_string(),
        parent_resource_id: row.parent_resource_id.map(|u| u.to_string()),
        owner_user_id: row.owner_user_id.to_string(),
        created_at: row.created_at.to_rfc3339(),
        updated_at: row.updated_at.to_rfc3339(),
        deleted_at: row.deleted_at.map(|t| t.to_rfc3339()),
        content_blob: row.content_blob,
        content_signature: row.content_signature,
        last_modified_by: row.last_modified_by.to_string(),
        schema_version: row.schema_version,
        change_seq: u64::try_from(row.change_seq).unwrap_or(0),
    }
}

/// Map a registered-app row to its wire form.
fn app_to_proto(row: registry::RegisteredAppRow) -> AppRegistration {
    AppRegistration {
        id: row.id.to_string(),
        app_identifier: row.app_identifier,
        display_name: row.display_name,
        publisher: row.publisher,
        schema_version: row.schema_version,
        resource_types: row.resource_types,
        status: row.status,
        created_at: row.created_at.to_rfc3339(),
        updated_at: row.updated_at.to_rfc3339(),
    }
}

/// Serve the gRPC API on an already-bound `listener` until `shutdown` resolves.
/// Taking a pre-bound listener lets the caller (`hearth::serve`, and tests on
/// port 0) control binding and learn the assigned port.
pub async fn serve_grpc(
    ctx: PlatformContext,
    listener: tokio::net::TcpListener,
    shutdown: impl std::future::Future<Output = ()> + Send,
) -> Result<(), tonic::transport::Error> {
    tonic::transport::Server::builder()
        .add_service(platform_server(ctx.clone()))
        .add_service(resources_server(ctx.clone()))
        .add_service(account::account_server(ctx))
        .serve_with_incoming_shutdown(TcpListenerStream::new(listener), shutdown)
        .await
}
