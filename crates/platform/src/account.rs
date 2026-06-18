//! The `Account` gRPC service — Sylva Hub's identity / device-enrollment plane
//! (see `docs/design/hub.md`). Distinct from Platform/Resources: the Hub is core
//! infrastructure, not a registered app.
//!
//! `Bootstrap` + `Login` are unauthenticated; the rest require a session token
//! and are owner-scoped. Auth uses the Argon2id password verifier (over TLS);
//! the master key is wrapped *client-side* under `KDF(password, secret_key)` —
//! the server stores only the ciphertext it is handed. Peer-IP rate-limiting on
//! the unauthenticated RPCs + the signed discovery endpoint land in 2c.

use identity::{
    Device, DeviceId, DeviceRepository, InstanceRole, MachineRepository, NewDevice, User, UserId,
    UserKeyMaterial, UserKeyRepository, UserLifecycle, UserRepository,
};
use proto::account::v1::{
    BootstrapRequest, Device as ProtoDevice, DeviceEnrollment, DeviceId as ProtoDeviceId, Empty,
    GetKeyMaterialResponse, KeyMaterial as ProtoKeyMaterial, ListMyDevicesResponse, LoginRequest,
    LoginResponse, MfaRequired, RegisterDeviceRequest, Session as ProtoSession, VerifyMfaRequest,
    account_server::{Account, AccountServer},
    login_response,
};
use tonic::{Request, Response, Status};

use crate::{PlatformContext, authenticate, internal, parse_uuid};

/// The `Account` gRPC service implementation.
pub struct AccountService {
    ctx: PlatformContext,
}

#[tonic::async_trait]
impl Account for AccountService {
    async fn bootstrap(
        &self,
        request: Request<BootstrapRequest>,
    ) -> Result<Response<ProtoSession>, Status> {
        let req = request.into_inner();
        let email = req.email.trim().to_string();
        let display_name = req.display_name.trim().to_string();
        if email.is_empty() || display_name.is_empty() || req.password.is_empty() {
            return Err(Status::invalid_argument(
                "email, display_name, and password are required",
            ));
        }
        let km = req
            .key_material
            .ok_or_else(|| Status::invalid_argument("key_material is required"))?;
        let dev = req
            .device
            .ok_or_else(|| Status::invalid_argument("device is required"))?;
        validate_device(&dev)?;

        // First-owner gate: refuse once any user exists.
        let count = self
            .ctx
            .users
            .count()
            .await
            .map_err(|err| internal(&err, "bootstrap:count"))?;
        if count > 0 {
            return Err(Status::failed_precondition("an account already exists"));
        }

        let phc =
            auth::hash_password(&req.password).map_err(|err| internal(&err, "bootstrap:hash"))?;

        let mut tx = self
            .ctx
            .pool
            .begin()
            .await
            .map_err(|err| internal(&err, "bootstrap:begin"))?;
        let user = UserRepository::create(
            &mut tx,
            &email,
            &display_name,
            InstanceRole::Owner,
            UserLifecycle::Active,
        )
        .await
        .map_err(|err| internal(&err, "bootstrap:user"))?;
        auth::create_credentials(&mut tx, user.id, &phc)
            .await
            .map_err(|err| internal(&err, "bootstrap:credentials"))?;
        UserKeyRepository::create(&mut tx, user.id, &to_key_material(km))
            .await
            .map_err(|err| internal(&err, "bootstrap:keys"))?;
        let device = enroll_device(&mut tx, &user, dev).await?;
        let actor = actor_of(&user);
        audit::append(
            &mut tx,
            Some(&actor),
            None,
            "owner_bootstrapped",
            serde_json::json!({ "email": user.email, "device_id": device.device_id }),
        )
        .await
        .map_err(|err| internal(&err, "bootstrap:audit"))?;
        let (session, token) =
            auth::SessionRepository::create(&mut tx, user.id, auth::DEFAULT_SESSION_TTL, None, None)
                .await
                .map_err(|err| internal(&err, "bootstrap:session"))?;
        tx.commit()
            .await
            .map_err(|err| internal(&err, "bootstrap:commit"))?;
        Ok(Response::new(ProtoSession {
            token,
            user_id: user.id.to_string(),
            expires_at: session.expires_at.to_rfc3339(),
        }))
    }

    async fn login(
        &self,
        request: Request<LoginRequest>,
    ) -> Result<Response<LoginResponse>, Status> {
        let req = request.into_inner();
        if req.email.trim().is_empty() {
            return Err(Status::invalid_argument("email is required"));
        }
        match auth::verify_credentials(&self.ctx.pool, &req.email, &req.password).await {
            Ok(Ok(user)) => {
                // A second factor present → the Hub can't complete it yet (slice
                // 1); signal mfa_required rather than issuing a session that would
                // bypass it.
                if auth::has_second_factor(&self.ctx.pool, user.id)
                    .await
                    .map_err(|err| internal(&err, "login:mfa"))?
                {
                    return Ok(Response::new(LoginResponse {
                        outcome: Some(login_response::Outcome::MfaRequired(MfaRequired {
                            mfa_challenge_token: String::new(),
                            methods: vec!["totp".to_string()],
                        })),
                    }));
                }
                let session = self.new_session(user.id).await?;
                Ok(Response::new(LoginResponse {
                    outcome: Some(login_response::Outcome::Session(session)),
                }))
            }
            Ok(Err(_)) => Err(Status::unauthenticated("invalid email or password")),
            Err(err) => Err(internal(&err, "login:verify")),
        }
    }

    async fn verify_mfa(
        &self,
        _request: Request<VerifyMfaRequest>,
    ) -> Result<Response<ProtoSession>, Status> {
        Err(Status::unimplemented(
            "MFA verification over the hub is not yet supported",
        ))
    }

    async fn get_key_material(
        &self,
        request: Request<Empty>,
    ) -> Result<Response<GetKeyMaterialResponse>, Status> {
        let user = authenticate(&self.ctx, request.metadata()).await?.user;
        match self.ctx.user_keys.get(user.id).await {
            Ok(Some(km)) => Ok(Response::new(GetKeyMaterialResponse {
                key_material: Some(from_key_material(km)),
            })),
            Ok(None) => Err(Status::failed_precondition(
                "no key material is provisioned for this account",
            )),
            Err(err) => Err(internal(&err, "get_key_material")),
        }
    }

    async fn register_device(
        &self,
        request: Request<RegisterDeviceRequest>,
    ) -> Result<Response<ProtoDevice>, Status> {
        let user = authenticate(&self.ctx, request.metadata()).await?.user;
        let dev = request
            .into_inner()
            .device
            .ok_or_else(|| Status::invalid_argument("device is required"))?;
        validate_device(&dev)?;

        let mut tx = self
            .ctx
            .pool
            .begin()
            .await
            .map_err(|err| internal(&err, "register_device:begin"))?;
        let device = enroll_device(&mut tx, &user, dev).await?;
        let actor = actor_of(&user);
        audit::append(
            &mut tx,
            Some(&actor),
            None,
            "device_registered",
            serde_json::json!({ "device_id": device.device_id, "platform": device.platform }),
        )
        .await
        .map_err(|err| internal(&err, "register_device:audit"))?;
        tx.commit()
            .await
            .map_err(|err| internal(&err, "register_device:commit"))?;
        Ok(Response::new(device))
    }

    async fn list_my_devices(
        &self,
        request: Request<Empty>,
    ) -> Result<Response<ListMyDevicesResponse>, Status> {
        let user = authenticate(&self.ctx, request.metadata()).await?.user;
        match self.ctx.devices.list_for_user(user.id).await {
            Ok(devices) => Ok(Response::new(ListMyDevicesResponse {
                devices: devices.into_iter().map(device_to_proto).collect(),
            })),
            Err(err) => Err(internal(&err, "list_my_devices")),
        }
    }

    async fn revoke_device(
        &self,
        request: Request<ProtoDeviceId>,
    ) -> Result<Response<Empty>, Status> {
        let user = authenticate(&self.ctx, request.metadata()).await?.user;
        let device_id =
            DeviceId::new(parse_uuid(&request.into_inner().device_id, "device_id")?);
        match self.ctx.devices.revoke_owned(device_id, user.id).await {
            Ok(true) => {
                self.audit_device_revoked(&user, device_id).await;
                Ok(Response::new(Empty {}))
            }
            Ok(false) => Err(Status::not_found("device not found")),
            Err(err) => Err(internal(&err, "revoke_device")),
        }
    }
}

impl AccountService {
    /// Mint a session for `user_id` in its own transaction; returns the proto.
    async fn new_session(&self, user_id: UserId) -> Result<ProtoSession, Status> {
        let mut tx = self
            .ctx
            .pool
            .begin()
            .await
            .map_err(|err| internal(&err, "session:begin"))?;
        let (session, token) =
            auth::SessionRepository::create(&mut tx, user_id, auth::DEFAULT_SESSION_TTL, None, None)
                .await
                .map_err(|err| internal(&err, "session:create"))?;
        tx.commit()
            .await
            .map_err(|err| internal(&err, "session:commit"))?;
        Ok(ProtoSession {
            token,
            user_id: user_id.to_string(),
            expires_at: session.expires_at.to_rfc3339(),
        })
    }

    /// Best-effort `device_revoked` audit. The revoke itself is already
    /// committed, so a failed audit is logged, not fatal.
    async fn audit_device_revoked(&self, user: &User, device_id: DeviceId) {
        let actor = actor_of(user);
        let outcome = async {
            let mut tx = self.ctx.pool.begin().await?;
            audit::append(
                &mut tx,
                Some(&actor),
                None,
                "device_revoked",
                serde_json::json!({ "device_id": device_id.to_string() }),
            )
            .await?;
            tx.commit().await?;
            Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
        }
        .await;
        if let Err(err) = outcome {
            tracing::warn!(?err, "device_revoked audit append failed (revoke stands)");
        }
    }
}

/// Build the tonic service wrapper for the `Account` service.
pub fn account_server(ctx: PlatformContext) -> AccountServer<AccountService> {
    AccountServer::new(AccountService { ctx })
}

// ── helpers ──────────────────────────────────────────────────────────────────

fn actor_of(user: &User) -> audit::Actor {
    audit::Actor {
        user_id: user.id,
        display_name: user.display_name.clone(),
    }
}

fn validate_device(dev: &DeviceEnrollment) -> Result<(), Status> {
    if dev.device_label.trim().is_empty()
        || dev.platform.trim().is_empty()
        || dev.device_public_key.is_empty()
    {
        return Err(Status::invalid_argument(
            "device_label, platform, and device_public_key are required",
        ));
    }
    Ok(())
}

/// Create a machine + device enrollment for `user` within the caller's
/// transaction (no audit — the caller appends the appropriate event). Slice 1
/// creates one machine per enrollment; the full machine plane is slice 2.
async fn enroll_device(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user: &User,
    dev: DeviceEnrollment,
) -> Result<ProtoDevice, Status> {
    let machine_label = if dev.machine_label.trim().is_empty() {
        dev.device_label.clone()
    } else {
        dev.machine_label.clone()
    };
    let machine = MachineRepository::create(tx, &machine_label, &dev.platform, Some(user.id))
        .await
        .map_err(|err| internal(&err, "enroll:machine"))?;
    let device = DeviceRepository::register(
        tx,
        &NewDevice {
            user_id: user.id,
            machine_id: Some(machine.id),
            device_label: dev.device_label,
            platform: dev.platform,
            device_public_key: dev.device_public_key,
        },
    )
    .await
    .map_err(|err| internal(&err, "enroll:device"))?;
    Ok(device_to_proto(device))
}

fn device_to_proto(d: Device) -> ProtoDevice {
    ProtoDevice {
        device_id: d.id.to_string(),
        device_label: d.device_label,
        platform: d.platform,
        machine_id: d.machine_id.map(|m| m.to_string()).unwrap_or_default(),
        created_at: d.created_at.to_rfc3339(),
        last_seen_at: d.last_seen_at.map(|t| t.to_rfc3339()).unwrap_or_default(),
        revoked_at: d.revoked_at.map(|t| t.to_rfc3339()).unwrap_or_default(),
    }
}

fn to_key_material(km: ProtoKeyMaterial) -> UserKeyMaterial {
    UserKeyMaterial {
        x25519_public: km.x25519_public,
        ed25519_public: km.ed25519_public,
        x25519_private_wrapped: km.x25519_private_wrapped,
        ed25519_private_wrapped: km.ed25519_private_wrapped,
        master_key_wrapped: km.master_key_wrapped,
        kdf_salt: km.kdf_salt,
        kdf_params: km.kdf_params,
    }
}

fn from_key_material(km: UserKeyMaterial) -> ProtoKeyMaterial {
    ProtoKeyMaterial {
        x25519_public: km.x25519_public,
        ed25519_public: km.ed25519_public,
        x25519_private_wrapped: km.x25519_private_wrapped,
        ed25519_private_wrapped: km.ed25519_private_wrapped,
        master_key_wrapped: km.master_key_wrapped,
        kdf_salt: km.kdf_salt,
        kdf_params: km.kdf_params,
    }
}
