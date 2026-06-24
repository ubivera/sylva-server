//! The `Account` gRPC service — Sylva Hub's identity / device-enrollment plane
//! (see `docs/design/hub.md`). Distinct from Platform/Resources: the Hub is core
//! infrastructure, not a registered app.
//!
//! `Bootstrap` + `Login` are unauthenticated (peer-IP rate-limited via
//! [`crate::PlatformContext::auth_rate_limiter`]); the rest require a session
//! token and are owner-scoped. Auth uses the Argon2id password verifier (over
//! TLS); the master key is wrapped *client-side* under `KDF(password,
//! secret_key)` — the server stores only the ciphertext it is handed.

use identity::{
    Device, DeviceId, DeviceRepository, InstanceRole, MachineRepository, NewDevice, User, UserId,
    UserKeyMaterial, UserKeyRepository, UserLifecycle, UserRepository,
};
use proto::account::v1::{
    BootstrapRequest, ChangePasswordRequest, Device as ProtoDevice, DeviceEnrollment,
    DeviceId as ProtoDeviceId, Empty, GetAvatarResponse, GetKeyMaterialResponse,
    KeyMaterial as ProtoKeyMaterial, ListMyDevicesResponse, LoginRequest, LoginResponse,
    MfaRequired, Profile as ProtoProfile, RegisterDeviceRequest, Session as ProtoSession,
    SetAvatarRequest, UpdateDisplayNameRequest, UpdateEmailRequest, VerifyMfaRequest,
    account_server::{Account, AccountServer},
    login_response,
};
use tonic::{Request, Response, Status};

use crate::{PlatformContext, authenticate, internal, parse_uuid, rate_key};

/// Hard ceiling on the opaque (client-sealed) avatar blob the server will store.
/// The server never sees plaintext, so this is the only avatar policy it enforces.
const MAX_AVATAR_BYTES: usize = 1024 * 1024; // 1 MiB

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
        let client_key = rate_key(&request, self.ctx.trust_proxy);
        if !self.ctx.auth_rate_limiter.allowed(&client_key) {
            return Err(Status::resource_exhausted(
                "too many attempts; try again later",
            ));
        }
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
            self.ctx.auth_rate_limiter.record_failure(&client_key);
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
        let client_key = rate_key(&request, self.ctx.trust_proxy);
        if !self.ctx.auth_rate_limiter.allowed(&client_key) {
            return Err(Status::resource_exhausted(
                "too many attempts; try again later",
            ));
        }
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
            Ok(Err(_)) => {
                self.ctx.auth_rate_limiter.record_failure(&client_key);
                Err(Status::unauthenticated("invalid email or password"))
            }
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

    // ── Account self-service ───────────────────────────────────────────────────

    async fn get_profile(
        &self,
        request: Request<Empty>,
    ) -> Result<Response<ProtoProfile>, Status> {
        let user = authenticate(&self.ctx, request.metadata()).await?.user;
        Ok(Response::new(profile_of(&user)))
    }

    async fn update_display_name(
        &self,
        request: Request<UpdateDisplayNameRequest>,
    ) -> Result<Response<ProtoProfile>, Status> {
        let user = authenticate(&self.ctx, request.metadata()).await?.user;
        let display_name = request.into_inner().display_name.trim().to_string();
        if display_name.is_empty() {
            return Err(Status::invalid_argument("display_name is required"));
        }

        let mut tx = self
            .ctx
            .pool
            .begin()
            .await
            .map_err(|err| internal(&err, "update_display_name:begin"))?;
        let updated = UserRepository::update_profile(&mut tx, user.id, Some(&display_name), None)
            .await
            .map_err(|err| internal(&err, "update_display_name:update"))?;
        let actor = actor_of(&updated);
        audit::append(
            &mut tx,
            Some(&actor),
            None,
            "display_name_changed",
            serde_json::json!({ "display_name": updated.display_name }),
        )
        .await
        .map_err(|err| internal(&err, "update_display_name:audit"))?;
        tx.commit()
            .await
            .map_err(|err| internal(&err, "update_display_name:commit"))?;
        Ok(Response::new(profile_of(&updated)))
    }

    async fn update_email(
        &self,
        request: Request<UpdateEmailRequest>,
    ) -> Result<Response<ProtoProfile>, Status> {
        let user = authenticate(&self.ctx, request.metadata()).await?.user;
        let req = request.into_inner();
        // Re-auth before a sensitive change (mirrors the destructive-action
        // password gate on the members surface).
        if !auth::verify_user_password(&self.ctx.pool, user.id, &req.current_password)
            .await
            .map_err(|err| internal(&err, "update_email:verify"))?
        {
            return Err(Status::unauthenticated("current password is incorrect"));
        }
        let new_email = req.new_email.trim().to_string();
        if new_email.is_empty() {
            return Err(Status::invalid_argument("new_email is required"));
        }

        let mut tx = self
            .ctx
            .pool
            .begin()
            .await
            .map_err(|err| internal(&err, "update_email:begin"))?;
        let updated = match UserRepository::update_email(&mut tx, user.id, &new_email).await {
            Ok(user) => user,
            // The `email_lower` unique index rejects an address already in use.
            Err(identity::IdentityError::Database(sqlx::Error::Database(dbe)))
                if dbe.code().as_deref() == Some("23505") =>
            {
                return Err(Status::already_exists("that email address is already in use"));
            }
            Err(err) => return Err(internal(&err, "update_email:update")),
        };
        let actor = actor_of(&updated);
        audit::append(
            &mut tx,
            Some(&actor),
            None,
            "email_changed",
            serde_json::json!({ "email": updated.email }),
        )
        .await
        .map_err(|err| internal(&err, "update_email:audit"))?;
        tx.commit()
            .await
            .map_err(|err| internal(&err, "update_email:commit"))?;
        Ok(Response::new(profile_of(&updated)))
    }

    async fn change_password(
        &self,
        request: Request<ChangePasswordRequest>,
    ) -> Result<Response<Empty>, Status> {
        let user = authenticate(&self.ctx, request.metadata()).await?.user;
        let req = request.into_inner();
        if !auth::verify_user_password(&self.ctx.pool, user.id, &req.current_password)
            .await
            .map_err(|err| internal(&err, "change_password:verify"))?
        {
            return Err(Status::unauthenticated("current password is incorrect"));
        }
        if req.new_password.is_empty() {
            return Err(Status::invalid_argument("new_password is required"));
        }

        let new_phc = auth::hash_password(&req.new_password)
            .map_err(|err| internal(&err, "change_password:hash"))?;

        let mut tx = self
            .ctx
            .pool
            .begin()
            .await
            .map_err(|err| internal(&err, "change_password:begin"))?;
        // Server-side verifier (recomputed) + the client's 2SKD re-wrap of the
        // master key go together: a return needs only the new password.
        auth::update_password_hash(&mut tx, user.id, &new_phc)
            .await
            .map_err(|err| internal(&err, "change_password:credentials"))?;
        UserKeyRepository::update(
            &mut tx,
            user.id,
            &req.new_master_key_wrapped,
            &req.new_kdf_salt,
            &req.new_kdf_params,
        )
        .await
        .map_err(|err| internal(&err, "change_password:keys"))?;
        let actor = actor_of(&user);
        audit::append(
            &mut tx,
            Some(&actor),
            None,
            "password_changed",
            serde_json::json!({}),
        )
        .await
        .map_err(|err| internal(&err, "change_password:audit"))?;
        tx.commit()
            .await
            .map_err(|err| internal(&err, "change_password:commit"))?;
        // Deferred hardening: other live sessions are NOT revoked here — a
        // password change should eventually invalidate sibling sessions.
        Ok(Response::new(Empty {}))
    }

    // ── Avatar (E2E; opaque to the server) ─────────────────────────────────────

    async fn get_avatar(
        &self,
        request: Request<Empty>,
    ) -> Result<Response<GetAvatarResponse>, Status> {
        let user = authenticate(&self.ctx, request.metadata()).await?.user;
        match self.ctx.user_avatars.get(user.id).await {
            // No avatar set → empty bytes (the contract's "unset" signal).
            Ok(avatar) => Ok(Response::new(GetAvatarResponse {
                avatar: avatar.unwrap_or_default(),
            })),
            Err(err) => Err(internal(&err, "get_avatar")),
        }
    }

    async fn set_avatar(
        &self,
        request: Request<SetAvatarRequest>,
    ) -> Result<Response<Empty>, Status> {
        let user = authenticate(&self.ctx, request.metadata()).await?.user;
        let req = request.into_inner();
        if req.avatar.len() > MAX_AVATAR_BYTES {
            return Err(Status::invalid_argument("avatar too large"));
        }
        match self.ctx.user_avatars.upsert(user.id, &req.avatar).await {
            Ok(()) => Ok(Response::new(Empty {})),
            Err(err) => Err(internal(&err, "set_avatar")),
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

/// Map an `identity::User` to the wire `Profile`. The role token is spelled out
/// explicitly so the contract doesn't ride on serde's `InstanceRole` encoding
/// (mirrors `Platform::who_am_i`).
fn profile_of(user: &User) -> ProtoProfile {
    let instance_role = match user.instance_role {
        InstanceRole::Owner => "owner",
        InstanceRole::Admin => "admin",
        InstanceRole::Member => "member",
    };
    ProtoProfile {
        user_id: user.id.to_string(),
        email: user.email.clone(),
        display_name: user.display_name.clone(),
        instance_role: instance_role.to_string(),
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
