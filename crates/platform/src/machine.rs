//! The `Machine` gRPC service — Sylva's machine / management plane (slice 2; see
//! `docs/design/agent.md`). The always-on agent's API, distinct from the
//! user/identity `Account` service: it authenticates a *machine* (not a user) by
//! a machine session token, and the server is zero-knowledge — telemetry it
//! relays is end-to-end encrypted (CP3). The spine (this checkpoint) handles only
//! machine identity, liveness, and the keep-alive push channel.
//!
//! `RegisterMachine` is unauthenticated (peer-IP rate-limited) and proves the
//! machine holds its identity key via an Ed25519 self-signature; the rest carry
//! the issued machine session token in `authorization: Bearer <token>`.

use std::pin::Pin;
use std::time::Duration as StdDuration;

use identity::{
    DeviceAdminGroupRepository, MachineId, MachineRepository, MachineSessionRepository,
    MachineTelemetryRepository, NewTelemetry,
};
use proto::machine::v1::{
    CheckInRequest, Empty, MachineConfig, MachineSession as ProtoMachineSession,
    RegisterMachineRequest, ReportTelemetryRequest, ServerPush,
    machine_server::{Machine, MachineServer},
    server_push,
};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

use crate::{PlatformContext, internal, rate_key};

/// How often the keep-alive stream emits when otherwise idle.
const KEEP_ALIVE_INTERVAL: StdDuration = StdDuration::from_secs(30);

/// The `Machine` gRPC service implementation.
pub struct MachineService {
    ctx: PlatformContext,
    machines: MachineRepository,
    sessions: MachineSessionRepository,
    telemetry: MachineTelemetryRepository,
    groups: DeviceAdminGroupRepository,
}

#[tonic::async_trait]
impl Machine for MachineService {
    async fn register_machine(
        &self,
        request: Request<RegisterMachineRequest>,
    ) -> Result<Response<ProtoMachineSession>, Status> {
        let client_key = rate_key(&request, self.ctx.trust_proxy);
        if !self.ctx.auth_rate_limiter.allowed(&client_key) {
            return Err(Status::resource_exhausted(
                "too many attempts; try again later",
            ));
        }
        let req = request.into_inner();
        if req.platform.trim().is_empty() || req.label.trim().is_empty() {
            return Err(Status::invalid_argument("platform and label are required"));
        }
        if !verify_pop(
            &req.machine_identity_public,
            &req.platform,
            &req.label,
            &req.signature,
        ) {
            self.ctx.auth_rate_limiter.record_failure(&client_key);
            return Err(Status::permission_denied("invalid machine identity signature"));
        }

        let mut tx = self
            .ctx
            .pool
            .begin()
            .await
            .map_err(|err| internal(&err, "register_machine:begin"))?;
        let machine_id = MachineRepository::register_or_update(
            &mut tx,
            &req.machine_identity_public,
            req.platform.trim(),
            req.label.trim(),
        )
        .await
        .map_err(|err| internal(&err, "register_machine:upsert"))?;
        let (session, token) =
            MachineSessionRepository::create(&mut tx, machine_id, auth::DEFAULT_SESSION_TTL)
                .await
                .map_err(|err| internal(&err, "register_machine:session"))?;
        // System event — no user actor (machine registration is server↔agent).
        audit::append(
            &mut tx,
            None,
            None,
            "machine_registered",
            serde_json::json!({ "machine_id": machine_id.to_string(), "platform": req.platform }),
        )
        .await
        .map_err(|err| internal(&err, "register_machine:audit"))?;
        tx.commit()
            .await
            .map_err(|err| internal(&err, "register_machine:commit"))?;

        Ok(Response::new(ProtoMachineSession {
            machine_id: machine_id.to_string(),
            token,
            expires_at: session.expires_at.to_rfc3339(),
        }))
    }

    async fn check_in(&self, request: Request<CheckInRequest>) -> Result<Response<Empty>, Status> {
        let machine_id = self.authenticate_machine(request.metadata()).await?;
        let req = request.into_inner();
        self.machines
            .touch_checkin(machine_id, req.agent_version.trim())
            .await
            .map_err(|err| internal(&err, "check_in"))?;
        Ok(Response::new(Empty {}))
    }

    async fn report_telemetry(
        &self,
        request: Request<ReportTelemetryRequest>,
    ) -> Result<Response<Empty>, Status> {
        let machine_id = self.authenticate_machine(request.metadata()).await?;
        let blobs: Vec<NewTelemetry> = request
            .into_inner()
            .blobs
            .into_iter()
            .map(|b| NewTelemetry {
                kind: b.kind,
                recipient_key_id: b.recipient_key_id,
                seq: i64::try_from(b.seq).unwrap_or(i64::MAX),
                ciphertext: b.ciphertext,
                signature: b.signature,
            })
            .collect();
        if blobs.is_empty() {
            return Ok(Response::new(Empty {}));
        }
        self.telemetry
            .insert(machine_id, &blobs)
            .await
            .map_err(|err| internal(&err, "report_telemetry"))?;
        Ok(Response::new(Empty {}))
    }

    type SubscribeStream =
        Pin<Box<dyn tokio_stream::Stream<Item = Result<ServerPush, Status>> + Send>>;

    async fn subscribe(
        &self,
        request: Request<Empty>,
    ) -> Result<Response<Self::SubscribeStream>, Status> {
        let machine_id = self.authenticate_machine(request.metadata()).await?;

        // Effective config at subscribe-time: the per-machine location toggle + the
        // active device-admin group key (what the agent seals telemetry to).
        // ponytail: pushed once on subscribe — a toggle change reaches the agent on
        // its next reconnect; live re-push on change is a CP4 refinement.
        let location_enabled = self
            .machines
            .location_enabled(machine_id)
            .await
            .map_err(|err| internal(&err, "subscribe:location_enabled"))?;
        let group = self
            .groups
            .active()
            .await
            .map_err(|err| internal(&err, "subscribe:group"))?;
        let (device_admin_group_public, group_key_id) = match group {
            Some(g) => (g.public, g.id.as_bytes().to_vec()),
            None => (Vec::new(), Vec::new()),
        };

        // ponytail: the spine delivery channel is a timer — an initial config
        // push then periodic keep-alives. Real server-driven command push (tied
        // to admin actions) lands in CP4.
        let (tx, rx) = tokio::sync::mpsc::channel(8);
        tokio::spawn(async move {
            let config = ServerPush {
                payload: Some(server_push::Payload::Config(MachineConfig {
                    location_enabled,
                    device_admin_group_public,
                    group_key_id,
                })),
            };
            if tx.send(Ok(config)).await.is_err() {
                return;
            }
            let mut ticker = tokio::time::interval(KEEP_ALIVE_INTERVAL);
            ticker.tick().await; // consume the immediate first tick
            loop {
                ticker.tick().await;
                let keep_alive = ServerPush {
                    payload: Some(server_push::Payload::KeepAlive(Empty {})),
                };
                if tx.send(Ok(keep_alive)).await.is_err() {
                    break; // client disconnected
                }
            }
        });
        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }
}

impl MachineService {
    /// Resolve `authorization: Bearer <token>` into the calling machine's id via
    /// its session token. Coarse `unauthenticated` on any failure (specifics to
    /// `tracing`).
    async fn authenticate_machine(
        &self,
        metadata: &tonic::metadata::MetadataMap,
    ) -> Result<MachineId, Status> {
        let token = metadata
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .ok_or_else(|| Status::unauthenticated("invalid_authorization"))?;
        let session = self
            .sessions
            .find_active(token)
            .await
            .map_err(|err| {
                tracing::error!(?err, "grpc machine auth: session lookup failed");
                Status::unauthenticated("invalid_session")
            })?
            .ok_or_else(|| Status::unauthenticated("invalid_session"))?;
        Ok(session.machine_id)
    }
}

/// Build the tonic service wrapper for the `Machine` service.
pub fn machine_server(ctx: PlatformContext) -> MachineServer<MachineService> {
    let machines = MachineRepository::new(ctx.pool.clone());
    let sessions = MachineSessionRepository::new(ctx.pool.clone());
    let telemetry = MachineTelemetryRepository::new(ctx.pool.clone());
    let groups = DeviceAdminGroupRepository::new(ctx.pool.clone());
    MachineServer::new(MachineService {
        ctx,
        machines,
        sessions,
        telemetry,
        groups,
    })
}

// ── proof-of-possession ────────────────────────────────────────────────────

/// The bytes a machine signs at registration to prove it holds the private key
/// for `public`. Domain-separated; the agent must build it identically.
fn canonical_machine_bytes(public: &[u8], platform: &str, label: &str) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(b"sylva-machine-registration:v1\n");
    v.extend_from_slice(public);
    v.push(b'\n');
    v.extend_from_slice(platform.as_bytes());
    v.push(b'\n');
    v.extend_from_slice(label.as_bytes());
    v
}

/// Verify the machine's Ed25519 self-signature (proof of possession). False on
/// any malformed key/signature or mismatch — never panics.
fn verify_pop(public: &[u8], platform: &str, label: &str, signature: &[u8]) -> bool {
    let Ok(vk_bytes): Result<[u8; 32], _> = public.try_into() else {
        return false;
    };
    let Ok(verifying_key) = ed25519_dalek::VerifyingKey::from_bytes(&vk_bytes) else {
        return false;
    };
    let Ok(sig_bytes): Result<[u8; 64], _> = signature.try_into() else {
        return false;
    };
    let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    verifying_key
        .verify_strict(&canonical_machine_bytes(public, platform, label), &signature)
        .is_ok()
}
