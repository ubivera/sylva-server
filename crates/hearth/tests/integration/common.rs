use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use audit::Actor;
use auth::SessionRepository;
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Method, Request, StatusCode, header::AUTHORIZATION},
};
use chrono::{DateTime, Utc};
use hearth::{app, db, postgres::PostgresProcess};
use identity::{InstanceRole, InvitationRepository, UserId, UserRepository};
use serde::de::DeserializeOwned;
use serde_json::Value;
use sqlx::{Connection, Executor, PgConnection, PgPool};
use tokio::sync::OnceCell;
use tower::ServiceExt;
use uuid::Uuid;

/// Postgres port used by the test harness. Matches production on purpose —
/// tests refuse to run while `hearth` (which would already be bound to this
/// port) is up.
const TEST_PG_PORT: u16 = 15432;

/// Superuser baked into the bundled cluster by `bootstrap`.
const SUPERUSER: &str = "hearth";

struct SharedPg {
    port: u16,
}

static SHARED_PG: OnceCell<SharedPg> = OnceCell::const_new();

/// True once we've installed the Windows JobObject for child cleanup.
static JOB_OBJECT_INSTALLED: AtomicBool = AtomicBool::new(false);

async fn shared_pg() -> &'static SharedPg {
    SHARED_PG.get_or_init(init_shared_postgres).await
}

async fn init_shared_postgres() -> SharedPg {
    install_job_object();

    let workspace = workspace_root();
    let pg_bin = workspace.join("data").join("postgres");
    let pg_data = workspace.join("data").join("postgres-data");

    let pg = PostgresProcess::start(pg_bin, pg_data, TEST_PG_PORT)
        .await
        .expect(
            "starting bundled postgres for tests \
             (is `cargo run --bin hearth` already running? \
             stop it before running tests)",
        );
    // Leak so the tokio::process::Child's `kill_on_drop(true)` doesn't fire
    // when this future is dropped. The OS process is reaped by the JobObject
    // when the test binary exits.
    std::mem::forget(pg);

    // hearth's PostgresProcess::start only waits for the TCP listener; the
    // SQL layer may still be in recovery. Block on the shared db helper
    // (same logic prod uses) so subsequent tests never race against
    // startup-not-ready errors.
    hearth::db::wait_until_ready(&format!(
        "postgresql://{SUPERUSER}@127.0.0.1:{TEST_PG_PORT}/postgres"
    ))
    .await
    .expect("postgres never became SQL-ready for tests");

    // Clear orphan test databases from prior runs via a single connection
    // (NOT a pool) — sqlx pools are bound to the tokio runtime that created
    // them, and our tests each spin up a fresh runtime. A bare PgConnection
    // has cleaner drop semantics.
    let mut conn = maint_conn(TEST_PG_PORT).await;
    drop_orphan_test_dbs(&mut conn).await;
    let _ = conn.close().await;

    SharedPg {
        port: TEST_PG_PORT,
    }
}

/// Open a single connection to the `postgres` maintenance database.
///
/// Retries on Postgres `57P03` ("the database system is starting up") for up
/// to 30 seconds — hearth's `PostgresProcess::start` waits only for the TCP
/// listener, which races against the SQL layer becoming usable. Callers
/// should `close()` the returned connection explicitly when done.
async fn maint_conn(port: u16) -> PgConnection {
    let url = format!("postgresql://{SUPERUSER}@127.0.0.1:{port}/postgres");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let mut delay = std::time::Duration::from_millis(100);
    loop {
        match PgConnection::connect(&url).await {
            Ok(c) => return c,
            Err(err) => {
                // Postgres serves up several startup-related fatal errors under
                // SQLSTATE class 57 ("Operator Intervention"). The TCP listener
                // comes up before the SQL layer is ready, so racing here is
                // normal; retry until the cluster settles.
                let transient = matches!(
                    &err,
                    sqlx::Error::Database(dbe)
                        if dbe.code().as_deref().is_some_and(|c| c.starts_with("57"))
                );
                if transient && std::time::Instant::now() < deadline {
                    tokio::time::sleep(delay).await;
                    delay = (delay * 2).min(std::time::Duration::from_millis(500));
                    continue;
                }
                panic!("connecting to maintenance db: {err:?}");
            }
        }
    }
}

fn install_job_object() {
    #[cfg(windows)]
    {
        if JOB_OBJECT_INSTALLED.swap(true, Ordering::SeqCst) {
            return;
        }
        match hearth::job_object::JobObject::assign_current_process_for_kill_on_close() {
            Ok(job) => {
                std::mem::forget(job);
            }
            Err(err) => {
                // Tests still work without the JobObject; we just risk
                // leaking postgres workers if the test binary is killed.
                eprintln!("warning: could not install JobObject for tests: {err:#}");
            }
        }
    }
    #[cfg(not(windows))]
    {
        let _ = JOB_OBJECT_INSTALLED.swap(true, Ordering::SeqCst);
    }
}

/// Drop any `hearth_test_*` databases left over from a previous test run.
/// Best-effort: we ignore errors so a transient hiccup here doesn't mask the
/// real failure that comes later.
async fn drop_orphan_test_dbs(conn: &mut PgConnection) {
    let names: Vec<String> = sqlx::query_scalar(
        "SELECT datname::text FROM pg_database WHERE datname LIKE 'hearth\\_test\\_%' ESCAPE '\\'",
    )
    .fetch_all(&mut *conn)
    .await
    .unwrap_or_default();

    for name in names {
        let safe_name = name.replace('"', "\"\"");
        let _ = sqlx::query(
            "SELECT pg_terminate_backend(pid) \
             FROM pg_stat_activity \
             WHERE datname = $1 AND pid <> pg_backend_pid()",
        )
        .bind(&name)
        .execute(&mut *conn)
        .await;
        let _ = conn
            .execute(format!("DROP DATABASE IF EXISTS \"{safe_name}\"").as_str())
            .await;
    }
}

fn workspace_root() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .and_then(std::path::Path::parent)
        .expect("CARGO_MANIFEST_DIR has two parents (crates/hearth)")
        .to_path_buf()
}

/// One end-to-end fixture: a fresh database, all migrations applied, and a
/// fully wired `Router` ready to receive requests via `oneshot`.
pub struct TestApp {
    pub router: Router,
    pub pool: PgPool,
    /// Test-side notification worker. Defaults to [`notifications::NotifierImpl::Log`]
    /// — tests that need to observe failure paths swap it via
    /// [`TestApp::set_notifier`].
    pub notification_worker: std::sync::Mutex<notifications::Worker>,
    /// The CSRF secret used by this app's `AppState`. Held here so tests
    /// can compute valid tokens via [`TestApp::csrf_for`] without scraping
    /// rendered HTML.
    csrf_secret: std::sync::Arc<[u8; hearth::csrf::SECRET_LEN]>,
    #[allow(dead_code)] // retained so a future Drop impl can clean up the DB
    db_name: String,
}

impl TestApp {
    pub async fn new() -> Self {
        let shared = shared_pg().await;
        let db_name = format!("hearth_test_{}", Uuid::new_v4().simple());

        let mut mc = maint_conn(shared.port).await;
        mc.execute(format!("CREATE DATABASE \"{db_name}\"").as_str())
            .await
            .expect("creating test db");
        let _ = mc.close().await;

        // Production's bootstrap step creates the `hearth_meta` schema before
        // any migration runs (sqlx's `_sqlx_migrations` lands there). Mirror
        // that here so the migrator behaves identically to a real install.
        let setup_url = format!(
            "postgresql://{SUPERUSER}@127.0.0.1:{}/{}",
            shared.port, db_name
        );
        let setup_pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&setup_url)
            .await
            .expect("connecting to test db for setup");
        sqlx::query("CREATE SCHEMA IF NOT EXISTS hearth_meta")
            .execute(&setup_pool)
            .await
            .expect("creating hearth_meta schema");
        setup_pool.close().await;

        // Use a small pool so highly-parallel tests don't blow past the
        // bundled cluster's `max_connections`. Production hearth uses 20
        // connections per pool; tests cap at 4.
        let opts: sqlx::postgres::PgConnectOptions = setup_url
            .parse::<sqlx::postgres::PgConnectOptions>()
            .expect("parse setup_url")
            .options([("search_path", "hearth_meta,public")]);
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .acquire_timeout(std::time::Duration::from_secs(15))
            .connect_with(opts)
            .await
            .expect("connecting test pool with search_path pinned");
        db::run_migrations(&pool)
            .await
            .expect("running migrations against fresh test db");

        let users = UserRepository::new(pool.clone());
        let sessions = SessionRepository::new(pool.clone());
        let invitations = InvitationRepository::new(pool.clone());

        // Compose the same shape as production: API under `/api`, the web
        // UI at root, plus `/health`. Mirrors the composition in
        // `hearth::serve` and `web::ui_router`.
        let csrf_secret = std::sync::Arc::new(hearth::csrf::generate_secret());
        let app_state = app::AppState {
            started_at: Instant::now(),
            db: pool.clone(),
            users,
            sessions,
            invitations,
            public_base_url: "http://127.0.0.1:8443".to_string(),
            instance_name: "test-instance".to_string(),
            csrf_secret: csrf_secret.clone(),
        };
        let health = axum::Router::new()
            .route(
                "/health",
                axum::routing::get(hearth::health::handler),
            )
            .with_state(app_state.clone());
        let router = Router::new()
            .nest("/api", app::api_router(app_state.clone()))
            .merge(web::ui_router(app_state))
            .merge(health);

        let worker =
            notifications::Worker::new(pool.clone(), notifications::NotifierImpl::Log);

        TestApp {
            router,
            pool,
            notification_worker: std::sync::Mutex::new(worker),
            csrf_secret,
            db_name,
        }
    }

    /// Compute a CSRF token valid for the given session id. Use this to
    /// build `csrf_token` form values when posting to web endpoints from
    /// tests; equivalent to scraping the value out of a rendered form.
    pub fn csrf_for(&self, session_id: Uuid) -> String {
        hearth::csrf::compute_token(&self.csrf_secret, session_id)
    }

    /// Look up the `auth.sessions.id` for a session whose token lives in
    /// the given `hearth_session=<token>` cookie pair. The web login
    /// helper returns the full `Set-Cookie` header; trim it down to just
    /// `hearth_session=<token>` (e.g. via `cookie_name_value`) before
    /// passing in.
    pub async fn session_id_for_cookie(&self, cookie_value: &str) -> Uuid {
        let token = cookie_value
            .strip_prefix("hearth_session=")
            .expect("cookie value must start with hearth_session=");
        let token_hash = auth::hash_token(token);
        sqlx::query_scalar("SELECT id FROM auth.sessions WHERE token_hash = $1")
            .bind(&token_hash[..])
            .fetch_one(&self.pool)
            .await
            .expect("looking up session by token hash")
    }

    /// Replace the notification worker's notifier (e.g. with
    /// `NotifierImpl::AlwaysFail` to drive the retry/dead path). Returns
    /// nothing; callers that need to flip back to log mode build a fresh
    /// worker with `notifications::NotifierImpl::Log`.
    pub fn set_notifier(&self, notifier: notifications::NotifierImpl) {
        let mut guard = self.notification_worker.lock().expect("worker mutex poisoned");
        *guard = notifications::Worker::new(self.pool.clone(), notifier);
    }

    /// Run a single drain cycle of the notification worker. Returns the
    /// number of rows processed.
    pub async fn run_notifications_once(&self) -> usize {
        // Clone the worker out so we don't hold the mutex across the await.
        let worker = self
            .notification_worker
            .lock()
            .expect("worker mutex poisoned")
            .clone();
        worker
            .process_pending()
            .await
            .expect("notification worker cycle failed")
    }

    /// Run a single cycle of the pending-transitions worker. Tests use this
    /// instead of waiting for the real 30-second poll interval.
    pub async fn run_pending_transitions_once(&self) -> usize {
        let worker = pending::Worker::new(self.pool.clone());
        worker
            .process_due()
            .await
            .expect("pending-transitions worker cycle failed")
    }

    /// Bootstrap a recovery code as if `provision` had run. Returns the
    /// raw code so the test can use it for bypass attempts.
    pub async fn seed_recovery_code(&self) -> String {
        let raw = auth::recovery_code::generate_code();
        let mut tx = self.pool.begin().await.expect("begin");
        auth::recovery_code::bootstrap(&mut tx, &raw, None)
            .await
            .expect("bootstrap recovery code");
        tx.commit().await.expect("commit");
        raw
    }

    /// Seed a user with the given role + an `active` lifecycle and a real
    /// Argon2id password hash. Emits a minimal audit event so the chain
    /// never starts from genesis when seeded data exists (matches what
    /// `provision` does in production).
    pub async fn seed_user(
        &self,
        email: &str,
        display_name: &str,
        password: &str,
        role: InstanceRole,
    ) -> SeededUser {
        let password_hash = auth::hash_password(password).expect("hashing seed password");
        let mut tx = self.pool.begin().await.expect("begin tx");
        let user_id: Uuid = sqlx::query_scalar(
            "INSERT INTO identity.users (email, display_name, lifecycle, instance_role)
             VALUES ($1, $2, 'active', $3)
             RETURNING id",
        )
        .bind(email)
        .bind(display_name)
        .bind(role)
        .fetch_one(&mut *tx)
        .await
        .expect("inserting seed user");

        sqlx::query("INSERT INTO auth.credentials (user_id, password_hash) VALUES ($1, $2)")
            .bind(user_id)
            .bind(&password_hash)
            .execute(&mut *tx)
            .await
            .expect("inserting credentials");

        let actor = Actor {
            user_id: UserId::new(user_id),
            display_name: display_name.to_string(),
        };
        audit::append(
            &mut tx,
            Some(&actor),
            None,
            "test_seed_user",
            serde_json::json!({ "email": email, "instance_role": role }),
        )
        .await
        .expect("audit append");

        tx.commit().await.expect("commit seed");

        SeededUser {
            id: UserId::new(user_id),
            email: email.to_string(),
            display_name: display_name.to_string(),
            password: password.to_string(),
            role,
        }
    }

    /// Hit `/api/auth/login` and return the bearer token. Panics on non-200.
    pub async fn login(&self, email: &str, password: &str) -> String {
        let resp = self
            .post(
                "/api/auth/login",
                None,
                Some(serde_json::json!({ "email": email, "password": password })),
            )
            .await;
        if resp.status != StatusCode::OK {
            panic!(
                "login({email}) failed: status={} body={}",
                resp.status,
                resp.body_as_text()
            );
        }
        resp.json::<LoginBody>().token
    }

    pub async fn get(&self, path: &str, token: Option<&str>) -> ApiResponse {
        self.request(Method::GET, path, token, None).await
    }

    pub async fn post(
        &self,
        path: &str,
        token: Option<&str>,
        body: Option<Value>,
    ) -> ApiResponse {
        self.request(Method::POST, path, token, body).await
    }

    pub async fn patch(
        &self,
        path: &str,
        token: Option<&str>,
        body: Option<Value>,
    ) -> ApiResponse {
        self.request(Method::PATCH, path, token, body).await
    }

    pub async fn request(
        &self,
        method: Method,
        path: &str,
        token: Option<&str>,
        body: Option<Value>,
    ) -> ApiResponse {
        let mut builder = Request::builder().method(method).uri(path);
        if let Some(t) = token {
            builder = builder.header(AUTHORIZATION, format!("Bearer {t}"));
        }
        let req = match body {
            Some(v) => builder
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&v).expect("serialize body")))
                .expect("building request with body"),
            None => builder
                .body(Body::empty())
                .expect("building request without body"),
        };

        let resp = self
            .router
            .clone()
            .oneshot(req)
            .await
            .expect("oneshot failed");
        let status = resp.status();
        let bytes = to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("reading response body");
        ApiResponse {
            status,
            body: bytes.to_vec(),
        }
    }
}

pub struct SeededUser {
    pub id: UserId,
    pub email: String,
    #[allow(dead_code)]
    pub display_name: String,
    pub password: String,
    #[allow(dead_code)]
    pub role: InstanceRole,
}

pub struct ApiResponse {
    pub status: StatusCode,
    pub body: Vec<u8>,
}

impl ApiResponse {
    pub fn json<T: DeserializeOwned>(&self) -> T {
        serde_json::from_slice(&self.body).unwrap_or_else(|e| {
            panic!(
                "json decode failed: {e}\nstatus: {}\nraw body: {}",
                self.status,
                self.body_as_text(),
            )
        })
    }

    pub fn body_as_text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    pub fn error_code(&self) -> String {
        let v: Value = serde_json::from_slice(&self.body).unwrap_or(Value::Null);
        v.get("error")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string()
    }

    pub fn assert_status(&self, expected: StatusCode) -> &Self {
        if self.status != expected {
            panic!(
                "expected status {expected}, got {} - body: {}",
                self.status,
                self.body_as_text()
            );
        }
        self
    }

    pub fn assert_error(&self, expected_code: &str) -> &Self {
        let got = self.error_code();
        if got != expected_code {
            panic!(
                "expected error code {expected_code:?}, got {got:?} \
                 - status {}, body: {}",
                self.status,
                self.body_as_text()
            );
        }
        self
    }
}

#[derive(serde::Deserialize)]
pub struct LoginBody {
    pub token: String,
    #[allow(dead_code)]
    pub expires_at: DateTime<Utc>,
    pub user_id: Uuid,
}

/// Response body for `POST /api/auth/accept-invite`. Mirrors
/// `LoginBody` plus the one-time `recovery_code` plaintext stamped
/// into `auth.user_recovery_codes` inside the same transaction. Used
/// by tests that need to assert the code's existence + verify it
/// round-trips through `auth::recovery_code::hash_code`.
#[derive(serde::Deserialize)]
pub struct AcceptInviteBody {
    #[allow(dead_code)]
    pub token: String,
    #[allow(dead_code)]
    pub expires_at: DateTime<Utc>,
    pub user_id: Uuid,
    pub recovery_code: String,
}
