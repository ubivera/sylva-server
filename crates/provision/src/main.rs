#![allow(clippy::print_stderr)]
#![allow(clippy::print_stdout)]

//! `provision` — one-time instance **infrastructure** init.
//!
//! Since the Sylva Hub pivot the first **Owner** is created by the Hub
//! (`Account.Bootstrap`), which carries the client-generated end-to-end crypto
//! the server only ever stores as ciphertext. `provision` no longer creates a
//! user; it initializes the infra that should exist before the first sign-in:
//! migrations, the server identity keypair, and the break-glass server recovery
//! code.

use std::fs;
use std::path::Path;
use std::process::{Command, ExitCode};

use anyhow::{Context, Result, bail};
use hearth::{config::Config, db, instance, postgres::PostgresProcess};

#[tokio::main]
async fn main() -> ExitCode {
    init_tracing();

    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("provision: error: {err:#}");
            ExitCode::from(1)
        }
    }
}

async fn run() -> Result<()> {
    if std::env::args().skip(1).any(|a| a == "--help" || a == "-h") {
        print_help();
        return Ok(());
    }

    let config = Config::from_env()?;
    eprintln!("provision: workspace data dir = {}", config.data_dir.display());

    refuse_if_postgres_running(&config)?;

    let postgres = PostgresProcess::start(
        config.pg_bin_dir(),
        config.pg_data_dir(),
        config.postgres_port(),
    )
    .await
    .context("starting bundled postgres")?;

    let result = init_infrastructure(&config).await;

    if let Err(err) = postgres.stop().await {
        tracing::warn!(?err, "error stopping postgres");
    }

    result?;

    eprintln!();
    eprintln!("Infrastructure initialized (migrations + server identity + recovery code).");
    eprintln!("Create the first Owner from Sylva Hub — it calls Account.Bootstrap with");
    eprintln!("client-generated keys. Then run `cargo run --bin hearth` to start the server.");
    Ok(())
}

/// Infra-only bootstrap: migrations, the server identity keypair, and the
/// break-glass server recovery code. No Owner is created here.
async fn init_infrastructure(config: &Config) -> Result<()> {
    let pool = db::connect(&config.postgres_url).await?;
    db::run_migrations(&pool).await?;
    tracing::info!("migrations up to date");

    // The recovery code is what `provision` uniquely creates, so its presence
    // is our "already initialized" guard — re-running is refused.
    let (codes,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM auth.recovery_codes")
        .fetch_one(&pool)
        .await
        .context("counting existing recovery codes")?;
    if codes > 0 {
        pool.close().await;
        bail!(
            "instance infrastructure is already initialized ({codes} recovery code(s) present).\n\
             Rotate the server recovery code via POST /admin/server/recovery-code/rotate,\n\
             or run `cargo run --bin clean` to start over."
        );
    }

    // Server identity keypair (idempotent — serve() would otherwise generate it
    // on first start). Sealed with the instance secret key.
    let secret_key = config.load_secret_key()?;
    instance::ensure_server_identity(&pool, &secret_key)
        .await
        .context("generating server identity key")?;
    tracing::info!("server identity key ready");

    // Break-glass server recovery code — the Owner-on-Owner veto bypass. Minted
    // as a system event (no owner exists yet); the first Owner inherits it and
    // can rotate it later. See docs/dev/hearth-owner-protection.md.
    let recovery_code = auth::recovery_code::generate_code();
    let mut tx = pool.begin().await?;
    let code_id = auth::recovery_code::bootstrap(&mut tx, &recovery_code, None)
        .await
        .context("bootstrapping recovery code")?;
    audit::append(
        &mut tx,
        None,
        None,
        "recovery_code_generated",
        serde_json::json!({ "code_id": code_id, "by": "provision" }),
    )
    .await
    .context("emitting recovery_code_generated audit event")?;
    tx.commit().await.context("committing transaction")?;
    pool.close().await;

    eprintln!();
    eprintln!("====================================================================");
    eprintln!("  SERVER RECOVERY CODE  (SAVE THIS NOW — IT WILL NOT BE SHOWN AGAIN)");
    eprintln!("====================================================================");
    eprintln!("  {recovery_code}");
    eprintln!("====================================================================");
    eprintln!("  Break-glass credential: bypasses the Owner-on-Owner veto window for");
    eprintln!("  emergency cleanup. Store it offline (password manager / paper safe).");
    eprintln!("  Rotate later via POST /admin/server/recovery-code/rotate.");
    eprintln!("====================================================================");
    Ok(())
}

fn refuse_if_postgres_running(config: &Config) -> Result<()> {
    let pid_file = config.pg_data_dir().join("postmaster.pid");
    if !pid_file.exists() {
        return Ok(());
    }
    match read_postmaster_pid(&pid_file) {
        Some(pid) if pid_is_running(pid) => {
            bail!(
                "Postgres is already running (PID {pid}; lock file {}).\n\
                 Stop hearth first (Ctrl+C in the server window).",
                pid_file.display()
            );
        }
        Some(pid) => {
            eprintln!(
                "provision: stale lock file from PID {pid} (not running); removing and proceeding."
            );
            fs::remove_file(&pid_file)
                .with_context(|| format!("removing stale lock {}", pid_file.display()))?;
        }
        None => {
            eprintln!("provision: lock file present but unparseable; removing and proceeding.");
            fs::remove_file(&pid_file)
                .with_context(|| format!("removing unparseable lock {}", pid_file.display()))?;
        }
    }
    Ok(())
}

fn read_postmaster_pid(path: &Path) -> Option<u32> {
    let contents = fs::read_to_string(path).ok()?;
    contents.lines().next()?.trim().parse::<u32>().ok()
}

fn pid_is_running(pid: u32) -> bool {
    let output = Command::new("tasklist.exe")
        .args(["/FI", &format!("PID eq {pid}"), "/NH", "/FO", "CSV"])
        .output();
    match output {
        Ok(out) if out.status.success() => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            !stdout.trim().is_empty() && !stdout.contains("INFO:")
        }
        _ => false,
    }
}

fn print_help() {
    eprintln!("Usage: provision");
    eprintln!();
    eprintln!("Initializes instance infrastructure: runs migrations, generates the server");
    eprintln!("identity keypair, and mints the break-glass server recovery code. Refuses if");
    eprintln!("a recovery code already exists (instance already initialized).");
    eprintln!();
    eprintln!("The first Owner is NOT created here — create it from Sylva Hub, which calls");
    eprintln!("Account.Bootstrap. Stop hearth first (Ctrl+C) before running provision.");
}

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_target(false)
        .with_max_level(tracing::Level::INFO)
        .try_init();
}
