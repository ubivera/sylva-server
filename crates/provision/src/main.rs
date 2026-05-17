#![allow(clippy::print_stderr)]
#![allow(clippy::print_stdout)]

use std::fs;
use std::io::{self, BufRead, Write};
use std::path::Path;
use std::process::{Command, ExitCode};

use anyhow::{Context, Result, bail};
use audit::Actor;
use hearth::{config::Config, db, postgres::PostgresProcess};
use identity::UserId;
use uuid::Uuid;

struct Args {
    email: String,
    display_name: String,
    password: String,
}

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
    let args = parse_args()?;
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

    let result = provision_owner(&config, &args).await;

    if let Err(err) = postgres.stop().await {
        tracing::warn!(?err, "error stopping postgres");
    }

    result?;

    eprintln!();
    eprintln!("Provisioned Owner: {} ({})", args.email, args.display_name);
    eprintln!("Run `cargo run --bin hearth` to start the server.");
    Ok(())
}

async fn provision_owner(config: &Config, args: &Args) -> Result<()> {
    let pool = db::connect(&config.postgres_url).await?;
    db::run_migrations(&pool).await?;
    tracing::info!("migrations up to date");

    let (existing,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM identity.users")
        .fetch_one(&pool)
        .await
        .context("counting existing users")?;
    if existing > 0 {
        pool.close().await;
        bail!(
            "identity.users already has {existing} row(s).\n\
             provision is for the first Owner only - use the eventual web admin to create more users.\n\
             To start over, run `cargo run --bin clean`."
        );
    }

    let password_hash =
        auth::hash_password(&args.password).map_err(|err| anyhow::anyhow!("hashing password: {err}"))?;

    let mut tx = pool.begin().await?;

    let user_id: Uuid = sqlx::query_scalar(
        "INSERT INTO identity.users (email, display_name, lifecycle, instance_role) \
         VALUES ($1, $2, 'active', 'owner') \
         RETURNING id",
    )
    .bind(&args.email)
    .bind(&args.display_name)
    .fetch_one(&mut *tx)
    .await
    .context("inserting user")?;

    sqlx::query(
        "INSERT INTO auth.credentials (user_id, password_hash) \
         VALUES ($1, $2)",
    )
    .bind(user_id)
    .bind(&password_hash)
    .execute(&mut *tx)
    .await
    .context("inserting credentials")?;

    let actor = Actor {
        user_id: UserId::new(user_id),
        display_name: args.display_name.clone(),
    };
    audit::append(
        &mut tx,
        Some(&actor),
        None,
        "owner_provisioned",
        serde_json::json!({
            "email": args.email,
            "display_name": args.display_name,
        }),
    )
    .await
    .context("emitting owner_provisioned audit event")?;

    // Generate the initial server recovery code. Owner saves this offline;
    // it's the bypass credential for the Owner-on-Owner veto window. See
    // docs/dev/hearth-owner-protection.md.
    let recovery_code = auth::recovery_code::generate_code();
    let code_id = auth::recovery_code::bootstrap(
        &mut tx,
        &recovery_code,
        Some(UserId::new(user_id)),
    )
    .await
    .context("bootstrapping recovery code")?;
    audit::append(
        &mut tx,
        Some(&actor),
        None,
        "recovery_code_generated",
        serde_json::json!({
            "code_id": code_id,
            "by_user_id": user_id,
        }),
    )
    .await
    .context("emitting recovery_code_generated audit event")?;

    tx.commit().await.context("committing transaction")?;
    pool.close().await;

    tracing::info!(%user_id, email = %args.email, "provisioned owner");
    eprintln!();
    eprintln!("====================================================================");
    eprintln!("  SERVER RECOVERY CODE  (SAVE THIS NOW — IT WILL NOT BE SHOWN AGAIN)");
    eprintln!("====================================================================");
    eprintln!("  {recovery_code}");
    eprintln!("====================================================================");
    eprintln!("  This code bypasses the Owner-on-Owner veto window for emergency");
    eprintln!("  cleanup. Store it offline (password manager / paper safe). You can");
    eprintln!("  rotate it later via POST /admin/server/recovery-code/rotate.");
    eprintln!("====================================================================");
    eprintln!();
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

fn parse_args() -> Result<Args> {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    if raw.iter().any(|a| a == "--help" || a == "-h") {
        print_help();
        std::process::exit(0);
    }

    let mut email: Option<String> = None;
    let mut display_name: Option<String> = None;
    let mut password: Option<String> = None;

    let mut it = raw.into_iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--email" => email = it.next(),
            "--display-name" => display_name = it.next(),
            "--password" => password = it.next(),
            other => bail!("unknown argument: {other}\nRun with --help for usage."),
        }
    }

    let email = email.ok_or_else(|| anyhow::anyhow!("--email is required"))?;
    let display_name =
        display_name.ok_or_else(|| anyhow::anyhow!("--display-name is required"))?;

    let password = match password {
        Some(p) => p,
        None => match std::env::var("HEARTH_PROVISION_PASSWORD") {
            Ok(p) => p,
            Err(_) => read_password_from_stdin()?,
        },
    };

    if password.is_empty() {
        bail!("password is empty");
    }

    Ok(Args {
        email,
        display_name,
        password,
    })
}

fn read_password_from_stdin() -> Result<String> {
    eprint!("Password: ");
    io::stderr().flush()?;
    let mut buf = String::new();
    io::stdin()
        .lock()
        .read_line(&mut buf)
        .context("reading password from stdin")?;
    Ok(buf.trim_end_matches(['\n', '\r']).to_string())
}

fn print_help() {
    eprintln!("Usage: provision --email <email> --display-name <name> [--password <pw>]");
    eprintln!();
    eprintln!("Creates the first Owner user. Refuses if any user already exists.");
    eprintln!("Stop hearth first (Ctrl+C) before running provision.");
    eprintln!();
    eprintln!("Password source priority:");
    eprintln!("  1. --password argument (warning: appears in shell history)");
    eprintln!("  2. HEARTH_PROVISION_PASSWORD env var");
    eprintln!("  3. stdin (echoes on interactive terminals - pipe or use env var to avoid)");
}

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_target(false)
        .with_max_level(tracing::Level::INFO)
        .try_init();
}
