use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tokio::net::TcpStream;
use tokio::process::{Child, Command};
use tokio::time::{sleep, timeout};

const READY_POLL_INTERVAL: Duration = Duration::from_millis(500);
const READY_TIMEOUT: Duration = Duration::from_secs(30);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(15);

pub struct PostgresProcess {
    child: Option<Child>,
    pg_bin_dir: PathBuf,
    data_dir: PathBuf,
}

impl PostgresProcess {
    /// Spawn `postgres.exe -D <data_dir>` and wait for the listener to come up.
    pub async fn start(pg_bin_dir: PathBuf, data_dir: PathBuf, port: u16) -> Result<Self> {
        let postgres_exe = pg_bin_dir.join("bin").join("postgres.exe");
        if !postgres_exe.exists() {
            bail!(
                "postgres.exe not found at {}. Run `cargo run --bin bootstrap` first.",
                postgres_exe.display()
            );
        }
        if !data_dir.exists() {
            bail!(
                "Postgres data directory {} does not exist. Run `cargo run --bin bootstrap` first.",
                data_dir.display()
            );
        }

        tracing::info!(
            postgres_exe = %postgres_exe.display(),
            data_dir = %data_dir.display(),
            port,
            "spawning bundled postgres",
        );

        let mut child = Command::new(&postgres_exe)
            .arg("-D")
            .arg(&data_dir)
            .kill_on_drop(true)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .with_context(|| format!("spawning {}", postgres_exe.display()))?;

        let ready = wait_until_ready(&mut child, port);
        match timeout(READY_TIMEOUT, ready).await {
            Ok(Ok(())) => {
                tracing::info!(port, "bundled postgres ready");
                Ok(Self {
                    child: Some(child),
                    pg_bin_dir,
                    data_dir,
                })
            }
            Ok(Err(err)) => {
                let _ = child.start_kill();
                Err(err)
            }
            Err(_) => {
                let _ = child.start_kill();
                bail!(
                    "postgres did not start accepting connections on 127.0.0.1:{port} within {}s",
                    READY_TIMEOUT.as_secs()
                );
            }
        }
    }

    /// Graceful shutdown: ask Postgres to stop via pg_ctl, fall back to kill.
    pub async fn stop(mut self) -> Result<()> {
        let pg_ctl = self.pg_bin_dir.join("bin").join("pg_ctl.exe");
        if pg_ctl.exists() {
            let stop_status = Command::new(&pg_ctl)
                .args(["stop", "-m", "fast", "-w", "-t", "10", "-D"])
                .arg(&self.data_dir)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .await;
            match stop_status {
                Ok(status) if status.success() => {
                    tracing::info!("pg_ctl stop succeeded");
                }
                Ok(status) => {
                    tracing::warn!(?status, "pg_ctl stop returned non-zero status");
                }
                Err(err) => {
                    tracing::warn!(?err, "failed to invoke pg_ctl stop");
                }
            }
        } else {
            tracing::warn!(
                pg_ctl = %pg_ctl.display(),
                "pg_ctl.exe missing; will rely on direct child shutdown"
            );
        }

        if let Some(mut child) = self.child.take() {
            match timeout(SHUTDOWN_TIMEOUT, child.wait()).await {
                Ok(Ok(status)) => {
                    tracing::info!(?status, "postgres exited");
                }
                Ok(Err(err)) => {
                    tracing::warn!(?err, "error waiting for postgres exit");
                }
                Err(_) => {
                    tracing::warn!("postgres did not exit in time, killing");
                    let _ = child.kill().await;
                }
            }
        }
        Ok(())
    }
}

async fn wait_until_ready(child: &mut Child, port: u16) -> Result<()> {
    loop {
        if let Some(status) = child
            .try_wait()
            .context("checking postgres child status")?
        {
            bail!("postgres exited before becoming ready: {status}");
        }
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return Ok(());
        }
        sleep(READY_POLL_INTERVAL).await;
    }
}
