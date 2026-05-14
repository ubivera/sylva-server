#![allow(clippy::print_stderr)]

use std::error::Error;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

type SetupResult<T> = Result<T, Box<dyn Error>>;

const POSTGRES_DOWNLOAD_URL: &str =
    "https://sbp.enterprisedb.com/getfile.jsp?fileid=1260146";
const POSTGRES_VERSION: &str = "18.3";

/// Pin the expected SHA256 here once you've verified a download.
/// Empty string means "compute and display, do not enforce".
const EXPECTED_SHA256: &str = "d5e16a9317216731c0e564ab63fca7c049fd7e2f727a28628cb649207748129c";

const DEFAULT_PORT: u16 = 15432;
const DEFAULT_SUPERUSER: &str = "hearth";
const DEFAULT_DATABASE: &str = "hearth";

const KEEP_EXECUTABLES: &[&str] = &["postgres.exe", "initdb.exe", "pg_ctl.exe"];

/// Wholesale-deletable top-level/known directories from the EDB distribution.
/// pgAdmin 4 (GUI tool) and StackBuilder (extension installer) dominate the
/// untrimmed install — removing them and the other entries here drops the
/// install size by roughly an order of magnitude.
const REMOVE_SUBDIRS: &[&str] = &[
    "doc",
    "include",
    "symbols",
    "pgAdmin 4",
    "StackBuilder",
    "installer",
    "share/tsearch_data",
    "share/locale",
    "share/doc",
    "share/man",
    "lib/pgxs",
    "lib/pkgconfig",
];

/// File-extension prefixes we don't need at runtime (build-time artifacts).
const REMOVE_LIB_SUFFIXES: &[&str] = &[".a", ".lib", ".pdb"];

fn main() {
    if let Err(err) = run() {
        eprintln!("bootstrap: error: {err}");
        let mut source = err.source();
        while let Some(inner) = source {
            eprintln!("  caused by: {inner}");
            source = inner.source();
        }
        std::process::exit(1);
    }
}

fn run() -> SetupResult<()> {
    let workspace_root = locate_workspace_root()?;
    let data_dir = workspace_root.join("data");
    let pg_dir = data_dir.join("postgres");
    let pg_data_dir = data_dir.join("postgres-data");

    eprintln!("bootstrap: target version Postgres {POSTGRES_VERSION}");
    eprintln!("bootstrap: workspace root = {}", workspace_root.display());

    if pg_dir.exists() && pg_data_dir.exists() {
        eprintln!();
        eprintln!("Postgres is already set up:");
        eprintln!("  binaries: {}", pg_dir.display());
        eprintln!("  data:     {}", pg_data_dir.display());
        eprintln!();
        eprintln!("Delete both directories to re-run setup, or just");
        eprintln!("`cargo run --bin hearth` to use the existing install.");
        return Ok(());
    }

    fs::create_dir_all(&data_dir)
        .map_err(|e| format!("creating {}: {e}", data_dir.display()))?;

    let temp_dir = std::env::temp_dir().join(format!(
        "hearth-bootstrap-{}",
        std::process::id()
    ));
    fs::create_dir_all(&temp_dir)
        .map_err(|e| format!("creating temp dir {}: {e}", temp_dir.display()))?;
    let _cleanup = TempDirGuard(temp_dir.clone());

    let zip_path = temp_dir.join("postgres.zip");

    eprintln!();
    eprintln!("[1/6] Downloading Postgres {POSTGRES_VERSION} binaries...");
    download(POSTGRES_DOWNLOAD_URL, &zip_path)?;
    let download_size = fs::metadata(&zip_path)
        .map(|m| m.len())
        .unwrap_or(0);
    eprintln!("      Downloaded {} MB.", download_size / (1024 * 1024));

    eprintln!();
    eprintln!("[2/6] Computing SHA256...");
    let hash = compute_sha256(&zip_path)?;
    eprintln!("      sha256: {hash}");
    if EXPECTED_SHA256.is_empty() {
        eprintln!(
            "      (no hash pinned in source; pin EXPECTED_SHA256 in main.rs \
             after auditing this value)"
        );
    } else if !hash.eq_ignore_ascii_case(EXPECTED_SHA256) {
        return Err(format!(
            "SHA256 mismatch: expected {EXPECTED_SHA256}, got {hash}"
        )
        .into());
    } else {
        eprintln!("      Matches pinned EXPECTED_SHA256.");
    }

    eprintln!();
    eprintln!("[3/6] Extracting...");
    let extract_dir = temp_dir.join("extracted");
    fs::create_dir_all(&extract_dir)?;
    extract_zip(&zip_path, &extract_dir)?;

    let extracted_pgsql = extract_dir.join("pgsql");
    if !extracted_pgsql.exists() {
        return Err(format!(
            "expected {} after extraction, not found",
            extracted_pgsql.display()
        )
        .into());
    }

    eprintln!();
    eprintln!("[4/6] Moving to {} and trimming...", pg_dir.display());
    fs::rename(&extracted_pgsql, &pg_dir).map_err(|e| {
        format!(
            "renaming {} -> {}: {e}",
            extracted_pgsql.display(),
            pg_dir.display()
        )
    })?;
    trim_distribution(&pg_dir)?;
    let kept_size = directory_size(&pg_dir).unwrap_or(0);
    eprintln!("      Trimmed install size: {} MB.", kept_size / (1024 * 1024));

    eprintln!();
    eprintln!("[5/6] Initializing cluster at {}...", pg_data_dir.display());
    initdb(&pg_dir, &pg_data_dir)?;
    configure_postgres(&pg_data_dir)?;

    eprintln!();
    eprintln!("[6/6] Creating database '{DEFAULT_DATABASE}'...");
    create_database(&pg_dir, &pg_data_dir, DEFAULT_DATABASE)?;

    eprintln!();
    eprintln!("Setup complete.");
    eprintln!("  Postgres binaries: {}", pg_dir.display());
    eprintln!("  Postgres data:     {}", pg_data_dir.display());
    eprintln!("  Listen address:    127.0.0.1:{DEFAULT_PORT}");
    eprintln!("  Superuser:         {DEFAULT_SUPERUSER}");
    eprintln!("  Database:          {DEFAULT_DATABASE}");
    eprintln!();
    eprintln!("Run `cargo run --bin hearth` to start the server.");

    Ok(())
}

/// Walk up from the current executable's manifest dir to find the workspace root.
/// We use CARGO_MANIFEST_DIR at compile time, which always points at this crate's
/// directory inside the workspace.
fn locate_workspace_root() -> SetupResult<PathBuf> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir
        .parent()
        .and_then(Path::parent)
        .ok_or("could not derive workspace root from CARGO_MANIFEST_DIR")?;
    Ok(workspace_root.to_path_buf())
}

fn download(url: &str, dest: &Path) -> SetupResult<()> {
    let status = Command::new("curl.exe")
        .args(["-L", "--fail", "--progress-bar", "-o"])
        .arg(dest)
        .arg(url)
        .status()
        .map_err(|e| format!("spawning curl.exe: {e}"))?;
    if !status.success() {
        return Err(format!("curl exited with status {status}").into());
    }
    Ok(())
}

fn compute_sha256(path: &Path) -> SetupResult<String> {
    let output = Command::new("certutil.exe")
        .args(["-hashfile"])
        .arg(path)
        .arg("SHA256")
        .output()
        .map_err(|e| format!("spawning certutil.exe: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "certutil exited with status {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let hash_line = stdout
        .lines()
        .map(str::trim)
        .find(|line| {
            !line.is_empty()
                && !line.starts_with("SHA256")
                && !line.starts_with("CertUtil")
        })
        .ok_or("could not find hash line in certutil output")?;
    let normalized: String = hash_line
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_ascii_lowercase();
    if normalized.len() != 64 || !normalized.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(
            format!("certutil output did not look like a SHA256 hex: {normalized}").into(),
        );
    }
    Ok(normalized)
}

fn extract_zip(zip_path: &Path, dest: &Path) -> SetupResult<()> {
    let status = Command::new("tar.exe")
        .args(["-xf"])
        .arg(zip_path)
        .args(["-C"])
        .arg(dest)
        .status()
        .map_err(|e| format!("spawning tar.exe: {e}"))?;
    if !status.success() {
        return Err(format!("tar exited with status {status}").into());
    }
    Ok(())
}

fn trim_distribution(pg_dir: &Path) -> SetupResult<()> {
    for relative in REMOVE_SUBDIRS {
        let path = pg_dir.join(relative);
        if path.exists() {
            fs::remove_dir_all(&path)
                .map_err(|e| format!("removing {}: {e}", path.display()))?;
        }
    }

    let bin = pg_dir.join("bin");
    if bin.is_dir() {
        for entry in fs::read_dir(&bin)? {
            let entry = entry?;
            let name = entry.file_name();
            let name_lossy = name.to_string_lossy().to_string();
            let lower = name_lossy.to_ascii_lowercase();
            let drop = if lower.ends_with(".exe") {
                !KEEP_EXECUTABLES.iter().any(|keep| keep.eq_ignore_ascii_case(&name_lossy))
            } else if lower.ends_with(".dll") {
                lower.starts_with("wx")
            } else {
                false
            };
            if drop {
                fs::remove_file(entry.path()).map_err(|e| {
                    format!("removing {}: {e}", entry.path().display())
                })?;
            }
        }
    }

    let lib = pg_dir.join("lib");
    if lib.is_dir() {
        for entry in fs::read_dir(&lib)? {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                continue;
            }
            let name = entry.file_name();
            let name_lossy = name.to_string_lossy().to_string();
            let lower = name_lossy.to_ascii_lowercase();
            let drop = REMOVE_LIB_SUFFIXES.iter().any(|suffix| lower.ends_with(suffix))
                || (lower.ends_with(".dll") && lower.starts_with("wx"));
            if drop {
                fs::remove_file(entry.path()).map_err(|e| {
                    format!("removing {}: {e}", entry.path().display())
                })?;
            }
        }
    }

    Ok(())
}

fn initdb(pg_dir: &Path, data_dir: &Path) -> SetupResult<()> {
    let initdb_exe = pg_dir.join("bin").join("initdb.exe");
    if !initdb_exe.exists() {
        return Err(format!("initdb.exe not found at {}", initdb_exe.display()).into());
    }
    let status = Command::new(&initdb_exe)
        .arg("-D")
        .arg(data_dir)
        .args([
            &format!("--username={DEFAULT_SUPERUSER}"),
            "--auth-host=trust",
            "--auth-local=trust",
            "--encoding=UTF8",
            "--locale=C",
            "--no-instructions",
        ])
        .status()
        .map_err(|e| format!("spawning initdb: {e}"))?;
    if !status.success() {
        return Err(format!("initdb exited with status {status}").into());
    }
    Ok(())
}

fn configure_postgres(data_dir: &Path) -> SetupResult<()> {
    let conf_path = data_dir.join("postgresql.conf");
    let mut existing = fs::read_to_string(&conf_path)
        .map_err(|e| format!("reading {}: {e}", conf_path.display()))?;
    let appended = format!(
        "\n\
         # ── Hearth bundled-Postgres overrides ──────────────────────────\n\
         port = {DEFAULT_PORT}\n\
         listen_addresses = '127.0.0.1'\n\
         unix_socket_directories = ''\n\
         max_connections = 50\n\
         shared_buffers = 64MB\n\
         dynamic_shared_memory_type = windows\n\
         log_destination = 'stderr'\n\
         logging_collector = off\n\
         log_min_messages = warning\n\
         log_min_error_statement = error\n\
         "
    );
    existing.push_str(&appended);
    fs::write(&conf_path, existing)
        .map_err(|e| format!("writing {}: {e}", conf_path.display()))?;

    let hba_path = data_dir.join("pg_hba.conf");
    let hba_content = "\
        # Hearth bundled-Postgres authentication\n\
        # Loopback-only; trust auth is safe because the listener is bound to\n\
        # 127.0.0.1 with no Unix socket exposed to other local users.\n\
        host all all 127.0.0.1/32 trust\n\
        host all all ::1/128       trust\n\
        ";
    fs::write(&hba_path, hba_content)
        .map_err(|e| format!("writing {}: {e}", hba_path.display()))?;

    Ok(())
}

fn create_database(pg_dir: &Path, data_dir: &Path, db_name: &str) -> SetupResult<()> {
    let postgres_exe = pg_dir.join("bin").join("postgres.exe");
    let mut child = Command::new(&postgres_exe)
        .arg("--single")
        .arg("-D")
        .arg(data_dir)
        .arg("postgres")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| format!("spawning postgres --single: {e}"))?;

    {
        let stdin = child
            .stdin
            .as_mut()
            .ok_or("postgres --single stdin not piped")?;
        writeln!(stdin, "CREATE DATABASE {};", quote_ident(db_name))
            .map_err(|e| format!("writing to postgres stdin: {e}"))?;
    }
    drop(child.stdin.take());

    let status = child
        .wait()
        .map_err(|e| format!("waiting for postgres --single: {e}"))?;
    if !status.success() {
        return Err(format!("postgres --single exited with status {status}").into());
    }
    Ok(())
}

fn quote_ident(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        if ch == '"' {
            out.push('"');
        }
        out.push(ch);
    }
    out.push('"');
    out
}

fn directory_size(path: &Path) -> std::io::Result<u64> {
    let mut total = 0u64;
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let metadata = entry.metadata()?;
        if metadata.is_dir() {
            total = total.saturating_add(directory_size(&entry.path())?);
        } else {
            total = total.saturating_add(metadata.len());
        }
    }
    Ok(total)
}

struct TempDirGuard(PathBuf);

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::{directory_size, quote_ident};
    use std::fs;

    #[test]
    fn quote_ident_wraps_simple_name() {
        assert_eq!(quote_ident("hearth"), "\"hearth\"");
    }

    #[test]
    fn quote_ident_escapes_embedded_double_quotes() {
        assert_eq!(quote_ident("ev\"il"), "\"ev\"\"il\"");
    }

    #[test]
    fn quote_ident_handles_empty() {
        assert_eq!(quote_ident(""), "\"\"");
    }

    #[test]
    fn quote_ident_preserves_non_ascii() {
        assert_eq!(quote_ident("café"), "\"café\"");
    }

    #[test]
    fn directory_size_counts_nested_files() {
        let tmp = std::env::temp_dir()
            .join(format!("hearth-bootstrap-test-dirsize-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(tmp.join("nested")).unwrap();
        fs::write(tmp.join("a.txt"), b"1234567890").unwrap();
        fs::write(tmp.join("nested").join("b.txt"), b"abc").unwrap();

        let total = directory_size(&tmp).unwrap();
        fs::remove_dir_all(&tmp).ok();
        assert_eq!(total, 13);
    }
}
