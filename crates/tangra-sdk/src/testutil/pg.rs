//! A throwaway PostgreSQL for module tests (feature `testutil-pg`), started
//! from local binaries the way `tools/livestack` does it: `initdb` into a
//! temporary directory, `postgres` on a free loopback port without a Unix
//! socket, trust authentication for the `postgres` superuser.
//!
//! Where the server comes from, in order:
//!
//! 1. `TANGRA_TEST_PG_DSN`: an existing server (a superuser DSN, e.g. a CI
//!    service container); each [`Postgres::database`] creates a fresh
//!    database on it.
//! 2. `PG_DIR`: a PostgreSQL directory with `bin/`, `lib/` and `share/`
//!    (livestack's variable).
//! 3. The cache, `$TANGRA_TEST_PG_CACHE` or
//!    `$XDG_CACHE_HOME/tangra-sdk/pg-<version>` (`~/.cache/...`).
//! 4. A download of the zonky `embedded-postgres-binaries-linux-amd64`
//!    `$PG_VERSION` (default [`PG_VERSION`]) jar from Maven Central into the
//!    cache, with `curl`, `unzip` and `tar -xJ` (unless
//!    `TANGRA_TEST_PG_OFFLINE=1`).
//!
//! When none of these works (no binaries, offline, running as root),
//! [`Postgres::start`] returns `None` after printing why, and the test
//! skips its database checks, like the Valkey tests.
//!
//! ```rust,ignore
//! let Some(pg) = tangra_sdk::testutil::pg::Postgres::start().await else { return };
//! let dsn = pg.database("bookmark").await?;   // superuser DSN of a new database
//! ```

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use sqlx::{Connection, PgConnection};

use super::{TestCa, TestError, terr};

/// The zonky embedded-postgres version downloaded when no binaries are
/// configured (what `tools/livestack` uses).
pub const PG_VERSION: &str = "16.9.0";

/// Options for [`Postgres::start_with`].
#[derive(Debug, Clone, Default)]
pub struct Options {
    /// Serve TLS (`ssl=on`) with a server certificate for `localhost` (not
    /// `127.0.0.1`) from a fresh CA; [`Postgres::ca_file`] holds the CA for
    /// `sslrootcert=`. Ignored with `TANGRA_TEST_PG_DSN`.
    pub tls: bool,
}

/// A running test server (stopped and removed on drop) or an external one.
#[derive(Debug)]
pub struct Postgres {
    /// `host:port` of the server.
    pub addr: String,
    base: String,
    owned: Option<Owned>,
}

#[derive(Debug)]
struct Owned {
    bin: PathBuf,
    dir: PathBuf,
    ca_file: Option<PathBuf>,
}

impl Drop for Owned {
    fn drop(&mut self) {
        let _ = Command::new(self.bin.join("pg_ctl"))
            .arg("-D")
            .arg(self.dir.join("data"))
            .args(["-m", "immediate", "-w", "stop"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn skip(why: &str) -> Option<Postgres> {
    eprintln!(
        "no PostgreSQL for this test ({why}); set PG_DIR or TANGRA_TEST_PG_DSN: database checks skipped"
    );
    None
}

fn cache_dir() -> Option<PathBuf> {
    if let Some(d) = std::env::var_os("TANGRA_TEST_PG_CACHE") {
        return Some(PathBuf::from(d));
    }
    let base = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))?;
    Some(base.join("tangra-sdk").join(format!("pg-{}", version())))
}

fn version() -> String {
    std::env::var("PG_VERSION").unwrap_or_else(|_| PG_VERSION.to_owned())
}

fn has_postgres(dir: &Path) -> bool {
    dir.join("bin").join("postgres").is_file() && dir.join("bin").join("initdb").is_file()
}

/// Downloads and unpacks the zonky jar into `cache` (via a sibling
/// temporary directory renamed into place, so concurrent tests do not see a
/// half-unpacked tree).
fn download(cache: &Path) -> Result<(), String> {
    let parent = cache.parent().ok_or("cache dir has no parent")?;
    std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    let tmp = parent.join(format!(".pg-download-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir_all(&tmp).map_err(|e| e.to_string())?;
    let v = version();
    let url = format!(
        "https://repo1.maven.org/maven2/io/zonky/test/postgres/embedded-postgres-binaries-linux-amd64/{v}/embedded-postgres-binaries-linux-amd64-{v}.jar"
    );
    let jar = tmp.join("pg.jar");
    let run = || -> Result<(), String> {
        let ok = Command::new("curl")
            .args(["-sfL", "--max-time", "300", "-o"])
            .arg(&jar)
            .arg(&url)
            .status()
            .map_err(|e| format!("curl: {e}"))?
            .success();
        if !ok {
            return Err(format!("download of {url} failed"));
        }
        let out = tmp.join("pg");
        std::fs::create_dir_all(&out).map_err(|e| e.to_string())?;
        let script = format!(
            "unzip -p '{}' '*.txz' | tar -xJ -C '{}'",
            jar.display(),
            out.display()
        );
        let ok = Command::new("sh")
            .args(["-c", &script])
            .status()
            .map_err(|e| format!("unpack: {e}"))?
            .success();
        if !ok || !has_postgres(&out) {
            return Err("unpacking the PostgreSQL binaries failed".into());
        }
        match std::fs::rename(&out, cache) {
            Ok(()) => Ok(()),
            // Another test won the race.
            Err(_) if has_postgres(cache) => Ok(()),
            Err(e) => Err(e.to_string()),
        }
    };
    let res = run();
    let _ = std::fs::remove_dir_all(&tmp);
    res
}

/// The PostgreSQL directory to run, or why there is none.
fn binaries() -> Result<PathBuf, String> {
    if let Some(d) = std::env::var_os("PG_DIR") {
        let d = PathBuf::from(d);
        return if has_postgres(&d) {
            Ok(d)
        } else {
            Err(format!("PG_DIR={} has no bin/postgres", d.display()))
        };
    }
    let cache = cache_dir().ok_or("no cache directory (HOME unset)")?;
    if has_postgres(&cache) {
        return Ok(cache);
    }
    if std::env::var("TANGRA_TEST_PG_OFFLINE").is_ok_and(|v| v == "1") {
        return Err("TANGRA_TEST_PG_OFFLINE=1 and no cached binaries".into());
    }
    download(&cache)?;
    Ok(cache)
}

fn is_root() -> bool {
    Command::new("id")
        .arg("-u")
        .output()
        .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).trim() == "0")
}

fn free_port() -> Result<u16, String> {
    let l = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    l.local_addr().map(|a| a.port()).map_err(|e| e.to_string())
}

fn write_tls(dir: &Path) -> Result<PathBuf, TestError> {
    let ca = TestCa::new("example.org")?;
    let leaf = ca.issue_tls_server(&["localhost"], &[])?;
    let data = dir.join("data");
    std::fs::write(data.join("server.crt"), &leaf.cert_pem).map_err(terr)?;
    let key_path = data.join("server.key");
    std::fs::write(&key_path, &leaf.key_pem).map_err(terr)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).map_err(terr)?;
    }
    let ca_file = dir.join("ca.pem");
    std::fs::write(&ca_file, ca.bundle_pem()).map_err(terr)?;
    Ok(ca_file)
}

impl Postgres {
    /// [`Postgres::start_with`] with default options.
    pub async fn start() -> Option<Self> {
        Self::start_with(Options::default()).await
    }

    /// Starts (or attaches to) a server, or prints why there is none and
    /// returns `None`.
    pub async fn start_with(o: Options) -> Option<Self> {
        if let Ok(dsn) = std::env::var("TANGRA_TEST_PG_DSN") {
            return Some(Self {
                addr: String::new(),
                base: dsn,
                owned: None,
            });
        }
        if is_root() {
            return skip("initdb refuses to run as root");
        }
        let bin = match binaries() {
            Ok(d) => d.join("bin"),
            Err(e) => return skip(&e),
        };
        match Self::spawn(&bin, &o).await {
            Ok(pg) => Some(pg),
            Err(e) => skip(&e),
        }
    }

    async fn spawn(bin: &Path, o: &Options) -> Result<Self, String> {
        let dir = std::env::temp_dir().join(format!("tangra-pg-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let mut owned = Owned {
            bin: bin.to_owned(),
            dir: dir.clone(),
            ca_file: None,
        };
        let data = dir.join("data");
        let out = Command::new(bin.join("initdb"))
            .arg("-D")
            .arg(&data)
            .args(["-U", "postgres", "--auth=trust", "-E", "UTF8", "--no-sync"])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()
            .map_err(|e| format!("initdb: {e}"))?;
        if !out.status.success() {
            return Err(format!("initdb: {}", String::from_utf8_lossy(&out.stderr).trim()));
        }
        let mut server_opts = String::from(
            "-c listen_addresses=127.0.0.1 -c unix_socket_directories='' -c fsync=off -c synchronous_commit=off -c full_page_writes=off",
        );
        if o.tls {
            owned.ca_file = Some(write_tls(&dir).map_err(|e| e.0)?);
            server_opts.push_str(" -c ssl=on -c ssl_cert_file=server.crt -c ssl_key_file=server.key");
        }
        // A port picked free can be taken before postgres binds it: retry.
        let mut last = String::new();
        for _ in 0..5 {
            let port = free_port()?;
            let st = Command::new(bin.join("pg_ctl"))
                .arg("-D")
                .arg(&data)
                .arg("-l")
                .arg(dir.join("postgres.log"))
                .args([
                    "-w",
                    "-t",
                    "60",
                    "-o",
                    &format!("-p {port} {server_opts}"),
                    "start",
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .map_err(|e| format!("pg_ctl: {e}"))?;
            if !st.success() {
                last = std::fs::read_to_string(dir.join("postgres.log")).unwrap_or_default();
                continue;
            }
            let addr = format!("127.0.0.1:{port}");
            let pg = Self {
                base: format!("postgres://postgres@{addr}/postgres?sslmode=disable"),
                addr,
                owned: Some(owned),
            };
            pg.wait_ready().await?;
            return Ok(pg);
        }
        Err(format!("postgres did not start: {}", last.trim()))
    }

    async fn wait_ready(&self) -> Result<(), String> {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            match PgConnection::connect(&self.base).await {
                Ok(c) => {
                    let _ = c.close().await;
                    return Ok(());
                }
                Err(e) if Instant::now() > deadline => return Err(e.to_string()),
                Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
            }
        }
    }

    /// The superuser DSN of the `postgres` database.
    pub fn superuser_dsn(&self) -> &str {
        &self.base
    }

    /// The CA certificate (PEM file) of a TLS server ([`Options::tls`]).
    pub fn ca_file(&self) -> Option<&Path> {
        self.owned.as_ref().and_then(|o| o.ca_file.as_deref())
    }

    /// `base` with its database replaced by `db`.
    fn with_db(&self, db: &str) -> String {
        let (head, query) = match self.base.split_once('?') {
            Some((h, q)) => (h, format!("?{q}")),
            None => (self.base.as_str(), String::new()),
        };
        let root = match head.find("://").map(|i| i + 3) {
            Some(start) => match head[start..].find('/') {
                Some(j) => &head[..start + j],
                None => head,
            },
            None => head,
        };
        format!("{root}/{db}{query}")
    }

    /// Creates a fresh database named after `prefix` (unique per call) and
    /// returns its superuser DSN.
    pub async fn database(&self, prefix: &str) -> Result<String, TestError> {
        let clean: String = prefix
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
            .take(30)
            .collect::<String>()
            .to_ascii_lowercase();
        let name = format!("{clean}_{}", uuid::Uuid::now_v7().simple());
        self.exec(&format!("CREATE DATABASE \"{name}\"")).await?;
        Ok(self.with_db(&name))
    }

    /// Runs `sql` as the superuser on the `postgres` database (roles,
    /// databases).
    pub async fn exec(&self, sql: &str) -> Result<(), TestError> {
        let mut c = PgConnection::connect(&self.base).await.map_err(terr)?;
        sqlx::raw_sql(sql).execute(&mut c).await.map_err(terr)?;
        let _ = c.close().await;
        Ok(())
    }

    /// `dsn` with its user (and password) replaced, e.g. the application
    /// role of a module: `pg.dsn_as(&dsn, "notes_app", "pw")`.
    pub fn dsn_as(dsn: &str, user: &str, password: &str) -> String {
        match dsn.split_once("://") {
            Some((scheme, rest)) => {
                let host = rest.split_once('@').map_or(rest, |(_, h)| h);
                if password.is_empty() {
                    format!("{scheme}://{user}@{host}")
                } else {
                    format!("{scheme}://{user}:{password}@{host}")
                }
            }
            None => dsn.to_owned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dsn_helpers() {
        let pg = Postgres {
            addr: "127.0.0.1:1".into(),
            base: "postgres://postgres@127.0.0.1:1/postgres?sslmode=disable".into(),
            owned: None,
        };
        assert_eq!(
            pg.with_db("x_1"),
            "postgres://postgres@127.0.0.1:1/x_1?sslmode=disable"
        );
        let pg = Postgres {
            addr: String::new(),
            base: "postgres://u:p@db:5432".into(),
            owned: None,
        };
        assert_eq!(pg.with_db("y"), "postgres://u:p@db:5432/y");
        assert_eq!(
            Postgres::dsn_as("postgres://postgres@h:1/d?x=1", "app", "pw"),
            "postgres://app:pw@h:1/d?x=1"
        );
        assert_eq!(
            Postgres::dsn_as("postgres://a:b@h/d", "app", ""),
            "postgres://app@h/d"
        );
    }
}
