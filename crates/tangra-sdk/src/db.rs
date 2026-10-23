//! PostgreSQL for modules (feature `db`): the `db:` config section, the
//! application pool, embedded migrations and the tenant-scoped transaction,
//! as the Go modules do it (deployer `internal/config` `DB`,
//! `internal/store/store.go` `Open`/`Migrate`/`Tx`, `cmd/deployersvc`
//! `bootstrap`).
//!
//! ```yaml
//! db:
//!   dsn: postgres://notes_app:...@notes-db:5432/notes?sslmode=verify-full&sslrootcert=/tls/ca.pem
//!   migrate_dsn: postgres://postgres:...@notes-db:5432/notes?sslmode=verify-full&sslrootcert=/tls/ca.pem
//!   max_conns: 16
//! ```
//!
//! - `dsn` is the application role (no `BYPASSRLS`): the pool the module
//!   serves from ([`connect`]).
//! - `migrate_dsn` is the migration role (the database owner); empty means
//!   `dsn`. `<module> bootstrap` and the start-up path apply the embedded
//!   migrations with it ([`migrate`]), then the module opens the pool.
//! - The database CA travels in the DSN (`sslrootcert=`), as with pgx;
//!   production refuses a DSN without `sslmode=verify-full` or
//!   `sslmode=verify-ca` ([`DbConfig::validate`]).
//!
//! Migrations are embedded with sqlx's macro (the module depends on `sqlx`
//! directly; [`sqlx`] is the version the SDK accepts):
//!
//! ```rust,ignore
//! static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");
//! tangra_sdk::db::migrate(&cfg.module.db, &MIGRATOR).await?;
//! let pool = tangra_sdk::db::connect(&cfg.module.db).await?;
//! let mut tx = tangra_sdk::db::begin(&pool, &Scope::tenant(&user.tenant_id)).await?;
//! ```

use std::time::Duration;

use serde::{Deserialize, Serialize};
use sqlx::migrate::Migrator;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{ConnectOptions, Connection, PgConnection, PgPool, Postgres, Transaction};

use crate::config::ConfigError;

/// The `sqlx` crate the SDK's pool and migrator are built with (modules
/// depend on the same version; `sqlx::migrate!` names its crate).
pub use sqlx;

/// The deployer's default pool size (`config.Default`: `DB{MaxConns: 16}`).
pub const DEFAULT_MAX_CONNS: i32 = 16;

/// A database failure: a DSN that does not parse, an unreachable server,
/// a failed migration.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct DbError(pub String);

/// The module config section `db:` (deployer `config.DB`).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct DbConfig {
    /// The application role's DSN (URL or key/value form, as libpq).
    pub dsn: String,
    /// The migration role's DSN; empty uses [`DbConfig::dsn`].
    pub migrate_dsn: String,
    /// Pool size; `0` (or less) is pgxpool's default, `max(4, CPUs)`.
    pub max_conns: i32,
}

impl Default for DbConfig {
    fn default() -> Self {
        Self {
            dsn: String::new(),
            migrate_dsn: String::new(),
            max_conns: DEFAULT_MAX_CONNS,
        }
    }
}

/// The DSN with its password replaced (`postgres://u:***@h/db`), for
/// `Debug` and logs.
pub fn redact(dsn: &str) -> String {
    // URL form: scheme://user:password@host...
    if let Some((scheme, rest)) = dsn.split_once("://") {
        let (auth, tail) = match rest.find(['/', '?']) {
            Some(i) => rest.split_at(i),
            None => (rest, ""),
        };
        if let Some((userinfo, host)) = auth.rsplit_once('@')
            && let Some((user, _)) = userinfo.split_once(':')
        {
            return format!("{scheme}://{user}:***@{host}{tail}");
        }
        return dsn.to_owned();
    }
    // key/value form: password=... (optionally quoted).
    let mut out = Vec::new();
    for kv in dsn.split_whitespace() {
        match kv.split_once('=') {
            Some(("password", _)) => out.push("password=***".to_owned()),
            _ => out.push(kv.to_owned()),
        }
    }
    out.join(" ")
}

impl std::fmt::Debug for DbConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DbConfig")
            .field("dsn", &redact(&self.dsn))
            .field("migrate_dsn", &redact(&self.migrate_dsn))
            .field("max_conns", &self.max_conns)
            .finish()
    }
}

/// Whether `dsn` names a verifying `sslmode` (the deployer's substring test,
/// `internal/config/config.go`: `sslmode=verify-full` or `sslmode=verify-ca`).
fn verifies(dsn: &str) -> bool {
    dsn.contains("sslmode=verify-full") || dsn.contains("sslmode=verify-ca")
}

impl DbConfig {
    /// The deployer's checks (`config.Validate`): `db.dsn` is required; in
    /// production it must use `sslmode=verify-full` (or `verify-ca`). The
    /// migration DSN is held to the same rule (it reaches the same server
    /// with the owner's password).
    pub fn validate(&self, production: bool) -> Result<(), ConfigError> {
        if self.dsn.is_empty() {
            return Err(ConfigError("config: db.dsn is required".into()));
        }
        if production && !verifies(&self.dsn) {
            return Err(ConfigError(
                "config: db.dsn must use sslmode=verify-full (or verify-ca) in production".into(),
            ));
        }
        if production && !self.migrate_dsn.is_empty() && !verifies(&self.migrate_dsn) {
            return Err(ConfigError(
                "config: db.migrate_dsn must use sslmode=verify-full (or verify-ca) in production".into(),
            ));
        }
        Ok(())
    }

    /// Accepted deviations to log at start: a DSN that does not verify the
    /// server (development; production refuses it).
    pub fn warnings(&self) -> Vec<String> {
        let mut w = Vec::new();
        if !self.dsn.is_empty() && !verifies(&self.dsn) {
            w.push("db.dsn: the database server certificate is not verified (development only)".into());
        }
        if !self.migrate_dsn.is_empty() && !verifies(&self.migrate_dsn) {
            w.push(
                "db.migrate_dsn: the database server certificate is not verified (development only)".into(),
            );
        }
        w
    }

    /// The DSN migrations run with: `migrate_dsn`, else `dsn`
    /// (`cmd/deployersvc` `bootstrap`).
    pub fn effective_migrate_dsn(&self) -> &str {
        if self.migrate_dsn.is_empty() {
            &self.dsn
        } else {
            &self.migrate_dsn
        }
    }

    /// The pool size: `max_conns`, or pgxpool's default `max(4, CPUs)`.
    pub fn pool_size(&self) -> u32 {
        match u32::try_from(self.max_conns) {
            Ok(n) if n > 0 => n,
            _ => {
                let cpus = std::thread::available_parallelism().map_or(1, usize::from);
                u32::try_from(cpus.max(4)).unwrap_or(4)
            }
        }
    }
}

fn options(dsn: &str) -> Result<PgConnectOptions, DbError> {
    let o: PgConnectOptions = dsn
        .parse()
        .map_err(|e| DbError(format!("store: {} ({e})", redact(dsn))))?;
    // sqlx logs every statement at INFO by default; the Go modules log none.
    Ok(o.disable_statement_logging())
}

/// Opens the application pool with `db.dsn` and checks the server answers
/// (deployer `store.Open`: parse, `MaxConns`, connect, ping).
///
/// The first connection is made directly, so an unreachable server, a
/// refused certificate or a bad password fail at once (the pool would
/// retry until its acquire timeout); the pool then connects on demand.
pub async fn connect(cfg: &DbConfig) -> Result<PgPool, DbError> {
    let opts = options(&cfg.dsn)?;
    let mut first = PgConnection::connect_with(&opts)
        .await
        .map_err(|e| DbError(format!("store: {e}")))?;
    let pinged = first.ping().await;
    let _ = first.close().await;
    pinged.map_err(|e| DbError(format!("store: ping: {e}")))?;
    Ok(PgPoolOptions::new()
        .max_connections(cfg.pool_size())
        .acquire_timeout(Duration::from_secs(30))
        .connect_lazy_with(opts))
}

/// Checks the server answers (readiness, deployer `Store.Ping`).
pub async fn ping(pool: &PgPool) -> Result<(), DbError> {
    let mut c = pool
        .acquire()
        .await
        .map_err(|e| DbError(format!("store: ping: {e}")))?;
    c.ping().await.map_err(|e| DbError(format!("store: ping: {e}")))
}

/// Applies `migrator` with the migration role (`db.migrate_dsn`, else
/// `db.dsn`) over one connection (deployer `store.Migrate`; sqlx holds a
/// PostgreSQL advisory lock for the run, as the deployer does around goose).
pub async fn migrate(cfg: &DbConfig, migrator: &Migrator) -> Result<(), DbError> {
    migrate_dsn(cfg.effective_migrate_dsn(), migrator).await
}

/// [`migrate`] with an explicit DSN.
pub async fn migrate_dsn(dsn: &str, migrator: &Migrator) -> Result<(), DbError> {
    let mut conn = PgConnection::connect_with(&options(dsn)?)
        .await
        .map_err(|e| DbError(format!("store: migrate: {e}")))?;
    let res = migrator
        .run(&mut conn)
        .await
        .map_err(|e| DbError(format!("store: migrate: {e}")));
    let _ = conn.close().await;
    res
}

/// The row-level-security settings a transaction runs under (deployer
/// `store.Scope`): the tenant (`app.tenant_id`) and, for trusted worker
/// paths, `app.system`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Scope {
    /// `app.tenant_id` (a UUID); empty sets nothing.
    pub tenant_id: String,
    /// `app.system = on`: the policy admits cross-tenant access.
    pub system: bool,
}

impl Scope {
    /// The caller's tenant.
    pub fn tenant(tenant_id: impl Into<String>) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            system: false,
        }
    }

    /// A trusted cross-tenant path (jobs, cleanup).
    pub fn system() -> Self {
        Self {
            tenant_id: String::new(),
            system: true,
        }
    }
}

/// The nil UUID system scopes pin `app.tenant_id` to, so a policy casting it
/// to `uuid` stays valid (deployer `store.Tx`).
const NIL_TENANT: &str = "00000000-0000-0000-0000-000000000000";

/// Begins a transaction with `scope` applied by `set_config(.., true)`
/// (transaction-local; deployer `store.Tx`). Commit it to keep the work;
/// dropping it rolls back.
pub async fn begin(pool: &PgPool, scope: &Scope) -> Result<Transaction<'static, Postgres>, sqlx::Error> {
    let mut tx = pool.begin().await?;
    if !scope.tenant_id.is_empty() {
        sqlx::query("SELECT set_config('app.tenant_id', $1, true)")
            .bind(&scope.tenant_id)
            .execute(&mut *tx)
            .await?;
    }
    if scope.system {
        sqlx::query("SELECT set_config('app.system', 'on', true)")
            .execute(&mut *tx)
            .await?;
        if scope.tenant_id.is_empty() {
            sqlx::query("SELECT set_config('app.tenant_id', $1, true)")
                .bind(NIL_TENANT)
                .execute(&mut *tx)
                .await?;
        }
    }
    Ok(tx)
}

/// Whether `e` is a unique-constraint violation (SQLSTATE `23505`; deployer
/// `store.conflict` maps it to `ErrConflict`, answered `409 conflict`).
pub fn is_unique_violation(e: &sqlx::Error) -> bool {
    matches!(e, sqlx::Error::Database(d) if d.code().as_deref() == Some("23505"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_and_warnings() {
        let mut c = DbConfig::default();
        assert_eq!(c.max_conns, 16);
        assert_eq!(c.validate(false).unwrap_err().0, "config: db.dsn is required");
        c.dsn = "postgres://app:pw@db:5432/x?sslmode=disable".into();
        c.validate(false).unwrap();
        assert_eq!(
            c.validate(true).unwrap_err().0,
            "config: db.dsn must use sslmode=verify-full (or verify-ca) in production"
        );
        assert_eq!(c.warnings().len(), 1);
        c.dsn = "postgres://app:pw@db:5432/x?sslmode=verify-ca&sslrootcert=/tls/ca.pem".into();
        c.validate(true).unwrap();
        assert!(c.warnings().is_empty());
        assert_eq!(c.effective_migrate_dsn(), c.dsn);
        c.migrate_dsn = "postgres://postgres:pw@db:5432/x".into();
        assert!(c.validate(true).unwrap_err().0.contains("db.migrate_dsn"));
        c.migrate_dsn = "postgres://postgres:pw@db:5432/x?sslmode=verify-full".into();
        c.validate(true).unwrap();
        assert_eq!(c.effective_migrate_dsn(), c.migrate_dsn);
    }

    #[test]
    fn strict_yaml() {
        let c: DbConfig = serde_norway::from_str("dsn: x\n").unwrap();
        assert_eq!((c.dsn.as_str(), c.max_conns), ("x", 16));
        assert!(serde_norway::from_str::<DbConfig>("dsn: x\nsslmode: y\n").is_err());
    }

    #[test]
    fn pool_size_defaults_like_pgxpool() {
        let mut c = DbConfig {
            max_conns: 3,
            ..DbConfig::default()
        };
        assert_eq!(c.pool_size(), 3);
        c.max_conns = 0;
        assert!(c.pool_size() >= 4);
        c.max_conns = -1;
        assert!(c.pool_size() >= 4);
    }

    #[test]
    fn redacts_passwords() {
        assert_eq!(
            redact("postgres://app:s3cret@db:5432/x?sslmode=disable"),
            "postgres://app:***@db:5432/x?sslmode=disable"
        );
        assert_eq!(redact("postgres://app@db/x"), "postgres://app@db/x");
        assert_eq!(
            redact("host=db password=s3cret dbname=x"),
            "host=db password=*** dbname=x"
        );
        let c = DbConfig {
            dsn: "postgres://app:s3cret@db/x".into(),
            ..DbConfig::default()
        };
        assert!(!format!("{c:?}").contains("s3cret"));
    }

    #[test]
    fn bad_dsn_is_an_error_without_the_password() {
        let e = options("postgres://app:s3cret@db:notaport/x").unwrap_err();
        assert!(!e.0.contains("s3cret"), "{e}");
    }
}
