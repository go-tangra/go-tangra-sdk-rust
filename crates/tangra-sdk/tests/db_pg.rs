//! `db` against a real PostgreSQL from `testutil::pg`: migrations with the
//! migration role, the application pool, tenant-scoped transactions under
//! row-level security, unique violations, and TLS with `sslmode=verify-full`
//! (the only kind production accepts). Skipped with a notice when no
//! PostgreSQL binaries can be found or downloaded.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use sqlx::Row;
use tangra_sdk::db::{self, DbConfig, Scope};
use tangra_sdk::testutil::pg::{Options, Postgres};

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./tests/fixtures/db/migrations");

const T1: &str = "00000000-0000-0000-0000-0000000000a1";
const T2: &str = "00000000-0000-0000-0000-0000000000a2";

#[tokio::test]
async fn migrate_connect_and_tenant_scope() {
    let Some(pg) = Postgres::start().await else { return };
    let owner = pg.database("sdkdb").await.unwrap();
    pg.exec("DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='items_app') THEN CREATE ROLE items_app LOGIN NOBYPASSRLS; END IF; END $$")
        .await
        .unwrap();
    let cfg = DbConfig {
        dsn: Postgres::dsn_as(&owner, "items_app", ""),
        migrate_dsn: owner.clone(),
        max_conns: 4,
    };
    cfg.validate(false).unwrap();
    assert!(!cfg.warnings().is_empty(), "sslmode=disable is warned about");
    // Production refuses a DSN that does not verify the server.
    assert_eq!(
        cfg.validate(true).unwrap_err().0,
        "config: db.dsn must use sslmode=verify-full (or verify-ca) in production"
    );

    // The application role cannot create the schema; the migration role can,
    // and a second run is a no-op.
    assert!(db::migrate_dsn(&cfg.dsn, &MIGRATOR).await.is_err());
    db::migrate(&cfg, &MIGRATOR).await.unwrap();
    db::migrate(&cfg, &MIGRATOR).await.unwrap();

    let pool = db::connect(&cfg).await.unwrap();
    db::ping(&pool).await.unwrap();
    for (t, id) in [(T1, "a"), (T1, "b"), (T2, "a")] {
        let mut tx = db::begin(&pool, &Scope::tenant(t)).await.unwrap();
        sqlx::query("INSERT INTO items (tenant_id, id, name) VALUES ($1::uuid, $2, $3)")
            .bind(t)
            .bind(id)
            .bind(format!("{t}/{id}"))
            .execute(&mut *tx)
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }
    // Row-level security: a tenant scope sees only its rows, even without a
    // tenant predicate; no scope sees nothing; a write into another tenant
    // is refused.
    let count = |scope: Scope| {
        let pool = pool.clone();
        async move {
            let mut tx = db::begin(&pool, &scope).await.unwrap();
            let n: i64 = sqlx::query("SELECT count(*) AS n FROM items")
                .fetch_one(&mut *tx)
                .await
                .unwrap()
                .get("n");
            n
        }
    };
    assert_eq!(count(Scope::tenant(T1)).await, 2);
    assert_eq!(count(Scope::tenant(T2)).await, 1);
    assert_eq!(count(Scope::system()).await, 3);
    let mut tx = db::begin(&pool, &Scope::tenant(T1)).await.unwrap();
    let e = sqlx::query("INSERT INTO items (tenant_id, id, name) VALUES ($1::uuid, 'x', 'x')")
        .bind(T2)
        .execute(&mut *tx)
        .await
        .unwrap_err();
    assert!(e.to_string().contains("row-level security"), "{e}");
    drop(tx);
    // Unique violations map to conflict.
    let mut tx = db::begin(&pool, &Scope::tenant(T1)).await.unwrap();
    let e = sqlx::query("INSERT INTO items (tenant_id, id, name) VALUES ($1::uuid, 'a', 'dup')")
        .bind(T1)
        .execute(&mut *tx)
        .await
        .unwrap_err();
    assert!(db::is_unique_violation(&e), "{e}");
    pool.close().await;
}

#[tokio::test]
async fn tls_verify_full() {
    if std::env::var_os("TANGRA_TEST_PG_DSN").is_some() {
        eprintln!("TANGRA_TEST_PG_DSN set: the TLS check needs a server it starts itself; skipped");
        return;
    }
    let Some(pg) = Postgres::start_with(Options { tls: true }).await else {
        return;
    };
    let ca = pg.ca_file().unwrap().display().to_string();
    let port = pg.addr.rsplit_once(':').unwrap().1.to_owned();
    let dsn = format!("postgres://postgres@localhost:{port}/postgres?sslmode=verify-full&sslrootcert={ca}");
    let cfg = DbConfig {
        dsn: dsn.clone(),
        ..DbConfig::default()
    };
    cfg.validate(true).unwrap();
    assert!(cfg.warnings().is_empty());
    let pool = db::connect(&cfg).await.unwrap();
    let ssl: bool = sqlx::query("SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()")
        .fetch_one(&pool)
        .await
        .unwrap()
        .get("ssl");
    assert!(ssl, "the connection uses TLS");
    pool.close().await;

    // Another CA does not verify the server.
    let other = tangra_sdk::testutil::TestCa::new("other.org").unwrap();
    let dir = std::env::temp_dir().join(format!("tangra-pg-ca-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let wrong = dir.join("ca.pem");
    std::fs::write(&wrong, other.bundle_pem()).unwrap();
    let bad = DbConfig {
        dsn: dsn.replace(&ca, &wrong.display().to_string()),
        ..DbConfig::default()
    };
    assert!(db::connect(&bad).await.is_err());
    // A host name the certificate does not carry fails verify-full.
    let bad = DbConfig {
        dsn: dsn.replace("localhost", "127.0.0.1"),
        ..DbConfig::default()
    };
    assert!(db::connect(&bad).await.is_err());
    let _ = std::fs::remove_dir_all(&dir);
}
