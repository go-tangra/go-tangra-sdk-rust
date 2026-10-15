//! Cross-check of the manifest validator and the OpenAPI route derivation
//! against the Go originals.
//!
//! `tests/fixtures/manifest/expected.go.json` was produced by running the
//! portal's real `internal/manifest` (`Parse` for `json/*.json`, `FromProto`
//! for `pb/*.pb`, then `sha256(json.Marshal(m))` like `registry.hashManifest`)
//! in a scratch copy of the portal repository; `*_routes.go.json` and
//! `pb/go_*.pb` came from the deployer's and warden's real
//! `pkg/*manifest` (see `tests/fixtures/manifest/xcheck/README.md`).
//!
//! `pb/rust_*.pb` are written by this file:
//! `TANGRA_WRITE_XCHECK=1 cargo test --test manifest_xcheck`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::time::Duration;

use prost::Message;
use serde_json::{Value, json};
use tangra_proto::gateway::v1 as pb;
use tangra_sdk::manifest::{self, Ability, Manifest, NavEntry, Route};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/manifest")
}

fn base() -> Manifest {
    Manifest::new("orders", "Orders", "1.0.0")
        .prefix("/api/orders")
        .permission("orders", "read", "Read orders")
        .route(Route::protected("GET", "/api/orders/v1/orders", "orders:read"))
        .exposes(["./routes", "./nav"])
}

fn cond(v: Value) -> serde_json::Map<String, Value> {
    v.as_object().unwrap().clone()
}

/// Wire manifests built in Rust (some bypass the builder to reach states only
/// a hand-made proto can have).
fn rust_pb_cases() -> Vec<(&'static str, pb::Manifest)> {
    let p = |m: Manifest| m.to_proto().unwrap();
    let mut out = vec![
        ("rust_minimal", p(base())),
        ("rust_trailing_slash_prefix", p(Manifest { prefixes: vec!["/api/orders/".into()], ..base() })),
        ("rust_timeouts", p(base()
            .route(Route { timeout: Duration::from_millis(1500), ..Route::protected("GET", "/api/orders/v1/a", "orders:read") })
            .route(Route { timeout: Duration::from_secs(90), ..Route::protected("GET", "/api/orders/v1/b", "orders:read") })
            .route(Route { timeout: Duration::from_secs(300), ..Route::protected("GET", "/api/orders/v1/c", "orders:read") })
            .route(Route { max_body_bytes: 65536, client_address: true, ..Route::public("POST", "/api/orders/v1/d") }))),
        ("rust_timeout_sub_ms", p(base().route(Route { timeout: Duration::from_micros(500), ..Route::protected("GET", "/api/orders/v1/a", "orders:read") }))),
        ("rust_timeout_301s", p(base().route(Route { timeout: Duration::from_secs(301), ..Route::protected("GET", "/api/orders/v1/a", "orders:read") }))),
        ("rust_body_wraps_negative", p(base().route(Route { max_body_bytes: u64::MAX, ..Route::protected("GET", "/api/orders/v1/a", "orders:read") }))),
        ("rust_conditions", p(base().ability(Ability {
            action: vec!["read".into(), "update".into()],
            subject: vec!["Order".into()],
            fields: vec!["status".into()],
            conditions: cond(json!({"ownerId": {"$eq": "${user.id}"}, "n": {"$in": [1, 2.5, 1e21, 1e-7]}, "z<&>": {"$exists": true}})),
            inverted: true,
            reason: "not <yours>".into(),
            requires: "orders:read".into(),
        }).nav(NavEntry { title: "Orders".into(), path: "/orders".into(), icon: "mdi-cart".into(), order: 10, requires: "orders:read".into() }))),
        ("rust_conditions_bad_op", p(base().ability(Ability {
            action: vec!["read".into()],
            subject: vec!["Order".into()],
            conditions: cond(json!({"a": {"$where": "1"}})),
            requires: "orders:read".into(),
            ..Ability::default()
        }))),
        ("rust_stream_method", p(base().method(manifest::Method {
            full_method: "/orders.v1.Orders/Watch".into(),
            permission: "orders:read".into(),
            streaming: true,
            max_stream_duration: Duration::from_secs(86400),
            ..manifest::Method::default()
        }))),
        ("rust_stream_too_long", p(base().method(manifest::Method {
            full_method: "/orders.v1.Orders/Watch".into(),
            public: true,
            max_stream_duration: Duration::from_secs(86401),
            ..manifest::Method::default()
        }))),
        ("rust_no_exposes", p(Manifest { exposes: vec![], ..base() })),
        ("rust_undeclared_route_perm", p(base().route(Route::protected("GET", "/api/orders/v1/x", "orders:write")))),
        ("rust_public_and_perm", p(base().route(Route { public: true, ..Route::protected("GET", "/api/orders/v1/x", "orders:read") }))),
        ("rust_unsorted_prefixes", p(base().prefix("/api/aaa"))),
        ("rust_overlap_after_normalize", p(base().prefix("/api/orders/v1/"))),
    ];
    let mut no_action = p(base());
    no_action.abilities.push(pb::Ability {
        subject: vec!["Order".into()],
        requires: "orders:read".into(),
        ..Default::default()
    });
    out.push(("rust_ability_nil_action", no_action));
    let mut empty_cond = p(base());
    empty_cond.abilities.push(pb::Ability {
        action: vec!["read".into()],
        subject: vec!["Order".into()],
        conditions: Some(prost_types::Struct::default()),
        requires: "orders:read".into(),
        ..Default::default()
    });
    out.push(("rust_ability_empty_conditions", empty_cond));
    let mut no_remote = p(base());
    no_remote.remote = None;
    out.push(("rust_no_remote", no_remote));
    out.push(("rust_deployer", p(deployer())));
    out
}

/// The deployer manifest (deployer `pkg/deployermanifest/manifest.go`) built
/// with the Rust SDK from the same OpenAPI document.
fn deployer() -> Manifest {
    let perms = [
        (
            "configurations",
            "read",
            "List and read deployment endpoint configurations (credentials redacted)",
        ),
        (
            "configurations",
            "manage",
            "Create, change, delete and validate deployment configurations",
        ),
        (
            "targets",
            "read",
            "List and read deployment targets and their filters",
        ),
        (
            "targets",
            "manage",
            "Create, change and delete deployment targets and attachments",
        ),
        ("jobs", "read", "List and read deployment jobs and their history"),
        ("jobs", "manage", "Cancel and retry deployment jobs"),
        (
            "deploy",
            "execute",
            "Deploy, verify and roll back certificates to endpoints",
        ),
        ("stats", "read", "Read deployment statistics"),
        (
            "backup",
            "manage",
            "Export and import tenant deployment configuration",
        ),
    ];
    let mut m = Manifest::new("deployer", "Deployer", "1.1.0").prefix("/api/deployer");
    for (r, a, d) in perms {
        m = m.permission(r, a, d);
    }
    let doc = std::fs::read(fixtures().join("deployer.yaml")).unwrap();
    let routes = manifest::openapi::routes(&doc, &m.permission_refs()).unwrap();
    let ab = |action: &[&str], subject: &str, requires: &str| Ability {
        action: action.iter().map(|s| (*s).to_owned()).collect(),
        subject: vec![subject.to_owned()],
        requires: requires.to_owned(),
        ..Ability::default()
    };
    let nav = |title: &str, path: &str, icon: &str, order: i32, requires: &str| NavEntry {
        title: title.into(),
        path: path.into(),
        icon: icon.into(),
        order,
        requires: requires.into(),
    };
    m.routes(routes)
        .ability(ab(
            &["read", "create", "update", "delete"],
            "DeployerConfiguration",
            "configurations:read",
        ))
        .ability(ab(
            &["read", "create", "update", "delete"],
            "DeployerTarget",
            "targets:read",
        ))
        .ability(ab(&["read", "manage"], "DeployerJob", "jobs:read"))
        .ability(ab(&["execute"], "Deployment", "deploy:execute"))
        .ability(ab(&["read"], "DeployerStats", "stats:read"))
        .ability(ab(&["manage"], "DeployerBackup", "backup:manage"))
        .exposes(["./routes", "./nav", "./boot"])
        .nav(nav(
            "Dashboard",
            "/deployer",
            "mdi-view-dashboard-outline",
            400,
            "stats:read",
        ))
        .nav(nav(
            "Targets",
            "/deployer/targets",
            "mdi-target",
            410,
            "targets:read",
        ))
        .nav(nav(
            "Configurations",
            "/deployer/configurations",
            "mdi-cog-outline",
            420,
            "configurations:read",
        ))
        .nav(nav(
            "Jobs",
            "/deployer/jobs",
            "mdi-progress-clock",
            430,
            "jobs:read",
        ))
}

#[test]
fn pb_fixtures_up_to_date() {
    let dir = fixtures().join("pb");
    let write = std::env::var_os("TANGRA_WRITE_XCHECK").is_some();
    for (name, m) in rust_pb_cases() {
        let path = dir.join(format!("{name}.pb"));
        let bytes = m.encode_to_vec();
        if write {
            std::fs::write(&path, &bytes).unwrap();
        } else {
            let on_disk = std::fs::read(&path).unwrap_or_default();
            assert!(
                pb::Manifest::decode(on_disk.as_slice()).ok() == Some(m),
                "{name}: fixture stale (TANGRA_WRITE_XCHECK=1), then rerun the Go cross-check"
            );
        }
    }
}

fn route_json(r: &Route) -> Value {
    json!({
        "method": r.method, "path": r.path, "permission": r.permission, "public": r.public,
        "max_body_bytes": r.max_body_bytes, "timeout_seconds": r.timeout.as_secs(), "client_address": r.client_address,
    })
}

fn check_routes(yaml: &str, go: &str, perms: &[&str]) {
    let doc = std::fs::read(fixtures().join(yaml)).unwrap();
    let rust: Vec<Value> = manifest::openapi::routes(&doc, perms)
        .unwrap()
        .iter()
        .map(route_json)
        .collect();
    let go: Vec<Value> = serde_json::from_slice(&std::fs::read(fixtures().join(go)).unwrap()).unwrap();
    assert!(!go.is_empty());
    assert_eq!(rust.len(), go.len());
    for (r, g) in rust.iter().zip(&go) {
        assert_eq!(r, g);
    }
}

#[test]
fn routes_match_go_deployer() {
    check_routes(
        "deployer.yaml",
        "deployer_routes.go.json",
        &deployer()
            .permission_refs()
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
    );
}

#[test]
fn routes_match_go_warden() {
    check_routes(
        "warden.yaml",
        "warden_routes.go.json",
        &[
            "secrets:read",
            "secrets:write",
            "secrets:delete",
            "secrets:share",
            "folders:manage",
            "permissions:manage",
            "transfer:import",
            "transfer:export",
            "backup:manage",
            "stats:read",
        ],
    );
}

#[test]
fn validator_agrees_with_gateway() {
    let expected: Vec<Value> =
        serde_json::from_slice(&std::fs::read(fixtures().join("expected.go.json")).unwrap()).unwrap();
    let mut checked = 0;
    for e in &expected {
        let file = e["file"].as_str().unwrap();
        let path = fixtures().join(file);
        let got = if file.ends_with(".pb") {
            let m = pb::Manifest::decode(std::fs::read(&path).unwrap().as_slice()).unwrap();
            manifest::validate(&m)
        } else {
            manifest::parse(&std::fs::read(&path).unwrap())
        };
        let go_ok = e["ok"].as_bool().unwrap();
        match (&got, go_ok) {
            (Ok(m), true) => assert_eq!(m.content_hash(), e["hash"].as_str().unwrap(), "{file}: hash"),
            (Err(err), false) => {
                let go_err = e["error"].as_str().unwrap();
                let decode = go_err.contains("unexpected EOF") || go_err.contains("invalid character");
                if go_err.starts_with("manifest: invalid: schema:") {
                    // Schema messages come from different libraries.
                    assert!(
                        err.0.starts_with("manifest: invalid: schema:"),
                        "{file}: go {go_err} / rust {err}"
                    );
                } else if decode {
                    // Malformed JSON: both refuse; the decoder messages differ.
                    assert!(
                        err.0.starts_with("manifest: invalid: ") && !err.0.contains("schema"),
                        "{file}: {err}"
                    );
                } else {
                    assert_eq!(err.0, go_err, "{file}");
                }
            }
            _ => panic!("{file}: go ok={go_ok} ({}), rust {got:?}", e["error"]),
        }
        checked += 1;
    }
    assert!(checked > 100, "{checked}");
}

#[test]
fn deployer_hash_matches_go() {
    let go = pb::Manifest::decode(
        std::fs::read(fixtures().join("pb/go_deployer.pb"))
            .unwrap()
            .as_slice(),
    )
    .unwrap();
    let rust = deployer().to_proto().unwrap();
    assert_eq!(
        rust, go,
        "the Rust-built deployer manifest equals the Go one on the wire"
    );
    assert_eq!(
        deployer().content_hash().unwrap(),
        manifest::validate(&go).unwrap().content_hash()
    );
}
