//! Ports of portal `internal/manifest/manifest_test.go` and gatewayclient
//! `TestManifestProto`.
#![allow(clippy::type_complexity)]

use serde_json::{Value, json};

use super::validate::dur;
use super::*;

const VALID: &str = include_str!("../../tests/fixtures/manifest/valid.json");

fn mutate(f: impl FnOnce(&mut serde_json::Map<String, Value>)) -> Vec<u8> {
    let mut v: Value = serde_json::from_str(VALID).unwrap();
    f(v.as_object_mut().unwrap());
    serde_json::to_vec(&v).unwrap()
}

#[test]
fn parse_valid() {
    let m = parse(VALID.as_bytes()).unwrap();
    assert_eq!(m.module, "orders");
    assert_eq!((m.routes.len(), m.methods.len(), m.abilities.len()), (4, 3, 2));
    assert_eq!(m.prefixes[0], "/api/orders");
    assert_eq!(m.subjects(), ["Order"]);
    let ok = mutate(|m| {
        m.insert(
            "routes".into(),
            json!([{"method": "GET", "path": "/api/orders/files/{rest...}", "permission": "orders:read"}]),
        );
    });
    parse(&ok).expect("catch-all route");
}

#[test]
fn parse_refusals() {
    let route = |r: Value| {
        move |m: &mut serde_json::Map<String, Value>| {
            m.insert("routes".into(), r);
        }
    };
    let cases: Vec<(&str, Box<dyn FnOnce(&mut serde_json::Map<String, Value>)>)> = vec![
        (
            "bad module name",
            Box::new(|m| {
                m.insert("module".into(), json!("Orders!"));
            }),
        ),
        (
            "unknown field",
            Box::new(|m| {
                m.insert("extra".into(), json!(1));
            }),
        ),
        (
            "prefix overlap",
            Box::new(|m| {
                m.insert("prefixes".into(), json!(["/api", "/api/orders"]));
            }),
        ),
        (
            "relative prefix",
            Box::new(|m| {
                m.insert("prefixes".into(), json!(["api/orders"]));
            }),
        ),
        (
            "dot prefix",
            Box::new(|m| {
                m.insert("prefixes".into(), json!(["/api/../x"]));
            }),
        ),
        (
            "route outside prefix",
            Box::new(route(
                json!([{"method": "GET", "path": "/elsewhere", "permission": "orders:read"}]),
            )),
        ),
        (
            "route unprotected",
            Box::new(route(json!([{"method": "GET", "path": "/api/orders"}]))),
        ),
        (
            "route public+perm",
            Box::new(route(
                json!([{"method": "GET", "path": "/api/orders", "public": true, "permission": "orders:read"}]),
            )),
        ),
        (
            "route undeclared perm",
            Box::new(route(
                json!([{"method": "GET", "path": "/api/orders", "permission": "orders:nope"}]),
            )),
        ),
        (
            "route bad param",
            Box::new(route(
                json!([{"method": "GET", "path": "/api/orders/{Id}", "permission": "orders:read"}]),
            )),
        ),
        (
            "route long timeout",
            Box::new(route(
                json!([{"method": "GET", "path": "/api/orders", "permission": "orders:read", "timeout": "10m"}]),
            )),
        ),
        (
            "duplicate route",
            Box::new(route(
                json!([{"method": "GET", "path": "/api/orders", "permission": "orders:read"}, {"method": "GET", "path": "/api/orders", "permission": "orders:read"}]),
            )),
        ),
        (
            "method unprotected",
            Box::new(|m| {
                m.insert("methods".into(), json!([{"full_method": "/a.b.C/D"}]));
            }),
        ),
        (
            "method bad name",
            Box::new(|m| {
                m.insert(
                    "methods".into(),
                    json!([{"full_method": "a.b.C/D", "public": true}]),
                );
            }),
        ),
        (
            "ability undeclared",
            Box::new(|m| {
                m.insert(
                    "abilities".into(),
                    json!([{"action": ["read"], "subject": ["Order"], "requires": "x:y"}]),
                );
            }),
        ),
        (
            "ability bad operator",
            Box::new(|m| {
                m.insert("abilities".into(), json!([{"action": ["read"], "subject": ["Order"], "conditions": {"a": {"$where": "1"}}, "requires": "orders:read"}]));
            }),
        ),
        (
            "ability huge condition",
            Box::new(|m| {
                m.insert("abilities".into(), json!([{"action": ["read"], "subject": ["Order"], "conditions": {"a": "x".repeat(5000)}, "requires": "orders:read"}]));
            }),
        ),
        (
            "nav undeclared",
            Box::new(|m| {
                m.insert(
                    "nav".into(),
                    json!([{"title": "x", "path": "/x", "order": 1, "requires": "a:b"}]),
                );
            }),
        ),
        (
            "remote wrong entry",
            Box::new(|m| {
                m.insert(
                    "remote".into(),
                    json!({"entry": "/m/other/mf-manifest.json", "exposes": ["./routes"]}),
                );
            }),
        ),
        (
            "remote bad expose",
            Box::new(|m| {
                m.insert(
                    "remote".into(),
                    json!({"entry": "/m/orders/mf-manifest.json", "exposes": ["./evil"]}),
                );
            }),
        ),
        (
            "duplicate perm",
            Box::new(|m| {
                m.insert("permissions".into(), json!([{"resource": "orders", "action": "read"}, {"resource": "orders", "action": "read"}]));
            }),
        ),
    ];
    for (name, f) in cases {
        let e = parse(&mutate(f)).expect_err(name);
        assert!(e.0.starts_with("manifest: invalid"), "{name}: {e}");
    }
    assert!(parse(b"{").is_err());
    assert!(parse(" ".repeat(MAX_MANIFEST_BYTES + 1).as_bytes()).is_err());
}

#[test]
fn normalize_and_overlap() {
    assert_eq!(normalize_prefix("/api/orders/").as_deref(), Some("/api/orders"));
    assert_eq!(normalize_prefix("/a").as_deref(), Some("/a"));
    let long = format!("/{}", "x".repeat(200));
    for bad in [
        "",
        "/",
        "api",
        "/a//b",
        "/a/./b",
        "/a/{id}",
        "/a%2Fb",
        "/a b",
        long.as_str(),
    ] {
        assert!(normalize_prefix(bad).is_none(), "{bad:?}");
    }
    assert!(
        overlaps("/api", "/api/x")
            && overlaps("/api/x", "/api")
            && !overlaps("/api", "/apix")
            && overlaps("/a", "/a")
    );
}

fn proto_manifest() -> pb::Manifest {
    let mut cond = serde_json::Map::new();
    cond.insert("ownerId".into(), json!({"$eq": "me"}));
    pb::Manifest {
        module: "orders".into(),
        display_name: "Orders".into(),
        version: "1.0.0".into(),
        prefixes: vec!["/api/orders/".into()],
        routes: vec![pb::Route {
            method: "GET".into(),
            path: "/api/orders".into(),
            permission: "orders:read".into(),
            ..Default::default()
        }],
        methods: vec![pb::Method {
            full_method: "/orders.v1.Orders/Get".into(),
            permission: "orders:read".into(),
            ..Default::default()
        }],
        permissions: vec![pb::Permission {
            resource: "orders".into(),
            action: "read".into(),
            description: String::new(),
        }],
        abilities: vec![pb::Ability {
            action: vec!["read".into()],
            subject: vec!["Order".into()],
            conditions: Some(super::struct_pb(&cond)),
            requires: "orders:read".into(),
            ..Default::default()
        }],
        remote: Some(pb::Remote {
            entry: "/m/orders/mf-manifest.json".into(),
            exposes: vec!["./routes".into()],
            integrity: String::new(),
        }),
        nav: vec![pb::NavEntry {
            title: "Orders".into(),
            path: "/orders".into(),
            icon: String::new(),
            order: 1,
            requires: "orders:read".into(),
        }],
    }
}

#[test]
fn from_proto() {
    let mut p = proto_manifest();
    let m = validate(&p).unwrap();
    assert_eq!(m.prefixes[0], "/api/orders");
    assert!(m.abilities[0].conditions.contains_key("ownerId"));
    p.routes[0].permission.clear();
    assert!(validate(&p).is_err(), "unprotected route accepted via proto");
    const MS: i128 = 1_000_000;
    for (d, want) in [
        (0, ""),
        (3_600_000 * MS, "60m"),
        (90_000 * MS, "90s"),
        (1500 * MS, "1500ms"),
        (5000 * MS, "5s"),
    ] {
        assert_eq!(dur(d), want);
    }
    p.routes[0].permission = "orders:read".into();
    p.methods[0].max_stream_duration = Some(prost_types::Duration {
        seconds: 3600,
        nanos: 0,
    });
    p.methods[0].streaming = true;
    validate(&p).expect("hour-long stream cap");
    // No remote: the entry is required.
    assert!(
        validate(&pb::Manifest {
            module: "orders".into(),
            ..Default::default()
        })
        .is_err()
    );
}

#[test]
fn validate_direct() {
    let base = || parse(VALID.as_bytes()).unwrap();
    let cases: Vec<(&str, Box<dyn Fn(&mut GatewayManifest)>)> = vec![
        (
            "bad permission ref",
            Box::new(|m| {
                m.permissions.push(validate::GwPermission {
                    resource: "Bad!".into(),
                    action: "x".into(),
                    description: String::new(),
                })
            }),
        ),
        (
            "bad route timeout",
            Box::new(|m| m.routes[0].timeout = "soon".into()),
        ),
        (
            "negative route timeout",
            Box::new(|m| m.routes[0].timeout = "-5s".into()),
        ),
        (
            "bad stream duration",
            Box::new(|m| m.methods[1].max_stream_duration = "later".into()),
        ),
        (
            "huge stream duration",
            Box::new(|m| m.methods[1].max_stream_duration = "48h".into()),
        ),
        (
            "duplicate method",
            Box::new(|m| {
                let x = m.methods[0].clone();
                m.methods.push(x);
            }),
        ),
        (
            "method undeclared perm",
            Box::new(|m| m.methods[0].permission = "x:y".into()),
        ),
        ("bad prefix", Box::new(|m| m.prefixes = vec!["relative".into()])),
        ("route unprotected", Box::new(|m| m.routes[0].permission.clear())),
        (
            "route bad param",
            Box::new(|m| m.routes[1].path = "/api/orders/{Id}".into()),
        ),
        (
            "catch-all not last",
            Box::new(|m| m.routes[1].path = "/api/orders/{rest...}/x".into()),
        ),
        (
            "method unprotected",
            Box::new(|m| m.methods[0].permission.clear()),
        ),
    ];
    for (name, f) in cases {
        let mut m = base();
        f(&mut m);
        assert!(m.check().is_err(), "{name}");
    }
    let obj = |v: Value| v.as_object().unwrap().clone();
    for (name, c) in [
        ("empty key", json!({"": 1})),
        ("long key", json!({"k".repeat(70): 1})),
        ("key with space", json!({"a b": 1})),
        (
            "nested deep",
            json!({"a": {"b": {"c": {"d": {"e": {"f": {"g": {"h": 1}}}}}}}}),
        ),
        ("long list", json!({"a": {"$in": vec![Value::Null; 101]}})),
        ("bad nested", json!({"a": [{"$where": 1}]})),
    ] {
        assert!(validate_conditions(&obj(c)).is_err(), "{name}");
    }
    validate_conditions(&obj(json!({"a": ["x", 1.5, true, null, {"$gt": 1}]}))).unwrap();
}

#[test]
fn manifest_proto_and_builder() {
    let mut cond = serde_json::Map::new();
    cond.insert("ownerId".into(), json!({"$eq": "${user.id}"}));
    let m = Manifest::new("orders", "Orders", "1.0.0")
        .prefix("/api/orders")
        .route(Route {
            timeout: Duration::from_secs(5),
            ..Route::protected("GET", "/api/orders", &perm("orders", "read"))
        })
        .route(Route::public("GET", "/api/orders/health"))
        .method(Method {
            full_method: "/orders.v1.Orders/Watch".into(),
            permission: "orders:read".into(),
            streaming: true,
            max_stream_duration: Duration::from_secs(3600),
            ..Method::default()
        })
        .permission("orders", "read", "Read")
        .ability(Ability {
            action: vec!["read".into()],
            subject: vec!["Order".into()],
            conditions: cond,
            requires: "orders:read".into(),
            ..Ability::default()
        })
        .exposes(["./routes"])
        .nav(NavEntry {
            title: "Orders".into(),
            path: "/orders".into(),
            order: 1,
            requires: "orders:read".into(),
            ..NavEntry::default()
        });
    let pm = m.to_proto().unwrap();
    assert_eq!(pm.remote.as_ref().unwrap().entry, "/m/orders/mf-manifest.json");
    assert_eq!(pm.routes[0].timeout.as_ref().unwrap().seconds, 5);
    assert!(pm.routes[1].timeout.is_none());
    assert_eq!(pm.methods[0].max_stream_duration.as_ref().unwrap().seconds, 3600);
    assert!(
        pm.abilities[0]
            .conditions
            .as_ref()
            .unwrap()
            .fields
            .contains_key("ownerId")
    );
    assert_eq!(pm.nav[0].order, 1);
    assert!(Manifest::default().to_proto().is_err());
    let g = m.validate().unwrap();
    assert_eq!(g.content_hash().len(), 64);
    assert_eq!(m.content_hash().unwrap(), g.content_hash());
    assert_eq!(m.permission_refs(), ["orders:read"]);
}

#[test]
fn pin_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("manifest.sha256");
    let m = Manifest::new("orders", "Orders", "1.0.0")
        .prefix("/api/orders")
        .permission("orders", "read", "")
        .route(Route::protected("GET", "/api/orders", "orders:read"))
        .exposes(["./routes"]);
    assert!(pin::check(&m, &file).is_err(), "missing pin file");
    std::fs::write(&file, format!("{}\n", pin::line(&m).unwrap())).unwrap();
    pin::check(&m, &file).unwrap();
    let changed = m.clone().route(Route::public("GET", "/api/orders/health"));
    assert!(pin::check(&changed, &file).unwrap_err().contains("still 1.0.0"));
    let bumped = Manifest {
        version: "1.0.1".into(),
        ..changed
    };
    assert!(
        pin::check(&bumped, &file)
            .unwrap_err()
            .contains("bumped to 1.0.1")
    );
}
