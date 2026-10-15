//! The manifest the module registers: valid for the gateway, pinned to its
//! version, consistent with the auth registration, and every OpenAPI route
//! is served by the router (deployer `pkg/deployermanifest` tests).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use axum::body::Body;
use tangra_notes::api::{self, ApiState};
use tangra_notes::manifest;
use tangra_notes::store::Store;
use tangra_sdk::app::ServiceConn;
use tangra_sdk::auth::{self, AuthzClient, StaticKeys, Verifier};
use tower::ServiceExt;

/// The gateway keeps one manifest per module and accepts a different one
/// only under a higher version. After bumping `manifest::VERSION`:
/// `TANGRA_UPDATE_MANIFEST_PIN=1 cargo test -p tangra-notes --test manifest pinned`.
#[test]
fn manifest_version_pinned() {
    let m = manifest::manifest().unwrap();
    let pin = concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/manifest.sha256");
    tangra_sdk::manifest::pin::check(&m, pin).unwrap();
}

#[test]
fn manifest_is_valid_for_the_gateway() {
    let m = manifest::manifest().unwrap();
    let gw = m.validate().unwrap();
    let p = m.to_proto().unwrap();
    assert_eq!(p.remote.unwrap().entry, "/m/notes/mf-manifest.json");
    assert_eq!(p.prefixes, ["/api/notes"]);
    let routes: Vec<String> = m
        .routes
        .iter()
        .map(|r| {
            format!(
                "{} {} {}",
                r.method,
                r.path,
                if r.public { "public" } else { &r.permission }
            )
        })
        .collect();
    assert_eq!(
        routes,
        [
            "GET /api/notes/v1/info public",
            "GET /api/notes/v1/notes notes:read",
            "GET /api/notes/v1/notes/{id} notes:read",
            "POST /api/notes/v1/notes notes:write",
            "POST /api/notes/v1/notes/{id}/remove notes:write",
        ]
    );
    let create = m
        .routes
        .iter()
        .find(|r| r.method == "POST" && r.path.ends_with("/notes"))
        .unwrap();
    assert_eq!(create.timeout, std::time::Duration::from_secs(10));
    assert!(!gw.to_json().is_empty());
}

/// Roles, grants, abilities and nav name declared permissions only, and
/// auth would accept the registration.
#[test]
fn registration_matches_the_manifest() {
    let perms = manifest::permission_refs();
    assert_eq!(perms, ["notes:read", "notes:write", "notes:admin"]);
    let reg = manifest::registration();
    reg.validate().unwrap();
    for r in &reg.roles {
        assert!(r.permissions.iter().all(|p| perms.contains(p)), "{}", r.slug);
    }
    for (role, ps) in &reg.builtin_grants {
        assert!(auth::BUILTIN_ROLES.contains(&role.as_str()));
        assert!(ps.iter().all(|p| perms.contains(p)), "{role}");
    }
    let req = reg.request();
    assert!(req.declares_roles && req.declares_builtin_grants);
    assert_eq!(req.module, "notes");
}

/// Nav icons must be in the `@go-tangra/ui` kit set (the shell's stylesheet
/// only carries those); this list is the subset of the kit's `ICONS` the
/// module may use.
#[test]
fn nav_icons_in_kit_set() {
    const KIT: [&str; 3] = [
        "mdi-file-document-edit-outline",
        "mdi-file-document-outline",
        "mdi-message-text-outline",
    ];
    for n in manifest::nav() {
        assert!(KIT.contains(&n.icon.as_str()), "{}", n.icon);
    }
}

fn router() -> axum::Router {
    let verifier = Arc::new(Verifier::new(
        auth::Config {
            issuer: "https://portal.example.org".into(),
            ..auth::Config::default()
        },
        Arc::new(StaticKeys(Default::default())),
        None,
    ));
    let ch = tonic::transport::Endpoint::from_static("http://127.0.0.1:1").connect_lazy();
    let state = ApiState::new(
        Arc::new(Store::new(10)),
        None,
        AuthzClient::new(ServiceConn::channel(ch)),
        tangra_sdk::log::Logger::new(std::io::sink(), tangra_sdk::log::Level::Info),
        "test",
    );
    api::router(state, verifier)
}

/// Every declared operation is implemented: without a token a protected
/// route is 401 (it matched and asked for the user), the public route 200;
/// an undeclared path is the catch-all 404 and a wrong method 405.
#[tokio::test]
async fn every_openapi_route_is_served() {
    let m = manifest::manifest().unwrap();
    for r in &m.routes {
        let path = r.path.replace("{id}", "0190");
        let req = http::Request::builder()
            .method(r.method.as_str())
            .uri(&path)
            .header("x-csrf-token", "t")
            .body(Body::empty())
            .unwrap();
        let resp = router().oneshot(req).await.unwrap();
        let want = if r.public { 200 } else { 401 };
        assert_eq!(resp.status().as_u16(), want, "{} {}", r.method, r.path);
        assert_eq!(resp.headers()["x-frame-options"], "DENY");
    }
    let get = |uri: &str, method: &str| {
        http::Request::builder()
            .method(method)
            .uri(uri)
            .body(Body::empty())
            .unwrap()
    };
    let resp = router().oneshot(get("/api/notes/v1/nope", "GET")).await.unwrap();
    assert_eq!(resp.status(), 404);
    let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
    assert_eq!(&body[..], b"{\"reason\":\"not_found\"}\n");
    let resp = router()
        .oneshot(get("/api/notes/v1/info", "DELETE"))
        .await
        .unwrap();
    assert_eq!(resp.status(), 405);
}
