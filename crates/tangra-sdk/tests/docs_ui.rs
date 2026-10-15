//! Help docs and the UI remote served by the real App over mTLS: the
//! gateway gets 200/304 and HEAD, another verified peer the handler's 403,
//! a peer the service policy does not admit the chain's 403.
#![allow(clippy::expect_used, clippy::unwrap_used)]

mod common;

use std::time::Duration;

use common::{TD, h2};
use tangra_sdk::app::{App, Services};
use tangra_sdk::config::{Config, NoModule};
use tangra_sdk::helpdocs::{self, AllowServices};
use tangra_sdk::testutil::{MemoryProvider, TestCa};

const POLICY: &str = r#"version: docs-1
rules:
  - {id: peers, from: ["spiffe://example.org/svc/gateway", "spiffe://example.org/svc/lcm"], to: ["orders"], operations: ["GET *", "HEAD *"], effect: allow}
"#;

#[tokio::test]
async fn bundle_and_ui_over_mtls() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("policy.yaml"), POLICY).unwrap();
    let yaml = format!(
        "service_name: orders\ntrust_domain: {TD}\nidentity: {{provider: provided}}\n\
authz: {{source: file, path: {}}}\n\
server: {{grpc_addr: \"\", http_addr: \"127.0.0.1:0\"}}\nadmin: {{addr: \"127.0.0.1:0\"}}\n",
        dir.path().join("policy.yaml").display()
    );
    let cfg = Config::<NoModule>::from_yaml(yaml.as_bytes()).unwrap().framework;
    let ca = TestCa::new(TD).unwrap();
    let provider = MemoryProvider::new(&ca, &ca.issue("orders").unwrap()).unwrap();
    let app = App::builder(cfg)
        .identity_provider(provider)
        .logger(tangra_sdk::log::Logger::new(
            std::io::sink(),
            tangra_sdk::log::Level::Info,
        ))
        .build()
        .await
        .unwrap();

    let fixtures = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");
    let bundle = helpdocs::load_dir(format!("{fixtures}/helpdocs/valid/rich"), "orders").unwrap();
    let digest = bundle.digest().to_owned();
    let json = bundle.marshal();
    #[cfg_attr(not(feature = "ui"), allow(unused_mut))]
    let mut router = axum::Router::new().merge(helpdocs::router(bundle, AllowServices::new(["gateway"])));
    #[cfg(feature = "ui")]
    {
        let remote = tangra_sdk::ui::Remote::from_dir(format!("{fixtures}/ui/dist")).unwrap();
        router = router.merge(tangra_sdk::ui::router(remote));
    }
    let addr = app.http_local_addr().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let app2 = app.clone();
    let done = tokio::spawn(async move {
        let _ = app2
            .run_until(Services::new().http(router), async {
                let _ = rx.await;
            })
            .await;
    });

    let gw = ca.issue("gateway").unwrap();
    let lcm = ca.issue("lcm").unwrap();
    let other = ca.issue("billing").unwrap();
    let path = helpdocs::BUNDLE_PATH;
    let etag = format!("\"{digest}\"");

    let r = h2(addr, &gw, "GET", path, &[], "").await.unwrap();
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(r.body.as_bytes(), json.as_slice());
    assert_eq!(r.headers["etag"], etag.as_str());
    assert_eq!(r.headers["cache-control"], "no-cache");
    assert_eq!(r.headers["content-type"], "application/json");
    assert!(r.headers.contains_key("x-request-id"));

    let r = h2(addr, &gw, "GET", path, &[("if-none-match", &etag)], "")
        .await
        .unwrap();
    assert_eq!(r.status, 304);
    assert!(r.body.is_empty());
    assert_eq!(r.headers["etag"], etag.as_str());

    let r = h2(addr, &gw, "HEAD", path, &[], "").await.unwrap();
    assert_eq!(r.status, 200);
    assert!(r.body.is_empty());
    assert_eq!(r.headers["content-length"], json.len().to_string().as_str());
    assert_eq!(r.headers["etag"], etag.as_str());

    // A verified peer the policy admits but the handler does not.
    let r = h2(addr, &lcm, "GET", path, &[], "").await.unwrap();
    assert_eq!((r.status, r.body.as_str()), (403, "forbidden\n"));
    // A peer the service policy refuses: the chain's {"reason":"denied"}.
    let r = h2(addr, &other, "GET", path, &[], "").await.unwrap();
    assert_eq!((r.status, r.body.as_str()), (403, "{\"reason\":\"denied\"}\n"));

    #[cfg(feature = "ui")]
    {
        let r = h2(addr, &gw, "GET", "/ui/assets/app-1a2b.js", &[], "")
            .await
            .unwrap();
        assert_eq!((r.status, r.body.as_str()), (200, "console.log(1)"));
        assert_eq!(r.headers["cache-control"], "public, max-age=31536000, immutable");
        assert_eq!(r.headers["content-type"], "text/javascript; charset=utf-8");
        let r = h2(addr, &gw, "HEAD", "/ui/mf-manifest.json", &[], "")
            .await
            .unwrap();
        assert_eq!(r.status, 200);
        assert!(r.body.is_empty());
        assert_eq!(r.headers["content-length"], "17");
        assert_eq!(r.headers["cache-control"], "no-cache");
        let r = h2(addr, &gw, "GET", "/ui/", &[], "").await.unwrap();
        assert_eq!((r.status, r.body.as_str()), (404, "{\"reason\":\"not_found\"}\n"));
    }

    let _ = tx.send(());
    let _ = tokio::time::timeout(Duration::from_secs(15), done).await;
}
