//! The embedded help pages (deployer `docs/embed_test.go`): they load, have
//! a start page and an operator page, gate pages only on the module's own
//! permissions, and the bundle handler serves the gateway only.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::SystemTime;

use axum::body::Body;
use tangra_notes::{docs, manifest};
use tangra_sdk::app::PeerIdentity;
use tangra_sdk::helpdocs::{self, AllowServices, Audience};
use tangra_sdk::identity::SpiffeId;
use tower::ServiceExt;

#[test]
fn embedded_help_loads() {
    let b = docs::bundle().unwrap();
    assert_eq!(b.module, manifest::MODULE);
    assert!(b.pages.len() >= 5, "{} pages", b.pages.len());
    assert_eq!(b.digest(), helpdocs::compute_digest(&b));
    let perms = manifest::permission_refs();
    for p in &b.pages {
        assert!(
            p.requires.is_empty() || perms.contains(&p.requires),
            "{} requires {}",
            p.slug,
            p.requires
        );
    }
    assert!(b.pages.iter().any(|p| p.slug == "index"));
    assert!(b.pages.iter().any(|p| p.audience == Audience::Operator.as_str()));
    helpdocs::lint(&docs::help()).unwrap();
}

fn request(peer: Option<&str>) -> http::Request<Body> {
    let mut r = http::Request::get(helpdocs::BUNDLE_PATH)
        .body(Body::empty())
        .unwrap();
    if let Some(svc) = peer {
        r.extensions_mut().insert(PeerIdentity {
            id: SpiffeId::new("example.org", svc).unwrap(),
            service_name: svc.to_owned(),
            serial: "1".into(),
            verified_at: SystemTime::now(),
        });
    }
    r
}

/// The handler wired in `module::build` serves the configured gateway only.
#[tokio::test]
async fn help_handler_serves_gateway_only() {
    let b = docs::bundle().unwrap();
    let router = helpdocs::router(b.clone(), AllowServices::new(["gateway"]));
    for (peer, status) in [(Some("gateway"), 200), (Some("lcm"), 403), (None, 403)] {
        let resp = router.clone().oneshot(request(peer)).await.unwrap();
        assert_eq!(resp.status().as_u16(), status, "{peer:?}");
        if status != 200 {
            continue;
        }
        assert_eq!(resp.headers()["etag"], format!("\"{}\"", b.digest()).as_str());
        let body = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        let got = helpdocs::decode(&body).unwrap();
        assert_eq!(got.digest(), b.digest());
        assert_eq!(got.pages.len(), b.pages.len());
    }
}
