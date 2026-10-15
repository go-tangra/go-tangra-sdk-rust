//! End-to-end: real mTLS listeners, a test CA, the security chain, policy,
//! correlation, admin endpoints, the outbound client and cert rotation.
#![allow(clippy::expect_used, clippy::unwrap_used)]

mod common;

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use common::*;
use tangra_proto::lcm::v1::EnrollRequest;
use tangra_proto::lcm::v1::enrollment_client::EnrollmentClient;
use tangra_sdk::identity::{Reason, SpiffeId, parse_leaf};
use tangra_sdk::testutil::{IssueOptions, MemoryProvider, TestCa};
use tonic_types::StatusExt;

#[tokio::test]
async fn handshake_with_correct_spiffe_peer_succeeds() {
    let mut h = start().await;
    let gw = h.ca.issue("gateway").unwrap();
    let r = h2(h.http, &gw, "GET", "/api/orders/v1/ping", &[], "")
        .await
        .unwrap();
    assert_eq!(r.status, 200, "{}", r.body);
    let rid = r.headers["x-request-id"].to_str().unwrap().to_owned();
    assert_eq!(r.body, format!("pong spiffe://example.org/svc/gateway {rid}"));
    // The server presented the orders SVID and negotiated h2.
    let (cfg, seen) = raw_client(Some(&gw), &[b"h2"]);
    let tls = tls_connect(h.http, cfg).await.unwrap();
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
    assert_eq!(
        tls.get_ref().1.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3)
    );
    let leaf = parse_leaf(&seen.lock().unwrap()[0]).unwrap();
    assert_eq!(leaf.uris, vec!["spiffe://example.org/svc/orders".to_owned()]);
    // One request line with the slog fields.
    assert!(eventually(|| h.log.lines().iter().any(|l| l["msg"] == "request")).await);
    let line = h.log.lines().into_iter().find(|l| l["msg"] == "request").unwrap();
    assert_eq!(line["service"], "orders");
    assert_eq!(line["caller"], "gateway");
    assert_eq!(line["caller_id"], "spiffe://example.org/svc/gateway");
    assert_eq!(line["callee"], "orders");
    assert_eq!(line["operation"], "/api/orders/v1/ping");
    assert_eq!(line["outcome"], "ok");
    assert_eq!(line["correlation_id"], rid.as_str());
    assert_eq!(line["trace_id"], "");
    assert!(line["duration_ms"].is_number());
    h.stop().await;
}

async fn refused(h: &Harness, cert: Option<&tangra_sdk::testutil::Issued>) -> bool {
    let (cfg, _) = raw_client(cert, &[b"h2"]);
    // TLS 1.3: the client learns of a refused certificate on first read.
    match tls_connect(h.http, cfg).await {
        Err(_) => true,
        Ok(tls) => {
            let r = hyper::client::conn::http2::handshake(
                hyper_util::rt::TokioExecutor::new(),
                hyper_util::rt::TokioIo::new(tls),
            )
            .await;
            match r {
                Err(_) => true,
                Ok((mut s, c)) => {
                    tokio::spawn(c);
                    let req = http::Request::get("https://orders/api/orders/v1/ping")
                        .body(http_body_util::Empty::<bytes::Bytes>::new())
                        .unwrap();
                    s.send_request(req).await.is_err()
                }
            }
        }
    }
}

#[tokio::test]
async fn bad_client_identities_are_refused_at_the_handshake() {
    let mut h = start().await;
    let evil_ca = TestCa::new("evil.org").unwrap();
    let other_ca = TestCa::new(TD).unwrap();
    let with = |uris: &[&str]| IssueOptions {
        uris: Some(uris.iter().map(|s| (*s).to_owned()).collect()),
        ..IssueOptions::default()
    };
    let now = SystemTime::now();
    let cases: Vec<(&str, Option<tangra_sdk::testutil::Issued>, &str)> = vec![
        ("no client certificate", None, "no_identity"),
        (
            "wrong trust domain",
            Some(evil_ca.issue("gateway").unwrap()),
            "untrusted",
        ),
        (
            "foreign SAN from our CA",
            Some(
                h.ca.issue_with("gateway", with(&["spiffe://evil.org/svc/gateway"]))
                    .unwrap(),
            ),
            "untrusted",
        ),
        (
            "missing SAN",
            Some(h.ca.issue_with("gateway", with(&[])).unwrap()),
            "untrusted",
        ),
        (
            "two SANs",
            Some(
                h.ca.issue_with(
                    "gateway",
                    with(&[
                        "spiffe://example.org/svc/gateway",
                        "spiffe://example.org/svc/other",
                    ]),
                )
                .unwrap(),
            ),
            "untrusted",
        ),
        (
            "untrusted CA, same trust domain",
            Some(other_ca.issue("gateway").unwrap()),
            "untrusted",
        ),
        (
            "expired beyond skew",
            Some(
                h.ca.issue_with(
                    "gateway",
                    IssueOptions {
                        not_before: Some(now - Duration::from_secs(7200)),
                        not_after: Some(now - Duration::from_secs(3600)),
                        ..IssueOptions::default()
                    },
                )
                .unwrap(),
            ),
            "identity_expired",
        ),
    ];
    for (name, cert, reason) in &cases {
        assert!(refused(&h, cert.as_ref()).await, "{name}: must be refused");
        let r = *reason;
        assert!(
            eventually(|| h
                .log
                .lines()
                .iter()
                .any(|l| l["msg"] == "audit" && l["type"] == "authn_refused" && l["reason"] == r))
            .await,
            "{name}: no authn_refused audit with {reason}: {}",
            h.log.contents()
        );
    }
    h.stop().await;
}

#[tokio::test]
async fn client_pins_the_expected_peer_id() {
    let mut h = start().await;
    let ca = &h.ca;
    let me = MemoryProvider::new(ca, &ca.issue("gateway").unwrap()).unwrap();
    for (expect, ok) in [("orders", true), ("billing", false)] {
        let id = SpiffeId::new(TD, expect).unwrap();
        let cfg = tangra_sdk::tls::client_config(me.clone(), id, tangra_sdk::tls::Options::new(TD)).unwrap();
        let res = tls_connect(h.grpc, cfg).await;
        assert_eq!(res.is_ok(), ok, "expect {expect}");
        if let Err(e) = res {
            assert_eq!(tangra_sdk::tls::classify(&e), Reason::NameMismatch);
        }
    }
    // A client in another trust domain is refused by configuration.
    let id = SpiffeId::new("evil.org", "orders").unwrap();
    assert!(tangra_sdk::tls::client_config(me, id, tangra_sdk::tls::Options::new(TD)).is_err());
    h.stop().await;
}

#[tokio::test]
async fn policy_on_http() {
    let mut h = start().await;
    let gw = h.ca.issue("gateway").unwrap();
    let web = h.ca.issue("web").unwrap();
    let legacy1 = h.ca.issue("legacy-1").unwrap();
    // Allowed by operation glob.
    let r = h2(h.http, &gw, "POST", "/api/orders/v1/items", &[], "12345")
        .await
        .unwrap();
    assert_eq!((r.status, r.body.as_str()), (200, "got 5"));
    // Method outside the allowed operations.
    let r = h2(h.http, &gw, "DELETE", "/api/orders/v1/items", &[], "")
        .await
        .unwrap();
    assert_eq!((r.status, r.body.as_str()), (403, "{\"reason\":\"denied\"}\n"));
    assert_eq!(r.headers["content-type"], "application/json");
    assert!(r.headers.contains_key("x-request-id"));
    // No rule for this caller.
    let r = h2(h.http, &web, "GET", "/api/orders/v1/ping", &[], "")
        .await
        .unwrap();
    assert_eq!(r.status, 403);
    // Deny wins over a matching allow.
    let r = h2(h.http, &legacy1, "GET", "/api/orders/v1/ping", &[], "")
        .await
        .unwrap();
    assert_eq!(r.status, 403);
    // The chain runs before routing: an unknown path is denied, not 404.
    let r = h2(h.http, &web, "GET", "/nope", &[], "").await.unwrap();
    assert_eq!(r.status, 403);
    // ... and for an allowed caller it is net/http's 404.
    let r = h2(h.http, &gw, "GET", "/nope", &[], "").await.unwrap();
    assert_eq!((r.status, r.body.as_str()), (404, "404 page not found\n"));
    assert!(
        eventually(|| h.log.lines().iter().any(|l| l["msg"] == "audit"
            && l["type"] == "authz_refused"
            && l["reason"] == "explicit_deny"
            && l["rule_id"] == "legacy-deny"
            && l["policy_version"] == "test-1"))
        .await
    );
    let refused_line = h
        .log
        .lines()
        .into_iter()
        .find(|l| l["msg"] == "request" && l["caller"] == "web")
        .unwrap();
    assert_eq!(refused_line["outcome"], "authz_refused");
    h.stop().await;
}

#[tokio::test]
async fn policy_on_grpc() {
    let mut h = start().await;
    let gw = h.ca.issue("gateway").unwrap();
    let web = h.ca.issue("web").unwrap();
    let mut ok = EnrollmentClient::new(grpc_channel(h.grpc, &gw));
    let r = ok.enroll(EnrollRequest::default()).await.unwrap();
    assert_eq!(r.get_ref().cert_pem, "spiffe://example.org/svc/gateway");
    assert!(r.metadata().get("x-request-id").is_some());
    let mut denied = EnrollmentClient::new(grpc_channel(h.grpc, &web));
    let st = denied.enroll(EnrollRequest::default()).await.unwrap_err();
    assert_eq!(st.code(), tonic::Code::PermissionDenied);
    assert_eq!(st.message(), "");
    assert_eq!(st.get_details_error_info().unwrap().reason, "denied");
    // A handler error is logged with its outcome when the trailers arrive.
    let st = ok
        .enroll(EnrollRequest {
            tenant_id: "fail".into(),
            ..EnrollRequest::default()
        })
        .await
        .unwrap_err();
    assert_eq!(st.code(), tonic::Code::NotFound);
    assert!(
        eventually(|| h.log.lines().iter().any(|l| l["msg"] == "request"
            && l["operation"] == "/lcm.v1.Enrollment/Enroll"
            && l["caller"] == "web"
            && l["outcome"] == "authz_refused"))
        .await
    );
    assert!(
        eventually(|| h
            .log
            .lines()
            .iter()
            .any(|l| l["msg"] == "request" && l["caller"] == "gateway" && l["outcome"] == "error"))
        .await
    );
    // A gRPC client must negotiate h2 by ALPN.
    let (cfg, _) = raw_client(Some(&gw), &[]);
    let tls = tls_connect(h.grpc, cfg).await;
    if let Ok(mut s) = tls {
        use tokio::io::AsyncReadExt;
        let mut b = [0u8; 1];
        assert!(
            matches!(s.read(&mut b).await, Ok(0) | Err(_)),
            "no-ALPN connection must be closed"
        );
    }
    h.stop().await;
}

#[tokio::test]
async fn correlation_header_rules() {
    let mut h = start().await;
    let gw = h.ca.issue("gateway").unwrap();
    let r = h2(
        h.http,
        &gw,
        "GET",
        "/api/orders/v1/ping",
        &[("x-request-id", "abc.DEF_1-2")],
        "",
    )
    .await
    .unwrap();
    assert_eq!(r.headers["x-request-id"], "abc.DEF_1-2");
    let r = h2(
        h.http,
        &gw,
        "GET",
        "/api/orders/v1/ping",
        &[("x-request-id", "bad id!")],
        "",
    )
    .await
    .unwrap();
    let id = r.headers["x-request-id"].to_str().unwrap();
    assert!(id != "bad id!" && id.len() == 36 && &id[14..15] == "7", "{id}");
    let r = h2(h.http, &gw, "GET", "/api/orders/v1/ping", &[], "")
        .await
        .unwrap();
    assert_eq!(r.headers["x-request-id"].len(), 36);
    // The trace id of an incoming traceparent lands in the request log.
    let tp = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
    h2(
        h.http,
        &gw,
        "GET",
        "/api/orders/v1/ping",
        &[("traceparent", tp), ("x-request-id", "trace-1")],
        "",
    )
    .await
    .unwrap();
    assert!(
        eventually(|| h.log.lines().iter().any(|l| l["msg"] == "request"
            && l["correlation_id"] == "trace-1"
            && l["trace_id"] == "4bf92f3577b34da6a3ce929d0e0e4736"))
        .await
    );
    h.stop().await;
}

#[tokio::test]
async fn outbound_client_verifies_callee_and_propagates_correlation() {
    // Discovery points at the app's own gRPC listener (a free port).
    let ca = TestCa::new(TD).unwrap();
    let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);
    let mut h = start_with(ca, None, |c| {
        c.server.grpc_addr = format!("127.0.0.1:{port}");
        c.discovery
            .r#static
            .insert("orders".into(), vec![format!("127.0.0.1:{port}")]);
        c.discovery
            .r#static
            .insert("billing".into(), vec![format!("127.0.0.1:{port}")]);
    })
    .await;
    let gw = h.ca.issue("gateway").unwrap();
    let r = h2(
        h.http,
        &gw,
        "GET",
        "/api/orders/v1/outbound",
        &[("x-request-id", "corr-42")],
        "",
    )
    .await
    .unwrap();
    assert_eq!(r.body, "outbound spiffe://example.org/svc/orders");
    let seen = h.seen.lock().unwrap().clone();
    assert_eq!(
        seen.request_ids,
        vec!["corr-42".to_owned()],
        "x-request-id propagated"
    );
    // billing resolves to the same address, but the peer is not svc/billing.
    let ch = h.app.client("billing").unwrap();
    let st = EnrollmentClient::new(ch)
        .enroll(EnrollRequest::default())
        .await
        .unwrap_err();
    assert_eq!(st.code(), tonic::Code::Unavailable, "{st}");
    assert!(
        eventually(|| h.log.lines().iter().any(|l| l["type"] == "authn_refused"
            && l["reason"] == "name_mismatch"
            && l["operation"] == "dial spiffe://example.org/svc/billing"))
        .await
    );
    assert!(h.app.client("unknown").is_err());
    assert!(h.app.client("Bad_Name").is_err());
    h.stop().await;
}

#[tokio::test]
async fn admin_endpoints() {
    let mut h = start().await;
    let gw = h.ca.issue("gateway").unwrap();
    h2(h.http, &gw, "GET", "/api/orders/v1/ping", &[], "")
        .await
        .unwrap();
    assert!(eventually(|| h.app.ready()).await);
    let get = |path: &str| {
        let url = format!("{}{path}", h.admin);
        async move {
            let uri: http::Uri = url.parse().unwrap();
            let addr = format!("{}:{}", uri.host().unwrap(), uri.port_u16().unwrap());
            let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
            let (mut s, c) = hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tcp))
                .await
                .unwrap();
            tokio::spawn(c);
            let req = http::Request::get(uri.path())
                .header("host", "admin")
                .body(http_body_util::Empty::<bytes::Bytes>::new())
                .unwrap();
            let r = s.send_request(req).await.unwrap();
            let status = r.status().as_u16();
            let ct = r
                .headers()
                .get("content-type")
                .map(|v| v.to_str().unwrap().to_owned())
                .unwrap_or_default();
            use http_body_util::BodyExt;
            let body = String::from_utf8(r.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap();
            (status, ct, body)
        }
    };
    assert!(h.admin.starts_with("http://127.0.0.1:"));
    assert_eq!(
        get("/healthz").await,
        (200, "text/plain; charset=utf-8".into(), "ok\n".into())
    );
    assert_eq!(get("/readyz").await.2, "ready\n");
    let (st, ct, body) = get("/metrics").await;
    assert_eq!(
        (st, ct.as_str()),
        (200, "text/plain; version=0.0.4; charset=utf-8")
    );
    assert!(body.starts_with("# HELP freya_up Always 1 while the admin listener serves.\n"));
    assert!(
        body.contains("freya_calls_total{outcome=\"ok\",peer=\"gateway\"} 1\n"),
        "{body}"
    );
    assert!(body.contains("freya_call_duration_seconds_count{outcome=\"ok\",peer=\"gateway\"} 1\n"));
    assert_eq!(get("/nope").await.0, 404);
    h.stop().await;
    assert!(!h.app.ready(), "closed apps are not ready");
}

#[tokio::test]
async fn admin_must_be_loopback_unless_allowed() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = base_config(dir.path());
    cfg.admin.addr = "0.0.0.0:0".into();
    let ca = TestCa::new(TD).unwrap();
    let p = MemoryProvider::new(&ca, &ca.issue("orders").unwrap()).unwrap();
    let e = tangra_sdk::app::App::builder(cfg.clone())
        .identity_provider(p.clone())
        .build()
        .await
        .unwrap_err();
    assert!(e.0.contains("allow_non_loopback"), "{e}");
    cfg.admin.allow_non_loopback = true;
    let app = tangra_sdk::app::App::builder(cfg)
        .identity_provider(p)
        .logger(tangra_sdk::log::Logger::new(
            std::io::sink(),
            tangra_sdk::log::Level::Info,
        ))
        .build()
        .await
        .unwrap();
    assert!(app.admin_url().starts_with("https://"), "{}", app.admin_url());
    app.close().await;
}

#[tokio::test]
async fn startup_refusals() {
    let ca = TestCa::new(TD).unwrap();
    let dir = tempfile::tempdir().unwrap();
    // Identity for another service.
    let cfg = base_config(dir.path());
    let p = MemoryProvider::new(&ca, &ca.issue("billing").unwrap()).unwrap();
    let e = tangra_sdk::app::App::builder(cfg.clone())
        .identity_provider(p)
        .build()
        .await
        .unwrap_err();
    assert!(e.0.contains("does not match configured service"), "{e}");
    // Allow-all in production.
    let mut prod = cfg.clone();
    prod.env = "production".into();
    let p = MemoryProvider::new(&ca, &ca.issue("orders").unwrap()).unwrap();
    let e = tangra_sdk::app::App::builder(prod)
        .identity_provider(p.clone())
        .allow_all_policy()
        .build()
        .await
        .unwrap_err();
    assert!(e.0.contains("refused when env is production"), "{e}");
    // Invalid discovery.
    let mut bad = cfg.clone();
    bad.discovery
        .r#static
        .insert("auth".into(), vec!["https://auth:1".into()]);
    let e = tangra_sdk::app::App::builder(bad)
        .identity_provider(p.clone())
        .build()
        .await
        .unwrap_err();
    assert!(e.0.contains("without scheme"), "{e}");
    // Missing policy file.
    let mut nopol = cfg;
    nopol.authz.path = dir.path().join("missing.yaml").display().to_string();
    assert!(
        tangra_sdk::app::App::builder(nopol)
            .identity_provider(p)
            .build()
            .await
            .is_err()
    );
}

#[tokio::test]
async fn limits_recovery_and_timeouts() {
    let mut h = start_with(TestCa::new(TD).unwrap(), None, |c| {
        c.limits.max_request_bytes = 16;
        c.limits.request_timeout = tangra_sdk::GoDuration::from_secs(1);
    })
    .await;
    let gw = h.ca.issue("gateway").unwrap();
    let r = h2(h.http, &gw, "POST", "/api/orders/v1/items", &[], &"x".repeat(64))
        .await
        .unwrap();
    assert_eq!(r.status, 413, "{}", r.body);
    assert!(
        eventually(|| h
            .log
            .lines()
            .iter()
            .any(|l| l["type"] == "limit_exceeded" && l["attr_limit"] == "request_body"))
        .await
    );
    let r = h2(h.http, &gw, "GET", "/api/orders/v1/panic", &[], "")
        .await
        .unwrap();
    assert_eq!((r.status, r.body.as_str()), (500, "{\"reason\":\"internal\"}\n"));
    let r = h2(h.http, &gw, "GET", "/api/orders/v1/slow", &[], "")
        .await
        .unwrap();
    assert_eq!((r.status, r.body.as_str()), (504, "{\"reason\":\"timeout\"}\n"));
    // The server is still healthy afterwards.
    let r = h2(h.http, &gw, "GET", "/api/orders/v1/ping", &[], "")
        .await
        .unwrap();
    assert_eq!(r.status, 200);
    h.stop().await;
}

#[tokio::test]
async fn certificate_rotation_without_restart() {
    let ca = TestCa::new(TD).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let first = ca.issue("orders").unwrap();
    std::fs::write(dir.path().join("cert.pem"), &first.cert_pem).unwrap();
    std::fs::write(dir.path().join("key.pem"), &first.key_pem).unwrap();
    std::fs::write(dir.path().join("bundle.pem"), ca.bundle_pem()).unwrap();
    let fp = tangra_sdk::identity::file::FileProvider::new(tangra_sdk::identity::file::FileConfig {
        cert: dir.path().join("cert.pem"),
        key: dir.path().join("key.pem"),
        bundle: dir.path().join("bundle.pem"),
        trust_domain: TD.into(),
        poll_interval: Duration::from_millis(50),
    })
    .unwrap();
    let mut h = start_with(ca, Some(fp), |_| {}).await;
    let gw = h.ca.issue("gateway").unwrap();
    let serial_of = |h: &Harness, gw| {
        let addr = h.http;
        async move {
            let (cfg, seen) = raw_client(Some(gw), &[b"h2"]);
            let _ = tls_connect(addr, cfg).await.unwrap();
            let der = seen.lock().unwrap()[0].clone();
            parse_leaf(&der).unwrap().serial
        }
    };
    let before = serial_of(&h, &gw).await;
    // A long-lived connection opened before the rotation keeps working.
    let mut ch = EnrollmentClient::new(grpc_channel(h.grpc, &gw));
    ch.enroll(EnrollRequest::default()).await.unwrap();
    let second = h.ca.issue("orders").unwrap();
    let tmp = dir.path().join("key.tmp");
    std::fs::write(&tmp, &second.key_pem).unwrap();
    std::fs::write(dir.path().join("cert.pem"), &second.cert_pem).unwrap();
    std::fs::rename(&tmp, dir.path().join("key.pem")).unwrap();
    let mut after = before.clone();
    for _ in 0..100 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        after = serial_of(&h, &gw).await;
        if after != before {
            break;
        }
    }
    assert_ne!(after, before, "new handshakes present the rotated certificate");
    assert_eq!(after, parse_leaf(&second.cert_der).unwrap().serial);
    ch.enroll(EnrollRequest::default()).await.unwrap();
    assert!(
        eventually(|| h.log.lines().iter().any(|l| l["msg"] == "identity renewed")).await,
        "{}",
        h.log.contents()
    );
    assert_eq!(h.app.identity().unwrap().serial, after);
    h.stop().await;
}

#[tokio::test]
async fn ready_hook_runs_after_ready_and_stops_on_shutdown() {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let f2 = Arc::clone(&flag);
    let ca = TestCa::new(TD).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let cfg = base_config(dir.path());
    let p = MemoryProvider::new(&ca, &ca.issue("orders").unwrap()).unwrap();
    let app = tangra_sdk::app::App::builder(cfg)
        .identity_provider(p)
        .logger(tangra_sdk::log::Logger::new(
            std::io::sink(),
            tangra_sdk::log::Level::Info,
        ))
        .build()
        .await
        .unwrap();
    app.on_ready(move |app, stop| async move {
        f2.store(app.ready(), std::sync::atomic::Ordering::SeqCst);
        let _ = tx.send(());
        stop.cancelled().await;
    });
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let a2 = app.clone();
    let run = tokio::spawn(async move {
        a2.run_until(tangra_sdk::app::Services::new(), async {
            let _ = stop_rx.await;
        })
        .await
    });
    tokio::time::timeout(Duration::from_secs(5), rx)
        .await
        .unwrap()
        .unwrap();
    assert!(flag.load(std::sync::atomic::Ordering::SeqCst));
    assert!(app.http_url().unwrap().starts_with("https://127.0.0.1:"));
    assert!(app.grpc_target().unwrap().starts_with("127.0.0.1:"));
    stop_tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(15), run)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}
