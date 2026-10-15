//! Platform integration over the SDK's own mTLS: in-process fake `gateway`
//! (gateway.v1.Registry) and `auth` (auth.v1.Keys, Sessions, Authorization,
//! Profiles) services, each a real App with its own SPIFFE identity, and an
//! `orders` module App wired with `gateway_registration`, `user_auth` and
//! `auth_registration`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::type_complexity)]

mod common;

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::json;
use tangra_proto::auth::v1 as apb;
use tangra_proto::auth::v1::authorization_server::AuthorizationServer;
use tangra_proto::auth::v1::keys_server::KeysServer;
use tangra_proto::auth::v1::profiles_server::ProfilesServer;
use tangra_proto::auth::v1::sessions_server::SessionsServer;
use tangra_proto::gateway::v1::registry_server::RegistryServer;
use tangra_sdk::app::{App, ServiceConn, Services};
use tangra_sdk::auth::{
    self, AuthzClient, ModuleRole, Permission, Registration, TestSigner, User, UserAuthLayer, VerifyError,
};
use tangra_sdk::config::{Config, NoModule};
use tangra_sdk::gateway;
use tangra_sdk::log::{Capture, Level, Logger};
use tangra_sdk::manifest::{Manifest, Route};
use tangra_sdk::testutil::platform::{FakeAuth, FakeGateway};
use tangra_sdk::testutil::{MemoryProvider, TestCa};
use tokio::sync::oneshot;

const TD: &str = "example.org";
const ISS: &str = "https://auth.example.org";

// --- harness ---------------------------------------------------------------

struct Running {
    app: App,
    stop: Option<oneshot::Sender<()>>,
    done: Option<tokio::task::JoinHandle<()>>,
    log: Capture,
    _dir: tempfile::TempDir,
}

impl Running {
    async fn stop(&mut self) {
        if let Some(s) = self.stop.take() {
            let _ = s.send(());
        }
        if let Some(d) = self.done.take() {
            tokio::time::timeout(Duration::from_secs(20), d)
                .await
                .unwrap()
                .unwrap();
        }
    }
}

async fn build(
    ca: &TestCa,
    name: &str,
    discovery: &[(&str, SocketAddr)],
) -> (App, Capture, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let mut yaml = format!(
        "service_name: {name}\ntrust_domain: {TD}\nidentity: {{provider: provided}}\n\
server: {{grpc_addr: \"127.0.0.1:0\", http_addr: \"127.0.0.1:0\"}}\nadmin: {{addr: \"127.0.0.1:0\"}}\n"
    );
    if !discovery.is_empty() {
        yaml.push_str("discovery:\n  static:\n");
        for (svc, addr) in discovery {
            yaml.push_str(&format!("    {svc}: [\"{addr}\"]\n"));
        }
    }
    let cfg = Config::<NoModule>::from_yaml(yaml.as_bytes()).unwrap().framework;
    let log = Capture::new();
    let app = App::builder(cfg)
        .identity_provider(MemoryProvider::new(ca, &ca.issue(name).unwrap()).unwrap())
        .allow_all_policy()
        .logger(Logger::new(log.clone(), Level::Debug))
        .build()
        .await
        .unwrap();
    (app, log, dir)
}

fn run(app: App, log: Capture, dir: tempfile::TempDir, services: Services) -> Running {
    let (tx, rx) = oneshot::channel::<()>();
    let a = app.clone();
    let done = tokio::spawn(async move {
        a.run_until(services, async {
            let _ = rx.await;
        })
        .await
        .unwrap();
    });
    Running {
        app,
        stop: Some(tx),
        done: Some(done),
        log,
        _dir: dir,
    }
}

struct Platform {
    ca: TestCa,
    gw: FakeGateway,
    auth: FakeAuth,
    gw_app: Running,
    auth_app: Running,
}

async fn platform() -> Platform {
    let ca = TestCa::new(TD).unwrap();
    let gw = FakeGateway::default();
    let auth = FakeAuth::default();
    let (gapp, glog, gdir) = build(&ca, "gateway", &[]).await;
    let gw_app = run(
        gapp,
        glog,
        gdir,
        Services::new().grpc(tonic::service::Routes::new(RegistryServer::new(gw.clone()))),
    );
    let (aapp, alog, adir) = build(&ca, "auth", &[]).await;
    let routes = tonic::service::Routes::new(KeysServer::new(auth.clone()))
        .add_service(SessionsServer::new(auth.clone()))
        .add_service(AuthorizationServer::new(auth.clone()))
        .add_service(ProfilesServer::new(auth.clone()));
    let auth_app = run(aapp, alog, adir, Services::new().grpc(routes));
    Platform {
        ca,
        gw,
        auth,
        gw_app,
        auth_app,
    }
}

async fn module(p: &Platform) -> (App, Capture, tempfile::TempDir) {
    build(
        &p.ca,
        "orders",
        &[
            ("gateway", p.gw_app.app.grpc_local_addr().unwrap()),
            ("auth", p.auth_app.app.grpc_local_addr().unwrap()),
        ],
    )
    .await
}

fn manifest() -> Manifest {
    Manifest::new("orders", "Orders", "1.0.0")
        .prefix("/api/orders")
        .permission("orders", "read", "Read orders")
        .route(Route::protected("GET", "/api/orders/v1/me", "orders:read"))
        .exposes(["./routes"])
}

async fn eventually(mut f: impl FnMut() -> bool) -> bool {
    for _ in 0..400 {
        if f() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    false
}

fn now_secs() -> i64 {
    i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()).unwrap()
}

// --- tests -----------------------------------------------------------------

/// Register → renew → re-register on NotFound → deregister on shutdown.
#[tokio::test]
async fn gateway_lease_lifecycle() {
    let mut p = platform().await;
    let (app, log, dir) = module(&p).await;
    gateway::set_build_version("1.2.3");
    app.gateway_registration(manifest()).unwrap();
    let mut m = run(app.clone(), log, dir, Services::new());
    assert!(eventually(|| p.gw.counts().1 >= 2).await, "renewals");
    let last = p.gw.0.lock().unwrap().last.clone().unwrap();
    assert_eq!(last.manifest.as_ref().unwrap().module, "orders");
    assert_eq!(
        last.manifest.unwrap().remote.unwrap().entry,
        "/m/orders/mf-manifest.json"
    );
    let backend = last.backend.unwrap();
    assert_eq!(Some(backend.http_url), app.http_url());
    assert_eq!(Some(backend.grpc_target), app.grpc_target());
    assert_eq!(last.instance_id.len(), 32);
    assert_eq!(last.build_version, "1.2.3");
    assert_eq!(p.gw.0.lock().unwrap().peers[0], "spiffe://example.org/svc/orders");
    // The gateway forgets the lease: the module registers again (after 1s).
    p.gw.0.lock().unwrap().renew_err = Some(tonic::Status::not_found("unknown_lease"));
    assert!(eventually(|| p.gw.counts().0 >= 2).await, "re-register");
    p.gw.0.lock().unwrap().renew_err = None;
    let instance = p.gw.0.lock().unwrap().last.clone().unwrap().instance_id;
    assert_eq!(instance, last.instance_id, "stable instance id");
    assert!(eventually(|| p.gw.counts().1 >= 4).await);
    m.stop().await;
    assert_eq!(p.gw.counts().2, 1, "deregistered on shutdown");
    assert!(m.log.contents().contains("\"msg\":\"gateway lease\""));
    gateway::set_build_version("");
    p.gw_app.stop().await;
    p.auth_app.stop().await;
}

/// Permanent refusals switch to the maximum backoff and report `refused`.
#[tokio::test]
async fn gateway_permanent_refusal() {
    let mut p = platform().await;
    p.gw.0.lock().unwrap().refuse = Some(tonic::Status::permission_denied("prefix_not_granted"));
    let (app, log, dir) = module(&p).await;
    let states = Arc::new(Mutex::new(Vec::<gateway::State>::new()));
    let st = Arc::clone(&states);
    app.gateway_registration_with(
        "gateway",
        gateway::Options {
            manifest: manifest(),
            max_backoff: Duration::from_millis(300),
            on_state: Some(Arc::new(move |s: &gateway::State| {
                st.lock().unwrap().push(s.clone())
            })),
            ..gateway::Options::default()
        },
    )
    .unwrap();
    let mut m = run(app, log, dir, Services::new());
    assert!(eventually(|| p.gw.counts().0 >= 3).await);
    let s = states.lock().unwrap().last().cloned().unwrap();
    let e = s.err.unwrap();
    assert!(e.refused && e.code == tonic::Code::PermissionDenied && e.message == "prefix_not_granted");
    m.stop().await;
    assert_eq!(p.gw.counts().2, 0, "nothing to deregister");
    p.gw_app.stop().await;
    p.auth_app.stop().await;
}

/// A manifest the gateway would refuse fails at wiring time.
#[tokio::test]
async fn gateway_registration_validates_manifest() {
    let mut p = platform().await;
    let (app, _log, _dir) = module(&p).await;
    let bad = manifest().route(Route::protected("GET", "/api/orders/v1/x", "orders:write"));
    let e = app.gateway_registration(bad).unwrap_err();
    assert!(e.0.contains("undeclared permission"), "{e}");
    let digest = gateway::Options {
        manifest: manifest(),
        docs_digest: "nope".into(),
        ..gateway::Options::default()
    };
    assert!(app.gateway_registration_with("gateway", digest).is_err());
    app.close().await;
    p.gw_app.stop().await;
    p.auth_app.stop().await;
}

/// The JWT matrix with keys and revocations fetched over mTLS.
#[tokio::test]
async fn user_auth_over_mtls() {
    let mut p = platform().await;
    let k1 = TestSigner::new("k1").unwrap();
    let k2 = TestSigner::new("k2").unwrap();
    p.auth.set_keys(&[&k1]);
    let (app, log, dir) = module(&p).await;
    let v = app
        .user_auth(auth::Config {
            issuer: ISS.into(),
            revocation_poll: Duration::from_millis(100),
            ..auth::Config::default()
        })
        .unwrap();
    let router = axum::Router::new()
        .route(
            "/api/orders/v1/me",
            axum::routing::get(
                |u: User| async move { format!("{} {} {}", u.user_id, u.tenant_id, u.is_admin()) },
            ),
        )
        .layer(UserAuthLayer::new(Arc::clone(&v)));
    let mut m = run(app.clone(), log, dir, Services::new().http(router));
    assert!(
        eventually(|| v.keys_fetched_at().is_some()).await,
        "keys fetched over mTLS"
    );
    let now = now_secs();
    let claims = || TestSigner::claims(ISS, "u1", "t1", "s1", now, 600);
    let tok = k1.mint(&claims());

    // Through the module's HTTP server, as the gateway would call it.
    let gw_cert = p.ca.issue("gateway").unwrap();
    let addr = app.http_local_addr().unwrap();
    let get = |auth: Option<String>| {
        let gw_cert = &gw_cert;
        async move {
            let h: Vec<(&str, &str)> = auth
                .as_deref()
                .map(|a| vec![("authorization", a)])
                .unwrap_or_default();
            common::h2(addr, gw_cert, "GET", "/api/orders/v1/me", &h, "")
                .await
                .unwrap()
        }
    };
    let r = get(Some(format!("Bearer {tok}"))).await;
    assert_eq!((r.status, r.body.as_str()), (200, "u1 t1 true"));
    let r = get(None).await;
    assert_eq!(r.status, 401);
    assert_eq!(r.headers["www-authenticate"], "Bearer realm=\"freya\"");
    assert_eq!(r.body, r#"{"reason":"unauthenticated"}"#);

    // The refusal matrix.
    let with = |f: &dyn Fn(&mut serde_json::Value)| {
        let mut c = claims();
        f(&mut c);
        k1.mint(&c)
    };
    for (name, t) in [
        (
            "alg HS256",
            k1.sign_raw(&json!({"alg": "HS256", "kid": "k1"}), &claims()),
        ),
        ("kid missing", k1.sign_raw(&json!({"alg": "EdDSA"}), &claims())),
        ("wrong issuer", with(&|c| c["iss"] = json!("https://evil"))),
        (
            "expired",
            with(&|c| {
                c["iat"] = json!(now - 1000);
                c["nbf"] = json!(now - 1000);
                c["exp"] = json!(now - 120);
            }),
        ),
        ("nbf future", with(&|c| c["nbf"] = json!(now + 120))),
        ("lifetime too long", with(&|c| c["exp"] = json!(now + 901))),
        ("oversized", with(&|c| c["pad"] = json!("x".repeat(9000)))),
    ] {
        assert!(
            matches!(v.verify(&t).await, Err(VerifyError::Unauthenticated(_))),
            "{name}"
        );
    }

    // Unknown kid: auth rotated to k2; the first unknown kid refreshes.
    let calls = p.auth.0.lock().unwrap().key_calls;
    p.auth.set_keys(&[&k1, &k2]);
    let t2 = k2.mint(&claims());
    assert!(v.verify(&t2).await.is_ok(), "refreshed on unknown kid");
    assert_eq!(p.auth.0.lock().unwrap().key_calls, calls + 1);
    let t3 = TestSigner::new("k3").unwrap().mint(&claims());
    assert!(v.verify(&t3).await.is_err());
    assert_eq!(
        p.auth.0.lock().unwrap().key_calls,
        calls + 1,
        "capped at one refresh a minute"
    );
    let in_a_minute = SystemTime::now() + Duration::from_secs(61);
    v.set_clock(move || in_a_minute);
    assert!(v.verify(&t3).await.is_err());
    assert_eq!(
        p.auth.0.lock().unwrap().key_calls,
        calls + 2,
        "refreshed again after the cap"
    );
    v.set_clock(SystemTime::now);

    // Revocations, polled every 100ms.
    let session = |sid: &str| k1.mint(&TestSigner::claims(ISS, "u1", "t1", sid, now, 600));
    let user = |sub: &str, tid: &str| k1.mint(&TestSigner::claims(ISS, sub, tid, "sx", now, 600));
    p.auth.revoke("session", "s-dead", "");
    p.auth.revoke("user", "u-dead", "t1");
    p.auth.revoke("tenant", "t-dead", "");
    let (ts, tu, tt) = (session("s-dead"), user("u-dead", "t1"), user("u9", "t-dead"));
    assert!(eventually(|| p.auth.0.lock().unwrap().rev_calls >= 3).await);
    for (name, t) in [("session", &ts), ("user", &tu), ("tenant", &tt)] {
        let mut revoked = false;
        for _ in 0..40 {
            if v.verify(t).await == Err(VerifyError::Revoked) {
                revoked = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(revoked, "{name} revocation");
    }
    assert_eq!(get(Some(format!("Bearer {ts}"))).await.status, 401);
    assert!(
        v.verify(&user("u-dead", "t2")).await.is_ok(),
        "user revocation is per tenant"
    );
    assert!(v.verify(&tok).await.is_ok());

    // Stale feed: auth's feed is down and an hour passes: fail closed.
    p.auth.0.lock().unwrap().rev_fail = true;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let later = SystemTime::now() + Duration::from_secs(61 * 60);
    v.set_clock(move || later);
    let fresh = k1.mint(&TestSigner::claims(ISS, "u1", "t1", "s1", now + 61 * 60, 600));
    assert_eq!(v.verify(&fresh).await, Err(VerifyError::Stale));
    assert_eq!(get(Some(format!("Bearer {fresh}"))).await.status, 401);
    m.stop().await;
    p.gw_app.stop().await;
    p.auth_app.stop().await;
}

fn registration() -> Registration {
    Registration {
        module: "orders".into(),
        display_name: "Orders".into(),
        permissions: vec![Permission {
            resource: "orders".into(),
            action: "read".into(),
            description: "Read orders".into(),
        }],
        roles: vec![ModuleRole {
            slug: "viewer".into(),
            display_name: " Orders viewer ".into(),
            description: String::new(),
            permissions: vec!["orders:orders:read".into()],
        }],
        builtin_grants: BTreeMap::from([("member".to_owned(), vec!["orders:read".to_owned()])]),
        declares_grants: true,
        tenant_ids: vec![],
    }
}

/// Retry until auth accepts, then refresh periodically; stop on shutdown.
#[tokio::test]
async fn auth_registration_loop() {
    let mut p = platform().await;
    p.auth.0.lock().unwrap().register_fail_first = 2;
    let (app, log, dir) = module(&p).await;
    assert!(
        app.auth_registration(Registration::default()).is_err(),
        "validated up front"
    );
    app.auth_registration_every(
        registration(),
        Duration::from_millis(200),
        Duration::from_millis(600),
    );
    let mut m = run(app, log, dir, Services::new());
    let n = || p.auth.0.lock().unwrap().registers.len();
    assert!(eventually(|| n() >= 3).await, "two failures then success");
    let first_ok = std::time::Instant::now();
    assert!(eventually(|| n() >= 4).await, "periodic refresh");
    assert!(
        first_ok.elapsed() >= Duration::from_millis(400),
        "refresh waits the period"
    );
    {
        let a = p.auth.0.lock().unwrap();
        let (peer, req) = &a.registers[2];
        assert_eq!(peer, "spiffe://example.org/svc/orders");
        assert_eq!(req.module, "orders");
        assert!(req.declares_roles && req.declares_builtin_grants);
        assert_eq!(req.roles[0].display_name, "Orders viewer");
        assert_eq!(req.roles[0].permissions, ["orders:read"]);
        assert_eq!(req.builtin_grants[0].role, "member");
    }
    let logs = m.log.contents();
    assert!(logs.contains("auth registration failed; retrying"));
    assert!(logs.contains("auth registration: built-in grant skipped"));
    m.stop().await;
    let after = n();
    tokio::time::sleep(Duration::from_millis(800)).await;
    assert_eq!(n(), after, "loop stopped with the app");
    p.gw_app.stop().await;
    p.auth_app.stop().await;
}

/// Authorization/Check, BatchCheck and Profiles/ListMembers over mTLS.
#[tokio::test]
async fn authz_client_calls() {
    let mut p = platform().await;
    let (app, _log, _dir) = module(&p).await;
    let c = AuthzClient::new(ServiceConn::app(&app, "auth"));
    let r = c
        .check(apb::CheckRequest {
            tenant_id: "t1".into(),
            user_id: "u1".into(),
            resource: "jobs".into(),
            action: "read".into(),
            module: "orders".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(r.allowed && r.reason == "role:admin" && r.policy_version == "7");
    let r = c
        .batch_check(apb::BatchCheckRequest {
            tenant_id: "t1".into(),
            user_id: "u1".into(),
            permissions: vec![apb::PermissionRef::default(); 3],
        })
        .await
        .unwrap();
    assert_eq!(
        r.results.iter().map(|x| x.allowed).collect::<Vec<_>>(),
        [true, false, true]
    );
    assert_eq!(
        c.list_members("t1").await.unwrap(),
        ["u1", "u2", "u3", "u4", "u5"]
    );
    app.close().await;
    p.gw_app.stop().await;
    p.auth_app.stop().await;
}
