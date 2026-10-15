//! Ports of gatewayclient `client_test.go`, `docs_test.go`,
//! `version_test.go` (over a plain in-process channel, like Go's bufconn).

use std::sync::{Arc, Mutex};
use std::time::Duration;

use tangra_proto::gateway::v1::registry_server::{Registry, RegistryServer};

use super::*;
use crate::manifest::{Manifest, Route};

#[derive(Default)]
struct Fake {
    registers: u32,
    renews: u32,
    deregisters: u32,
    refuse: Option<tonic::Status>,
    renew_err: Option<tonic::Status>,
    last: Option<pb::RegisterRequest>,
}

#[derive(Clone, Default)]
struct FakeRegistry(Arc<Mutex<Fake>>);

fn dur(ms: u64) -> Option<prost_types::Duration> {
    Some(prost_types::Duration {
        seconds: i64::try_from(ms / 1000).unwrap_or(0),
        nanos: i32::try_from((ms % 1000) * 1_000_000).unwrap_or(0),
    })
}

#[tonic::async_trait]
impl Registry for FakeRegistry {
    async fn register(
        &self,
        r: tonic::Request<pb::RegisterRequest>,
    ) -> Result<tonic::Response<pb::Lease>, tonic::Status> {
        let mut f = self.0.lock().unwrap();
        f.registers += 1;
        let r = r.into_inner();
        let module = r.manifest.as_ref().map(|m| m.module.clone()).unwrap_or_default();
        f.last = Some(r);
        if let Some(s) = &f.refuse {
            return Err(s.clone());
        }
        Ok(tonic::Response::new(pb::Lease {
            lease_id: "L1".into(),
            ttl: dur(90),
            renew_every: dur(30),
            module,
            registry_version: 1,
        }))
    }

    async fn renew(
        &self,
        r: tonic::Request<pb::RenewRequest>,
    ) -> Result<tonic::Response<pb::Lease>, tonic::Status> {
        let mut f = self.0.lock().unwrap();
        f.renews += 1;
        if let Some(s) = &f.renew_err {
            return Err(s.clone());
        }
        Ok(tonic::Response::new(pb::Lease {
            lease_id: r.into_inner().lease_id,
            ttl: dur(90),
            renew_every: dur(30),
            module: "orders".into(),
            registry_version: 2,
        }))
    }

    async fn deregister(
        &self,
        _: tonic::Request<pb::DeregisterRequest>,
    ) -> Result<tonic::Response<pb::DeregisterResponse>, tonic::Status> {
        self.0.lock().unwrap().deregisters += 1;
        Ok(tonic::Response::new(pb::DeregisterResponse {}))
    }

    type WatchStream = futures_util::stream::Empty<Result<pb::RegistryEvent, tonic::Status>>;

    async fn watch(
        &self,
        _: tonic::Request<pb::WatchRequest>,
    ) -> Result<tonic::Response<Self::WatchStream>, tonic::Status> {
        Err(tonic::Status::unimplemented("watch"))
    }
}

impl FakeRegistry {
    fn counts(&self) -> (u32, u32, u32) {
        let f = self.0.lock().unwrap();
        (f.registers, f.renews, f.deregisters)
    }
}

async fn dial(f: &FakeRegistry) -> ServiceConn {
    let lis = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = lis.local_addr().unwrap();
    let svc = RegistryServer::new(f.clone());
    let incoming = futures_util::stream::unfold(lis, |lis| async move {
        let r = lis.accept().await.map(|(s, _)| s);
        Some((r, lis))
    });
    tokio::spawn(async move {
        let _ = tonic::transport::Server::builder()
            .add_service(svc)
            .serve_with_incoming(incoming)
            .await;
    });
    let ch = tonic::transport::Endpoint::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect_lazy();
    ServiceConn::channel(ch)
}

fn manifest() -> Manifest {
    Manifest::new("orders", "Orders", "1.0.0")
        .prefix("/api/orders")
        .permission("orders", "read", "Read")
        .route(Route {
            timeout: Duration::from_secs(5),
            ..Route::protected("GET", "/api/orders", "orders:read")
        })
        .route(Route::public("GET", "/api/orders/health"))
        .exposes(["./routes"])
}

async fn eventually(mut f: impl FnMut() -> bool) -> bool {
    for _ in 0..300 {
        if f() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    false
}

fn spawn(
    c: &Arc<Client>,
) -> (
    CancellationToken,
    tokio::task::JoinHandle<Result<(), GatewayError>>,
) {
    let stop = CancellationToken::new();
    let (c2, s2) = (Arc::clone(c), stop.clone());
    (stop, tokio::spawn(async move { c2.run(s2).await }))
}

#[tokio::test]
async fn register_renew_deregister() {
    let f = FakeRegistry::default();
    let states = Arc::new(Mutex::new(Vec::<State>::new()));
    let st = Arc::clone(&states);
    let c = Arc::new(
        Client::new(
            dial(&f).await,
            Options {
                manifest: manifest(),
                http_url: "https://127.0.0.1:1".into(),
                on_state: Some(Arc::new(move |s: &State| st.lock().unwrap().push(s.clone()))),
                ..Options::default()
            },
        )
        .unwrap(),
    );
    let (stop, done) = spawn(&c);
    assert!(eventually(|| f.counts().1 >= 2).await);
    let s = c.state();
    assert!(s.registered && s.lease_id == "L1" && s.version == 2, "{s:?}");
    stop.cancel();
    done.await.unwrap().unwrap();
    let (regs, renews, deregs) = f.counts();
    assert_eq!((regs, deregs), (1, 1));
    assert!(renews >= 2);
    assert!(!c.state().registered);
    let last = f.0.lock().unwrap().last.clone().unwrap();
    assert_eq!(last.instance_id.len(), 32);
    assert_eq!(last.backend.unwrap().http_url, "https://127.0.0.1:1");
    let states = states.lock().unwrap();
    assert!(states.len() >= 2 && states[0].registered);
}

#[tokio::test]
async fn refusal_and_lease_loss() {
    let f = FakeRegistry::default();
    f.0.lock().unwrap().refuse = Some(tonic::Status::permission_denied("identity_not_allowed"));
    let mut c = Client::new(
        dial(&f).await,
        Options {
            manifest: manifest(),
            grpc_target: "127.0.0.1:1".into(),
            max_backoff: Duration::from_millis(20),
            ..Options::default()
        },
    )
    .unwrap();
    c.rand = || 0.5;
    let c = Arc::new(c);
    let (stop, done) = spawn(&c);
    assert!(eventually(|| f.counts().0 >= 2).await);
    let s = c.state();
    assert!(
        !s.registered && s.err.as_ref().is_some_and(|e| e.refused),
        "{s:?}"
    );
    assert!(
        s.err
            .unwrap()
            .to_string()
            .starts_with("gatewayclient: registration refused: rpc error: code = PermissionDenied")
    );
    // The gateway starts accepting, then drops the lease: re-register.
    {
        let mut g = f.0.lock().unwrap();
        g.refuse = None;
        g.renew_err = Some(tonic::Status::not_found("unknown_lease"));
    }
    assert!(eventually(|| f.counts().0 >= 4).await);
    assert!(f.counts().1 >= 1);
    stop.cancel();
    let _ = done.await;
}

#[tokio::test]
async fn renewal_failures_lose_the_lease_after_ttl() {
    let f = FakeRegistry::default();
    f.0.lock().unwrap().renew_err = Some(tonic::Status::unavailable("blip"));
    let c = Arc::new(
        Client::new(
            dial(&f).await,
            Options {
                manifest: manifest(),
                http_url: "https://x".into(),
                ..Options::default()
            },
        )
        .unwrap(),
    );
    let (stop, done) = spawn(&c);
    // renew_every 30ms, ttl 90ms: three transient failures lose the lease,
    // then the loop registers again after the 1s pause.
    assert!(eventually(|| f.counts().0 >= 2).await);
    assert!(f.counts().1 >= 3);
    stop.cancel();
    let _ = done.await;
}

#[tokio::test]
async fn permanent_refusal_waits_max_backoff() {
    let f = FakeRegistry::default();
    f.0.lock().unwrap().refuse = Some(tonic::Status::invalid_argument("manifest_invalid"));
    let c = Arc::new(
        Client::new(
            dial(&f).await,
            Options {
                manifest: manifest(),
                http_url: "https://x".into(),
                max_backoff: Duration::from_millis(400),
                ..Options::default()
            },
        )
        .unwrap(),
    );
    let (stop, done) = spawn(&c);
    tokio::time::sleep(Duration::from_millis(600)).await;
    // t=0, then max backoff at once (t=400ms); not the 1s/2s ladder.
    assert_eq!(f.counts().0, 2);
    stop.cancel();
    let _ = done.await;
}

#[tokio::test]
async fn transient_errors_back_off_from_one_second() {
    let f = FakeRegistry::default();
    f.0.lock().unwrap().refuse = Some(tonic::Status::unavailable("down"));
    let c = Arc::new(
        Client::new(
            dial(&f).await,
            Options {
                manifest: manifest(),
                http_url: "https://x".into(),
                ..Options::default()
            },
        )
        .unwrap(),
    );
    let (stop, done) = spawn(&c);
    tokio::time::sleep(Duration::from_millis(1500)).await;
    // t=0 and t=1s; the next is at t=3s.
    assert_eq!(f.counts().0, 2);
    assert!(
        c.state()
            .err
            .is_some_and(|e| !e.refused && e.code == tonic::Code::Unavailable)
    );
    stop.cancel();
    let _ = done.await;
}

#[tokio::test]
async fn new_validation() {
    let f = FakeRegistry::default();
    let conn = dial(&f).await;
    assert!(
        Client::new(conn.clone(), Options::default()).is_err(),
        "empty manifest"
    );
    let no_backend = Options {
        manifest: manifest(),
        ..Options::default()
    };
    assert!(Client::new(conn.clone(), no_backend).is_err(), "no backend");
    let c = Client::new(
        conn,
        Options {
            manifest: manifest(),
            http_url: "https://x".into(),
            ..Options::default()
        },
    )
    .unwrap();
    assert_eq!(c.options().instance_id.len(), 32);
    assert_eq!(c.options().max_backoff, Duration::from_secs(30));
    for _ in 0..100 {
        assert!((0.0..1.0).contains(&jitter()));
    }
    assert_ne!(new_instance_id(), new_instance_id());
}

const DIGEST_A: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
const DIGEST_B: &str = "60303ae22b998861bce3b28f33eec1be758a213c86c93c076dbe9f558c11c752";

#[test]
fn validate_docs_digest_table() {
    for (name, d, ok) in [
        ("empty means no docs", String::new(), true),
        ("sha256 hex", DIGEST_A.to_owned(), true),
        ("uppercase", DIGEST_A.to_uppercase(), false),
        ("too short", DIGEST_A[..63].to_owned(), false),
        ("too long", format!("{DIGEST_A}0"), false),
        ("non hex", format!("g{}", &DIGEST_A[1..]), false),
        ("surrounding space", format!(" {}", &DIGEST_A[1..]), false),
        ("prefixed", format!("sha256:{}", &DIGEST_A[7..]), false),
    ] {
        assert_eq!(validate_docs_digest(&d).is_ok(), ok, "{name}");
    }
}

/// The process-wide build version and docs digest (one test: globals).
#[tokio::test]
async fn process_build_version_and_docs_digest() {
    let f = FakeRegistry::default();
    let conn = dial(&f).await;
    let registered = |o: Options| {
        let conn = conn.clone();
        let f = f.clone();
        async move {
            let c = Arc::new(
                Client::new(
                    conn,
                    Options {
                        manifest: manifest(),
                        http_url: "https://127.0.0.1:1".into(),
                        ..o
                    },
                )
                .unwrap(),
            );
            let before = f.counts().0;
            let (stop, done) = spawn(&c);
            assert!(eventually(|| f.counts().0 > before).await);
            stop.cancel();
            done.await.unwrap().unwrap();
            f.0.lock().unwrap().last.clone().unwrap()
        }
    };
    set_build_version(" 4.6.2 ");
    assert_eq!(build_version(), "4.6.2");
    assert_eq!(registered(Options::default()).await.build_version, "4.6.2");
    let o = Options {
        build_version: "4.7.0".into(),
        ..Options::default()
    };
    assert_eq!(registered(o).await.build_version, "4.7.0");
    set_build_version("");
    assert_eq!(registered(Options::default()).await.build_version, "");

    assert_eq!(registered(Options::default()).await.docs_digest, "");
    set_docs_digest(DIGEST_A);
    assert_eq!(docs_digest(), DIGEST_A);
    assert_eq!(registered(Options::default()).await.docs_digest, DIGEST_A);
    let o = Options {
        docs_digest: DIGEST_B.into(),
        ..Options::default()
    };
    assert_eq!(registered(o).await.docs_digest, DIGEST_B);
    let bad = Options {
        manifest: manifest(),
        http_url: "https://x".into(),
        docs_digest: "not-a-digest".into(),
        ..Options::default()
    };
    assert!(
        Client::new(conn.clone(), bad)
            .unwrap_err()
            .0
            .contains("docs digest")
    );
    set_docs_digest(&DIGEST_A.to_uppercase());
    let base = Options {
        manifest: manifest(),
        http_url: "https://x".into(),
        ..Options::default()
    };
    assert!(Client::new(conn, base).unwrap_err().0.contains("docs digest"));
    set_docs_digest("");
}
