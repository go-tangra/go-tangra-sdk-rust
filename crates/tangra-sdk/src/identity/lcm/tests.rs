//! The lcm provider against an in-process fake enrol endpoint (HTTPS) and a
//! fake `lcm.v1.Enrollment` server (mTLS gRPC).

use super::*;
use crate::testutil::{MemoryProvider, TestCa};
use std::pin::Pin;
use std::sync::atomic::AtomicU32;
use std::task::{Context, Poll};
use tangra_proto::lcm::v1::CertificateBundle;
use tangra_proto::lcm::v1::enrollment_server::{Enrollment, EnrollmentServer};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};

const TD: &str = "example.org";
const TOKEN: &str = "join-token-1";

struct Fake {
    ca: TestCa,
    lifetime: Duration,
    http_calls: AtomicU32,
    http_fail_first: AtomicU32,
    grpc_calls: AtomicU32,
    grpc_peers: Mutex<Vec<String>>,
    grpc_tokens: Mutex<Vec<String>>,
}

impl Fake {
    fn sign(&self, csr: &str) -> Result<String, String> {
        self.ca.sign_csr(csr, self.lifetime).map_err(|e| e.to_string())
    }
}

/// HTTPS enrol endpoint presenting lcm's SVID (mesh mode).
async fn start_http(fake: Arc<Fake>) -> String {
    let lcm = fake.ca.issue("lcm").expect("lcm svid");
    let key = lcm.key_der().expect("key");
    let cfg = rustls::ServerConfig::builder_with_provider(crate::identity::x509::crypto())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("versions")
        .with_no_client_auth()
        .with_single_cert(vec![lcm.cert_der.clone()], key)
        .expect("cert");
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    let lis = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = lis.local_addr().expect("addr");
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = lis.accept().await else { return };
            let acceptor = acceptor.clone();
            let fake = Arc::clone(&fake);
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let svc = hyper::service::service_fn(move |req: http::Request<hyper::body::Incoming>| {
                    let fake = Arc::clone(&fake);
                    async move {
                        fake.http_calls.fetch_add(1, Ordering::SeqCst);
                        let ok_path =
                            req.method() == http::Method::POST && req.uri().path() == "/api/lcm/v1/enroll";
                        let ct = req
                            .headers()
                            .get(http::header::CONTENT_TYPE)
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("")
                            .to_owned();
                        let body = req
                            .into_body()
                            .collect()
                            .await
                            .map(|c| c.to_bytes())
                            .unwrap_or_default();
                        let reply = |status: u16, body: String| {
                            http::Response::builder()
                                .status(status)
                                .body(Full::new(Bytes::from(body)))
                                .map_err(|e| e.to_string())
                        };
                        if fake.http_fail_first.load(Ordering::SeqCst) > 0 {
                            fake.http_fail_first.fetch_sub(1, Ordering::SeqCst);
                            return reply(503, "{\"reason\":\"temporarily_unavailable\"}".into());
                        }
                        let v: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
                        let keys: Vec<&String> =
                            v.as_object().map(|o| o.keys().collect()).unwrap_or_default();
                        if !ok_path
                            || ct != "application/json"
                            || keys != ["csr_pem", "enrollment_token", "spiffe_id"]
                            || v["enrollment_token"] != TOKEN
                            || v["spiffe_id"] != "spiffe://example.org/svc/orders"
                        {
                            return reply(403, "{\"reason\":\"forbidden\"}".into());
                        }
                        let cert = fake.sign(v["csr_pem"].as_str().unwrap_or(""))?;
                        let out = serde_json::json!({
                            "cert_pem": cert, "chain_pem": "", "bundle_pem": fake.ca.bundle_pem(), "extra": 1
                        });
                        reply(200, out.to_string())
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(hyper_util::rt::TokioIo::new(tls), svc)
                    .await;
            });
        }
    });
    format!("https://localhost:{}/api/lcm/v1/enroll", addr.port())
}

/// A TLS stream that tells tonic who the (verified) client is.
struct TlsIo(tokio_rustls::server::TlsStream<TcpStream>);

#[derive(Clone)]
struct PeerUris(Vec<String>);

impl tonic::transport::server::Connected for TlsIo {
    type ConnectInfo = PeerUris;
    fn connect_info(&self) -> PeerUris {
        let uris = self
            .0
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|c| c.first())
            .and_then(|c| parse_leaf(c).ok())
            .map(|l| l.uris)
            .unwrap_or_default();
        PeerUris(uris)
    }
}

impl AsyncRead for TlsIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for TlsIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

struct EnrollSvc(Arc<Fake>);

#[tonic::async_trait]
impl Enrollment for EnrollSvc {
    async fn enroll(
        &self,
        req: tonic::Request<EnrollRequest>,
    ) -> Result<tonic::Response<CertificateBundle>, tonic::Status> {
        self.0.grpc_calls.fetch_add(1, Ordering::SeqCst);
        if let Some(p) = req.extensions().get::<PeerUris>()
            && let Ok(mut v) = self.0.grpc_peers.lock()
        {
            v.extend(p.0.iter().cloned());
        }
        let r = req.into_inner();
        if let Ok(mut v) = self.0.grpc_tokens.lock() {
            v.push(r.enrollment_token.clone());
        }
        let cert = self.0.sign(&r.csr_pem).map_err(tonic::Status::internal)?;
        Ok(tonic::Response::new(CertificateBundle {
            cert_pem: cert,
            bundle_pem: self.0.ca.bundle_pem(),
            ..CertificateBundle::default()
        }))
    }
}

/// The renewal endpoint: mTLS, lcm's SVID, SPIFFE-verified clients.
async fn start_grpc(fake: Arc<Fake>) -> String {
    let lcm = fake.ca.issue("lcm").expect("lcm svid");
    let prov = MemoryProvider::new(&fake.ca, &lcm).expect("lcm provider");
    let cfg = crate::tls::server_config(prov, crate::tls::Options::new(TD)).expect("server cfg");
    let acceptor = tokio_rustls::TlsAcceptor::from(cfg);
    let lis = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = lis.local_addr().expect("addr");
    let (tx, rx) = mpsc::channel::<Result<TlsIo, std::io::Error>>(8);
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = lis.accept().await else { return };
            let acceptor = acceptor.clone();
            let tx = tx.clone();
            tokio::spawn(async move {
                if let Ok(tls) = acceptor.accept(tcp).await {
                    let _ = tx.send(Ok(TlsIo(tls))).await;
                }
            });
        }
    });
    let incoming = tokio_stream_from(rx);
    tokio::spawn(
        tonic::transport::Server::builder()
            .add_service(EnrollmentServer::new(EnrollSvc(fake)))
            .serve_with_incoming(incoming),
    );
    format!("localhost:{}", addr.port())
}

fn tokio_stream_from<T: Send + 'static>(
    mut rx: mpsc::Receiver<T>,
) -> impl futures_util::Stream<Item = T> + Send + 'static {
    futures_util::stream::poll_fn(move |cx| rx.poll_recv(cx))
}

fn fake(lifetime: Duration, fail_first: u32) -> Arc<Fake> {
    Arc::new(Fake {
        ca: TestCa::new(TD).expect("ca"),
        lifetime,
        http_calls: AtomicU32::new(0),
        http_fail_first: AtomicU32::new(fail_first),
        grpc_calls: AtomicU32::new(0),
        grpc_peers: Mutex::new(Vec::new()),
        grpc_tokens: Mutex::new(Vec::new()),
    })
}

async fn net_config(f: &Arc<Fake>, state: Option<PathBuf>) -> NetConfig {
    let url = start_http(Arc::clone(f)).await;
    let grpc = start_grpc(Arc::clone(f)).await;
    let mut c = NetConfig::new(TD, "orders");
    c.enroll_url = url;
    c.lcm_grpc_target = grpc;
    c.tenant_id = "t1".into();
    c.enrollment_token = TOKEN.into();
    c.state_file = state;
    c.first_enroll_interval = Duration::from_millis(20);
    c.renew_retry_interval = Duration::from_millis(100);
    c.enroll_tls = Some(
        enroll_client_config(EnrollOptions {
            ca_pem: Some(f.ca.bundle_pem().into_bytes()),
            server_id: SpiffeId::new(TD, "lcm").ok(),
            ..EnrollOptions::default()
        })
        .expect("enroll tls"),
    );
    c
}

#[tokio::test]
async fn first_enroll_over_https_with_retries_and_state_file() {
    let f = fake(Duration::from_secs(3600), 2);
    let dir = tempfile::tempdir().expect("dir");
    let state = dir.path().join("svid.json");
    let cfg = net_config(&f, Some(state.clone())).await;
    let p = LcmProvider::new(cfg.clone()).await.expect("enrol");
    assert_eq!(f.http_calls.load(Ordering::SeqCst), 3, "two 503s then success");
    let (id, bundle) = p.current().expect("current");
    assert_eq!(id.id.to_string(), "spiffe://example.org/svc/orders");
    assert_eq!(bundle.roots, vec![f.ca.root_der()]);
    assert_eq!(bundle.version, 1);
    // The state file is 0600 JSON with the Go field names.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&state).expect("meta").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
    let raw = std::fs::read_to_string(&state).expect("state");
    let v: serde_json::Value = serde_json::from_str(&raw).expect("json");
    assert!(raw.starts_with("{\"cert_pem\":"), "{raw}");
    assert!(
        v["key_pem"]
            .as_str()
            .unwrap_or("")
            .starts_with("-----BEGIN PRIVATE KEY-----\n")
    );
    assert_eq!(v["chain_pem"], "");
    assert!(
        v["bundle_pem"]
            .as_str()
            .unwrap_or("")
            .contains("BEGIN CERTIFICATE")
    );
    // A restart reuses the persisted SVID: no token spent.
    let p2 = LcmProvider::new(cfg).await.expect("restart");
    assert_eq!(f.http_calls.load(Ordering::SeqCst), 3);
    assert_eq!(p2.current().expect("current").0.serial, id.serial);
}

#[tokio::test]
async fn refuses_wrong_token_and_wrong_server_identity() {
    let f = fake(Duration::from_secs(3600), 0);
    let mut cfg = net_config(&f, None).await;
    cfg.first_enroll_retries = 1;
    cfg.enrollment_token = "wrong".into();
    let e = LcmProvider::new(cfg.clone()).await.expect_err("token");
    assert!(e.0.contains("http 403"), "{e}");
    assert_eq!(f.http_calls.load(Ordering::SeqCst), 2, "one retry");
    // Mesh mode refuses an enrol server that is not svc/lcm... here: expect gateway.
    cfg.enrollment_token = TOKEN.into();
    cfg.first_enroll_retries = 0;
    cfg.enroll_tls = Some(
        enroll_client_config(EnrollOptions {
            ca_pem: Some(f.ca.bundle_pem().into_bytes()),
            server_id: SpiffeId::new(TD, "gateway").ok(),
            ..EnrollOptions::default()
        })
        .expect("tls"),
    );
    let e = LcmProvider::new(cfg.clone()).await.expect_err("server id");
    assert!(e.0.contains("enroll"), "{e}");
    // Required fields, as NewNet.
    let mut bad = cfg.clone();
    bad.enrollment_token.clear();
    assert!(LcmProvider::new(bad).await.is_err());
    let mut bad = cfg;
    bad.insecure = true;
    assert!(
        LcmProvider::new(bad)
            .await
            .expect_err("both")
            .0
            .contains("mutually exclusive")
    );
}

#[tokio::test]
async fn renews_over_mtls_grpc_without_token() {
    // 3s certificates renew 1s before expiry (1/3 of the lifetime).
    let f = fake(Duration::from_secs(3), 0);
    let dir = tempfile::tempdir().expect("dir");
    let state = dir.path().join("svid.json");
    let cfg = net_config(&f, Some(state.clone())).await;
    let p = LcmProvider::new(cfg).await.expect("enrol");
    let serial0 = p.current().expect("cur").0.serial;
    let mut rx = p.watch().expect("watch");
    let u = tokio::time::timeout(Duration::from_secs(10), rx.recv())
        .await
        .expect("renewal in time")
        .expect("open");
    assert!(u.err.is_none(), "{:?}", u.err);
    let renewed = u.identity.expect("identity");
    assert_ne!(renewed.serial, serial0);
    assert_eq!(u.bundle.expect("bundle").version, 2);
    assert_eq!(p.current().expect("cur").0.serial, renewed.serial);
    assert_eq!(f.http_calls.load(Ordering::SeqCst), 1, "the token is spent once");
    assert!(f.grpc_calls.load(Ordering::SeqCst) >= 1);
    assert_eq!(
        f.grpc_peers.lock().map(|v| v[0].clone()).unwrap_or_default(),
        "spiffe://example.org/svc/orders",
        "renewal presents the current SVID"
    );
    assert!(
        f.grpc_tokens
            .lock()
            .map(|v| v.iter().all(String::is_empty))
            .unwrap_or(false)
    );
    // The renewed SVID is persisted.
    let raw = std::fs::read_to_string(&state).expect("state");
    let rec: PersistedSvid = serde_json::from_str(&raw).expect("json");
    let leaf = decode_certs(&rec.cert_pem);
    assert_eq!(parse_leaf(&leaf[0]).expect("leaf").serial, renewed.serial);
    p.close().await;
}
