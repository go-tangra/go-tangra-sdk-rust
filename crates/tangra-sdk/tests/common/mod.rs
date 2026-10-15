//! Shared harness: an in-test CA, a running App with HTTP + gRPC services,
//! and raw mTLS clients that can present arbitrary certificates.
#![allow(dead_code, clippy::expect_used, clippy::unwrap_used)]

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::routing::{get, post};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use tangra_proto::lcm::v1::enrollment_server::{Enrollment, EnrollmentServer};
use tangra_proto::lcm::v1::{CertificateBundle, EnrollRequest};
use tangra_sdk::app::{App, PeerIdentity, Services};
use tangra_sdk::config::{Config, FrameworkConfig, NoModule};
use tangra_sdk::correlation::RequestContext;
use tangra_sdk::identity::Provider;
use tangra_sdk::log::{Capture, Level, Logger};
use tangra_sdk::testutil::{Issued, MemoryProvider, TestCa};
use tokio::net::TcpStream;
use tokio::sync::oneshot;

pub const TD: &str = "example.org";

pub const POLICY: &str = r#"version: test-1
rules:
  - {id: gw-http, from: ["spiffe://example.org/svc/gateway"], to: ["orders"], operations: ["GET *", "POST /api/orders/v1/*"], effect: allow}
  - {id: gw-grpc, from: ["spiffe://example.org/svc/gateway"], to: ["orders"], operations: ["/lcm.v1.Enrollment/*"], effect: allow}
  - {id: self, from: ["spiffe://example.org/svc/orders"], to: ["orders"], effect: allow}
  - {id: legacy-deny, from: ["spiffe://example.org/svc/legacy-*"], to: ["*"], effect: deny}
  - {id: legacy-allow, from: ["spiffe://example.org/svc/legacy-1"], to: ["orders"], effect: allow}
"#;

/// What the gRPC test service saw.
#[derive(Default, Debug, Clone)]
pub struct Seen {
    pub peers: Vec<String>,
    pub request_ids: Vec<String>,
}

pub struct EnrollSvc(pub Arc<Mutex<Seen>>);

#[tonic::async_trait]
impl Enrollment for EnrollSvc {
    async fn enroll(
        &self,
        req: tonic::Request<EnrollRequest>,
    ) -> Result<tonic::Response<CertificateBundle>, tonic::Status> {
        let peer = PeerIdentity::of(&req)
            .map(|p| p.id.to_string())
            .unwrap_or_default();
        let rid = req
            .metadata()
            .get("x-request-id")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned();
        if let Ok(mut s) = self.0.lock() {
            s.peers.push(peer.clone());
            s.request_ids.push(rid);
        }
        if req.get_ref().tenant_id == "fail" {
            return Err(tonic::Status::not_found("nope"));
        }
        Ok(tonic::Response::new(CertificateBundle {
            cert_pem: peer,
            ..CertificateBundle::default()
        }))
    }
}

pub struct Harness {
    pub ca: TestCa,
    pub app: App,
    pub log: Capture,
    pub seen: Arc<Mutex<Seen>>,
    pub grpc: SocketAddr,
    pub http: SocketAddr,
    pub admin: String,
    pub stop: Option<oneshot::Sender<()>>,
    pub done: Option<tokio::task::JoinHandle<()>>,
    pub dir: tempfile::TempDir,
}

impl Harness {
    pub async fn stop(&mut self) {
        if let Some(s) = self.stop.take() {
            let _ = s.send(());
        }
        if let Some(d) = self.done.take() {
            let _ = tokio::time::timeout(Duration::from_secs(15), d).await;
        }
    }
}

pub fn base_config(dir: &std::path::Path) -> FrameworkConfig {
    let policy = dir.join("policy.yaml");
    std::fs::write(&policy, POLICY).expect("policy");
    let yaml = format!(
        "service_name: orders\ntrust_domain: {TD}\nidentity: {{provider: provided}}\n\
authz: {{source: file, path: {}}}\n\
server: {{grpc_addr: \"127.0.0.1:0\", http_addr: \"127.0.0.1:0\"}}\nadmin: {{addr: \"127.0.0.1:0\"}}\n",
        policy.display()
    );
    Config::<NoModule>::from_yaml(yaml.as_bytes())
        .expect("config")
        .framework
}

/// Starts `orders` with the given provider (default: an in-memory SVID).
pub async fn start_with(
    ca: TestCa,
    provider: Option<Arc<dyn Provider>>,
    mutate: impl FnOnce(&mut FrameworkConfig),
) -> Harness {
    let dir = tempfile::tempdir().expect("dir");
    let mut cfg = base_config(dir.path());
    mutate(&mut cfg);
    let provider = match provider {
        Some(p) => p,
        None => MemoryProvider::new(&ca, &ca.issue("orders").expect("issue")).expect("provider"),
    };
    let log = Capture::new();
    let app = App::builder(cfg)
        .identity_provider(provider)
        .logger(Logger::new(log.clone(), Level::Debug))
        .build()
        .await
        .expect("build");
    let seen = Arc::new(Mutex::new(Seen::default()));
    let app2 = app.clone();
    let router = axum::Router::new()
        .route(
            "/api/orders/v1/ping",
            get(|peer: PeerIdentity, ctx: RequestContext| async move {
                format!("pong {} {}", peer.id, ctx.correlation_id)
            }),
        )
        .route(
            "/api/orders/v1/items",
            post(|body: Bytes| async move { format!("got {}", body.len()) }),
        )
        .route(
            "/api/orders/v1/panic",
            get(|| async {
                if true {
                    panic!("boom");
                }
                "unreachable"
            }),
        )
        .route(
            "/api/orders/v1/slow",
            get(|| async {
                tokio::time::sleep(Duration::from_secs(5)).await;
                "late"
            }),
        )
        .route(
            "/api/orders/v1/outbound",
            get(move || {
                let app = app2.clone();
                async move {
                    let ch = match app.client("orders") {
                        Ok(c) => c,
                        Err(e) => return format!("client error: {e}"),
                    };
                    let mut c = tangra_proto::lcm::v1::enrollment_client::EnrollmentClient::new(ch);
                    match c.enroll(EnrollRequest::default()).await {
                        Ok(r) => format!("outbound {}", r.into_inner().cert_pem),
                        Err(s) => format!("outbound error {s}"),
                    }
                }
            }),
        );
    let grpc = tonic::service::Routes::new(EnrollmentServer::new(EnrollSvc(Arc::clone(&seen))));
    let (tx, rx) = oneshot::channel::<()>();
    let grpc_addr = app.grpc_local_addr().expect("grpc");
    let http_addr = app.http_local_addr().expect("http");
    let admin = app.admin_url().to_owned();
    let app3 = app.clone();
    let done = tokio::spawn(async move {
        let _ = app3
            .run_until(Services::new().http(router).grpc(grpc), async {
                let _ = rx.await;
            })
            .await;
    });
    Harness {
        ca,
        app,
        log,
        seen,
        grpc: grpc_addr,
        http: http_addr,
        admin,
        stop: Some(tx),
        done: Some(done),
        dir,
    }
}

pub async fn start() -> Harness {
    start_with(TestCa::new(TD).expect("ca"), None, |_| {}).await
}

// --- raw mTLS client ---------------------------------------------------

#[derive(Debug)]
pub struct AcceptAny(pub Arc<Mutex<Vec<CertificateDer<'static>>>>);

impl ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        ee: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if let Ok(mut v) = self.0.lock() {
            v.push(ee.clone().into_owned());
        }
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// A client presenting `cert` (or none), recording the server leaf.
pub fn raw_client(
    cert: Option<&Issued>,
    alpn: &[&[u8]],
) -> (
    Arc<rustls::ClientConfig>,
    Arc<Mutex<Vec<CertificateDer<'static>>>>,
) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let b = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAny(Arc::clone(&seen))));
    let mut cfg = match cert {
        Some(c) => {
            let key: PrivateKeyDer<'static> = c.key_der().expect("key");
            b.with_client_auth_cert(vec![c.cert_der.clone()], key)
                .expect("client cert")
        }
        None => b.with_no_client_auth(),
    };
    cfg.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
    (Arc::new(cfg), seen)
}

pub async fn tls_connect(
    addr: SocketAddr,
    cfg: Arc<rustls::ClientConfig>,
) -> std::io::Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let tcp = TcpStream::connect(addr).await?;
    let conn = tokio_rustls::TlsConnector::from(cfg)
        .connect(ServerName::try_from("localhost").expect("name"), tcp)
        .await?;
    Ok(conn)
}

pub struct Reply {
    pub status: u16,
    pub headers: http::HeaderMap,
    pub body: String,
}

/// One HTTP/2 request over a fresh mTLS connection.
pub async fn h2(
    addr: SocketAddr,
    cert: &Issued,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> Result<Reply, String> {
    let (cfg, _) = raw_client(Some(cert), &[b"h2"]);
    let tls = tls_connect(addr, cfg).await.map_err(|e| e.to_string())?;
    let (mut send, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
        .await
        .map_err(|e| e.to_string())?;
    tokio::spawn(conn);
    let mut req = http::Request::builder()
        .method(method)
        .uri(format!("https://orders{path}"));
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let req = req
        .body(Full::new(Bytes::from(body.to_owned())))
        .map_err(|e| e.to_string())?;
    let resp = send.send_request(req).await.map_err(|e| e.to_string())?;
    let status = resp.status().as_u16();
    let headers = resp.headers().clone();
    let body = resp
        .into_body()
        .collect()
        .await
        .map(|c| String::from_utf8_lossy(&c.to_bytes()).into_owned())
        .unwrap_or_default();
    Ok(Reply {
        status,
        headers,
        body,
    })
}

/// A tonic channel to `addr` presenting `cert`.
pub fn grpc_channel(addr: SocketAddr, cert: &Issued) -> tonic::transport::Channel {
    let (cfg, _) = raw_client(Some(cert), &[b"h2"]);
    let connector = tower::service_fn(move |_uri: http::Uri| {
        let cfg = Arc::clone(&cfg);
        async move { tls_connect(addr, cfg).await.map(TokioIo::new) }
    });
    tonic::transport::Endpoint::from_static("https://orders").connect_with_connector_lazy(connector)
}

/// Polls `f` until it holds or 10s pass.
pub async fn eventually(mut f: impl FnMut() -> bool) -> bool {
    for _ in 0..200 {
        if f() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}
