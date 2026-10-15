//! The separate, non-public operations listener (go-tangra
//! `observe/admin.go`): `/healthz` (`ok`), `/readyz` (`ready` or 503 `not
//! ready`) and `/metrics` (Prometheus text). On loopback it is plain HTTP; on
//! any other address (only with `admin.allow_non_loopback`) it speaks mTLS
//! with the service's SPIFFE configuration. pprof is a Go facility and is
//! not available; `admin.enable_pprof` is accepted and logged.

pub mod metrics;

pub use metrics::{Counter, Metrics};

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::routing::any;
use http::{HeaderValue, Response, StatusCode, header};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tower::util::BoxCloneSyncService;

use crate::app::serve::{self, Proto, ServeOptions};
use crate::config::AdminConfig;
use crate::log::{Logger, attr};

/// Readiness callback.
pub type ReadyFn = Arc<dyn Fn() -> bool + Send + Sync>;

/// An admin-listener failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct AdminError(pub String);

/// The bound admin listener.
pub struct Admin {
    lis: Option<TcpListener>,
    addr: SocketAddr,
    tls: Option<Arc<rustls::ServerConfig>>,
    router: Router,
}

impl std::fmt::Debug for Admin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Admin")
            .field("addr", &self.addr)
            .finish_non_exhaustive()
    }
}

fn text(status: StatusCode, body: &'static str) -> Response<Body> {
    let mut r = Response::new(Body::from(body));
    *r.status_mut() = status;
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    if status != StatusCode::OK {
        // net/http's http.Error.
        r.headers_mut()
            .insert("x-content-type-options", HeaderValue::from_static("nosniff"));
    }
    r
}

/// net/http's `NotFoundHandler`.
pub(crate) fn not_found() -> Response<Body> {
    text(StatusCode::NOT_FOUND, "404 page not found\n")
}

pub(crate) async fn bind_addr(addr: &str) -> std::io::Result<TcpListener> {
    let (host, port) = crate::config::split_host_port(addr)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    if host.is_empty() {
        // Go ":port" listens on every interface.
        if let Ok(l) = TcpListener::bind(format!("[::]:{port}")).await {
            return Ok(l);
        }
        return TcpListener::bind(format!("0.0.0.0:{port}")).await;
    }
    if host.contains(':') {
        return TcpListener::bind(format!("[{host}]:{port}")).await;
    }
    TcpListener::bind(format!("{host}:{port}")).await
}

impl Admin {
    /// Binds the listener. `tls` is required when the bound address is not
    /// loopback.
    pub async fn bind(
        cfg: &AdminConfig,
        ready: ReadyFn,
        metrics: Arc<Metrics>,
        log: &Logger,
        tls: Option<Arc<rustls::ServerConfig>>,
    ) -> Result<Self, AdminError> {
        let (host, _) =
            crate::config::split_host_port(&cfg.addr).map_err(|e| AdminError(format!("observe: {e}")))?;
        if !cfg.allow_non_loopback && !crate::config::is_loopback_host(&host) {
            return Err(AdminError(
                "observe: admin listener is not loopback; set admin.allow_non_loopback to accept the risk"
                    .into(),
            ));
        }
        let lis = bind_addr(&cfg.addr)
            .await
            .map_err(|e| AdminError(e.to_string()))?;
        let addr = lis.local_addr().map_err(|e| AdminError(e.to_string()))?;
        let secure = !addr.ip().is_loopback();
        let tls = if secure {
            let Some(t) = tls else {
                return Err(AdminError(
                    "observe: a non-loopback admin listener requires the mTLS configuration; plaintext is not allowed"
                        .into(),
                ));
            };
            log.warn(
                "admin listener bound to a non-loopback address; serving mTLS only",
                vec![attr("addr", addr.to_string())],
            );
            Some(t)
        } else {
            None
        };
        if cfg.enable_pprof {
            log.warn(
                "pprof is not available in the Rust SDK; admin.enable_pprof ignored",
                vec![attr("addr", addr.to_string())],
            );
        }
        let m = Arc::clone(&metrics);
        let router = Router::new()
            .route("/healthz", any(|| async { text(StatusCode::OK, "ok\n") }))
            .route(
                "/readyz",
                any(move || {
                    let ready = Arc::clone(&ready);
                    async move {
                        if ready() {
                            text(StatusCode::OK, "ready\n")
                        } else {
                            text(StatusCode::SERVICE_UNAVAILABLE, "not ready\n")
                        }
                    }
                }),
            )
            .route(
                "/metrics",
                any(move || {
                    let m = Arc::clone(&m);
                    async move {
                        let mut r = Response::new(Body::from(m.render()));
                        r.headers_mut().insert(
                            header::CONTENT_TYPE,
                            HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
                        );
                        r
                    }
                }),
            )
            .fallback(|| async { not_found() });
        Ok(Self {
            lis: Some(lis),
            addr,
            tls,
            router,
        })
    }

    /// The bound address.
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// The base URL (`https://` when mTLS is active; unspecified hosts
    /// shown as 127.0.0.1).
    pub fn url(&self) -> String {
        let mut a = self.addr;
        if a.ip().is_unspecified() {
            a.set_ip(std::net::IpAddr::from([127, 0, 0, 1]));
        }
        if self.tls.is_some() {
            format!("https://{a}")
        } else {
            format!("http://{a}")
        }
    }

    /// Serves until `shutdown`; connections then get 5s to finish.
    pub async fn serve(mut self, shutdown: CancellationToken) {
        let Some(lis) = self.lis.take() else { return };
        let tracker = TaskTracker::new();
        let force = CancellationToken::new();
        let svc = BoxCloneSyncService::new(self.router.clone().into_service::<Body>());
        let o = ServeOptions {
            proto: Proto::Http,
            handshake_timeout: Duration::from_secs(5),
            idle_timeout: Duration::from_secs(30),
            max_connection_age: None,
            age_grace: Duration::ZERO,
            max_concurrent_streams: 100,
            max_header_bytes: 8 << 10,
        };
        serve::serve_tls(
            lis,
            self.tls.clone(),
            svc,
            o,
            Arc::new(|_, _| {}),
            shutdown,
            force.clone(),
            tracker.clone(),
        )
        .await;
        tracker.close();
        if tokio::time::timeout(Duration::from_secs(5), tracker.wait())
            .await
            .is_err()
        {
            force.cancel();
        }
    }
}
