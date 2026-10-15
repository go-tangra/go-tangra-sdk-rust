//! The mTLS listener: eager TLS handshakes with a deadline (go-tangra
//! `transport/http/listener.go`), HTTP/2 (and, for the HTTP listener only,
//! HTTP/1.1 when the client negotiated no ALPN), header and stream limits,
//! idle timeout, maximum connection age with a grace period, and graceful
//! shutdown.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use axum::body::Body;
use bytes::Bytes;
use http::{Request, Response};
use hyper::body::{Frame, Incoming, SizeHint};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto;
use rustls_pki_types::CertificateDer;
use tokio::net::TcpListener;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tower::ServiceExt;
use tower::util::BoxCloneSyncService;

/// The service every listener serves.
pub(crate) type HttpService = BoxCloneSyncService<Request<Body>, Response<Body>, Infallible>;

/// What the connection knows about the peer; inserted into every request.
#[derive(Debug, Clone)]
pub struct ConnInfo {
    /// Remote address.
    pub remote: SocketAddr,
    /// The verified peer chain (leaf first); empty on plain listeners.
    pub peer_chain: Arc<Vec<CertificateDer<'static>>>,
}

/// Wire protocol of a listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Proto {
    /// HTTP/2 only (ALPN h2 required, as grpc-go).
    Grpc,
    /// HTTP/2 with ALPN h2, HTTP/1.1 when no ALPN was negotiated (net/http).
    Http,
}

/// Connection limits.
#[derive(Debug, Clone)]
pub(crate) struct ServeOptions {
    pub(crate) proto: Proto,
    pub(crate) handshake_timeout: Duration,
    pub(crate) idle_timeout: Duration,
    pub(crate) max_connection_age: Option<Duration>,
    pub(crate) age_grace: Duration,
    pub(crate) max_concurrent_streams: u32,
    pub(crate) max_header_bytes: u32,
}

/// Why a handshake failed.
#[derive(Debug)]
pub(crate) enum HandshakeError {
    Timeout,
    Tls(std::io::Error),
}

pub(crate) type OnHandshakeError = Arc<dyn Fn(HandshakeError, SocketAddr) + Send + Sync>;

#[derive(Debug)]
struct ConnState {
    inflight: AtomicUsize,
    last: Mutex<Instant>,
}

struct InflightGuard(Arc<ConnState>);

impl InflightGuard {
    fn new(s: &Arc<ConnState>) -> Self {
        s.inflight.fetch_add(1, Ordering::SeqCst);
        Self(Arc::clone(s))
    }
}

impl Drop for InflightGuard {
    fn drop(&mut self) {
        if let Ok(mut l) = self.0.last.lock() {
            *l = Instant::now();
        }
        self.0.inflight.fetch_sub(1, Ordering::SeqCst);
    }
}

pin_project_lite::pin_project! {
    /// A response body that keeps the connection's in-flight count until it ends.
    struct GuardBody {
        #[pin]
        inner: Body,
        guard: Option<InflightGuard>,
    }
}

impl http_body::Body for GuardBody {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, axum::Error>>> {
        let this = self.project();
        let r = this.inner.poll_frame(cx);
        if let Poll::Ready(None) = r {
            this.guard.take();
        }
        r
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

async fn idle_reached(state: &ConnState, idle: Duration) {
    let tick = idle.min(Duration::from_secs(1)).max(Duration::from_millis(10));
    loop {
        tokio::time::sleep(tick).await;
        let last = state.last.lock().map(|l| *l).unwrap_or_else(|_| Instant::now());
        if state.inflight.load(Ordering::SeqCst) == 0 && last.elapsed() >= idle {
            return;
        }
    }
}

async fn sleep_opt(d: Option<Instant>) {
    match d {
        Some(t) => tokio::time::sleep_until(t).await,
        None => std::future::pending().await,
    }
}

/// Accepts connections on `lis` until `shutdown`; connection tasks are
/// tracked by `tracker` and end gracefully on `shutdown`, or at once on
/// `force`.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn serve_tls(
    lis: TcpListener,
    tls: Option<Arc<rustls::ServerConfig>>,
    svc: HttpService,
    o: ServeOptions,
    on_err: OnHandshakeError,
    shutdown: CancellationToken,
    force: CancellationToken,
    tracker: TaskTracker,
) {
    let acceptor = tls.map(tokio_rustls::TlsAcceptor::from);
    loop {
        let (tcp, remote) = tokio::select! {
            () = shutdown.cancelled() => return,
            r = lis.accept() => match r {
                Ok(c) => c,
                Err(_) => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            },
        };
        let _ = tcp.set_nodelay(true);
        let (acceptor, svc, o, on_err, shutdown, force) = (
            acceptor.clone(),
            svc.clone(),
            o.clone(),
            Arc::clone(&on_err),
            shutdown.clone(),
            force.clone(),
        );
        tracker.spawn(async move {
            match acceptor {
                Some(acc) => {
                    let tls = match tokio::time::timeout(o.handshake_timeout, acc.accept(tcp)).await {
                        Ok(Ok(s)) => s,
                        Ok(Err(e)) => return on_err(HandshakeError::Tls(e), remote),
                        Err(_) => return on_err(HandshakeError::Timeout, remote),
                    };
                    let conn = tls.get_ref().1;
                    let h2 = conn.alpn_protocol() == Some(b"h2".as_slice());
                    if o.proto == Proto::Grpc && !h2 {
                        return;
                    }
                    let chain: Vec<CertificateDer<'static>> = conn
                        .peer_certificates()
                        .map(|c| c.iter().map(|c| c.clone().into_owned()).collect())
                        .unwrap_or_default();
                    let info = ConnInfo {
                        remote,
                        peer_chain: Arc::new(chain),
                    };
                    drive(TokioIo::new(tls), h2, info, svc, &o, shutdown, force).await;
                }
                None => {
                    let info = ConnInfo {
                        remote,
                        peer_chain: Arc::new(Vec::new()),
                    };
                    drive(TokioIo::new(tcp), false, info, svc, &o, shutdown, force).await;
                }
            }
        });
    }
}

async fn drive<I>(
    io: I,
    h2: bool,
    info: ConnInfo,
    svc: HttpService,
    o: &ServeOptions,
    shutdown: CancellationToken,
    force: CancellationToken,
) where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let state = Arc::new(ConnState {
        inflight: AtomicUsize::new(0),
        last: Mutex::new(Instant::now()),
    });
    let st = Arc::clone(&state);
    let hsvc = hyper::service::service_fn(move |req: Request<Incoming>| {
        let mut req = req.map(Body::new);
        req.extensions_mut().insert(info.clone());
        let guard = InflightGuard::new(&st);
        let svc = svc.clone();
        async move {
            let resp = svc.oneshot(req).await?;
            Ok::<_, Infallible>(resp.map(|b| {
                Body::new(GuardBody {
                    inner: b,
                    guard: Some(guard),
                })
            }))
        }
    });
    let mut b = auto::Builder::new(TokioExecutor::new());
    if h2 {
        b = b.http2_only();
    } else {
        b = b.http1_only();
    }
    b.http2()
        .timer(TokioTimer::new())
        .max_concurrent_streams(o.max_concurrent_streams)
        .max_header_list_size(o.max_header_bytes);
    b.http1()
        .timer(TokioTimer::new())
        .header_read_timeout(o.handshake_timeout)
        .max_buf_size((o.max_header_bytes as usize + 4096).max(8192));
    let conn = b.serve_connection(io, hsvc);
    tokio::pin!(conn);
    let age = sleep_opt(o.max_connection_age.map(|a| Instant::now() + a));
    tokio::pin!(age);
    let mut graceful = false;
    let mut deadline: Option<Instant> = None;
    loop {
        tokio::select! {
            _ = conn.as_mut() => return,
            () = force.cancelled() => return,
            () = sleep_opt(deadline), if deadline.is_some() => return,
            () = shutdown.cancelled(), if !graceful => {
                conn.as_mut().graceful_shutdown();
                graceful = true;
            }
            () = &mut age, if !graceful => {
                conn.as_mut().graceful_shutdown();
                graceful = true;
                deadline = Some(Instant::now() + o.age_grace);
            }
            () = idle_reached(&state, o.idle_timeout), if !graceful => {
                conn.as_mut().graceful_shutdown();
                graceful = true;
            }
        }
    }
}
