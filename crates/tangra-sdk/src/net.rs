//! Outbound TLS connections for tonic channels: a connector that dials the
//! configured `host:port` endpoints (rotating the start on each new
//! connection, so an unreachable endpoint fails over to the next) and runs
//! the rustls handshake with a SPIFFE-verifying client configuration.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};

use http::Uri;
use hyper_util::rt::TokioIo;
use rustls_pki_types::ServerName;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

/// A boxed connector error.
pub(crate) type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Dials one of `endpoints` and performs the TLS handshake.
#[derive(Clone)]
pub(crate) struct Connector {
    endpoints: Arc<Vec<String>>,
    tls: TlsConnector,
    next: Arc<AtomicUsize>,
}

impl Connector {
    pub(crate) fn new(endpoints: Vec<String>, tls: Arc<rustls::ClientConfig>) -> Self {
        Self {
            endpoints: Arc::new(endpoints),
            tls: TlsConnector::from(tls),
            next: Arc::new(AtomicUsize::new(0)),
        }
    }
}

fn server_name(host_port: &str) -> Result<ServerName<'static>, BoxError> {
    let (host, _) = crate::config::split_host_port(host_port)?;
    let host = if host.is_empty() {
        "localhost".to_owned()
    } else {
        host
    };
    Ok(ServerName::try_from(host)?)
}

pub(crate) async fn dial(tls: &TlsConnector, ep: &str) -> Result<TlsStream<TcpStream>, BoxError> {
    let name = server_name(ep)?;
    let tcp = TcpStream::connect(ep).await?;
    tcp.set_nodelay(true)?;
    Ok(tls.connect(name, tcp).await?)
}

impl tower::Service<Uri> for Connector {
    type Response = TokioIo<TlsStream<TcpStream>>;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _uri: Uri) -> Self::Future {
        let eps = Arc::clone(&self.endpoints);
        let tls = self.tls.clone();
        let start = self.next.fetch_add(1, Ordering::Relaxed);
        Box::pin(async move {
            let mut last: BoxError = "no endpoints".into();
            for i in 0..eps.len() {
                let ep = &eps[(start + i) % eps.len()];
                match dial(&tls, ep).await {
                    Ok(s) => return Ok(TokioIo::new(s)),
                    Err(e) => last = e,
                }
            }
            Err(last)
        })
    }
}
