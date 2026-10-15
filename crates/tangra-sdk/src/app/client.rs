//! The outbound client pool (go-tangra `transport/grpc/client.go`): one
//! mutually authenticated channel per callee logical name, resolved through
//! `discovery.static`; the callee is verified by SPIFFE ID
//! (`spiffe://<td>/svc/<service>`), never by the address.

use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::task::{Context, Poll};

use http::{Request, Response};
use tonic::transport::{Channel, Endpoint};

use super::Runtime;
use crate::audit::{self, Event, Outcome, Type};
use crate::correlation::RequestContext;
use crate::identity::SpiffeId;

/// Why a client could not be built.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct ClientError(pub String);

/// A pooled channel to one callee. It implements tonic's `GrpcService`, so
/// generated clients wrap it directly (`FooClient::new(app.client("foo")?)`).
/// Every call carries the current call's `x-request-id` (or a fresh one)
/// and its `traceparent`/`baggage`.
#[derive(Clone, Debug)]
pub struct PeerChannel {
    inner: Channel,
}

impl PeerChannel {
    /// The underlying tonic channel (no correlation injection).
    pub fn channel(&self) -> Channel {
        self.inner.clone()
    }
}

impl tower::Service<Request<tonic::body::Body>> for PeerChannel {
    type Response = Response<tonic::body::Body>;
    type Error = tonic::transport::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        tower::Service::poll_ready(&mut self.inner, cx)
    }

    fn call(&mut self, mut req: Request<tonic::body::Body>) -> Self::Future {
        RequestContext::current()
            .unwrap_or_default()
            .inject(req.headers_mut());
        let fut = tower::Service::call(&mut self.inner, req);
        Box::pin(fut)
    }
}

/// The pool.
pub(crate) struct Pool {
    discovery: Option<BTreeMap<String, Vec<String>>>,
    conns: RwLock<HashMap<String, PeerChannel>>,
}

impl Pool {
    pub(crate) fn new(discovery: Option<BTreeMap<String, Vec<String>>>) -> Self {
        Self {
            discovery,
            conns: RwLock::new(HashMap::new()),
        }
    }

    /// Drops the pooled channels (trust bundle changed): the next `client`
    /// dials fresh and re-verifies the callee against the new roots.
    pub(crate) fn rotate(&self) {
        if let Ok(mut g) = self.conns.write() {
            g.clear();
        }
    }

    pub(crate) fn client(&self, rt: &Arc<Runtime>, service: &str) -> Result<PeerChannel, ClientError> {
        let expected =
            SpiffeId::new(&rt.cfg.trust_domain, service).map_err(|e| ClientError(format!("client: {e}")))?;
        let disc = self
            .discovery
            .as_ref()
            .ok_or_else(|| ClientError("client: no discovery configured".into()))?;
        if !rt.local_identity_valid() {
            return Err(ClientError("client: identity_expired".into()));
        }
        if rt.is_closed() {
            return Err(ClientError("client: pool closed".into()));
        }
        if let Some(c) = self.conns.read().ok().and_then(|g| g.get(service).cloned()) {
            return Ok(c);
        }
        let endpoints = disc
            .get(service)
            .cloned()
            .ok_or_else(|| ClientError(format!("client: discovery: unknown service {service:?}")))?;
        let mut opts = rt.tls_options();
        let audit_rt = Arc::clone(rt);
        let dial = format!("dial {expected}");
        opts.on_refusal = Some(Arc::new(move |reason, claimed: &str| {
            let mut e = Event::new(
                Type::AuthnRefused,
                Outcome::Refused,
                reason.as_str(),
                &audit_rt.local_id,
            );
            e.claimed_peer_id = claimed.to_owned();
            e.operation.clone_from(&dial);
            audit::emit(&audit_rt.logger, e);
        }));
        let tls = crate::tls::client_config(Arc::clone(&rt.provider), expected, opts)
            .map_err(|e| ClientError(e.to_string()))?;
        let first = endpoints
            .first()
            .ok_or_else(|| ClientError(format!("client: discovery: {service} has no endpoints")))?;
        let ep = Endpoint::from_shared(format!("https://{first}"))
            .map_err(|e| ClientError(format!("client: {e}")))?
            .timeout(rt.cfg.limits.request_timeout.to_std());
        let ch = PeerChannel {
            inner: ep.connect_with_connector_lazy(crate::net::Connector::new(endpoints, tls)),
        };
        if let Ok(mut g) = self.conns.write() {
            g.insert(service.to_owned(), ch.clone());
        }
        Ok(ch)
    }
}

/// Validates the static discovery map (go-tangra `discovery.NewStatic`).
pub(crate) fn validate_static(m: &BTreeMap<String, Vec<String>>) -> Result<(), ClientError> {
    for (name, addrs) in m {
        if !crate::identity::valid_service_name(name) {
            return Err(ClientError(format!("discovery: invalid service name {name:?}")));
        }
        if addrs.is_empty() {
            return Err(ClientError(format!("discovery: {name} has no endpoints")));
        }
        for a in addrs {
            if a.contains("://") {
                return Err(ClientError(format!(
                    "discovery: {name} endpoint {a:?} must be host:port without scheme"
                )));
            }
            crate::config::split_host_port(a)
                .map_err(|e| ClientError(format!("discovery: {name} endpoint {a:?}: {e}")))?;
        }
    }
    Ok(())
}
