//! The fixed security chain every call passes, in go-tangra's order
//! (`transport/grpc/server.go` `SecurityChain`, applied to HTTP by
//! `transport/http/filter.go` before routing):
//!
//! recovery -> local identity guard (`identity_expired`) -> correlation ->
//! tracing -> request log/metrics -> authn (verified peer) -> authz (policy)
//! -> request limits -> handler.
//!
//! Refusals are encoded per protocol: HTTP through the framework error
//! encoder (`{"reason"}`; 5xx collapse to `internal`), gRPC as a status with
//! a `google.rpc.ErrorInfo{reason}` detail (Kratos `errors.GRPCStatus`).

use std::collections::{BTreeMap, HashMap};
use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Instant, SystemTime};

use axum::body::Body;
use bytes::Bytes;
use futures_util::FutureExt;
use http::{HeaderValue, Request, Response, StatusCode};
use http_body::{Frame, SizeHint};
use tonic_types::{ErrorDetails, StatusExt};

use super::Runtime;
use super::serve::ConnInfo;
use crate::audit::{self, Event, Outcome, Type};
use crate::correlation::{self, RequestContext};
use crate::identity::{Reason, SpiffeId};
use crate::log::attr;

/// The verified identity of the remote party (go-tangra `authn.PeerIdentity`),
/// available to handlers as an axum extractor and as a request extension.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerIdentity {
    /// SPIFFE ID.
    pub id: SpiffeId,
    /// Service name part of the ID.
    pub service_name: String,
    /// Certificate serial (decimal).
    pub serial: String,
    /// When the chain verified it.
    pub verified_at: SystemTime,
}

impl PeerIdentity {
    /// The peer of a tonic request.
    pub fn of<T>(req: &tonic::Request<T>) -> Option<&Self> {
        req.extensions().get::<Self>()
    }
}

impl<S: Send + Sync> axum::extract::FromRequestParts<S> for PeerIdentity {
    type Rejection = Response<Body>;

    async fn from_request_parts(parts: &mut http::request::Parts, _: &S) -> Result<Self, Self::Rejection> {
        parts.extensions.get::<Self>().cloned().ok_or_else(|| {
            crate::error::framework_error_response(StatusCode::UNAUTHORIZED, Reason::NoIdentity.as_str())
        })
    }
}

/// Which wire protocol the chain encodes refusals for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Flavor {
    Http,
    Grpc,
}

/// Kratos `ToGRPCCode`.
fn grpc_code(status: u16) -> tonic::Code {
    match status {
        200 => tonic::Code::Ok,
        400 => tonic::Code::InvalidArgument,
        401 => tonic::Code::Unauthenticated,
        403 => tonic::Code::PermissionDenied,
        404 => tonic::Code::NotFound,
        409 => tonic::Code::Aborted,
        429 => tonic::Code::ResourceExhausted,
        499 => tonic::Code::Cancelled,
        500 => tonic::Code::Internal,
        501 => tonic::Code::Unimplemented,
        412 => tonic::Code::FailedPrecondition,
        503 => tonic::Code::Unavailable,
        504 => tonic::Code::DeadlineExceeded,
        _ => tonic::Code::Unknown,
    }
}

/// Outcome of a call from the Kratos-level HTTP status of its error
/// (go-tangra `observe.classify`).
fn outcome_of(status: u16) -> &'static str {
    match status {
        0 => "ok",
        401 => "authn_refused",
        403 => "authz_refused",
        503 => "unavailable",
        504 => "timeout",
        _ => "error",
    }
}

/// Kratos `FromGRPCCode` for the outcome of a gRPC handler.
fn status_of_grpc(code: i32) -> u16 {
    match tonic::Code::from_i32(code) {
        tonic::Code::Ok => 0,
        tonic::Code::Cancelled => 499,
        tonic::Code::InvalidArgument => 400,
        tonic::Code::DeadlineExceeded => 504,
        tonic::Code::NotFound => 404,
        tonic::Code::AlreadyExists | tonic::Code::Aborted => 409,
        tonic::Code::PermissionDenied => 403,
        tonic::Code::Unauthenticated => 401,
        tonic::Code::ResourceExhausted => 429,
        tonic::Code::FailedPrecondition => 400,
        tonic::Code::OutOfRange => 400,
        tonic::Code::Unimplemented => 501,
        tonic::Code::Unavailable => 503,
        _ => 500,
    }
}

/// A refusal raised by the chain.
#[derive(Debug, Clone)]
pub(crate) struct Refusal {
    status: u16,
    reason: &'static str,
    message: &'static str,
}

impl Refusal {
    const fn new(status: u16, reason: &'static str) -> Self {
        Self {
            status,
            reason,
            message: "",
        }
    }
}

/// Encodes a refusal for the flavour.
pub(crate) fn refusal_response(flavor: Flavor, r: &Refusal) -> Response<Body> {
    match flavor {
        Flavor::Http => crate::error::framework_error_response(
            StatusCode::from_u16(r.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            r.reason,
        ),
        Flavor::Grpc => {
            let st = tonic::Status::with_error_details(
                grpc_code(r.status),
                r.message,
                ErrorDetails::with_error_info(r.reason, "", HashMap::<String, String>::new()),
            );
            st.into_http::<Body>()
        }
    }
}

/// The security middleware around the application service.
#[derive(Clone)]
pub(crate) struct Secure<S> {
    pub(crate) rt: Arc<Runtime>,
    pub(crate) inner: S,
    pub(crate) flavor: Flavor,
}

type BoxFut = Pin<Box<dyn Future<Output = Result<Response<Body>, Infallible>> + Send>>;

impl<S> tower::Service<Request<Body>> for Secure<S>
where
    S: tower::Service<Request<Body>, Response = Response<Body>, Error = Infallible> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = Response<Body>;
    type Error = Infallible;
    type Future = BoxFut;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<Body>) -> BoxFut {
        let rt = Arc::clone(&self.rt);
        let inner = self.inner.clone();
        let flavor = self.flavor;
        Box::pin(async move {
            // Recovery: a panic anywhere below becomes errors.InternalServer
            // ("UNKNOWN", "unknown request error").
            let fut =
                std::panic::AssertUnwindSafe(handle(Arc::clone(&rt), inner, flavor, req)).catch_unwind();
            match fut.await {
                Ok(r) => Ok(r),
                Err(_) => {
                    rt.logger.error("panic recovered", vec![]);
                    Ok(refusal_response(
                        flavor,
                        &Refusal {
                            status: 500,
                            reason: "UNKNOWN",
                            message: "unknown request error",
                        },
                    ))
                }
            }
        })
    }
}

struct Call {
    rt: Arc<Runtime>,
    start: Instant,
    operation: String,
    ctx: RequestContext,
    peer: Option<PeerIdentity>,
}

impl Call {
    fn finish(&self, outcome: &str, reason: &str) {
        let (svc, id) = self
            .peer
            .as_ref()
            .map_or(("unknown".to_owned(), String::new()), |p| {
                (p.service_name.clone(), p.id.to_string())
            });
        let dur = self.start.elapsed();
        // The authz refusal counter uses the transport operation (the path).
        self.rt
            .metrics
            .record_call(&svc, outcome, dur.as_secs_f64(), reason, &self.operation);
        // float64(dur)/1e6, as Go.
        #[allow(clippy::cast_precision_loss)]
        let dur_ms = dur.as_nanos() as f64 / 1e6;
        self.rt.logger.info(
            "request",
            vec![
                attr("caller", svc),
                attr("caller_id", id),
                attr("callee", self.rt.cfg.service_name.as_str()),
                attr("operation", self.operation.as_str()),
                attr("outcome", outcome),
                attr("duration_ms", dur_ms),
                attr("correlation_id", self.ctx.correlation_id.as_str()),
                attr("trace_id", self.ctx.trace_id()),
            ],
        );
    }

    fn audit(&self, mut e: Event) {
        e.correlation_id.clone_from(&self.ctx.correlation_id);
        e.trace_id = self.ctx.trace_id().to_owned();
        audit::emit(&self.rt.logger, e);
    }
}

fn with_correlation(mut r: Response<Body>, id: &str) -> Response<Body> {
    if let Ok(v) = HeaderValue::from_str(id) {
        r.headers_mut().insert(correlation::HEADER, v);
    }
    r
}

async fn handle<S>(rt: Arc<Runtime>, inner: S, flavor: Flavor, mut req: Request<Body>) -> Response<Body>
where
    S: tower::Service<Request<Body>, Response = Response<Body>, Error = Infallible> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    use tower::ServiceExt;

    // Local identity guard: neither accept nor make calls without a valid
    // identity of our own.
    if !rt.local_identity_valid() {
        return refusal_response(flavor, &Refusal::new(503, "identity_expired"));
    }
    // Correlation + tracing.
    let (ctx, replaced) = RequestContext::from_headers(req.headers());
    if replaced {
        let len = req
            .headers()
            .get(correlation::HEADER)
            .map_or(0, |v| v.as_bytes().len());
        rt.logger.debug(
            "correlation id replaced: invalid format",
            vec![attr("length", len)],
        );
    }
    let path = req.uri().path().to_owned();
    let mut call = Call {
        rt: Arc::clone(&rt),
        start: Instant::now(),
        operation: path.clone(),
        ctx: ctx.clone(),
        peer: None,
    };
    let remote = req
        .extensions()
        .get::<ConnInfo>()
        .map(|c| c.remote.to_string())
        .unwrap_or_default();

    // Authn: re-derive the peer from the verified TLS chain.
    let leaf = req
        .extensions()
        .get::<ConnInfo>()
        .and_then(|c| c.peer_chain.first().cloned());
    let refuse_authn = |call: &Call, reason: Reason, claimed: String| {
        let mut e = Event::new(
            Type::AuthnRefused,
            Outcome::Refused,
            reason.as_str(),
            &call.rt.local_id,
        );
        e.claimed_peer_id = claimed;
        e.remote_addr.clone_from(&remote);
        call.audit(e);
        call.finish("authn_refused", reason.as_str());
        with_correlation(
            refusal_response(flavor, &Refusal::new(401, reason.as_str())),
            &call.ctx.correlation_id,
        )
    };
    let Some(leaf) = leaf else {
        return refuse_authn(&call, Reason::NoIdentity, String::new());
    };
    let Ok(peer) = crate::tls::peer_from_leaf(&leaf) else {
        return refuse_authn(&call, Reason::Untrusted, String::new());
    };
    if peer.id.trust_domain() != rt.cfg.trust_domain {
        return refuse_authn(&call, Reason::Untrusted, peer.id.to_string());
    }
    if let Some(rc) = &rt.revocation {
        match rc.is_revoked(&peer.id, &peer.serial).await {
            Ok(false) => {}
            _ => return refuse_authn(&call, Reason::Revoked, peer.id.to_string()),
        }
    }
    let pid = PeerIdentity {
        service_name: peer.service_name.clone(),
        id: peer.id.clone(),
        serial: peer.serial.clone(),
        verified_at: SystemTime::now(),
    };
    call.peer = Some(pid.clone());

    // Authz: "/pkg.Svc/Method" for gRPC, "METHOD /path" for HTTP.
    let op = match flavor {
        Flavor::Grpc => path.clone(),
        Flavor::Http => format!("{} {}", req.method(), path),
    };
    let d = rt.authorizer().authorize(&pid.id, &rt.cfg.service_name, &op);
    let decision_event = |kind, outcome| {
        let mut e = Event::new(kind, outcome, d.reason.as_str(), &rt.local_id);
        e.claimed_peer_id = pid.id.to_string();
        e.verified_peer_id = pid.id.to_string();
        e.operation.clone_from(&op);
        e.rule_id.clone_from(&d.rule_id);
        e.policy_version.clone_from(&d.policy_version);
        e
    };
    if !d.allowed {
        call.audit(decision_event(Type::AuthzRefused, Outcome::Refused));
        call.finish("authz_refused", "");
        return with_correlation(
            refusal_response(flavor, &Refusal::new(403, "denied")),
            &ctx.correlation_id,
        );
    }
    if rt.sample_allowed {
        call.audit(decision_event(Type::AuthzAllowed, Outcome::Ok));
    }

    req.extensions_mut().insert(pid);
    req.extensions_mut().insert(ctx.clone());
    if flavor == Flavor::Http {
        let limit = usize::try_from(rt.cfg.limits.max_request_bytes).unwrap_or(usize::MAX);
        let audit_rt = Arc::clone(&rt);
        let audit_op = format!("{} {}", req.method(), path);
        let audit_remote = remote.clone();
        let audit_cid = ctx.correlation_id.clone();
        let on_exceed: OnExceed = Box::new(move || {
            let mut e = Event::new(
                Type::LimitExceeded,
                Outcome::Refused,
                "limit_exceeded",
                &audit_rt.local_id,
            );
            e.operation = audit_op;
            e.remote_addr = audit_remote;
            e.correlation_id = audit_cid;
            e.attrs = BTreeMap::from([("limit".to_owned(), "request_body".to_owned())]);
            audit::emit(&audit_rt.logger, e);
        });
        req = req.map(|b| Body::new(LimitedBody::new(b, limit, on_exceed)));
    }

    let timeout = rt.cfg.limits.request_timeout.to_std();
    let fut = ctx.clone().scope(inner.oneshot(req));
    let resp = match tokio::time::timeout(timeout, fut).await {
        Ok(Ok(r)) => r,
        Err(_) => {
            let mut e = Event::new(
                Type::LimitExceeded,
                Outcome::Refused,
                "limit_exceeded",
                &rt.local_id,
            );
            e.operation.clone_from(&path);
            e.remote_addr.clone_from(&remote);
            e.attrs = BTreeMap::from([("limit".to_owned(), "request_timeout".to_owned())]);
            call.audit(e);
            call.finish("timeout", "");
            let r = match flavor {
                Flavor::Http => {
                    crate::error::framework_error_response(StatusCode::GATEWAY_TIMEOUT, "timeout")
                }
                Flavor::Grpc => tonic::Status::deadline_exceeded("").into_http::<Body>(),
            };
            return with_correlation(r, &ctx.correlation_id);
        }
    };
    let resp = with_correlation(resp, &ctx.correlation_id);
    match flavor {
        Flavor::Http => {
            call.finish("ok", "");
            resp
        }
        Flavor::Grpc => {
            // Trailers-only responses carry grpc-status in the headers;
            // otherwise the outcome is known when the trailers arrive.
            if let Some(code) = grpc_status(resp.headers()) {
                let st = status_of_grpc(code);
                call.finish(outcome_of(st), "");
                return resp;
            }
            let call = Arc::new(Mutex::new(Some(call)));
            resp.map(|b| Body::new(ObservedBody { inner: b, call }))
        }
    }
}

fn grpc_status(h: &http::HeaderMap) -> Option<i32> {
    h.get("grpc-status")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok())
}

type OnExceed = Box<dyn FnOnce() + Send + Sync>;

pin_project_lite::pin_project! {
    /// `http.MaxBytesReader` with the audit of the first violation.
    struct LimitedBody {
        #[pin]
        inner: http_body_util::Limited<Body>,
        on_exceed: Option<OnExceed>,
    }
}

impl LimitedBody {
    fn new(b: Body, limit: usize, on_exceed: OnExceed) -> Self {
        Self {
            inner: http_body_util::Limited::new(b, limit),
            on_exceed: Some(on_exceed),
        }
    }
}

impl http_body::Body for LimitedBody {
    type Data = Bytes;
    type Error = Box<dyn std::error::Error + Send + Sync>;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        let this = self.project();
        let r = this.inner.poll_frame(cx);
        if let Poll::Ready(Some(Err(e))) = &r
            && e.downcast_ref::<http_body_util::LengthLimitError>().is_some()
            && let Some(f) = this.on_exceed.take()
        {
            f();
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

pin_project_lite::pin_project! {
    /// Logs a gRPC call once its trailers (status) arrive or the body ends.
    struct ObservedBody {
        #[pin]
        inner: Body,
        call: Arc<Mutex<Option<Call>>>,
    }

    impl PinnedDrop for ObservedBody {
        fn drop(this: Pin<&mut Self>) {
            // A stream torn down before its trailers: cancelled.
            if let Ok(mut c) = this.call.lock() && let Some(call) = c.take() {
                call.finish("error", "");
            }
        }
    }
}

impl http_body::Body for ObservedBody {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, axum::Error>>> {
        let this = self.project();
        let r = this.inner.poll_frame(cx);
        let status = match &r {
            Poll::Ready(Some(Ok(f))) => f.trailers_ref().map(|t| grpc_status(t).unwrap_or(0)),
            Poll::Ready(Some(Err(_))) => Some(2),
            Poll::Ready(None) => Some(0),
            Poll::Pending => None,
        };
        if let Some(code) = status
            && let Ok(mut c) = this.call.lock()
            && let Some(call) = c.take()
        {
            call.finish(outcome_of(status_of_grpc(code)), "");
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_mappings_follow_kratos() {
        assert_eq!(grpc_code(401), tonic::Code::Unauthenticated);
        assert_eq!(grpc_code(403), tonic::Code::PermissionDenied);
        assert_eq!(grpc_code(503), tonic::Code::Unavailable);
        assert_eq!(grpc_code(504), tonic::Code::DeadlineExceeded);
        assert_eq!(grpc_code(418), tonic::Code::Unknown);
        assert_eq!(outcome_of(status_of_grpc(16)), "authn_refused");
        assert_eq!(outcome_of(status_of_grpc(7)), "authz_refused");
        assert_eq!(outcome_of(status_of_grpc(14)), "unavailable");
        assert_eq!(outcome_of(status_of_grpc(4)), "timeout");
        assert_eq!(outcome_of(status_of_grpc(0)), "ok");
        assert_eq!(outcome_of(status_of_grpc(5)), "error");
    }

    #[test]
    fn grpc_refusal_carries_error_info() {
        let r = refusal_response(Flavor::Grpc, &Refusal::new(403, "denied"));
        let st = tonic::Status::from_header_map(r.headers()).expect("status");
        assert_eq!(st.code(), tonic::Code::PermissionDenied);
        assert_eq!(st.message(), "");
        let info = st.get_details_error_info().expect("error info");
        assert_eq!(info.reason, "denied");
    }
}
