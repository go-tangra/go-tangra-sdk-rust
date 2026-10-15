//! `GET|HEAD /docs/v1/bundle` (go-tangra `helpdocs/handler.go`).

use std::collections::HashSet;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::Request;
use axum::routing::{MethodRouter, any};
use http::{HeaderValue, Method, Response, StatusCode, header};

use super::Bundle;
use crate::app::PeerIdentity;

/// Where a module serves its bundle on its mTLS HTTP server.
pub const BUNDLE_PATH: &str = "/docs/v1/bundle";

/// The gateway's service name (`spiffe://<td>/svc/gateway`).
pub const DEFAULT_GATEWAY_SERVICE: &str = "gateway";

/// Decides whether the caller of a request may fetch the bundle.
pub trait Authorizer: Send + Sync + 'static {
    /// True to serve the request.
    fn authorize(&self, req: &http::request::Parts) -> bool;
}

impl<F> Authorizer for F
where
    F: Fn(&http::request::Parts) -> bool + Send + Sync + 'static,
{
    fn authorize(&self, req: &http::request::Parts) -> bool {
        self(req)
    }
}

/// Admits callers whose verified mTLS peer (the [`PeerIdentity`] the
/// security chain puts on the request; the trust domain is already enforced
/// there) has one of the given service names. A request without a verified
/// peer is refused (Go `AllowServices`).
#[derive(Debug, Clone)]
pub struct AllowServices(HashSet<String>);

impl AllowServices {
    /// Admits these service names.
    pub fn new<I, S>(names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self(names.into_iter().map(Into::into).collect())
    }
}

impl Authorizer for AllowServices {
    fn authorize(&self, req: &http::request::Parts) -> bool {
        req.extensions
            .get::<PeerIdentity>()
            .is_some_and(|p| self.0.contains(p.id.service_name()))
    }
}

/// Go `http.Error`: text body plus newline, `text/plain; charset=utf-8`,
/// `nosniff`, no `Content-Length` of its own.
fn text_error(mut base: http::response::Builder, status: StatusCode, text: &str) -> Response<Body> {
    base = base
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header("x-content-type-options", "nosniff");
    base.body(Body::from(format!("{text}\n")))
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

/// The weak comparison of `If-None-Match` (Go `etagMatch`).
fn etag_match<'a>(values: impl Iterator<Item = &'a HeaderValue>, etag: &str) -> bool {
    values.filter_map(|v| v.to_str().ok()).any(|h| {
        h.split(',').any(|t| {
            let t = t.trim();
            t == "*" || t.strip_prefix("W/").unwrap_or(t) == etag
        })
    })
}

/// Serves `bundle` as JSON for GET and HEAD with `ETag: "<digest>"`,
/// `Cache-Control: no-cache` and `If-None-Match` -> 304. `authorize` gates
/// every request (use [`AllowServices`] with the configured gateway
/// service). An empty bundle is served without an `ETag`.
///
/// Mount it on the app's HTTP router, which runs the mTLS security chain
/// (peer verification and service policy) before the handler, and before
/// any catch-all route: `Router::new().route(BUNDLE_PATH, handler(..))`.
pub fn handler(bundle: Bundle, authorize: impl Authorizer) -> MethodRouter {
    let body = bytes::Bytes::from(bundle.marshal());
    let etag = (!bundle.digest.is_empty()).then(|| format!("\"{}\"", bundle.digest));
    let authorize: Arc<dyn Authorizer> = Arc::new(authorize);
    any(move |req: Request| {
        let body = body.clone();
        let etag = etag.clone();
        let authorize = Arc::clone(&authorize);
        async move {
            let (parts, _) = req.into_parts();
            let base = Response::builder()
                .header("x-content-type-options", "nosniff")
                .header(header::CACHE_CONTROL, "no-cache");
            if parts.method != Method::GET && parts.method != Method::HEAD {
                return text_error(
                    base.header(header::ALLOW, "GET, HEAD"),
                    StatusCode::METHOD_NOT_ALLOWED,
                    "method not allowed",
                );
            }
            if !authorize.authorize(&parts) {
                return text_error(base, StatusCode::FORBIDDEN, "forbidden");
            }
            let mut base = base;
            if let Some(etag) = &etag {
                base = base.header(header::ETAG, etag.as_str());
                if etag_match(parts.headers.get_all(header::IF_NONE_MATCH).iter(), etag) {
                    return base
                        .status(StatusCode::NOT_MODIFIED)
                        .body(Body::empty())
                        .unwrap_or_else(|_| Response::new(Body::empty()));
                }
            }
            // For HEAD the router strips the body and keeps Content-Length.
            base.status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::CONTENT_LENGTH, body.len())
                .body(Body::from(body))
                .unwrap_or_else(|_| Response::new(Body::empty()))
        }
    })
}

/// A router serving [`handler`] at [`BUNDLE_PATH`]; merge it into the
/// module's router.
pub fn router(bundle: Bundle, authorize: impl Authorizer) -> axum::Router {
    axum::Router::new().route(BUNDLE_PATH, handler(bundle, authorize))
}
