//! Request integration (authclient `middleware.go`, `grpc.go`).
//!
//! - [`UserAuthLayer`] requires a valid bearer token on every request of
//!   the routes it wraps (authclient `Middleware`): a refusal is
//!   `401 {"reason":"unauthenticated"}` with `Content-Type:
//!   application/json` and `WWW-Authenticate: Bearer realm="freya"`.
//! - [`User`] is the axum extractor for the verified user (the same 401
//!   when no layer verified one).
//! - [`verify_grpc`] is the `UnaryInterceptor` check for tonic handlers
//!   (`Unauthenticated("unauthenticated")`).

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::body::Body;
use axum::extract::FromRequestParts;
use axum::response::{IntoResponse, Response};
use http::{HeaderValue, Request, StatusCode, header};

use super::verifier::{User, Verifier};

/// Extracts a bearer credential ("" when absent; authclient `BearerToken`).
pub fn bearer_token(authorization: &str) -> &str {
    let b = authorization.as_bytes();
    if b.len() > 7 && b[..7].eq_ignore_ascii_case(b"Bearer ") {
        return authorization[7..].trim();
    }
    ""
}

/// The bearer token of `headers` (first `Authorization` value).
pub fn bearer_from_headers(headers: &http::HeaderMap) -> String {
    headers
        .get(header::AUTHORIZATION)
        .map(|v| bearer_token(&String::from_utf8_lossy(v.as_bytes())).to_owned())
        .unwrap_or_default()
}

/// The 401 every refusal gets (authclient `Middleware`).
pub fn unauthenticated() -> Response {
    let mut r = Response::new(Body::from(r#"{"reason":"unauthenticated"}"#));
    *r.status_mut() = StatusCode::UNAUTHORIZED;
    let h = r.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    h.insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static(crate::error::WWW_AUTHENTICATE),
    );
    r
}

/// The rejection of the [`User`] extractor.
#[derive(Debug, Clone, Copy)]
pub struct Unauthenticated;

impl IntoResponse for Unauthenticated {
    fn into_response(self) -> Response {
        unauthenticated()
    }
}

impl<S: Send + Sync> FromRequestParts<S> for User {
    type Rejection = Unauthenticated;

    async fn from_request_parts(parts: &mut http::request::Parts, _: &S) -> Result<Self, Self::Rejection> {
        parts.extensions.get::<User>().cloned().ok_or(Unauthenticated)
    }
}

impl<S: Send + Sync> axum::extract::OptionalFromRequestParts<S> for User {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut http::request::Parts,
        _: &S,
    ) -> Result<Option<Self>, Self::Rejection> {
        Ok(parts.extensions.get::<User>().cloned())
    }
}

/// Requires a valid platform token on every request (authclient
/// `Middleware`); the verified [`User`] is put in the request extensions.
#[derive(Clone, Debug)]
pub struct UserAuthLayer {
    verifier: Arc<Verifier>,
}

impl UserAuthLayer {
    /// A layer over `verifier`.
    pub fn new(verifier: Arc<Verifier>) -> Self {
        Self { verifier }
    }
}

impl<S> tower::Layer<S> for UserAuthLayer {
    type Service = UserAuth<S>;

    fn layer(&self, inner: S) -> Self::Service {
        UserAuth {
            verifier: Arc::clone(&self.verifier),
            inner,
        }
    }
}

/// The service of [`UserAuthLayer`].
#[derive(Clone, Debug)]
pub struct UserAuth<S> {
    verifier: Arc<Verifier>,
    inner: S,
}

impl<S, B> tower::Service<Request<B>> for UserAuth<S>
where
    S: tower::Service<Request<B>, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
    B: Send + 'static,
{
    type Response = Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Response, S::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<B>) -> Self::Future {
        let v = Arc::clone(&self.verifier);
        // The clone that was polled ready serves this request.
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        Box::pin(async move {
            let tok = bearer_from_headers(req.headers());
            match v.verify(&tok).await {
                Ok(user) => {
                    req.extensions_mut().insert(user);
                    inner.call(req).await
                }
                Err(_) => Ok(unauthenticated()),
            }
        })
    }
}

/// Verifies the `authorization` metadata of a gRPC call (authclient
/// `UnaryInterceptor`).
pub async fn verify_grpc<T>(v: &Verifier, req: &tonic::Request<T>) -> Result<User, tonic::Status> {
    let tok = req
        .metadata()
        .get("authorization")
        .and_then(|m| m.to_str().ok())
        .map(|a| bearer_token(a).to_owned())
        .unwrap_or_default();
    v.verify(&tok)
        .await
        .map_err(|_| tonic::Status::unauthenticated("unauthenticated"))
}
