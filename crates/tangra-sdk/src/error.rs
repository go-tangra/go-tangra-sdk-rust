//! The `{"reason"[,"detail"]}` error vocabulary.
//!
//! Two encoders exist in Go and both are reproduced here:
//!
//! - Module handlers answer with a closed reason vocabulary and the status
//!   that goes with it (deployer `internal/httpapi/errors.go`): the body is
//!   `{"reason":"<id>"}` or `{"reason":"<id>","detail":{...}}`, never a
//!   message. [`ApiError`] implements axum's `IntoResponse` for this. A 5xx
//!   whose reason is not part of the vocabulary (an internal failure) is
//!   collapsed to `500 {"reason":"internal"}` so nothing internal leaks.
//! - Framework refusals raised by the security chain go through the
//!   transport error encoder (go-tangra `transport/http/errors.go`):
//!   [`framework_error_response`] writes `{"reason"}` only, maps 504 to
//!   `timeout` and collapses every other 5xx (and anything outside 4xx) to
//!   `500 internal`.

use std::borrow::Cow;

use axum::response::{IntoResponse, Response};
use http::{HeaderValue, StatusCode, header};
use serde_json::{Map, Value};

use crate::gofmt::json_html_escaped;

/// `401 unauthenticated`.
pub const UNAUTHENTICATED: &str = "unauthenticated";
/// `403 forbidden`.
pub const FORBIDDEN: &str = "forbidden";
/// `404 not_found`.
pub const NOT_FOUND: &str = "not_found";
/// `400 malformed_body`.
pub const MALFORMED_BODY: &str = "malformed_body";
/// `422 validation_failed` (an invalid query parameter adds `detail.param`).
pub const VALIDATION_FAILED: &str = "validation_failed";
/// `409 conflict`.
pub const CONFLICT: &str = "conflict";
/// `413 body_too_large`.
pub const BODY_TOO_LARGE: &str = "body_too_large";
/// `429 rate_limited`.
pub const RATE_LIMITED: &str = "rate_limited";
/// `503 temporarily_unavailable`.
pub const TEMPORARILY_UNAVAILABLE: &str = "temporarily_unavailable";
/// `501 not_implemented`.
pub const NOT_IMPLEMENTED: &str = "not_implemented";
/// `500 internal`: every collapsed server error.
pub const INTERNAL: &str = "internal";
/// `504 timeout` (framework encoder only).
pub const TIMEOUT: &str = "timeout";

/// The module vocabulary with its fixed statuses.
pub const VOCABULARY: [(&str, StatusCode); 10] = [
    (UNAUTHENTICATED, StatusCode::UNAUTHORIZED),
    (FORBIDDEN, StatusCode::FORBIDDEN),
    (NOT_FOUND, StatusCode::NOT_FOUND),
    (MALFORMED_BODY, StatusCode::BAD_REQUEST),
    (VALIDATION_FAILED, StatusCode::UNPROCESSABLE_ENTITY),
    (CONFLICT, StatusCode::CONFLICT),
    (BODY_TOO_LARGE, StatusCode::PAYLOAD_TOO_LARGE),
    (RATE_LIMITED, StatusCode::TOO_MANY_REQUESTS),
    (TEMPORARILY_UNAVAILABLE, StatusCode::SERVICE_UNAVAILABLE),
    (NOT_IMPLEMENTED, StatusCode::NOT_IMPLEMENTED),
];

/// A refusal with a stable reason (and optional detail object).
#[derive(Debug, Clone, PartialEq)]
pub struct ApiError {
    status: StatusCode,
    reason: Cow<'static, str>,
    detail: Option<Map<String, Value>>,
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.reason)
    }
}

impl std::error::Error for ApiError {}

impl ApiError {
    /// A refusal with an explicit status and reason identifier.
    pub fn new(status: StatusCode, reason: impl Into<Cow<'static, str>>) -> Self {
        Self {
            status,
            reason: reason.into(),
            detail: None,
        }
    }

    /// `401 unauthenticated`.
    pub fn unauthenticated() -> Self {
        Self::new(StatusCode::UNAUTHORIZED, UNAUTHENTICATED)
    }
    /// `403 forbidden`.
    pub fn forbidden() -> Self {
        Self::new(StatusCode::FORBIDDEN, FORBIDDEN)
    }
    /// `404 not_found`.
    pub fn not_found() -> Self {
        Self::new(StatusCode::NOT_FOUND, NOT_FOUND)
    }
    /// `400 malformed_body`.
    pub fn malformed_body() -> Self {
        Self::new(StatusCode::BAD_REQUEST, MALFORMED_BODY)
    }
    /// `422 validation_failed`.
    pub fn validation_failed() -> Self {
        Self::new(StatusCode::UNPROCESSABLE_ENTITY, VALIDATION_FAILED)
    }
    /// `422 validation_failed` with `detail.param` naming the parameter
    /// (never its value), as the deployer answers list/query errors.
    pub fn invalid_param(param: &str) -> Self {
        let mut d = Map::new();
        d.insert("param".to_owned(), Value::String(param.to_owned()));
        Self::validation_failed().with_detail(d)
    }
    /// `409 conflict`.
    pub fn conflict() -> Self {
        Self::new(StatusCode::CONFLICT, CONFLICT)
    }
    /// `413 body_too_large`.
    pub fn body_too_large() -> Self {
        Self::new(StatusCode::PAYLOAD_TOO_LARGE, BODY_TOO_LARGE)
    }
    /// `429 rate_limited`.
    pub fn rate_limited() -> Self {
        Self::new(StatusCode::TOO_MANY_REQUESTS, RATE_LIMITED)
    }
    /// `503 temporarily_unavailable`.
    pub fn temporarily_unavailable() -> Self {
        Self::new(StatusCode::SERVICE_UNAVAILABLE, TEMPORARILY_UNAVAILABLE)
    }
    /// `501 not_implemented`.
    pub fn not_implemented() -> Self {
        Self::new(StatusCode::NOT_IMPLEMENTED, NOT_IMPLEMENTED)
    }
    /// `500 internal`.
    pub fn internal() -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, INTERNAL)
    }

    /// Attaches a detail object (values must never be secrets).
    #[must_use]
    pub fn with_detail(mut self, detail: Map<String, Value>) -> Self {
        self.detail = Some(detail);
        self
    }

    /// The status that will be sent (after the 5xx collapse).
    pub fn status(&self) -> StatusCode {
        self.effective().0
    }

    /// The reason that will be sent (after the 5xx collapse).
    pub fn reason(&self) -> &str {
        self.effective().1
    }

    /// Server errors outside the vocabulary collapse to `500 internal`.
    fn effective(&self) -> (StatusCode, &str) {
        if self.status.is_server_error()
            && !VOCABULARY
                .iter()
                .any(|(r, s)| *r == self.reason && *s == self.status)
        {
            return (StatusCode::INTERNAL_SERVER_ERROR, INTERNAL);
        }
        (self.status, &self.reason)
    }

    /// The JSON body (Go `json.Encoder` output, trailing newline included).
    pub fn body(&self) -> String {
        let (status, reason) = self.effective();
        let mut m = Map::new();
        m.insert("reason".to_owned(), Value::String(reason.to_owned()));
        if let Some(d) = &self.detail
            && !status.is_server_error()
        {
            m.insert("detail".to_owned(), Value::Object(d.clone()));
        }
        // encoding/json writes map keys sorted, as serde_json's Map does.
        let mut s = json_html_escaped(&Value::Object(m));
        s.push('\n');
        s
    }
}

/// Writes a JSON body with the deployer's API headers (`Content-Type:
/// application/json`, `Cache-Control: no-store`).
pub fn json_response(status: StatusCode, body: String) -> Response {
    let mut r = (status, body).into_response();
    let h = r.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        json_response(self.status(), self.body())
    }
}

/// The framework transport encoder (go-tangra `transport/http/errors.go`):
/// `{"reason"}` only; 504 becomes `timeout`; any other 5xx, anything outside
/// 4xx, or an empty reason becomes `500 internal`.
pub fn framework_error_parts(status: StatusCode, reason: &str) -> (StatusCode, String) {
    let code = status.as_u16();
    if code == 504 {
        return (status, TIMEOUT.to_owned());
    }
    if !(400..500).contains(&code) || reason.is_empty() {
        return (StatusCode::INTERNAL_SERVER_ERROR, INTERNAL.to_owned());
    }
    (status, reason.to_owned())
}

/// Encodes a framework refusal as an HTTP response (`Content-Type:
/// application/json`, body `{"reason":"..."}` plus newline).
pub fn framework_error_response(status: StatusCode, reason: &str) -> Response {
    let (status, reason) = framework_error_parts(status, reason);
    let mut m = Map::new();
    m.insert("reason".to_owned(), Value::String(reason));
    let mut body = json_html_escaped(&Value::Object(m));
    body.push('\n');
    let mut r = (status, body).into_response();
    r.headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    r
}

/// Sets the response headers every deployer route shares (`nosniff`,
/// `no-referrer`, `DENY`, `no-store`; deployer `internal/httpapi/middleware.go`).
pub fn set_secure_headers(h: &mut http::HeaderMap) {
    h.insert("x-content-type-options", HeaderValue::from_static("nosniff"));
    h.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    h.insert("x-frame-options", HeaderValue::from_static("DENY"));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
}

/// The challenge sent with 401 `unauthenticated` for a bad platform token.
pub const WWW_AUTHENTICATE: &str = "Bearer realm=\"freya\"";

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;

    async fn body_of(r: Response) -> (StatusCode, http::HeaderMap, String) {
        let (parts, body) = r.into_parts();
        let bytes = body.collect().await.map(|c| c.to_bytes()).unwrap_or_default();
        (
            parts.status,
            parts.headers,
            String::from_utf8_lossy(&bytes).into_owned(),
        )
    }

    #[tokio::test]
    async fn vocabulary_statuses_and_bodies() {
        let cases = [
            (
                ApiError::unauthenticated(),
                401,
                "{\"reason\":\"unauthenticated\"}\n",
            ),
            (ApiError::forbidden(), 403, "{\"reason\":\"forbidden\"}\n"),
            (ApiError::not_found(), 404, "{\"reason\":\"not_found\"}\n"),
            (
                ApiError::malformed_body(),
                400,
                "{\"reason\":\"malformed_body\"}\n",
            ),
            (
                ApiError::validation_failed(),
                422,
                "{\"reason\":\"validation_failed\"}\n",
            ),
            (ApiError::conflict(), 409, "{\"reason\":\"conflict\"}\n"),
            (
                ApiError::body_too_large(),
                413,
                "{\"reason\":\"body_too_large\"}\n",
            ),
            (ApiError::rate_limited(), 429, "{\"reason\":\"rate_limited\"}\n"),
            (
                ApiError::temporarily_unavailable(),
                503,
                "{\"reason\":\"temporarily_unavailable\"}\n",
            ),
            (
                ApiError::not_implemented(),
                501,
                "{\"reason\":\"not_implemented\"}\n",
            ),
            (
                ApiError::invalid_param("page"),
                422,
                "{\"detail\":{\"param\":\"page\"},\"reason\":\"validation_failed\"}\n",
            ),
            // A server error outside the vocabulary collapses to internal.
            (
                ApiError::new(StatusCode::BAD_GATEWAY, "db_down"),
                500,
                "{\"reason\":\"internal\"}\n",
            ),
            (
                ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "pool_exhausted"),
                500,
                "{\"reason\":\"internal\"}\n",
            ),
            (ApiError::internal(), 500, "{\"reason\":\"internal\"}\n"),
        ];
        for (e, status, body) in cases {
            let (s, h, b) = body_of(e.clone().into_response()).await;
            assert_eq!(s.as_u16(), status, "{e}");
            assert_eq!(b, body, "{e}");
            assert_eq!(h[header::CONTENT_TYPE], "application/json");
            assert_eq!(h[header::CACHE_CONTROL], "no-store");
        }
    }

    #[tokio::test]
    async fn framework_encoder_collapses_like_go() {
        let cases = [
            (403, "denied", 403, "denied"),
            (401, "no_identity", 401, "no_identity"),
            (503, "identity_expired", 500, "internal"),
            (500, "UNKNOWN", 500, "internal"),
            (504, "anything", 504, "timeout"),
            (302, "moved", 500, "internal"),
            (404, "", 500, "internal"),
        ];
        for (code, reason, want_code, want_reason) in cases {
            let st = StatusCode::from_u16(code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            let (s, h, b) = body_of(framework_error_response(st, reason)).await;
            assert_eq!(s.as_u16(), want_code, "{code}");
            assert_eq!(b, format!("{{\"reason\":\"{want_reason}\"}}\n"));
            assert_eq!(h[header::CONTENT_TYPE], "application/json");
        }
    }

    #[test]
    fn detail_is_html_escaped_like_encoding_json() {
        let mut d = Map::new();
        d.insert("param".into(), Value::String("<x>".into()));
        let e = ApiError::validation_failed().with_detail(d);
        assert_eq!(
            e.body(),
            "{\"detail\":{\"param\":\"\\u003cx\\u003e\"},\"reason\":\"validation_failed\"}\n"
        );
    }
}
