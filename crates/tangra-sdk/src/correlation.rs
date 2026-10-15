//! Correlation IDs (`x-request-id`) and W3C trace context, per call
//! (go-tangra `observe/correlation.go`, `observe/tracing.go`).
//!
//! Server side: a valid incoming `x-request-id` (`^[A-Za-z0-9._-]{1,128}$`)
//! is accepted, an invalid one is replaced, an absent one is generated (a
//! UUIDv7), and the result is echoed in the response header. The
//! [`RequestContext`] of the current call is available to handlers as an
//! axum extractor / request extension and as a task-local, from which
//! outbound calls made through the SDK client inherit the correlation ID and
//! the incoming `traceparent`/`baggage`.

use std::future::Future;

use http::HeaderMap;

/// The metadata key / HTTP header carrying the correlation ID.
pub const HEADER: &str = "x-request-id";
/// W3C trace context header.
pub const TRACEPARENT: &str = "traceparent";
/// W3C baggage header.
pub const BAGGAGE: &str = "baggage";

/// Whether `s` satisfies `^[A-Za-z0-9._-]{1,128}$`.
pub fn valid(s: &str) -> bool {
    (1..=128).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// A new UUIDv7 correlation ID (time-ordered, random tail, lower-case).
pub fn new_id() -> String {
    uuid::Uuid::now_v7().hyphenated().to_string()
}

/// Resolves the server-side correlation ID from request headers: accept a
/// valid value, replace an invalid one, generate one when absent. The second
/// value reports whether an invalid incoming ID was replaced.
pub fn resolve(headers: &HeaderMap) -> (String, bool) {
    match headers.get(HEADER).map(|v| v.to_str().unwrap_or("\u{0}")) {
        Some(id) if !id.is_empty() && valid(id) => (id.to_owned(), false),
        Some(id) if !id.is_empty() => (new_id(), true),
        _ => (new_id(), false),
    }
}

/// A parsed W3C `traceparent` (version 00 layout).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceParent {
    /// 32 lower-case hex digits, not all zero.
    pub trace_id: String,
    /// 16 lower-case hex digits, not all zero.
    pub span_id: String,
    /// Trace flags.
    pub flags: u8,
}

impl TraceParent {
    /// Parses a `traceparent` header as the OpenTelemetry Go propagator does:
    /// `vv-<32hex>-<16hex>-<2hex>`, version `ff` refused, version 00 exact
    /// length, all-zero IDs refused.
    pub fn parse(h: &str) -> Option<Self> {
        let parts: Vec<&str> = h.trim().split('-').collect();
        if parts.len() < 4 {
            return None;
        }
        let hex = |s: &str, n: usize| {
            s.len() == n
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        };
        let (ver, tid, sid, fl) = (parts[0], parts[1], parts[2], parts[3]);
        if !hex(ver, 2) || ver == "ff" || (ver == "00" && parts.len() != 4) {
            return None;
        }
        if !hex(tid, 32) || !hex(sid, 16) || !hex(fl, 2) {
            return None;
        }
        if tid.bytes().all(|b| b == b'0') || sid.bytes().all(|b| b == b'0') {
            return None;
        }
        let flags = u8::from_str_radix(fl, 16).ok()?;
        Some(Self {
            trace_id: tid.to_owned(),
            span_id: sid.to_owned(),
            flags,
        })
    }

    /// The header value (`00-<trace>-<span>-<flags>`).
    pub fn header_value(&self) -> String {
        format!("00-{}-{}-{:02x}", self.trace_id, self.span_id, self.flags & 0x01)
    }
}

/// Per-call context established by the server chain.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RequestContext {
    /// The correlation ID of this call (echoed in `x-request-id`).
    pub correlation_id: String,
    /// The incoming trace parent, if any.
    pub trace: Option<TraceParent>,
    /// The incoming baggage header, forwarded verbatim on outbound calls.
    pub baggage: Option<String>,
}

impl RequestContext {
    /// The W3C trace ID, or "".
    pub fn trace_id(&self) -> &str {
        self.trace.as_ref().map_or("", |t| t.trace_id.as_str())
    }

    /// Builds the context from request headers.
    pub fn from_headers(headers: &HeaderMap) -> (Self, bool) {
        let (correlation_id, replaced) = resolve(headers);
        let trace = headers
            .get(TRACEPARENT)
            .and_then(|v| v.to_str().ok())
            .and_then(TraceParent::parse);
        let baggage = headers
            .get(BAGGAGE)
            .and_then(|v| v.to_str().ok())
            .filter(|b| !b.is_empty() && b.len() <= 8192)
            .map(str::to_owned);
        (
            Self {
                correlation_id,
                trace,
                baggage,
            },
            replaced,
        )
    }

    /// The context of the current task, if a server call is in progress.
    pub fn current() -> Option<Self> {
        CURRENT.try_with(Clone::clone).ok()
    }

    /// Runs `fut` with this context as the current task context.
    pub fn scope<F: Future>(self, fut: F) -> impl Future<Output = F::Output> {
        CURRENT.scope(self, fut)
    }

    /// Adds `x-request-id` (generating one when empty), `traceparent` and
    /// `baggage` to outbound headers (go-tangra `observe.ClientCorrelation`,
    /// `ClientTracing` with the default no-op tracer, which forwards the
    /// incoming span context unchanged).
    pub fn inject(&self, headers: &mut HeaderMap) {
        let id = if self.correlation_id.is_empty() {
            new_id()
        } else {
            self.correlation_id.clone()
        };
        if let Ok(v) = id.parse() {
            headers.insert(HEADER, v);
        }
        if let Some(t) = &self.trace
            && let Ok(v) = t.header_value().parse()
        {
            headers.insert(TRACEPARENT, v);
        }
        if let Some(b) = &self.baggage
            && let Ok(v) = b.parse()
        {
            headers.insert(BAGGAGE, v);
        }
    }
}

tokio::task_local! {
    static CURRENT: RequestContext;
}

impl<S: Send + Sync> axum::extract::FromRequestParts<S> for RequestContext {
    type Rejection = crate::error::ApiError;

    async fn from_request_parts(parts: &mut http::request::Parts, _: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<Self>()
            .cloned()
            .ok_or_else(crate::error::ApiError::internal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(v: Option<&str>) -> HeaderMap {
        let mut h = HeaderMap::new();
        if let Some(v) = v {
            h.insert(
                HEADER,
                v.parse().unwrap_or_else(|_| http::HeaderValue::from_static("x")),
            );
        }
        h
    }

    #[test]
    fn validity() {
        assert!(valid("abc-DEF_1.2"));
        assert!(valid(&"a".repeat(128)));
        assert!(!valid(&"a".repeat(129)));
        assert!(!valid(""));
        assert!(!valid("a b"));
        assert!(!valid("a/b"));
    }

    #[test]
    fn new_ids_are_uuid_v7() {
        let id = new_id();
        assert_eq!(id.len(), 36);
        assert_eq!(&id[14..15], "7");
        assert!(matches!(&id[19..20], "8" | "9" | "a" | "b"));
        assert!(valid(&id));
        assert_ne!(new_id(), id);
    }

    #[test]
    fn resolve_rules() {
        assert_eq!(resolve(&headers(Some("req-1"))), ("req-1".to_owned(), false));
        let (id, replaced) = resolve(&headers(Some("bad id!")));
        assert!(replaced && valid(&id) && id != "bad id!");
        let (id, replaced) = resolve(&headers(None));
        assert!(!replaced && id.len() == 36);
        let (id, replaced) = resolve(&headers(Some(&"x".repeat(200))));
        assert!(replaced && id.len() == 36);
    }

    #[test]
    fn traceparent() {
        let tp = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        let p = TraceParent::parse(tp).expect("valid");
        assert_eq!(p.trace_id, "4bf92f3577b34da6a3ce929d0e0e4736");
        assert_eq!(p.header_value(), tp);
        for bad in [
            "00-00000000000000000000000000000000-00f067aa0ba902b7-01",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01",
            "ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            "00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-extra",
            "garbage",
        ] {
            assert_eq!(TraceParent::parse(bad), None, "{bad}");
        }
    }

    #[tokio::test]
    async fn task_local_scope_and_inject() {
        assert_eq!(RequestContext::current(), None);
        let mut h = HeaderMap::new();
        h.insert(
            HEADER,
            "abc"
                .parse()
                .unwrap_or_else(|_| http::HeaderValue::from_static("x")),
        );
        h.insert(
            TRACEPARENT,
            http::HeaderValue::from_static("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"),
        );
        let (ctx, _) = RequestContext::from_headers(&h);
        let inner = ctx
            .clone()
            .scope(async { RequestContext::current().unwrap_or_default() })
            .await;
        assert_eq!(inner, ctx);
        let mut out = HeaderMap::new();
        inner.inject(&mut out);
        assert_eq!(out[HEADER], "abc");
        assert_eq!(
            out[TRACEPARENT],
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
        );
        let mut out2 = HeaderMap::new();
        RequestContext::default().inject(&mut out2);
        assert!(valid(out2[HEADER].to_str().unwrap_or("")));
        assert!(!out2.contains_key(TRACEPARENT));
    }
}
