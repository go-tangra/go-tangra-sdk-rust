//! Framework security events (go-tangra `audit/event.go`), written as one
//! `"audit"` log line each through the redacting logger (the default slog
//! sink, `audit.SlogSink`).

use std::collections::BTreeMap;
use std::time::SystemTime;

use crate::log::{Logger, attr};

/// Event types (closed vocabulary).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(missing_docs)]
pub enum Type {
    AuthnRefused,
    AuthzRefused,
    AuthzAllowed,
    IdentityIssued,
    IdentityRenewed,
    IdentityRenewFailed,
    IdentityExpired,
    TrustBundleUpdated,
    PolicyLoaded,
    PolicyLoadFailed,
    InsecureModeEnabled,
    LimitExceeded,
    ChannelRefusedDowngrade,
}

impl Type {
    /// The wire string.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AuthnRefused => "authn_refused",
            Self::AuthzRefused => "authz_refused",
            Self::AuthzAllowed => "authz_allowed",
            Self::IdentityIssued => "identity_issued",
            Self::IdentityRenewed => "identity_renewed",
            Self::IdentityRenewFailed => "identity_renewal_failed",
            Self::IdentityExpired => "identity_expired",
            Self::TrustBundleUpdated => "trust_bundle_updated",
            Self::PolicyLoaded => "policy_loaded",
            Self::PolicyLoadFailed => "policy_load_failed",
            Self::InsecureModeEnabled => "insecure_mode_enabled",
            Self::LimitExceeded => "limit_exceeded",
            Self::ChannelRefusedDowngrade => "channel_refused_downgrade",
        }
    }
}

/// Event outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Outcome {
    /// `refused`
    Refused,
    /// `ok`
    Ok,
    /// `failed`
    Failed,
}

impl Outcome {
    /// The wire string.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Refused => "refused",
            Self::Ok => "ok",
            Self::Failed => "failed",
        }
    }
}

/// One audit record. `reason` uses the closed audit vocabulary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    /// When (defaults to now).
    pub time: Option<SystemTime>,
    /// Type.
    pub kind: Type,
    /// Outcome.
    pub outcome: Outcome,
    /// Reason (closed vocabulary).
    pub reason: &'static str,
    /// The local SPIFFE ID.
    pub local_id: String,
    /// The ID the peer claimed.
    pub claimed_peer_id: String,
    /// The verified peer ID.
    pub verified_peer_id: String,
    /// The operation.
    pub operation: String,
    /// Correlation ID (generated when empty).
    pub correlation_id: String,
    /// W3C trace ID.
    pub trace_id: String,
    /// Deciding policy rule.
    pub rule_id: String,
    /// Policy version.
    pub policy_version: String,
    /// Remote address.
    pub remote_addr: String,
    /// Extra attributes (`attr_<key>`).
    pub attrs: BTreeMap<String, String>,
}

impl Event {
    /// A new event with empty optional fields.
    pub fn new(kind: Type, outcome: Outcome, reason: &'static str, local_id: &str) -> Self {
        Self {
            time: None,
            kind,
            outcome,
            reason,
            local_id: local_id.to_owned(),
            claimed_peer_id: String::new(),
            verified_peer_id: String::new(),
            operation: String::new(),
            correlation_id: String::new(),
            trace_id: String::new(),
            rule_id: String::new(),
            policy_version: String::new(),
            remote_addr: String::new(),
            attrs: BTreeMap::new(),
        }
    }
}

/// RFC 3339 with nanoseconds in UTC (`2006-01-02T15:04:05.000000000Z07:00`).
fn audit_time(t: SystemTime) -> String {
    chrono::DateTime::<chrono::Utc>::from(t)
        .format("%Y-%m-%dT%H:%M:%S%.9fZ")
        .to_string()
}

/// Writes `e` as an `audit` log line (go-tangra `audit.SlogSink.Emit`).
pub fn emit(log: &Logger, mut e: Event) {
    if e.correlation_id.is_empty() {
        e.correlation_id = crate::correlation::new_id();
    }
    let mut attrs = vec![
        attr("audit_time", audit_time(e.time.unwrap_or_else(SystemTime::now))),
        attr("type", e.kind.as_str()),
        attr("outcome", e.outcome.as_str()),
        attr("reason", e.reason),
        attr("local_id", e.local_id),
        attr("correlation_id", e.correlation_id),
    ];
    for (k, v) in [
        ("claimed_peer_id", e.claimed_peer_id),
        ("verified_peer_id", e.verified_peer_id),
        ("operation", e.operation),
        ("trace_id", e.trace_id),
        ("rule_id", e.rule_id),
        ("policy_version", e.policy_version),
        ("remote_addr", e.remote_addr),
    ] {
        if !v.is_empty() {
            attrs.push(attr(k, v));
        }
    }
    for (k, v) in e.attrs {
        attrs.push(attr(format!("attr_{k}"), v));
    }
    log.info("audit", attrs);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log::{Capture, Level};

    #[test]
    fn audit_line_shape() {
        let cap = Capture::new();
        let log = Logger::new(cap.clone(), Level::Info).with(vec![attr("service", "orders")]);
        let mut e = Event::new(
            Type::AuthzRefused,
            Outcome::Refused,
            "no_matching_rule",
            "spiffe://td/svc/orders",
        );
        e.claimed_peer_id = "spiffe://td/svc/x".into();
        e.verified_peer_id = "spiffe://td/svc/x".into();
        e.operation = "GET /v1/x".into();
        e.correlation_id = "c-1".into();
        e.attrs.insert("limit".into(), "request_body".into());
        emit(&log, e);
        let v = &cap.lines()[0];
        assert_eq!(v["msg"], "audit");
        assert_eq!(v["type"], "authz_refused");
        assert_eq!(v["outcome"], "refused");
        assert_eq!(v["reason"], "no_matching_rule");
        assert_eq!(v["correlation_id"], "c-1");
        assert_eq!(v["attr_limit"], "request_body");
        assert!(v.get("rule_id").is_none());
        let t = v["audit_time"].as_str().unwrap_or("");
        assert!(t.ends_with('Z') && t.len() == 30, "{t}");
    }
}
