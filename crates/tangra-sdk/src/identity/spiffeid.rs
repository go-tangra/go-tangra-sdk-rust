//! SPIFFE service identities `spiffe://<trust-domain>/svc/<service-name>`
//! (go-tangra `identity/spiffeid.go`).

use std::fmt;
use std::str::FromStr;

const SCHEME: &str = "spiffe://";
const SVC_PREFIX: &str = "/svc/";

/// Whether `td` is a syntactically valid trust domain (`^[a-z0-9._-]{1,255}$`).
pub fn valid_trust_domain(td: &str) -> bool {
    (1..=255).contains(&td.len())
        && td
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-'))
}

/// Whether `name` is a syntactically valid service name
/// (`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`).
pub fn valid_service_name(name: &str) -> bool {
    let b = name.as_bytes();
    let alnum = |c: &u8| c.is_ascii_lowercase() || c.is_ascii_digit();
    (1..=63).contains(&b.len())
        && b.iter().all(|c| alnum(c) || *c == b'-')
        && b.first().is_some_and(alnum)
        && b.last().is_some_and(alnum)
}

/// Why a string is not a canonical service SPIFFE ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SpiffeIdError {
    /// Empty input.
    #[error("spiffe id: empty")]
    Empty,
    /// Not `spiffe://`.
    #[error("spiffe id: scheme must be spiffe://")]
    Scheme,
    /// Path is not `/svc/<name>`.
    #[error("spiffe id: path must start with /svc/")]
    Path,
    /// Trust domain does not match `^[a-z0-9._-]{1,255}$`.
    #[error("spiffe id: invalid trust domain")]
    TrustDomain,
    /// Service name does not match the service name grammar.
    #[error("spiffe id: invalid service name")]
    ServiceName,
}

/// A validated, canonical service identity. Only the canonical lower-case
/// form parses; `Display` always round-trips.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SpiffeId {
    td: String,
    name: String,
}

impl SpiffeId {
    /// Parses and validates `s` (never normalises).
    pub fn parse(s: &str) -> Result<Self, SpiffeIdError> {
        if s.is_empty() {
            return Err(SpiffeIdError::Empty);
        }
        let rest = s.strip_prefix(SCHEME).ok_or(SpiffeIdError::Scheme)?;
        let slash = rest.find('/').ok_or(SpiffeIdError::Path)?;
        let (td, path) = rest.split_at(slash);
        if !valid_trust_domain(td) {
            return Err(SpiffeIdError::TrustDomain);
        }
        let name = path.strip_prefix(SVC_PREFIX).ok_or(SpiffeIdError::Path)?;
        if !valid_service_name(name) {
            return Err(SpiffeIdError::ServiceName);
        }
        Ok(Self {
            td: td.to_owned(),
            name: name.to_owned(),
        })
    }

    /// Builds an ID from its parts, validating both.
    pub fn new(trust_domain: &str, service_name: &str) -> Result<Self, SpiffeIdError> {
        Self::parse(&format!("{SCHEME}{trust_domain}{SVC_PREFIX}{service_name}"))
    }

    /// The trust domain.
    pub fn trust_domain(&self) -> &str {
        &self.td
    }

    /// The service name.
    pub fn service_name(&self) -> &str {
        &self.name
    }
}

impl fmt::Display for SpiffeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{SCHEME}{}{SVC_PREFIX}{}", self.td, self.name)
    }
}

impl fmt::Debug for SpiffeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SpiffeId({self})")
    }
}

impl FromStr for SpiffeId {
    type Err = SpiffeIdError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_canonical_only() {
        let id = SpiffeId::parse("spiffe://example.org/svc/orders").expect("valid");
        assert_eq!(id.trust_domain(), "example.org");
        assert_eq!(id.service_name(), "orders");
        assert_eq!(id.to_string(), "spiffe://example.org/svc/orders");
        assert_eq!(SpiffeId::new("example.org", "orders"), Ok(id));
        let bad = [
            ("", SpiffeIdError::Empty),
            ("https://example.org/svc/a", SpiffeIdError::Scheme),
            ("spiffe://example.org", SpiffeIdError::Path),
            ("spiffe://Example.org/svc/a", SpiffeIdError::TrustDomain),
            ("spiffe://example.org/ns/a", SpiffeIdError::Path),
            ("spiffe://example.org/svc/A", SpiffeIdError::ServiceName),
            ("spiffe://example.org/svc/a/b", SpiffeIdError::ServiceName),
            ("spiffe://example.org/svc/-a", SpiffeIdError::ServiceName),
            ("spiffe:///svc/a", SpiffeIdError::TrustDomain),
        ];
        for (s, want) in bad {
            assert_eq!(SpiffeId::parse(s), Err(want), "{s}");
        }
    }
}
