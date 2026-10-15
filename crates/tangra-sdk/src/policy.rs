//! Service (caller) authorization policy (go-tangra `authz/policy.go`,
//! `authz/loader.go`, `authz/file/source.go`).
//!
//! A YAML (or JSON) document `{version, rules: [{id, from, to, operations,
//! effect}]}`. `from` holds SPIFFE ID globs, `to` service-name globs,
//! `operations` operation globs (`"/pkg.Svc/Method"` for gRPC, `"METHOD
//! /path"` for HTTP; default `["*"]`). `*` matches any run (including `/`),
//! `?` one byte. Decision: any matching deny wins, else any matching allow,
//! else deny. Refused calls are answered `403 {"reason":"denied"}`.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use serde::Deserialize;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::identity::SpiffeId;

/// Decision reasons (identical to the audit vocabulary).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Reason {
    /// `explicit_allow`
    ExplicitAllow,
    /// `explicit_deny`
    ExplicitDeny,
    /// `no_matching_rule`
    NoMatchingRule,
    /// `no_policy`
    NoPolicy,
}

impl Reason {
    /// The audit string.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ExplicitAllow => "explicit_allow",
            Self::ExplicitDeny => "explicit_deny",
            Self::NoMatchingRule => "no_matching_rule",
            Self::NoPolicy => "no_policy",
        }
    }
}

/// The outcome of evaluating one call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    /// Whether the call may proceed.
    pub allowed: bool,
    /// Why.
    pub reason: Reason,
    /// The deciding rule, if any.
    pub rule_id: String,
    /// The policy version, if any.
    pub policy_version: String,
}

/// Decides whether `peer` may invoke `operation` on `callee`.
pub trait Authorizer: Send + Sync + 'static {
    /// Evaluates one call.
    fn authorize(&self, peer: &SpiffeId, callee: &str, operation: &str) -> Decision;
}

/// Permits everything (explicit development opt-in only).
#[derive(Debug, Clone, Copy, Default)]
pub struct AllowAll;

impl Authorizer for AllowAll {
    fn authorize(&self, _: &SpiffeId, _: &str, _: &str) -> Decision {
        Decision {
            allowed: true,
            reason: Reason::ExplicitAllow,
            rule_id: "allow-all".into(),
            policy_version: "allow-all".into(),
        }
    }
}

/// The deny-by-default authorizer used when no policy is loaded.
#[derive(Debug, Clone, Copy, Default)]
pub struct DenyAll;

impl Authorizer for DenyAll {
    fn authorize(&self, _: &SpiffeId, _: &str, _: &str) -> Decision {
        Decision {
            allowed: false,
            reason: Reason::NoPolicy,
            rule_id: String::new(),
            policy_version: String::new(),
        }
    }
}

/// Rule effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Effect {
    /// `allow`
    Allow,
    /// `deny`
    Deny,
}

/// One policy rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    /// Unique ID (`^[A-Za-z0-9._-]{1,64}$`).
    pub id: String,
    /// SPIFFE ID globs of callers.
    pub from: Vec<String>,
    /// Service-name globs of callees.
    pub to: Vec<String>,
    /// Operation globs (default `["*"]`).
    pub operations: Vec<String>,
    /// allow or deny.
    pub effect: Effect,
}

/// A loaded, validated, immutable policy document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    /// Document version.
    pub version: String,
    /// Rules, sorted by ID (decisions never depend on document order).
    pub rules: Vec<Rule>,
    /// Where it came from (`file:<path>`).
    pub source: String,
    /// When it was loaded.
    pub loaded_at: SystemTime,
}

/// A policy load or validation failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct PolicyError(pub String);

const MAX_RULES: usize = 10_000;
const MAX_VERSION_LEN: usize = 128;
const MAX_LIST_LEN: usize = 256;

fn rule_id_ok(s: &str) -> bool {
    (1..=64).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

fn svc_glob_ok(s: &str) -> bool {
    (1..=63).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'*' | b'?' | b'-'))
}

/// `^spiffe://[a-z0-9.-]{1,255}/svc/[a-z0-9*?-]{1,63}$`
fn spiffe_glob_ok(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("spiffe://") else {
        return false;
    };
    let Some(slash) = rest.find('/') else {
        return false;
    };
    let (td, path) = rest.split_at(slash);
    let td_ok = (1..=255).contains(&td.len())
        && td
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-'));
    td_ok && path.strip_prefix("/svc/").is_some_and(svc_glob_ok)
}

impl Policy {
    /// Validates `rules` and builds the policy (go-tangra `NewPolicy`).
    pub fn new(version: &str, rules: Vec<Rule>) -> Result<Self, PolicyError> {
        if version.is_empty() || version.len() > MAX_VERSION_LEN {
            return Err(PolicyError(
                "authz: version is required and at most 128 characters".into(),
            ));
        }
        if rules.len() > MAX_RULES {
            return Err(PolicyError(format!(
                "authz: {} rules exceed the maximum of {MAX_RULES}",
                rules.len()
            )));
        }
        let mut rules = rules;
        rules.sort_by(|a, b| a.id.cmp(&b.id));
        let mut seen = std::collections::HashSet::new();
        for (i, r) in rules.iter_mut().enumerate() {
            if !rule_id_ok(&r.id) {
                return Err(PolicyError(format!(
                    "authz: rule {i}: id must match ^[A-Za-z0-9._-]{{1,64}}$"
                )));
            }
            if !seen.insert(r.id.clone()) {
                return Err(PolicyError(format!("authz: duplicate rule id {:?}", r.id)));
            }
            if r.from.is_empty() || r.from.len() > MAX_LIST_LEN {
                return Err(PolicyError(format!(
                    "authz: rule {:?}: from must have 1..256 entries",
                    r.id
                )));
            }
            if let Some(f) = r.from.iter().find(|f| !spiffe_glob_ok(f)) {
                return Err(PolicyError(format!(
                    "authz: rule {:?}: from {f:?} is not a SPIFFE ID glob",
                    r.id
                )));
            }
            if r.to.is_empty() || r.to.len() > MAX_LIST_LEN {
                return Err(PolicyError(format!(
                    "authz: rule {:?}: to must have 1..256 entries",
                    r.id
                )));
            }
            if let Some(t) = r.to.iter().find(|t| !svc_glob_ok(t)) {
                return Err(PolicyError(format!(
                    "authz: rule {:?}: to {t:?} is not a service name glob",
                    r.id
                )));
            }
            if r.operations.is_empty() {
                r.operations = vec!["*".to_owned()];
            }
            if r.operations.len() > MAX_LIST_LEN {
                return Err(PolicyError(format!(
                    "authz: rule {:?}: operations must have at most 256 entries",
                    r.id
                )));
            }
            if r.operations.iter().any(|o| o.is_empty() || o.len() > 256) {
                return Err(PolicyError(format!(
                    "authz: rule {:?}: operations entries must be 1..256 characters",
                    r.id
                )));
            }
        }
        Ok(Self {
            version: version.to_owned(),
            rules,
            source: String::new(),
            loaded_at: SystemTime::now(),
        })
    }

    /// Parses a YAML or JSON document strictly (unknown fields refused).
    pub fn load(raw: &[u8]) -> Result<Self, PolicyError> {
        let raw = &raw[..raw.len().min(8 << 20)];
        if raw.iter().all(u8::is_ascii_whitespace) {
            return Err(PolicyError("authz: empty policy document".into()));
        }
        let doc: Doc =
            serde_norway::from_slice(raw).map_err(|e| PolicyError(format!("authz: parse: {e}")))?;
        let version = doc
            .version
            .ok_or_else(|| PolicyError("authz: version is required".into()))?;
        let rules = doc
            .rules
            .ok_or_else(|| PolicyError("authz: rules is required (use [] for none)".into()))?;
        let rules = rules
            .into_iter()
            .map(|r| {
                let effect = match r.effect.0.as_str() {
                    "allow" => Effect::Allow,
                    "deny" => Effect::Deny,
                    _ => {
                        return Err(PolicyError(format!(
                            "authz: rule {:?}: effect must be allow or deny",
                            r.id.0
                        )));
                    }
                };
                Ok(Rule {
                    id: r.id.0,
                    from: r.from.into_iter().map(|s| s.0).collect(),
                    to: r.to.into_iter().map(|s| s.0).collect(),
                    operations: r.operations.into_iter().map(|s| s.0).collect(),
                    effect,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(&version.0, rules)
    }
}

/// A YAML scalar read as its text (yaml.v3 decodes any scalar into a string).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Scalar(String);

impl<'de> Deserialize<'de> for Scalar {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl serde::de::Visitor<'_> for V {
            type Value = Scalar;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a scalar")
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Scalar, E> {
                Ok(Scalar(v.to_owned()))
            }
            fn visit_bool<E: serde::de::Error>(self, v: bool) -> Result<Scalar, E> {
                Ok(Scalar(v.to_string()))
            }
            fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Scalar, E> {
                Ok(Scalar(v.to_string()))
            }
            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Scalar, E> {
                Ok(Scalar(v.to_string()))
            }
            fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<Scalar, E> {
                Ok(Scalar(crate::gofmt::format_g(v)))
            }
        }
        d.deserialize_any(V)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Doc {
    version: Option<Scalar>,
    rules: Option<Vec<DocRule>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DocRule {
    #[serde(default)]
    id: Scalar,
    #[serde(default)]
    from: Vec<Scalar>,
    #[serde(default)]
    to: Vec<Scalar>,
    #[serde(default)]
    operations: Vec<Scalar>,
    #[serde(default)]
    effect: Scalar,
}

/// `*` matches any run (including `/`), `?` one byte; linear, single retry
/// point (go-tangra `globMatch`).
pub fn glob_match(pattern: &str, s: &str) -> bool {
    let (p, s) = (pattern.as_bytes(), s.as_bytes());
    let (mut px, mut sx) = (0usize, 0usize);
    let (mut star_px, mut star_sx): (Option<usize>, usize) = (None, 0);
    while sx < s.len() {
        if px < p.len() && (p[px] == b'?' || p[px] == s[sx]) {
            px += 1;
            sx += 1;
        } else if px < p.len() && p[px] == b'*' {
            star_px = Some(px);
            star_sx = sx;
            px += 1;
        } else if let Some(sp) = star_px {
            px = sp + 1;
            star_sx += 1;
            sx = star_sx;
        } else {
            return false;
        }
    }
    while px < p.len() && p[px] == b'*' {
        px += 1;
    }
    px == p.len()
}

fn any_match(patterns: &[String], s: &str) -> bool {
    patterns.iter().any(|p| glob_match(p, s))
}

impl Authorizer for Policy {
    /// Any matching deny wins; otherwise any allow; otherwise deny.
    fn authorize(&self, peer: &SpiffeId, callee: &str, operation: &str) -> Decision {
        let peer_s = peer.to_string();
        let mut allow_id: Option<&str> = None;
        for r in &self.rules {
            if !any_match(&r.from, &peer_s)
                || !any_match(&r.to, callee)
                || !any_match(&r.operations, operation)
            {
                continue;
            }
            if r.effect == Effect::Deny {
                return Decision {
                    allowed: false,
                    reason: Reason::ExplicitDeny,
                    rule_id: r.id.clone(),
                    policy_version: self.version.clone(),
                };
            }
            if allow_id.is_none() {
                allow_id = Some(&r.id);
            }
        }
        match allow_id {
            Some(id) => Decision {
                allowed: true,
                reason: Reason::ExplicitAllow,
                rule_id: id.to_owned(),
                policy_version: self.version.clone(),
            },
            None => Decision {
                allowed: false,
                reason: Reason::NoMatchingRule,
                rule_id: String::new(),
                policy_version: self.version.clone(),
            },
        }
    }
}

/// Loads the policy and reports changes (hot reload). Invalid updates are
/// never delivered; failed reloads go to the error channel.
pub trait PolicySource: Send + Sync + 'static {
    /// The current policy.
    fn load(&self) -> Result<Arc<Policy>, PolicyError>;
    /// New policies on every successful reload, and reload failures.
    fn watch(&self) -> Result<(mpsc::Receiver<Arc<Policy>>, mpsc::Receiver<PolicyError>), PolicyError>;
    /// Stops polling.
    fn close(&self);
}

struct FileInner {
    cur: Arc<Policy>,
    raw: Vec<u8>,
    subs: Vec<mpsc::Sender<Arc<Policy>>>,
    errs: Vec<mpsc::Sender<PolicyError>>,
    started: bool,
}

/// A policy file polled for changes (default every 2s), keeping the
/// last-known-good policy on a failed reload.
pub struct FileSource {
    path: PathBuf,
    poll: Duration,
    inner: Arc<Mutex<FileInner>>,
    stop: CancellationToken,
}

impl std::fmt::Debug for FileSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileSource")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

fn read_policy(path: &PathBuf) -> Result<(Policy, Vec<u8>), PolicyError> {
    let raw = std::fs::read(path).map_err(|e| PolicyError(format!("authz/file: {e}")))?;
    let mut pol =
        Policy::load(&raw).map_err(|e| PolicyError(format!("authz/file: {}: {}", path.display(), e.0)))?;
    pol.source = format!("file:{}", path.display());
    Ok((pol, raw))
}

impl FileSource {
    /// Loads `path` immediately; fails if it is missing or invalid.
    pub fn new(path: impl Into<PathBuf>, poll: Duration) -> Result<Self, PolicyError> {
        let path = path.into();
        let (pol, raw) = read_policy(&path)?;
        Ok(Self {
            path,
            poll: if poll.is_zero() {
                Duration::from_secs(2)
            } else {
                poll
            },
            inner: Arc::new(Mutex::new(FileInner {
                cur: Arc::new(pol),
                raw,
                subs: Vec::new(),
                errs: Vec::new(),
                started: false,
            })),
            stop: CancellationToken::new(),
        })
    }
}

async fn poll_file(path: PathBuf, every: Duration, inner: Arc<Mutex<FileInner>>, stop: CancellationToken) {
    let mut t = tokio::time::interval_at(tokio::time::Instant::now() + every, every);
    loop {
        tokio::select! {
            () = stop.cancelled() => return,
            _ = t.tick() => {}
        }
        match read_policy(&path) {
            Err(e) => {
                if let Ok(g) = inner.lock() {
                    for tx in &g.errs {
                        let _ = tx.try_send(e.clone());
                    }
                }
            }
            Ok((pol, raw)) => {
                let Ok(mut g) = inner.lock() else { return };
                if g.raw == raw {
                    continue;
                }
                let pol = Arc::new(pol);
                g.cur = Arc::clone(&pol);
                g.raw = raw;
                g.subs.retain(|tx| {
                    !matches!(
                        tx.try_send(Arc::clone(&pol)),
                        Err(mpsc::error::TrySendError::Closed(_))
                    )
                });
            }
        }
    }
}

impl PolicySource for FileSource {
    fn load(&self) -> Result<Arc<Policy>, PolicyError> {
        self.inner
            .lock()
            .map(|g| Arc::clone(&g.cur))
            .map_err(|_| PolicyError("authz/file: no policy loaded".into()))
    }

    fn watch(&self) -> Result<(mpsc::Receiver<Arc<Policy>>, mpsc::Receiver<PolicyError>), PolicyError> {
        if self.stop.is_cancelled() {
            return Err(PolicyError("authz/file: source closed".into()));
        }
        let (ptx, prx) = mpsc::channel(4);
        let (etx, erx) = mpsc::channel(16);
        let start = {
            let mut g = self
                .inner
                .lock()
                .map_err(|_| PolicyError("authz/file: poisoned".into()))?;
            g.subs.push(ptx);
            g.errs.push(etx);
            !std::mem::replace(&mut g.started, true)
        };
        if start {
            tokio::spawn(poll_file(
                self.path.clone(),
                self.poll,
                Arc::clone(&self.inner),
                self.stop.clone(),
            ));
        }
        Ok((prx, erx))
    }

    fn close(&self) {
        self.stop.cancel();
        if let Ok(mut g) = self.inner.lock() {
            g.subs.clear();
            g.errs.clear();
        }
    }
}

impl Drop for FileSource {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}

#[cfg(test)]
mod tests;
