//! Typed framework configuration, loaded strictly from one YAML file over the
//! secure defaults (go-tangra `config/config.go`, `config/load.go`).
//!
//! The framework keys sit at the top level of the file; a module adds its
//! own sections beside them through the `M` parameter of [`Config`]. Unknown
//! keys are refused everywhere: in the framework sections (every struct is
//! `deny_unknown_fields`) and in the module part (keys that `M` ignores are
//! detected with `serde_ignored`, so `M` need not opt in).
//!
//! There are no environment overrides of config keys (as in Go); values are
//! rendered into the file at install time.

mod enroll;

pub use enroll::{DEFAULT_ENROLL_SERVER_SERVICE, EnrollConfig, EnrollTls};

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::Path;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

pub use crate::gofmt::GoDuration;
use crate::identity::{valid_service_name, valid_trust_domain};

/// `identity.provider` values settable through configuration.
pub const PROVIDER_SPIFFE: &str = "spiffe";
/// File-backed PEM identity.
pub const PROVIDER_FILE: &str = "file";
/// Supplied in code (`AppBuilder::identity_provider`), e.g. the lcm enrol provider.
pub const PROVIDER_PROVIDED: &str = "provided";

/// `authz.source` values settable through configuration.
pub const AUTHZ_FILE: &str = "file";
/// Valkey policy source (supplied in code; see `AppBuilder::policy_source`).
pub const AUTHZ_VALKEY: &str = "valkey";
/// Supplied in code (`AppBuilder::policy_source` / `allow_all_policy`).
pub const AUTHZ_PROVIDED: &str = "provided";

/// Top-level keys owned by the framework (go-tangra `config.Config`).
pub const FRAMEWORK_KEYS: [&str; 9] = [
    "service_name",
    "trust_domain",
    "env",
    "identity",
    "authz",
    "limits",
    "admin",
    "discovery",
    "server",
];

/// A configuration problem. Messages name the offending key in snake_case
/// (identical to the Go messages where Go has one).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct ConfigError(pub String);

impl ConfigError {
    fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
}

/// Module sections of a service that has none.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NoModule {}

/// The complete configuration: framework keys plus the module's own sections.
#[derive(Debug, Clone, Default)]
pub struct Config<M = NoModule> {
    /// The framework keys (`service_name`, `identity`, `limits`, ...).
    pub framework: FrameworkConfig,
    /// The module's sections (every other top-level key).
    pub module: M,
}

/// The typed framework configuration (go-tangra `config.Config`).
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct FrameworkConfig {
    /// Logical name; must equal the identity's service name.
    pub service_name: String,
    /// SPIFFE trust domain every peer must belong to.
    pub trust_domain: String,
    /// Free-form environment label; "production" refuses insecure options.
    pub env: String,
    /// Identity provider.
    pub identity: IdentityConfig,
    /// Service policy source.
    pub authz: AuthzConfig,
    /// Resource limits.
    pub limits: Limits,
    /// Admin (health/metrics) listener.
    pub admin: AdminConfig,
    /// Static discovery.
    pub discovery: DiscoveryConfig,
    /// Public listeners.
    pub server: ServerConfig,
}

/// `identity` section.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct IdentityConfig {
    /// `spiffe`, `file` or `provided`.
    pub provider: String,
    /// Workload API socket (spiffe provider).
    pub workload_socket: String,
    /// PEM files (file provider).
    pub file: FileIdentity,
    /// Fraction of the validity window at which renewal starts (0.3..0.8).
    pub renew_at: f64,
    /// Clock skew accepted on peer certificates (0..15m).
    pub skew_tolerance: GoDuration,
    /// Maximum identity lifetime (1s..24h).
    pub max_lifetime: GoDuration,
    /// Bound on the wait for the first identity.
    pub startup_timeout: GoDuration,
}

/// `identity.file` section.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct FileIdentity {
    /// Leaf certificate (plus chain) PEM path.
    pub cert: String,
    /// Private key PEM path.
    pub key: String,
    /// Trust bundle PEM path.
    pub bundle: String,
}

/// `authz` section.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct AuthzConfig {
    /// `file`, `valkey` or `provided`.
    pub source: String,
    /// Policy file path (file source).
    pub path: String,
    /// Valkey key (valkey source).
    pub valkey_key: String,
    /// Emit `authz_allowed` audit events.
    pub sample_allowed: bool,
}

/// `limits` section (constitution defaults).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    /// Request body / gRPC message size cap.
    pub max_request_bytes: i64,
    /// Header block cap.
    pub max_header_bytes: i64,
    /// Per-call deadline.
    pub request_timeout: GoDuration,
    /// Idle connection timeout.
    pub idle_timeout: GoDuration,
    /// TLS handshake deadline.
    pub handshake_timeout: GoDuration,
    /// HTTP/2 concurrent streams per connection.
    pub max_concurrent_streams: u32,
    /// Forces long-lived connections to re-handshake at least this often.
    pub max_connection_age: GoDuration,
}

/// `admin` section.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct AdminConfig {
    /// host:port (loopback unless `allow_non_loopback`).
    pub addr: String,
    /// Accept a non-loopback admin address (served over mTLS).
    pub allow_non_loopback: bool,
    /// Go pprof switch; accepted for config compatibility, not supported in Rust.
    pub enable_pprof: bool,
}

/// `discovery` section.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct DiscoveryConfig {
    /// Logical service name to `host:port` endpoints.
    pub r#static: BTreeMap<String, Vec<String>>,
}

/// `server` section. An empty address disables that transport.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServerConfig {
    /// gRPC listener (default ":9443").
    pub grpc_addr: String,
    /// HTTP listener (default disabled).
    pub http_addr: String,
}

/// Constitution defaults (go-tangra `config/limits.go`).
pub const DEFAULT_MAX_REQUEST_BYTES: i64 = 1 << 20;
/// Default header block cap (8 KiB).
pub const DEFAULT_MAX_HEADER_BYTES: i64 = 8 << 10;

impl Default for IdentityConfig {
    fn default() -> Self {
        Self {
            provider: PROVIDER_SPIFFE.to_owned(),
            workload_socket: "unix:///run/spire/sockets/agent.sock".to_owned(),
            file: FileIdentity::default(),
            renew_at: 0.5,
            skew_tolerance: GoDuration::from_mins(5),
            max_lifetime: GoDuration::from_hours(1),
            startup_timeout: GoDuration::from_secs(30),
        }
    }
}

impl Default for AuthzConfig {
    fn default() -> Self {
        Self {
            source: AUTHZ_FILE.to_owned(),
            path: String::new(),
            valkey_key: String::new(),
            sample_allowed: false,
        }
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_request_bytes: DEFAULT_MAX_REQUEST_BYTES,
            max_header_bytes: DEFAULT_MAX_HEADER_BYTES,
            request_timeout: GoDuration::from_secs(30),
            idle_timeout: GoDuration::from_secs(60),
            handshake_timeout: GoDuration::from_secs(10),
            max_concurrent_streams: 100,
            max_connection_age: GoDuration::from_mins(30),
        }
    }
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            addr: "127.0.0.1:9090".to_owned(),
            allow_non_loopback: false,
            enable_pprof: false,
        }
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            grpc_addr: ":9443".to_owned(),
            http_addr: String::new(),
        }
    }
}

impl Default for FrameworkConfig {
    /// The secure defaults (go-tangra `config.Default`).
    fn default() -> Self {
        Self {
            service_name: String::new(),
            trust_domain: String::new(),
            env: String::new(),
            identity: IdentityConfig::default(),
            authz: AuthzConfig::default(),
            limits: Limits::default(),
            admin: AdminConfig::default(),
            discovery: DiscoveryConfig::default(),
            server: ServerConfig::default(),
        }
    }
}

fn env_ok(s: &str) -> bool {
    s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

impl FrameworkConfig {
    /// Returns the first problem (`ValidateAll()[0]` in Go).
    pub fn validate(&self) -> Result<(), ConfigError> {
        match self.validate_all().into_iter().next() {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// Every problem, in the order `validate` meets them.
    pub fn validate_all(&self) -> Vec<ConfigError> {
        let mut errs = Vec::new();
        if !valid_service_name(&self.service_name) {
            errs.push(ConfigError::new(
                "config: service_name must match ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$",
            ));
        }
        if !valid_trust_domain(&self.trust_domain) {
            errs.push(ConfigError::new(
                "config: trust_domain must be a lower-case DNS-like name",
            ));
        }
        if !env_ok(&self.env) {
            errs.push(ConfigError::new(
                "config: env may contain only letters, digits and '-'",
            ));
        }
        errs.extend(self.identity.validate());
        if let Err(e) = self.authz.validate() {
            errs.push(e);
        }
        if let Err(e) = self.limits.validate() {
            errs.push(e);
        }
        if let Err(e) = self.admin.validate() {
            errs.push(e);
        }
        errs
    }

    /// Deviations from the secure defaults that an operator accepted; logged
    /// at startup (go-tangra `Config.Warnings`).
    pub fn warnings(&self) -> Vec<String> {
        let d = Self::default();
        let (l, dl) = (&self.limits, &d.limits);
        let mut w = Vec::new();
        if l.max_request_bytes > dl.max_request_bytes {
            w.push(format!(
                "limits.max_request_bytes raised to {} (default {})",
                l.max_request_bytes, dl.max_request_bytes
            ));
        }
        if l.max_header_bytes > dl.max_header_bytes {
            w.push(format!(
                "limits.max_header_bytes raised to {} (default {})",
                l.max_header_bytes, dl.max_header_bytes
            ));
        }
        if l.request_timeout > dl.request_timeout {
            w.push(format!(
                "limits.request_timeout raised to {} (default {})",
                l.request_timeout, dl.request_timeout
            ));
        }
        if l.idle_timeout > dl.idle_timeout {
            w.push(format!(
                "limits.idle_timeout raised to {} (default {})",
                l.idle_timeout, dl.idle_timeout
            ));
        }
        if l.max_concurrent_streams > dl.max_concurrent_streams {
            w.push(format!(
                "limits.max_concurrent_streams raised to {} (default {})",
                l.max_concurrent_streams, dl.max_concurrent_streams
            ));
        }
        if self.admin.allow_non_loopback {
            w.push(
                "admin listener allowed on a non-loopback address; health/metrics are reachable from the network"
                    .to_owned(),
            );
        }
        if self.admin.enable_pprof {
            w.push("pprof enabled on the admin listener".to_owned());
        }
        if self.identity.skew_tolerance > d.identity.skew_tolerance {
            w.push(format!(
                "identity.skew_tolerance raised to {} (default {})",
                self.identity.skew_tolerance, d.identity.skew_tolerance
            ));
        }
        w
    }

    /// Whether `env` is "production" (case-insensitive).
    pub fn is_production(&self) -> bool {
        self.env.eq_ignore_ascii_case("production")
    }

    /// The SPIFFE ID this service must present.
    pub fn local_spiffe_id(&self) -> String {
        format!("spiffe://{}/svc/{}", self.trust_domain, self.service_name)
    }
}

impl IdentityConfig {
    fn validate(&self) -> Vec<ConfigError> {
        let mut errs = Vec::new();
        match self.provider.as_str() {
            PROVIDER_SPIFFE => {
                if self.workload_socket.is_empty() {
                    errs.push(ConfigError::new(
                        "config: identity.workload_socket is required for the spiffe provider",
                    ));
                }
            }
            PROVIDER_FILE => {
                if self.file.cert.is_empty() || self.file.key.is_empty() || self.file.bundle.is_empty() {
                    errs.push(ConfigError::new(
                        "config: identity.file.cert, identity.file.key and identity.file.bundle are required for the file provider",
                    ));
                }
            }
            PROVIDER_PROVIDED => {}
            "localdev" => {
                errs.push(ConfigError::new(
                    "config: identity.provider=localdev cannot be set from configuration; use freya.WithInsecureLocalDev()",
                ));
                return errs;
            }
            other => {
                errs.push(ConfigError(format!(
                    "config: identity.provider {} is not one of spiffe, file",
                    go_quote(other)
                )));
                return errs;
            }
        }
        if !(0.3..=0.8).contains(&self.renew_at) {
            errs.push(ConfigError::new(
                "config: identity.renew_at must be between 0.3 and 0.8",
            ));
        }
        if self.skew_tolerance < GoDuration(0) || self.skew_tolerance > GoDuration::from_mins(15) {
            errs.push(ConfigError::new(
                "config: identity.skew_tolerance must be between 0 and 15m",
            ));
        }
        if self.max_lifetime <= GoDuration(0) || self.max_lifetime > GoDuration::from_hours(24) {
            errs.push(ConfigError::new(
                "config: identity.max_lifetime must be between 1s and 24h",
            ));
        }
        if self.startup_timeout <= GoDuration(0) {
            errs.push(ConfigError::new(
                "config: identity.startup_timeout must be positive",
            ));
        }
        errs
    }
}

impl AuthzConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        match self.source.as_str() {
            AUTHZ_FILE if self.path.is_empty() => Err(ConfigError::new(
                "config: authz.path is required for the file source",
            )),
            AUTHZ_VALKEY if self.valkey_key.is_empty() => Err(ConfigError::new(
                "config: authz.valkey_key is required for the valkey source",
            )),
            AUTHZ_FILE | AUTHZ_VALKEY | AUTHZ_PROVIDED => Ok(()),
            "allow-all" => Err(ConfigError::new(
                "config: authz.source=allow-all cannot be set from configuration; use freya.WithAllowAllPolicy()",
            )),
            other => Err(ConfigError(format!(
                "config: authz.source {} is not one of file, valkey",
                go_quote(other)
            ))),
        }
    }
}

impl Limits {
    fn validate(&self) -> Result<(), ConfigError> {
        let zero = GoDuration(0);
        if self.max_request_bytes <= 0
            || self.max_header_bytes <= 0
            || self.request_timeout <= zero
            || self.idle_timeout <= zero
            || self.handshake_timeout <= zero
            || self.max_concurrent_streams == 0
            || self.max_connection_age <= zero
        {
            return Err(ConfigError::new("config: limits must all be positive"));
        }
        Ok(())
    }
}

impl AdminConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        let (host, port) = split_host_port(&self.addr)
            .map_err(|e| ConfigError(format!("config: admin.addr must be host:port: {e}")))?;
        if go_atoi(&port).is_none() {
            return Err(ConfigError(format!(
                "config: admin.addr port invalid: strconv.Atoi: parsing {}: invalid syntax",
                go_quote(&port)
            )));
        }
        if !self.allow_non_loopback && !is_loopback_host(&host) {
            return Err(ConfigError::new(
                "config: admin.addr is not loopback; set admin.allow_non_loopback=true to accept the risk",
            ));
        }
        Ok(())
    }
}

/// `strconv.Atoi` acceptance (optional sign, decimal digits, int64 range).
pub(crate) fn go_atoi(s: &str) -> Option<i64> {
    let digits = s.strip_prefix(['+', '-']).unwrap_or(s);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse::<i64>().ok()
}

/// Go's `%q` for plain strings (good enough for error messages).
pub(crate) fn go_quote(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| format!("\"{s}\""))
}

/// Port of Go's `net.SplitHostPort`.
pub fn split_host_port(hostport: &str) -> Result<(String, String), String> {
    let addr_err = |why: &str| format!("address {hostport}: {why}");
    let i = hostport
        .rfind(':')
        .ok_or_else(|| addr_err("missing port in address"))?;
    let (mut j, mut k) = (0, 0);
    let host;
    if hostport.starts_with('[') {
        let end = hostport
            .find(']')
            .ok_or_else(|| addr_err("missing ']' in address"))?;
        if end + 1 == hostport.len() {
            return Err(addr_err("missing port in address"));
        } else if end + 1 != i {
            if hostport.as_bytes()[end + 1] == b':' {
                return Err(addr_err("too many colons in address"));
            }
            return Err(addr_err("missing port in address"));
        }
        host = &hostport[1..end];
        j = 1;
        k = end + 1;
    } else {
        host = &hostport[..i];
        if host.contains(':') {
            return Err(addr_err("too many colons in address"));
        }
    }
    if hostport[j..].contains('[') {
        return Err(addr_err("unexpected '[' in address"));
    }
    if hostport[k..].contains(']') {
        return Err(addr_err("unexpected ']' in address"));
    }
    Ok((host.to_owned(), hostport[i + 1..].to_owned()))
}

/// Go `isLoopback`: "localhost" or a loopback IP literal (IPv4-mapped included).
pub(crate) fn is_loopback_host(host: &str) -> bool {
    if host == "localhost" {
        return true;
    }
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => v4.is_loopback(),
        Ok(IpAddr::V6(v6)) => v6.is_loopback() || v6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback()),
        Err(_) => false,
    }
}

impl<M> Config<M>
where
    M: DeserializeOwned,
{
    /// Reads `path` over the defaults. The result is NOT yet validated.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let raw = std::fs::read(path).map_err(|e| ConfigError(format!("config: {e}")))?;
        Self::from_yaml(&raw).map_err(|e| ConfigError(format!("config: {}: {}", path.display(), e.0)))
    }

    /// Decodes a YAML document strictly: unknown keys in the framework or the
    /// module sections are errors; absent keys keep their defaults.
    pub fn from_yaml(raw: &[u8]) -> Result<Self, ConfigError> {
        let doc: serde_norway::Value =
            serde_norway::from_slice(raw).map_err(|e| ConfigError(format!("yaml: {e}")))?;
        let map = match doc {
            // yaml.v3 Decode of an empty document returns io.EOF.
            serde_norway::Value::Null => return Err(ConfigError::new("EOF")),
            serde_norway::Value::Mapping(m) => m,
            other => {
                return Err(ConfigError(format!(
                    "yaml: cannot unmarshal {} into the configuration",
                    yaml_kind(&other)
                )));
            }
        };
        let mut fw = serde_norway::Mapping::new();
        let mut module = serde_norway::Mapping::new();
        for (k, v) in map {
            let is_fw = k.as_str().is_some_and(|s| FRAMEWORK_KEYS.contains(&s));
            if is_fw {
                fw.insert(k, v);
            } else {
                module.insert(k, v);
            }
        }
        let framework: FrameworkConfig = serde_norway::from_value(serde_norway::Value::Mapping(fw))
            .map_err(|e| ConfigError(format!("yaml: {e}")))?;
        let mut unknown = Vec::new();
        let module: M = serde_ignored::deserialize(serde_norway::Value::Mapping(module), |p| {
            unknown.push(p.to_string());
        })
        .map_err(|e| ConfigError(format!("yaml: {e}")))?;
        if let Some(first) = unknown.first() {
            return Err(ConfigError(format!("yaml: unknown field `{first}`")));
        }
        Ok(Self { framework, module })
    }
}

fn yaml_kind(v: &serde_norway::Value) -> &'static str {
    match v {
        serde_norway::Value::Null => "null",
        serde_norway::Value::Bool(_) => "!!bool",
        serde_norway::Value::Number(_) => "!!number",
        serde_norway::Value::String(_) => "!!str",
        serde_norway::Value::Sequence(_) => "!!seq",
        serde_norway::Value::Mapping(_) => "!!map",
        serde_norway::Value::Tagged(_) => "tagged value",
    }
}

#[cfg(test)]
mod tests;
