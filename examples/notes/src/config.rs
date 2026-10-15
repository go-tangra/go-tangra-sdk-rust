//! The notes configuration: the framework keys (`service_name`, `identity`,
//! `authz`, `server`, `admin`, `discovery`, `limits`, ...) plus the module's
//! own sections, shaped like the deployer's (`internal/config/config.go`):
//!
//! ```yaml
//! gateway: { service: gateway, issuer: https://portal.example.org:8443 }
//! events: { enabled: true }        # publish notes.created on the event bus
//! valkey: { addresses: [...], username: notes, password: ..., ca_file: ... }
//! enroll: { enabled: true, enroll_url: ..., lcm_grpc: ..., tenant_id: ..., token_file: ..., state_file: ... }
//! limits_notes: { max_notes_per_tenant: 10000 }
//! ```
//!
//! One YAML file, decoded strictly over these defaults; there are no
//! environment overrides (the install renders `${...}` placeholders).

use serde::{Deserialize, Serialize};
use tangra_sdk::config::{Config, ConfigError, EnrollConfig, FrameworkConfig};
use tangra_sdk::events::ValkeyConfig;

/// The whole configuration file.
pub type NotesFile = Config<NotesConfig>;

/// The module sections. Defaults live on each section: serde fills a
/// partly given section from the section's own `Default` (yaml.v3 decodes
/// over the whole default).
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct NotesConfig {
    /// The gateway service and the platform token issuer.
    pub gateway: Gateway,
    /// The platform event bus (required when `events.enabled`).
    pub valkey: Option<ValkeyConfig>,
    /// Realtime events.
    pub events: Events,
    /// Network enrolment with lcm (production identity).
    pub enroll: EnrollConfig,
    /// Module limits.
    pub limits_notes: Limits,
}

/// `gateway:`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Gateway {
    /// The gateway's service name (registration target and the only peer
    /// served the help bundle).
    pub service: String,
    /// The platform token issuer (`https://` origin).
    pub issuer: String,
}

/// `events:`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Events {
    /// Publish `notes.created` to `platform:events:<tenant>`.
    pub enabled: bool,
}

/// `limits_notes:`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    /// Notes one tenant may keep (1 - 1000000).
    pub max_notes_per_tenant: usize,
}

impl Default for Gateway {
    fn default() -> Self {
        Self {
            service: tangra_sdk::app::GATEWAY_SERVICE.to_owned(),
            issuer: String::new(),
        }
    }
}

impl Default for Events {
    fn default() -> Self {
        Self { enabled: true }
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_notes_per_tenant: 10_000,
        }
    }
}

fn invalid(msg: &str) -> ConfigError {
    ConfigError(format!("config: {msg}"))
}

/// Whether `s` is an `https://host[:port]` origin (Go: `url.Parse`,
/// scheme `https`, non-empty host).
fn https_origin(s: &str) -> bool {
    match s.parse::<http::Uri>() {
        Ok(u) => {
            u.scheme_str() == Some("https") && u.host().is_some_and(|h| !h.is_empty()) && u.query().is_none()
        }
        Err(_) => false,
    }
}

impl NotesConfig {
    /// Checks the module sections (the framework keys are checked by
    /// [`validate`]).
    pub fn validate(&self, fw: &FrameworkConfig) -> Result<(), ConfigError> {
        let prod = fw.is_production();
        if self.gateway.service.is_empty() {
            return Err(invalid("gateway.service is required"));
        }
        if !https_origin(&self.gateway.issuer) {
            return Err(invalid("gateway.issuer must be an https origin"));
        }
        if self.events.enabled {
            let v = self
                .valkey
                .as_ref()
                .ok_or_else(|| invalid("valkey is required when events.enabled"))?;
            v.validate(prod).map_err(|e| ConfigError(e.to_string()))?;
        }
        if self.enroll.enabled {
            for (k, v) in [
                ("enroll.enroll_url", &self.enroll.enroll_url),
                ("enroll.lcm_grpc", &self.enroll.lcm_grpc),
                ("enroll.token_file", &self.enroll.token_file),
            ] {
                if v.is_empty() {
                    return Err(invalid(&format!("{k} is required when enroll.enabled")));
                }
            }
            self.enroll.validate(&fw.trust_domain, prod)?;
        }
        if !(1..=1_000_000).contains(&self.limits_notes.max_notes_per_tenant) {
            return Err(invalid(
                "limits_notes.max_notes_per_tenant must be within [1, 1000000]",
            ));
        }
        Ok(())
    }

    /// Accepted insecure opt-outs of the module sections (logged at start;
    /// the framework's own are logged by the app).
    pub fn warnings(&self) -> Vec<String> {
        let mut w = self.enroll.warnings();
        if self.events.enabled
            && let Some(v) = &self.valkey
        {
            w.extend(v.warnings());
        }
        w
    }
}

/// Checks the framework keys and every module section.
pub fn validate(cfg: &NotesFile) -> Result<(), ConfigError> {
    cfg.framework.validate()?;
    cfg.module.validate(&cfg.framework)
}

/// Reads and validates `path`.
pub fn load(path: &str) -> Result<NotesFile, ConfigError> {
    let cfg = NotesFile::load(path)?;
    validate(&cfg)?;
    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = "service_name: notes\ntrust_domain: example.org\n\
identity: {provider: file, file: {cert: c.pem, key: k.pem, bundle: b.pem}}\n\
authz: {source: file, path: policy.yaml}\n\
gateway: {issuer: \"https://portal.example.org:8443\"}\n";

    fn parse(extra: &str) -> Result<NotesFile, ConfigError> {
        let cfg = NotesFile::from_yaml(format!("{BASE}{extra}").as_bytes())?;
        validate(&cfg)?;
        Ok(cfg)
    }

    #[test]
    fn defaults_and_rules() {
        let e = parse("").unwrap_err();
        assert_eq!(e.0, "config: valkey is required when events.enabled");
        let cfg = parse("events: {enabled: false}\n").unwrap();
        assert_eq!(cfg.module.gateway.service, "gateway");
        assert_eq!(cfg.module.limits_notes.max_notes_per_tenant, 10_000);
        assert!(
            parse("events: {enabled: false}\nnotes_typo: 1\n").is_err(),
            "unknown keys refused"
        );
        assert!(https_origin("https://portal.example.org:8443"));
        for bad in ["http://x", "https://", "portal.example.org", "https://x?y=1", ""] {
            assert!(!https_origin(bad), "{bad}");
        }
        let cfg = parse("valkey: {addresses: [\"v:6379\"], allow_plaintext: true}\n").unwrap();
        assert_eq!(cfg.module.warnings().len(), 1);
        let e = parse("events: {enabled: false}\nenroll: {enabled: true}\n").unwrap_err();
        assert_eq!(e.0, "config: enroll.enroll_url is required when enroll.enabled");
        let e = parse("events: {enabled: false}\nlimits_notes: {max_notes_per_tenant: 0}\n").unwrap_err();
        assert!(e.0.contains("max_notes_per_tenant"));
    }

    #[test]
    fn production_refuses_plaintext_event_bus() {
        let e =
            parse("env: production\nvalkey: {addresses: [\"v:6379\"], allow_plaintext: true}\n").unwrap_err();
        assert_eq!(
            e.0,
            "config: valkey.allow_plaintext is not permitted in production"
        );
    }
}
