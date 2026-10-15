//! Network enrolment settings (deployer `internal/config` `Enroll`, framework
//! `config/enroll.go` `EnrollTLS`). A module embeds [`EnrollConfig`] as its
//! `enroll:` section and hands it to the lcm identity provider.

use serde::{Deserialize, Serialize};

use super::ConfigError;
use crate::identity::SpiffeId;

/// The service whose SVID a workload expects at a mesh enroll endpoint when
/// `enroll.server_spiffe_id` is unset (lcm's keyless listener).
pub const DEFAULT_ENROLL_SERVER_SERVICE: &str = "lcm";

/// The `enroll:` block: first enrolment over HTTPS with a single-use join
/// token, renewal over mTLS gRPC (`lcm.v1.Enrollment/Enroll`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct EnrollConfig {
    /// Obtain the SVID by network enrolment.
    pub enabled: bool,
    /// First-enrol endpoint, e.g. `https://gateway:8443/api/lcm/v1/enroll`.
    pub enroll_url: String,
    /// lcm gRPC target for renewal, e.g. `lcm:9945`.
    #[serde(rename = "lcm_grpc")]
    pub lcm_grpc: String,
    /// Mesh tenant.
    pub tenant_id: String,
    /// File holding the single-use enrolment token.
    pub token_file: String,
    /// 0600 JSON state file; a restart reuses a still-valid SVID.
    pub state_file: String,
    /// Skip server verification on the first enrol (development only).
    pub insecure: bool,
    /// Mesh trust bundle for the first enrol (mesh mode).
    pub ca_file: String,
    /// SPIFFE ID the enrol server must present in mesh mode.
    pub server_spiffe_id: String,
}

/// The server verification of the first enrolment (go-tangra
/// `config.EnrollTLS`). Exactly one mode applies: public (system roots + host
/// name), mesh (`ca_file` + `server_spiffe_id`), or insecure (development).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EnrollTls {
    /// Skip server verification.
    pub insecure: bool,
    /// Mesh trust bundle PEM path.
    pub ca_file: String,
    /// Expected server SPIFFE ID (default `spiffe://<td>/svc/lcm`).
    pub server_spiffe_id: String,
}

impl EnrollConfig {
    /// The TLS mode fields.
    pub fn tls(&self) -> EnrollTls {
        EnrollTls {
            insecure: self.insecure,
            ca_file: self.ca_file.clone(),
            server_spiffe_id: self.server_spiffe_id.clone(),
        }
    }

    /// Checks the TLS mode, refusing insecure enrolment in production. The
    /// required fields are checked by the provider (as `lcmidentity.NewNet`).
    pub fn validate(&self, trust_domain: &str, production: bool) -> Result<(), ConfigError> {
        self.tls().validate(trust_domain, production)?;
        Ok(())
    }

    /// Accepted insecure settings (logged at start).
    pub fn warnings(&self) -> Vec<String> {
        self.tls().warnings()
    }
}

impl EnrollTls {
    /// Refuses contradictory settings, and insecure enrolment in production.
    pub fn validate(&self, trust_domain: &str, production: bool) -> Result<(), ConfigError> {
        if self.insecure && !self.ca_file.is_empty() {
            return Err(ConfigError(
                "config: enroll.insecure and enroll.ca_file are mutually exclusive".into(),
            ));
        }
        if !self.server_spiffe_id.is_empty() && self.ca_file.is_empty() {
            return Err(ConfigError(
                "config: enroll.server_spiffe_id requires enroll.ca_file (the mesh trust bundle)".into(),
            ));
        }
        if self.insecure && production {
            return Err(ConfigError(
                "config: enroll.insecure is refused in production; set enroll.ca_file to the mesh trust bundle \
                 (enrolling at lcm's keyless listener) or enroll through the gateway edge with a verifiable certificate"
                    .into(),
            ));
        }
        if !self.ca_file.is_empty() {
            self.server_id(trust_domain)?;
        }
        Ok(())
    }

    /// The SPIFFE ID the enrol server must present in mesh mode.
    pub fn server_id(&self, trust_domain: &str) -> Result<SpiffeId, ConfigError> {
        if self.server_spiffe_id.is_empty() {
            return SpiffeId::new(trust_domain, DEFAULT_ENROLL_SERVER_SERVICE)
                .map_err(|e| ConfigError(format!("config: enroll server identity: {e}")));
        }
        let id = SpiffeId::parse(&self.server_spiffe_id)
            .map_err(|e| ConfigError(format!("config: enroll.server_spiffe_id: {e}")))?;
        if id.trust_domain() != trust_domain {
            return Err(ConfigError(format!(
                "config: enroll.server_spiffe_id {id} is outside trust domain {trust_domain}"
            )));
        }
        Ok(id)
    }

    /// Accepted insecure enrolment settings.
    pub fn warnings(&self) -> Vec<String> {
        if self.insecure {
            return vec![
                "enroll.insecure: first enrollment does not verify the server (development only)".into(),
            ];
        }
        Vec::new()
    }
}
