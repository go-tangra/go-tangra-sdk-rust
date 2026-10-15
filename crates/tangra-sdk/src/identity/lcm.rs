//! Network enrolment with lcm (port of go-tangra-lcm-v4
//! `sdk/pkg/lcmidentity/net.go`, `NetProvider`).
//!
//! A workload obtains its FIRST SVID keylessly over lcm's public HTTPS
//! enrol route (`POST <enroll_url>` with a single-use join token), then
//! RENEWS over a direct mTLS gRPC channel to lcm (`lcm.v1.Enrollment/Enroll`,
//! no token) presenting the SVID it holds. The P-256 key is generated
//! locally and never leaves the workload. With a state file, a restart reuses
//! a still-valid SVID instead of spending a new token.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use rcgen::{CertificateParams, DistinguishedName, KeyPair, SanType};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde::{Deserialize, Serialize};
use tangra_proto::lcm::v1::EnrollRequest;
use tangra_proto::lcm::v1::enrollment_client::EnrollmentClient;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use super::x509::certified_from_parts;
use super::{Bundle, Credential, IdentityError, Provider, SpiffeId, Subscribers, Svid, Update, parse_leaf};
use crate::config::{EnrollConfig, FrameworkConfig};
use crate::tls::{EnrollOptions, Usage, chain_verify, custom_client_config, enroll_client_config};

type Now = Arc<dyn Fn() -> SystemTime + Send + Sync>;

/// Configuration of the network enrolment provider (Go `NetConfig`).
#[derive(Clone)]
pub struct NetConfig {
    /// First-enrol endpoint, e.g. `https://gateway:8443/api/lcm/v1/enroll`.
    pub enroll_url: String,
    /// lcm gRPC target for renewal, e.g. `lcm:9945`.
    pub lcm_grpc_target: String,
    /// Mesh tenant.
    pub tenant_id: String,
    /// Trust domain.
    pub trust_domain: String,
    /// Service name.
    pub service_name: String,
    /// Single-use token for the FIRST enrolment only.
    pub enrollment_token: String,
    /// Renew this long before expiry (zero = 1/3 of the lifetime).
    pub renew_before: Duration,
    /// Client TLS of the first-enrol HTTPS call (mesh or public mode);
    /// None = system roots + host name. Excludes `insecure`.
    pub enroll_tls: Option<Arc<rustls::ClientConfig>>,
    /// Skip server verification on the first enrol only (development).
    pub insecure: bool,
    /// Persists the SVID (0600 JSON) so a restart reuses it.
    pub state_file: Option<PathBuf>,
    /// First-enrol retries after the first attempt (Go: 20).
    pub first_enroll_retries: u32,
    /// Pause between first-enrol attempts (Go: 3s).
    pub first_enroll_interval: Duration,
    /// Pause after a failed renewal (Go: 5s).
    pub renew_retry_interval: Duration,
    /// Clock override (tests).
    pub now: Option<Now>,
}

impl std::fmt::Debug for NetConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NetConfig")
            .field("enroll_url", &self.enroll_url)
            .field("lcm_grpc_target", &self.lcm_grpc_target)
            .field("tenant_id", &self.tenant_id)
            .field("trust_domain", &self.trust_domain)
            .field("service_name", &self.service_name)
            .field("insecure", &self.insecure)
            .field("state_file", &self.state_file)
            .finish_non_exhaustive()
    }
}

impl NetConfig {
    /// A configuration with the Go timing defaults.
    pub fn new(trust_domain: &str, service_name: &str) -> Self {
        Self {
            enroll_url: String::new(),
            lcm_grpc_target: String::new(),
            tenant_id: String::new(),
            trust_domain: trust_domain.to_owned(),
            service_name: service_name.to_owned(),
            enrollment_token: String::new(),
            renew_before: Duration::ZERO,
            enroll_tls: None,
            insecure: false,
            state_file: None,
            first_enroll_retries: 20,
            first_enroll_interval: Duration::from_secs(3),
            renew_retry_interval: Duration::from_secs(5),
            now: None,
        }
    }

    /// Builds the configuration from the framework config and an `enroll:`
    /// block, as deployer `internal/app.Build` does: reads the token file
    /// (trimmed), validates the TLS mode (refusing insecure in production)
    /// and loads `ca_file` for mesh mode.
    pub fn from_config(fw: &FrameworkConfig, e: &EnrollConfig) -> Result<Self, IdentityError> {
        let tls = e.tls();
        tls.validate(&fw.trust_domain, fw.is_production())
            .map_err(|err| IdentityError(err.0))?;
        let raw = std::fs::read_to_string(&e.token_file)
            .map_err(|err| IdentityError(format!("enroll token: {err}")))?;
        let mut c = Self::new(&fw.trust_domain, &fw.service_name);
        c.enroll_url.clone_from(&e.enroll_url);
        c.lcm_grpc_target.clone_from(&e.lcm_grpc);
        c.tenant_id.clone_from(&e.tenant_id);
        c.enrollment_token = raw.trim().to_owned();
        c.insecure = e.insecure;
        if !e.state_file.is_empty() {
            c.state_file = Some(PathBuf::from(&e.state_file));
        }
        if !e.ca_file.is_empty() {
            let ca =
                std::fs::read(&e.ca_file).map_err(|err| IdentityError(format!("enroll.ca_file: {err}")))?;
            let server_id = tls
                .server_id(&fw.trust_domain)
                .map_err(|err| IdentityError(err.0))?;
            let cfg = enroll_client_config(EnrollOptions {
                ca_pem: Some(ca),
                server_id: Some(server_id),
                ..EnrollOptions::default()
            })
            .map_err(|err| IdentityError(err.to_string()))?;
            c.enroll_tls = Some(cfg);
        }
        Ok(c)
    }

    fn spiffe_id(&self) -> String {
        format!("spiffe://{}/svc/{}", self.trust_domain, self.service_name)
    }

    fn now(&self) -> SystemTime {
        self.now.as_ref().map_or_else(SystemTime::now, |f| f())
    }
}

/// What lcm returns (`lcmclient.Bundle`).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
struct SignedBundle {
    cert_pem: String,
    chain_pem: String,
    bundle_pem: String,
}

/// The on-disk state (all PEM; the file is 0600).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
struct PersistedSvid {
    cert_pem: String,
    chain_pem: String,
    key_pem: String,
    bundle_pem: String,
}

struct State {
    svid: Svid,
    bundle: Bundle,
    cred: Credential,
    chain: Vec<CertificateDer<'static>>,
    key_pkcs8: Vec<u8>,
}

/// The network enrolment provider.
pub struct LcmProvider {
    cfg: NetConfig,
    st: RwLock<Option<Arc<State>>>,
    ver: Mutex<u64>,
    first_done: AtomicBool,
    renew_conn: Mutex<Option<tonic::transport::Channel>>,
    subs: Subscribers,
    running: AtomicBool,
    close: CancellationToken,
    weak: std::sync::Weak<LcmProvider>,
}

impl std::fmt::Debug for LcmProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LcmProvider")
            .field("cfg", &self.cfg)
            .finish_non_exhaustive()
    }
}

fn pem_encode(tag: &str, ders: &[impl AsRef<[u8]>]) -> String {
    let cfg = pem::EncodeConfig::new().set_line_ending(pem::LineEnding::LF);
    ders.iter()
        .map(|d| pem::encode_config(&pem::Pem::new(tag, d.as_ref().to_vec()), cfg))
        .collect()
}

fn decode_certs(pem_str: &str) -> Vec<CertificateDer<'static>> {
    pem::parse_many(pem_str.as_bytes())
        .unwrap_or_default()
        .into_iter()
        .filter(|p| p.tag() == "CERTIFICATE")
        .map(|p| CertificateDer::from(p.into_contents()))
        .collect()
}

/// Assembles provider state from a signed bundle and the local key (Go
/// `buildStateFrom`): the leaf must name exactly this workload.
fn build_state(
    trust_domain: &str,
    service_name: &str,
    b: &SignedBundle,
    key: &KeyPair,
) -> Result<State, IdentityError> {
    let certs = decode_certs(&b.cert_pem);
    let leaf_der = certs
        .first()
        .ok_or_else(|| IdentityError::new("lcmidentity: certificate: no certificate"))?;
    let chain_extra = decode_certs(&b.chain_pem);
    let leaf = parse_leaf(leaf_der).map_err(|e| IdentityError(format!("lcmidentity: leaf: {e}")))?;
    let roots = decode_certs(&b.bundle_pem);
    for r in &roots {
        parse_leaf(r).map_err(|_| IdentityError::new("lcmidentity: empty trust bundle"))?;
    }
    if roots.is_empty() {
        return Err(IdentityError::new("lcmidentity: empty trust bundle"));
    }
    let sid = SpiffeId::new(trust_domain, service_name).map_err(|e| IdentityError(e.to_string()))?;
    if leaf.uris.len() != 1 || leaf.uris[0] != sid.to_string() {
        return Err(IdentityError(format!(
            "lcmidentity: certificate is not for {sid}"
        )));
    }
    let mut chain = vec![leaf_der.clone()];
    chain.extend(chain_extra);
    let key_pkcs8 = key.serialize_der();
    let pk = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pkcs8.clone()));
    let (cred, leaf) = certified_from_parts(chain.clone(), pk, leaf)?;
    Ok(State {
        svid: Svid {
            id: sid,
            not_before: leaf.not_before,
            not_after: leaf.not_after,
            serial: leaf.serial,
        },
        bundle: Bundle {
            trust_domain: trust_domain.to_owned(),
            roots,
            version: 0,
        },
        cred,
        chain,
        key_pkcs8,
    })
}

/// A CSR bound to the SPIFFE ID (URI SAN, empty subject), signed by `key`.
fn make_csr(spiffe_id: &str, key: &KeyPair) -> Result<String, IdentityError> {
    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    params.subject_alt_names = vec![SanType::URI(
        spiffe_id
            .to_owned()
            .try_into()
            .map_err(|e| IdentityError(format!("lcmidentity: csr: {e}")))?,
    )];
    let csr = params
        .serialize_request(key)
        .map_err(|e| IdentityError(format!("lcmidentity: csr: {e}")))?;
    csr.pem()
        .map_err(|e| IdentityError(format!("lcmidentity: csr: {e}")))
}

impl LcmProvider {
    /// Enrols for an initial SVID (reusing a persisted one when still valid)
    /// and returns a ready provider. Renewal starts on the first `watch`.
    pub async fn new(cfg: NetConfig) -> Result<Arc<Self>, IdentityError> {
        if cfg.enroll_url.is_empty() || cfg.lcm_grpc_target.is_empty() {
            return Err(IdentityError::new(
                "lcmidentity: EnrollURL and LCMGRPCTarget are required",
            ));
        }
        if cfg.trust_domain.is_empty() || cfg.service_name.is_empty() {
            return Err(IdentityError::new(
                "lcmidentity: TrustDomain and ServiceName are required",
            ));
        }
        if cfg.enrollment_token.is_empty() {
            return Err(IdentityError::new(
                "lcmidentity: an enrollment token is required for the first enroll",
            ));
        }
        if cfg.insecure && cfg.enroll_tls.is_some() {
            return Err(IdentityError::new(
                "lcmidentity: EnrollTLS and Insecure are mutually exclusive",
            ));
        }
        let p = Arc::new_cyclic(|weak| Self {
            cfg,
            st: RwLock::new(None),
            ver: Mutex::new(0),
            first_done: AtomicBool::new(false),
            renew_conn: Mutex::new(None),
            subs: Subscribers::default(),
            running: AtomicBool::new(false),
            close: CancellationToken::new(),
            weak: weak.clone(),
        });
        // Reuse a persisted, still-valid SVID: skip the single-use token.
        if let Some(st) = p.load_persisted() {
            p.install(st);
            p.first_done.store(true, Ordering::SeqCst);
            return Ok(p);
        }
        // The first enrol can race lcm's gateway registration on a cold
        // stack: retry so bootstrap is robust.
        let mut attempt = 0;
        let st = loop {
            match p.mint().await {
                Ok(st) => break st,
                Err(e) => {
                    if attempt >= p.cfg.first_enroll_retries {
                        return Err(e);
                    }
                    attempt += 1;
                    tokio::time::sleep(p.cfg.first_enroll_interval).await;
                }
            }
        };
        let st = p.install(st);
        p.first_done.store(true, Ordering::SeqCst);
        p.persist(&st);
        Ok(p)
    }

    fn install(&self, mut st: State) -> Arc<State> {
        let ver = match self.ver.lock() {
            Ok(mut v) => {
                *v += 1;
                *v
            }
            Err(_) => 0,
        };
        st.bundle.version = ver;
        let st = Arc::new(st);
        if let Ok(mut g) = self.st.write() {
            *g = Some(Arc::clone(&st));
        }
        st
    }

    fn snapshot(&self) -> Option<Arc<State>> {
        self.st.read().ok().and_then(|g| g.clone())
    }

    /// Generates a fresh key + CSR and obtains a signed SVID: over HTTPS with
    /// the token the first time, then over mTLS gRPC with the current SVID.
    async fn mint(&self) -> Result<State, IdentityError> {
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .map_err(|e| IdentityError(format!("lcmidentity: key: {e}")))?;
        let csr = make_csr(&self.cfg.spiffe_id(), &key)?;
        let b = if self.first_done.load(Ordering::SeqCst) {
            self.renew_mtls(csr).await?
        } else {
            self.enroll_http(csr).await?
        };
        build_state(&self.cfg.trust_domain, &self.cfg.service_name, &b, &key)
    }

    fn enroll_client(&self) -> Result<Option<Arc<rustls::ClientConfig>>, IdentityError> {
        if let Some(c) = &self.cfg.enroll_tls {
            return Ok(Some(Arc::clone(c)));
        }
        if self.cfg.insecure {
            // Go: InsecureSkipVerify with MinVersion TLS 1.3.
            return crate::tls::insecure_tls13_client_config()
                .map(Some)
                .map_err(|e| IdentityError(e.to_string()));
        }
        Ok(None)
    }

    /// The keyless first enrol over the public HTTPS route.
    async fn enroll_http(&self, csr_pem: String) -> Result<SignedBundle, IdentityError> {
        let mut body = BTreeMap::new();
        body.insert("spiffe_id", self.cfg.spiffe_id());
        body.insert("csr_pem", csr_pem);
        body.insert("enrollment_token", self.cfg.enrollment_token.clone());
        let body = serde_json::to_vec(&body).map_err(|e| IdentityError(e.to_string()))?;
        let tls = match self.enroll_client()? {
            Some(c) => c,
            None => {
                enroll_client_config(EnrollOptions::default()).map_err(|e| IdentityError(e.to_string()))?
            }
        };
        let fut = post_json(&self.cfg.enroll_url, tls, body);
        let (status, raw) = tokio::time::timeout(Duration::from_secs(20), fut)
            .await
            .map_err(|_| IdentityError::new("lcmidentity: enroll: timeout"))?
            .map_err(|e| IdentityError(format!("lcmidentity: enroll: {e}")))?;
        if status != 200 {
            return Err(IdentityError(format!(
                "lcmidentity: enroll: http {status}: {}",
                String::from_utf8_lossy(&raw)
            )));
        }
        serde_json::from_slice(&raw).map_err(|e| IdentityError(format!("lcmidentity: enroll response: {e}")))
    }

    /// Renews over mTLS gRPC presenting the current SVID (no token).
    async fn renew_mtls(&self, csr_pem: String) -> Result<SignedBundle, IdentityError> {
        let conn = self.mtls_conn()?;
        let resp = EnrollmentClient::new(conn)
            .enroll(EnrollRequest {
                tenant_id: self.cfg.tenant_id.clone(),
                spiffe_id: self.cfg.spiffe_id(),
                csr_pem,
                enrollment_token: String::new(),
            })
            .await
            .map_err(|s| IdentityError(format!("lcmidentity: renew: {s}")))?
            .into_inner();
        Ok(SignedBundle {
            cert_pem: resp.cert_pem,
            chain_pem: resp.chain_pem,
            bundle_pem: resp.bundle_pem,
        })
    }

    /// The lazily built renewal channel; its client certificate is the
    /// current SVID on every handshake and lcm's server SVID is chain-verified
    /// against the bundle held now and must name `svc/lcm`.
    fn mtls_conn(&self) -> Result<tonic::transport::Channel, IdentityError> {
        let mut g = self
            .renew_conn
            .lock()
            .map_err(|_| IdentityError::new("lcmidentity: poisoned"))?;
        if let Some(c) = g.as_ref() {
            return Ok(c.clone());
        }
        let weak = self.weak.clone();
        let cert_weak = self.weak.clone();
        let cert_fn: Arc<crate::tls::CertFn> = Arc::new(move || {
            cert_weak
                .upgrade()
                .and_then(|p| p.snapshot())
                .map(|s| Arc::clone(&s.cred.certified))
        });
        let want = format!("spiffe://{}/svc/lcm", self.cfg.trust_domain);
        let verify = Box::new(move |chain: &[CertificateDer<'_>]| {
            let p = weak.upgrade();
            let (roots, now) = match &p {
                Some(p) => (
                    p.snapshot().map(|s| s.bundle.roots.clone()).unwrap_or_default(),
                    p.cfg.now(),
                ),
                None => (Vec::new(), SystemTime::now()),
            };
            chain_verify(&roots, chain, now, Usage::ServerAuth).map_err(|_| {
                crate::identity::VerifyError::new(crate::identity::Reason::Untrusted)
                    .detail("lcmidentity: lcm server not trusted")
            })?;
            let leaf = chain
                .first()
                .and_then(|c| parse_leaf(c).ok())
                .ok_or_else(|| crate::identity::VerifyError::new(crate::identity::Reason::Untrusted))?;
            if leaf.uris.contains(&want) {
                Ok(())
            } else {
                Err(
                    crate::identity::VerifyError::new(crate::identity::Reason::NameMismatch)
                        .detail("lcmidentity: lcm server SPIFFE id mismatch"),
                )
            }
        });
        let tls = custom_client_config(verify, Some(cert_fn)).map_err(|e| IdentityError(e.to_string()))?;
        let endpoint =
            tonic::transport::Endpoint::from_shared(format!("https://{}", self.cfg.lcm_grpc_target))
                .map_err(|e| IdentityError(format!("lcmidentity: lcm target: {e}")))?;
        let ch = endpoint.connect_with_connector_lazy(crate::net::Connector::new(
            vec![self.cfg.lcm_grpc_target.clone()],
            tls,
        ));
        *g = Some(ch.clone());
        Ok(ch)
    }

    fn renew_delay(&self, st: &State) -> Duration {
        let rb = if self.cfg.renew_before.is_zero() {
            st.svid
                .not_after
                .duration_since(st.svid.not_before)
                .unwrap_or_default()
                / 3
        } else {
            self.cfg.renew_before
        };
        st.svid
            .not_after
            .duration_since(self.cfg.now())
            .unwrap_or_default()
            .saturating_sub(rb)
    }

    async fn run(self: Arc<Self>) {
        loop {
            let Some(st) = self.snapshot() else { return };
            let d = self.renew_delay(&st);
            tokio::select! {
                () = self.close.cancelled() => return,
                () = tokio::time::sleep(d) => {}
            }
            match self.mint().await {
                Err(e) => {
                    self.subs.notify(&Update {
                        identity: None,
                        bundle: None,
                        err: Some(e),
                    });
                    tokio::select! {
                        () = self.close.cancelled() => return,
                        () = tokio::time::sleep(self.cfg.renew_retry_interval) => {}
                    }
                }
                Ok(st) => {
                    let st = self.install(st);
                    self.persist(&st);
                    self.subs.notify(&Update {
                        identity: Some(st.svid.clone()),
                        bundle: Some(Arc::new(st.bundle.clone())),
                        err: None,
                    });
                }
            }
        }
    }

    /// Writes the current SVID to the state file (best effort, 0600).
    fn persist(&self, st: &State) {
        let Some(path) = &self.cfg.state_file else { return };
        let rec = PersistedSvid {
            cert_pem: pem_encode("CERTIFICATE", &st.chain[..1]),
            chain_pem: pem_encode("CERTIFICATE", &st.chain[1..]),
            key_pem: pem_encode("PRIVATE KEY", &[&st.key_pkcs8]),
            bundle_pem: pem_encode("CERTIFICATE", &st.bundle.roots),
        };
        let Ok(b) = serde_json::to_vec(&rec) else { return };
        let mut tmp = path.clone().into_os_string();
        tmp.push(".tmp");
        let tmp = PathBuf::from(tmp);
        if write_private(&tmp, &b).is_ok() {
            let _ = std::fs::rename(&tmp, path);
        }
    }

    /// A still-valid persisted SVID (more than a minute left), or None.
    fn load_persisted(&self) -> Option<State> {
        let path = self.cfg.state_file.as_ref()?;
        let raw = std::fs::read(path).ok()?;
        let rec: PersistedSvid = serde_json::from_slice(&raw).ok()?;
        let key = KeyPair::from_pem(&rec.key_pem).ok()?;
        let ec = [&rcgen::PKCS_ECDSA_P256_SHA256, &rcgen::PKCS_ECDSA_P384_SHA384];
        if !ec.iter().any(|a| *a == key.algorithm()) {
            return None;
        }
        let b = SignedBundle {
            cert_pem: rec.cert_pem,
            chain_pem: rec.chain_pem,
            bundle_pem: rec.bundle_pem,
        };
        let st = build_state(&self.cfg.trust_domain, &self.cfg.service_name, &b, &key).ok()?;
        let left = st
            .svid
            .not_after
            .duration_since(self.cfg.now())
            .unwrap_or_default();
        if left < Duration::from_secs(60) {
            return None;
        }
        Some(st)
    }
}

#[cfg(unix)]
fn write_private(path: &std::path::Path, b: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(b)
}

#[cfg(not(unix))]
fn write_private(path: &std::path::Path, b: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, b)
}

/// POSTs a JSON body over HTTP/1.1 (TLS for https) and returns the status
/// and at most 1 MiB of the response body. No proxy (Go's custom Transport).
async fn post_json(
    url: &str,
    tls: Arc<rustls::ClientConfig>,
    body: Vec<u8>,
) -> Result<(u16, Vec<u8>), crate::net::BoxError> {
    let uri: http::Uri = url.parse()?;
    let https = match uri.scheme_str() {
        Some("https") => true,
        Some("http") => false,
        _ => return Err("unsupported protocol scheme".into()),
    };
    let host = uri
        .host()
        .ok_or("missing host")?
        .trim_matches(['[', ']'])
        .to_owned();
    let port = uri.port_u16().unwrap_or(if https { 443 } else { 80 });
    let addr = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    let path = uri.path_and_query().map_or("/", |p| p.as_str()).to_owned();
    let authority = uri.authority().map(|a| a.as_str().to_owned()).unwrap_or_default();
    let req = http::Request::builder()
        .method(http::Method::POST)
        .uri(path)
        .header(http::header::HOST, authority)
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(body)))?;
    let tcp = tokio::net::TcpStream::connect(&addr).await?;
    let resp = if https {
        let name = rustls_pki_types::ServerName::try_from(host)?;
        let io = tokio_rustls::TlsConnector::from(tls).connect(name, tcp).await?;
        send(hyper_util::rt::TokioIo::new(io), req).await?
    } else {
        send(hyper_util::rt::TokioIo::new(tcp), req).await?
    };
    let status = resp.status().as_u16();
    let collected = Limited::new(resp.into_body(), 1 << 20).collect().await;
    let raw = collected.map(|c| c.to_bytes().to_vec()).unwrap_or_default();
    Ok((status, raw))
}

async fn send<T>(
    io: T,
    req: http::Request<Full<Bytes>>,
) -> Result<http::Response<hyper::body::Incoming>, crate::net::BoxError>
where
    T: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    Ok(sender.send_request(req).await?)
}

#[async_trait]
impl Provider for LcmProvider {
    fn current(&self) -> Result<(Svid, Arc<Bundle>), IdentityError> {
        let st = self
            .snapshot()
            .ok_or_else(|| IdentityError::new("lcmidentity: no identity"))?;
        Ok((st.svid.clone(), Arc::new(st.bundle.clone())))
    }

    fn credential(&self) -> Result<Credential, IdentityError> {
        let st = self
            .snapshot()
            .ok_or_else(|| IdentityError::new("lcmidentity: no credential"))?;
        Ok(st.cred.clone())
    }

    /// Renewal runs in one background task started by the first `watch`
    /// (Go starts one per Watch call; with a single watcher this is the same).
    fn watch(&self) -> Result<mpsc::Receiver<Update>, IdentityError> {
        let rx = self.subs.subscribe(1);
        if !self.running.swap(true, Ordering::SeqCst)
            && let Some(me) = self.weak.upgrade()
        {
            tokio::spawn(me.run());
        }
        Ok(rx)
    }

    async fn close(&self) {
        self.close.cancel();
        if let Ok(mut g) = self.renew_conn.lock() {
            *g = None;
        }
        self.subs.close();
    }
}

#[cfg(test)]
mod tests;
