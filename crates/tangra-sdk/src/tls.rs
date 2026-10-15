//! mTLS configurations (go-tangra `transport/tlsconf/tlsconf.go`, `enroll.go`).
//!
//! - TLS 1.3 only, ALPN `h2` only, session tickets and resumption off.
//! - Servers require a client certificate; the server certificate is fetched
//!   from the provider on every handshake (rotation without restart).
//! - Hostname verification is replaced by SPIFFE verification: the leaf must
//!   carry exactly one URI SAN, a SPIFFE ID in the trust domain, chain to the
//!   provider's *current* bundle roots and be valid within the skew
//!   tolerance. Clients additionally pin the exact expected peer ID.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::{ResolvesClientCert, Resumption};
use rustls::crypto::{
    CryptoProvider, WebPkiSupportedAlgorithms, verify_tls12_signature, verify_tls13_signature,
};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::{ClientHello, NoServerSessionStorage, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{CertificateError, DigitallySignedStruct, DistinguishedName, OtherError, SignatureScheme};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use webpki::{EndEntityCert, ExtendedKeyUsageValidator, KeyPurposeIdIter, KeyUsage};

use crate::identity::{Credential, Provider, Reason, SpiffeId, VerifyError, parse_leaf, valid_trust_domain};

/// Default skew tolerance (5m).
pub const DEFAULT_SKEW: Duration = Duration::from_secs(300);
/// Maximum skew tolerance (15m).
pub const MAX_SKEW: Duration = Duration::from_secs(900);
/// The only ALPN protocol offered/accepted.
pub const ALPN_H2: &[u8] = b"h2";

/// A TLS configuration failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("tlsconf: {0}")]
pub struct TlsError(pub String);

type Now = Arc<dyn Fn() -> SystemTime + Send + Sync>;
type OnRefusal = Arc<dyn Fn(Reason, &str) + Send + Sync>;

/// Verification options. `trust_domain` is required.
#[derive(Clone)]
pub struct Options {
    /// The trust domain every peer must belong to.
    pub trust_domain: String,
    /// Validity widening on both ends (default 5m, max 15m; zero = default).
    pub skew_tolerance: Duration,
    /// Clock override (tests).
    pub now: Option<Now>,
    /// Called with the classified reason and claimed ID whenever this
    /// configuration's verifier refuses a peer (audit).
    pub on_refusal: Option<OnRefusal>,
}

impl std::fmt::Debug for Options {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Options")
            .field("trust_domain", &self.trust_domain)
            .field("skew_tolerance", &self.skew_tolerance)
            .finish_non_exhaustive()
    }
}

impl Options {
    /// Options for a trust domain with the default skew.
    pub fn new(trust_domain: impl Into<String>) -> Self {
        Self {
            trust_domain: trust_domain.into(),
            skew_tolerance: Duration::ZERO,
            now: None,
            on_refusal: None,
        }
    }

    fn normalise(mut self) -> Result<Self, TlsError> {
        if !valid_trust_domain(&self.trust_domain) {
            return Err(TlsError("trust domain is required".into()));
        }
        if self.skew_tolerance.is_zero() {
            self.skew_tolerance = DEFAULT_SKEW;
        }
        if self.skew_tolerance > MAX_SKEW {
            return Err(TlsError(format!(
                "skew tolerance must be within 0..{}",
                crate::GoDuration::from(MAX_SKEW)
            )));
        }
        Ok(self)
    }

    fn now(&self) -> SystemTime {
        self.now.as_ref().map_or_else(SystemTime::now, |f| f())
    }
}

/// The verified remote identity extracted from a leaf certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peer {
    /// SPIFFE ID.
    pub id: SpiffeId,
    /// Service name part of the ID.
    pub service_name: String,
    /// Serial number (decimal).
    pub serial: String,
    /// Leaf expiry.
    pub not_after: SystemTime,
}

/// Which extended key usage the verification requires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Usage {
    /// Any EKU (Go `x509.ExtKeyUsageAny`): the mesh.
    Any,
    /// serverAuth (when the extension is present): the enroll client.
    ServerAuth,
}

struct AnyEku;

impl ExtendedKeyUsageValidator for AnyEku {
    fn validate(&self, _iter: KeyPurposeIdIter<'_, '_>) -> Result<(), webpki::Error> {
        Ok(())
    }
}

fn algorithms() -> WebPkiSupportedAlgorithms {
    crate::identity::x509::crypto().signature_verification_algorithms
}

/// `go Duration.String` of a std duration (for fixed-vocabulary details).
fn dur(d: Duration) -> String {
    crate::GoDuration::from(d).to_string()
}

/// The SPIFFE verification shared by the mesh and the enroll client
/// (go-tangra `tlsconf.verifyWith`): exactly one SPIFFE URI SAN in the trust
/// domain, a chain to the roots returned by `roots_for` (called only after
/// the SAN checks), validity within the skew tolerance, the key usage, and
/// (when `expected` is set) the exact ID.
pub fn verify_with(
    roots_for: impl FnOnce(&str) -> Result<Vec<CertificateDer<'static>>, VerifyError>,
    o: &Options,
    expected: Option<&SpiffeId>,
    usage: Usage,
    chain: &[CertificateDer<'_>],
) -> Result<Peer, VerifyError> {
    if chain.is_empty() {
        return Err(VerifyError::new(Reason::NoIdentity));
    }
    let mut leaf = None;
    for (i, c) in chain.iter().enumerate() {
        let info =
            parse_leaf(c).map_err(|_| VerifyError::new(Reason::Untrusted).detail("malformed certificate"))?;
        if i == 0 {
            leaf = Some(info);
        }
    }
    let leaf = leaf.ok_or_else(|| VerifyError::new(Reason::NoIdentity))?;
    if leaf.uris.len() != 1 {
        return Err(VerifyError::new(Reason::Untrusted).detail("leaf must carry exactly one URI SAN"));
    }
    let id = SpiffeId::parse(&leaf.uris[0])
        .map_err(|_| VerifyError::new(Reason::Untrusted).detail("SAN is not a SPIFFE ID"))?;
    let claimed = id.to_string();
    if id.trust_domain() != o.trust_domain {
        return Err(VerifyError::new(Reason::Untrusted)
            .detail("foreign trust domain")
            .claimed(&claimed));
    }
    let roots = roots_for(&claimed)?;
    let now = o.now();
    let skew = o.skew_tolerance;
    let mut at = now;
    if now < leaf.not_before {
        if leaf.not_before.duration_since(now).unwrap_or_default() > skew {
            return Err(VerifyError::new(Reason::NotYetValid)
                .detail(format!("beyond clock skew tolerance {}", dur(skew)))
                .claimed(&claimed));
        }
        at = leaf.not_before;
    } else if now > leaf.not_after {
        if now.duration_since(leaf.not_after).unwrap_or_default() > skew {
            return Err(VerifyError::new(Reason::Expired)
                .detail(format!("beyond clock skew tolerance {}", dur(skew)))
                .claimed(&claimed));
        }
        at = leaf.not_after;
    }
    let res = chain_verify(&roots, chain, at, usage);
    if let Err(e) = res {
        return Err(match e {
            webpki::Error::CertExpired { .. } | webpki::Error::CertNotValidYet { .. } => {
                VerifyError::new(Reason::Expired)
                    .detail("issuer validity")
                    .claimed(&claimed)
            }
            _ => VerifyError::new(Reason::Untrusted).claimed(&claimed),
        });
    }
    if let Some(exp) = expected
        && *exp != id
    {
        return Err(VerifyError::new(Reason::NameMismatch).claimed(&claimed));
    }
    Ok(Peer {
        service_name: id.service_name().to_owned(),
        id,
        serial: leaf.serial,
        not_after: leaf.not_after,
    })
}

/// Chain-verifies `chain` (leaf first) against `roots` at instant `at`.
pub(crate) fn chain_verify(
    roots: &[CertificateDer<'_>],
    chain: &[CertificateDer<'_>],
    at: SystemTime,
    usage: Usage,
) -> Result<(), webpki::Error> {
    let leaf_der = chain.first().ok_or(webpki::Error::BadDer)?;
    let anchors: Vec<_> = roots
        .iter()
        .filter_map(|r| webpki::anchor_from_trusted_cert(r).ok().map(|a| a.to_owned()))
        .collect();
    let ee = EndEntityCert::try_from(leaf_der)?;
    let secs = at
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let time = UnixTime::since_unix_epoch(Duration::from_secs(secs));
    let inter: Vec<CertificateDer<'_>> = chain[1..]
        .iter()
        .map(|c| CertificateDer::from(c.as_ref()))
        .collect();
    let algs = algorithms();
    match usage {
        Usage::Any => ee
            .verify_for_usage(algs.all, &anchors, &inter, time, AnyEku, None, None)
            .map(|_| ()),
        Usage::ServerAuth => ee
            .verify_for_usage(
                algs.all,
                &anchors,
                &inter,
                time,
                KeyUsage::server_auth(),
                None,
                None,
            )
            .map(|_| ()),
    }
}

/// A client configuration with a custom server verification and an
/// optional per-handshake client certificate (lcm renewal channel).
pub(crate) fn custom_client_config(
    verify: Box<ServerVerifyFn>,
    client_cert: Option<Arc<CertFn>>,
) -> Result<Arc<rustls::ClientConfig>, TlsError> {
    let verifier = Arc::new(SpiffeServerVerifier {
        verify,
        algs: algorithms(),
    });
    let b = rustls::ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| TlsError(e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(verifier);
    let mut cfg = match client_cert {
        Some(f) => b.with_client_cert_resolver(Arc::new(FnClientResolver(f))),
        None => b.with_no_client_auth(),
    };
    cfg.alpn_protocols = vec![ALPN_H2.to_vec()];
    cfg.resumption = Resumption::disabled();
    Ok(Arc::new(cfg))
}

/// Supplies the client certificate per handshake.
pub(crate) type CertFn = dyn Fn() -> Option<Arc<CertifiedKey>> + Send + Sync;

/// Presents whatever `CertFn` returns (lcm renewal: the current SVID without
/// the expiry check, as Go `lcmidentity.NetProvider.credential`).
struct FnClientResolver(Arc<CertFn>);

impl std::fmt::Debug for FnClientResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FnClientResolver")
    }
}

impl ResolvesClientCert for FnClientResolver {
    fn resolve(&self, _hints: &[&[u8]], _schemes: &[SignatureScheme]) -> Option<Arc<CertifiedKey>> {
        (self.0)()
    }
    fn has_certs(&self) -> bool {
        true
    }
}

/// No server verification, TLS 1.3 only (lcm `NetConfig.Insecure`).
pub(crate) fn insecure_tls13_client_config() -> Result<Arc<rustls::ClientConfig>, TlsError> {
    let mut c = rustls::ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| TlsError(e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify(algorithms())))
        .with_no_client_auth();
    c.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(c))
}

/// Extracts the peer from an already verified leaf (go-tangra `PeerFromChain`).
pub fn peer_from_leaf(leaf: &[u8]) -> Result<Peer, VerifyError> {
    let info =
        parse_leaf(leaf).map_err(|_| VerifyError::new(Reason::Untrusted).detail("no verified leaf"))?;
    if info.uris.len() != 1 {
        return Err(VerifyError::new(Reason::Untrusted).detail("no verified leaf"));
    }
    let id = SpiffeId::parse(&info.uris[0])
        .map_err(|_| VerifyError::new(Reason::Untrusted).detail("SAN is not a SPIFFE ID"))?;
    Ok(Peer {
        service_name: id.service_name().to_owned(),
        id,
        serial: info.serial,
        not_after: info.not_after,
    })
}

fn to_rustls(e: VerifyError) -> rustls::Error {
    rustls::Error::InvalidCertificate(CertificateError::Other(OtherError(Arc::new(e))))
}

/// The [`VerifyError`] carried by a rustls error, if any.
pub fn verify_error(e: &rustls::Error) -> Option<&VerifyError> {
    match e {
        rustls::Error::InvalidCertificate(CertificateError::Other(OtherError(inner))) => {
            inner.downcast_ref::<VerifyError>()
        }
        _ => None,
    }
}

/// Maps any handshake error to the closed vocabulary (go-tangra `Classify`).
pub fn classify(e: &(dyn std::error::Error + 'static)) -> Reason {
    let mut cur: Option<&(dyn std::error::Error + 'static)> = Some(e);
    while let Some(err) = cur {
        if let Some(ve) = err.downcast_ref::<VerifyError>() {
            return ve.reason;
        }
        if let Some(re) = err.downcast_ref::<rustls::Error>() {
            if let Some(ve) = verify_error(re) {
                return ve.reason;
            }
            match re {
                rustls::Error::NoCertificatesPresented
                | rustls::Error::AlertReceived(rustls::AlertDescription::CertificateRequired) => {
                    return Reason::NoIdentity;
                }
                rustls::Error::PeerIncompatible(_)
                | rustls::Error::AlertReceived(rustls::AlertDescription::ProtocolVersion) => {
                    return Reason::Downgrade;
                }
                rustls::Error::InvalidCertificate(
                    CertificateError::Expired | CertificateError::NotValidYet,
                ) => {
                    return Reason::Expired;
                }
                _ => {}
            }
        }
        if let Some(io) = err.downcast_ref::<std::io::Error>()
            && let Some(inner) = io.get_ref()
        {
            cur = Some(inner);
            continue;
        }
        cur = err.source();
    }
    let s = e.to_string().to_lowercase();
    if s.contains("certificate required") || s.contains("no certificates") {
        Reason::NoIdentity
    } else if s.contains("protocol version") || s.contains("incompatible") {
        Reason::Downgrade
    } else if s.contains("expired") || s.contains("not yet valid") {
        Reason::Expired
    } else {
        Reason::Untrusted
    }
}

/// Fail closed: an expired local identity is never presented (go-tangra
/// `tlsconf.credential`).
fn local_credential(p: &dyn Provider) -> Option<Arc<CertifiedKey>> {
    let c: Credential = p.credential().ok()?;
    if c.certified.cert.is_empty() {
        return None;
    }
    let now = SystemTime::now();
    if now > c.not_after || now + MAX_SKEW < c.not_before {
        return None;
    }
    Some(c.certified)
}

fn mesh_verify(
    p: &Arc<dyn Provider>,
    o: &Options,
    expected: Option<&SpiffeId>,
    chain: &[CertificateDer<'_>],
) -> Result<Peer, VerifyError> {
    let res = verify_with(
        |claimed| {
            let (_, bundle) = p
                .current()
                .map_err(|_| VerifyError::new(Reason::ProviderUnavailable).claimed(claimed))?;
            if bundle.roots.is_empty() {
                return Err(VerifyError::new(Reason::BundleEmpty).claimed(claimed));
            }
            Ok(bundle.roots.clone())
        },
        o,
        expected,
        Usage::Any,
        chain,
    );
    if let (Err(e), Some(cb)) = (&res, &o.on_refusal) {
        cb(e.reason, &e.claimed);
    }
    res
}

struct ServerResolver(Arc<dyn Provider>);

impl std::fmt::Debug for ServerResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ServerResolver")
    }
}

impl ResolvesServerCert for ServerResolver {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        local_credential(self.0.as_ref())
    }
}

struct ClientResolver(Arc<dyn Provider>);

impl std::fmt::Debug for ClientResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ClientResolver")
    }
}

impl ResolvesClientCert for ClientResolver {
    fn resolve(&self, _hints: &[&[u8]], _schemes: &[SignatureScheme]) -> Option<Arc<CertifiedKey>> {
        local_credential(self.0.as_ref())
    }
    fn has_certs(&self) -> bool {
        true
    }
}

struct SpiffeClientVerifier {
    p: Arc<dyn Provider>,
    o: Options,
    algs: WebPkiSupportedAlgorithms,
}

impl std::fmt::Debug for SpiffeClientVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpiffeClientVerifier")
            .field("o", &self.o)
            .finish()
    }
}

impl ClientCertVerifier for SpiffeClientVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }
    fn client_auth_mandatory(&self) -> bool {
        true
    }
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }
    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        let mut chain = Vec::with_capacity(1 + intermediates.len());
        chain.push(end_entity.clone());
        chain.extend(intermediates.iter().cloned());
        mesh_verify(&self.p, &self.o, None, &chain).map_err(to_rustls)?;
        Ok(ClientCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.algs)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.algs)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

pub(crate) type ServerVerifyFn = dyn Fn(&[CertificateDer<'_>]) -> Result<(), VerifyError> + Send + Sync;

struct SpiffeServerVerifier {
    verify: Box<ServerVerifyFn>,
    algs: WebPkiSupportedAlgorithms,
}

impl std::fmt::Debug for SpiffeServerVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SpiffeServerVerifier")
    }
}

impl ServerCertVerifier for SpiffeServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let mut chain = Vec::with_capacity(1 + intermediates.len());
        chain.push(end_entity.clone());
        chain.extend(intermediates.iter().cloned());
        (self.verify)(&chain).map_err(to_rustls)?;
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.algs)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.algs)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

fn provider() -> Arc<CryptoProvider> {
    crate::identity::x509::crypto()
}

/// The listener configuration: TLS 1.3 only, ALPN h2, client certificate
/// required and SPIFFE-verified against the provider's current bundle,
/// server certificate fetched per handshake, no session resumption.
pub fn server_config(p: Arc<dyn Provider>, o: Options) -> Result<Arc<rustls::ServerConfig>, TlsError> {
    let o = o.normalise()?;
    let verifier = Arc::new(SpiffeClientVerifier {
        p: Arc::clone(&p),
        o,
        algs: algorithms(),
    });
    let mut cfg = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| TlsError(e.to_string()))?
        .with_client_cert_verifier(verifier)
        .with_cert_resolver(Arc::new(ServerResolver(p)));
    cfg.alpn_protocols = vec![ALPN_H2.to_vec()];
    cfg.session_storage = Arc::new(NoServerSessionStorage {});
    cfg.send_tls13_tickets = 0;
    Ok(Arc::new(cfg))
}

/// The dial configuration for calling `expected`: the callee must present a
/// chain to a trusted root whose single URI SAN equals `expected`.
pub fn client_config(
    p: Arc<dyn Provider>,
    expected: SpiffeId,
    o: Options,
) -> Result<Arc<rustls::ClientConfig>, TlsError> {
    let o = o.normalise()?;
    if expected.trust_domain() != o.trust_domain {
        return Err(TlsError(format!(
            "expected peer {expected} is outside trust domain {}",
            o.trust_domain
        )));
    }
    let pv = Arc::clone(&p);
    let verifier = Arc::new(SpiffeServerVerifier {
        verify: Box::new(move |chain| mesh_verify(&pv, &o, Some(&expected), chain).map(|_| ())),
        algs: algorithms(),
    });
    let mut cfg = rustls::ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| TlsError(e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_cert_resolver(Arc::new(ClientResolver(p)));
    cfg.alpn_protocols = vec![ALPN_H2.to_vec()];
    cfg.resumption = Resumption::disabled();
    Ok(Arc::new(cfg))
}

/// Server verification of a workload's FIRST enrolment (go-tangra
/// `tlsconf.EnrollOptions`; see `config::EnrollTls` for the modes).
#[derive(Clone, Default)]
pub struct EnrollOptions {
    /// Mesh trust bundle PEM: the server must chain to it and present `server_id`.
    pub ca_pem: Option<Vec<u8>>,
    /// The SPIFFE ID the server must present (required with `ca_pem`).
    pub server_id: Option<SpiffeId>,
    /// Skip server verification (development only).
    pub insecure: bool,
    /// Clock override (tests).
    pub now: Option<Now>,
}

impl std::fmt::Debug for EnrollOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnrollOptions")
            .field("server_id", &self.server_id)
            .field("insecure", &self.insecure)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
struct NoVerify(WebPkiSupportedAlgorithms);

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.0)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.0)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.supported_schemes()
    }
}

/// The client configuration of the first enrolment (an HTTPS call with no
/// client certificate):
///
/// - `ca_pem` set: TLS 1.3, chain to those roots, exactly one SPIFFE URI SAN
///   equal to `server_id`, serverAuth, validity within the default skew;
/// - `insecure`: no server verification (TLS 1.2+);
/// - neither: system roots and the host name of the URL (TLS 1.2+).
pub fn enroll_client_config(o: EnrollOptions) -> Result<Arc<rustls::ClientConfig>, TlsError> {
    let has_ca = o.ca_pem.as_ref().is_some_and(|c| !c.is_empty());
    let builder = |versions: &[&'static rustls::SupportedProtocolVersion]| {
        rustls::ClientConfig::builder_with_provider(provider())
            .with_protocol_versions(versions)
            .map_err(|e| TlsError(e.to_string()))
    };
    let mut cfg = if o.insecure {
        if has_ca || o.server_id.is_some() {
            return Err(TlsError(
                "enroll: insecure excludes a CA bundle and a server identity".into(),
            ));
        }
        builder(rustls::DEFAULT_VERSIONS)?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify(algorithms())))
            .with_no_client_auth()
    } else if !has_ca {
        if o.server_id.is_some() {
            return Err(TlsError(
                "enroll: a server identity requires the mesh CA bundle".into(),
            ));
        }
        let mut roots = rustls::RootCertStore::empty();
        let native = rustls_native_certs::load_native_certs();
        for c in native.certs {
            let _ = roots.add(c);
        }
        builder(rustls::DEFAULT_VERSIONS)?
            .with_root_certificates(roots)
            .with_no_client_auth()
    } else {
        let server_id = o.server_id.clone().ok_or_else(|| {
            TlsError("enroll: the expected server identity is required with a CA bundle".into())
        })?;
        let roots = crate::identity::parse_certs_pem(o.ca_pem.as_deref().unwrap_or_default())
            .map_err(|e| TlsError(format!("enroll CA bundle: {e}")))?;
        if roots.is_empty() {
            return Err(TlsError("enroll CA bundle holds no certificates".into()));
        }
        let vo = Options {
            trust_domain: server_id.trust_domain().to_owned(),
            skew_tolerance: DEFAULT_SKEW,
            now: o.now.clone(),
            on_refusal: None,
        };
        let verifier = Arc::new(SpiffeServerVerifier {
            verify: Box::new(move |chain| {
                let r = roots.clone();
                verify_with(|_| Ok(r), &vo, Some(&server_id), Usage::ServerAuth, chain).map(|_| ())
            }),
            algs: algorithms(),
        });
        let mut c = builder(&[&rustls::version::TLS13])?
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        c.resumption = Resumption::disabled();
        c
    };
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(cfg))
}

#[cfg(test)]
mod tests;
