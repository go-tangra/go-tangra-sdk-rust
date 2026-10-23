//! Test helpers (go-tangra `freyatest/testutil`): an in-test SPIFFE CA and an
//! in-memory identity provider. Not for production use.

use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer,
    KeyPair, KeyUsagePurpose, SanType, SerialNumber,
};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio::sync::mpsc;

use crate::identity::{
    Bundle, Credential, IdentityError, Provider, SpiffeId, Subscribers, Svid, Update, load_certified_key,
};

#[cfg(feature = "testutil-pg")]
pub mod pg;
pub mod platform;

/// A test failure (string error, so tests can `?` it).
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct TestError(pub String);

fn terr(e: impl std::fmt::Display) -> TestError {
    TestError(e.to_string())
}

fn to_offset(t: SystemTime) -> time::OffsetDateTime {
    let secs = match t.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(d) => i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
        Err(e) => -i64::try_from(e.duration().as_secs()).unwrap_or(i64::MAX),
    };
    time::OffsetDateTime::from_unix_timestamp(secs).unwrap_or(time::OffsetDateTime::UNIX_EPOCH)
}

/// Options for [`TestCa::issue_with`].
#[derive(Debug, Clone)]
pub struct IssueOptions {
    /// URI SANs; defaults to the SPIFFE ID of the requested name.
    pub uris: Option<Vec<String>>,
    /// Defaults to now - 1m.
    pub not_before: Option<SystemTime>,
    /// Defaults to now + 1h.
    pub not_after: Option<SystemTime>,
    /// Extended key usages (default server + client auth, like Go's testutil).
    pub server_auth: bool,
    /// Include clientAuth.
    pub client_auth: bool,
}

impl Default for IssueOptions {
    fn default() -> Self {
        Self {
            uris: None,
            not_before: None,
            not_after: None,
            server_auth: true,
            client_auth: true,
        }
    }
}

/// An issued SVID.
#[derive(Debug, Clone)]
pub struct Issued {
    /// Leaf PEM.
    pub cert_pem: String,
    /// PKCS#8 key PEM.
    pub key_pem: String,
    /// Leaf DER.
    pub cert_der: CertificateDer<'static>,
}

impl Issued {
    /// The private key DER.
    pub fn key_der(&self) -> Result<PrivateKeyDer<'static>, TestError> {
        PrivateKeyDer::from_pem_slice(self.key_pem.as_bytes()).map_err(terr)
    }
}

/// A self-signed SPIFFE CA for one trust domain.
pub struct TestCa {
    trust_domain: String,
    issuer: Issuer<'static, KeyPair>,
    cert_der: CertificateDer<'static>,
    cert_pem: String,
    serial: std::sync::atomic::AtomicU64,
}

impl std::fmt::Debug for TestCa {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestCa")
            .field("trust_domain", &self.trust_domain)
            .finish_non_exhaustive()
    }
}

impl TestCa {
    /// A CA valid from now-1h to now+24h.
    pub fn new(trust_domain: &str) -> Result<Self, TestError> {
        let now = SystemTime::now();
        Self::with_validity(
            trust_domain,
            now - Duration::from_secs(3600),
            now + Duration::from_secs(86_400),
        )
    }

    /// A CA with explicit validity.
    pub fn with_validity(trust_domain: &str, nb: SystemTime, na: SystemTime) -> Result<Self, TestError> {
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).map_err(terr)?;
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, format!("freyatest CA {trust_domain}"));
        params.distinguished_name = dn;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params.subject_alt_names = vec![SanType::URI(
            format!("spiffe://{trust_domain}").try_into().map_err(terr)?,
        )];
        params.not_before = to_offset(nb);
        params.not_after = to_offset(na);
        params.serial_number = Some(SerialNumber::from(1u64));
        let cert = params.self_signed(&key).map_err(terr)?;
        let cert_der = cert.der().clone();
        let cert_pem = cert.pem();
        Ok(Self {
            trust_domain: trust_domain.to_owned(),
            issuer: Issuer::new(params, key),
            cert_der,
            cert_pem,
            serial: std::sync::atomic::AtomicU64::new(100),
        })
    }

    /// The trust domain.
    pub fn trust_domain(&self) -> &str {
        &self.trust_domain
    }

    /// The root certificate DER.
    pub fn root_der(&self) -> CertificateDer<'static> {
        self.cert_der.clone()
    }

    /// The trust bundle PEM.
    pub fn bundle_pem(&self) -> String {
        self.cert_pem.clone()
    }

    /// Issues `spiffe://<td>/svc/<name>` valid for an hour.
    pub fn issue(&self, name: &str) -> Result<Issued, TestError> {
        self.issue_with(name, IssueOptions::default())
    }

    /// Issues a leaf with explicit options.
    pub fn issue_with(&self, name: &str, o: IssueOptions) -> Result<Issued, TestError> {
        let now = SystemTime::now();
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).map_err(terr)?;
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, name);
        params.distinguished_name = dn;
        let uris = o
            .uris
            .unwrap_or_else(|| vec![format!("spiffe://{}/svc/{name}", self.trust_domain)]);
        params.subject_alt_names = uris
            .into_iter()
            .map(|u| u.try_into().map(SanType::URI).map_err(terr))
            .collect::<Result<_, _>>()?;
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        let mut ekus = Vec::new();
        if o.server_auth {
            ekus.push(ExtendedKeyUsagePurpose::ServerAuth);
        }
        if o.client_auth {
            ekus.push(ExtendedKeyUsagePurpose::ClientAuth);
        }
        params.extended_key_usages = ekus;
        params.not_before = to_offset(o.not_before.unwrap_or(now - Duration::from_secs(60)));
        params.not_after = to_offset(o.not_after.unwrap_or(now + Duration::from_secs(3600)));
        params.serial_number = Some(SerialNumber::from(
            self.serial.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        ));
        let cert = params.signed_by(&key, &self.issuer).map_err(terr)?;
        Ok(Issued {
            cert_pem: cert.pem(),
            key_pem: key.serialize_pem(),
            cert_der: cert.der().clone(),
        })
    }

    /// Issues a plain TLS server certificate (no SPIFFE ID) for DNS names
    /// and IP addresses, valid for an hour (test databases and other
    /// non-mesh servers).
    pub fn issue_tls_server(&self, dns: &[&str], ips: &[&str]) -> Result<Issued, TestError> {
        let now = SystemTime::now();
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).map_err(terr)?;
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, dns.first().copied().unwrap_or("localhost"));
        params.distinguished_name = dn;
        let mut sans = Vec::new();
        for d in dns {
            sans.push(SanType::DnsName((*d).try_into().map_err(terr)?));
        }
        for ip in ips {
            sans.push(SanType::IpAddress(ip.parse().map_err(terr)?));
        }
        params.subject_alt_names = sans;
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.not_before = to_offset(now - Duration::from_secs(60));
        params.not_after = to_offset(now + Duration::from_secs(3600));
        params.serial_number = Some(SerialNumber::from(
            self.serial.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        ));
        let cert = params.signed_by(&key, &self.issuer).map_err(terr)?;
        Ok(Issued {
            cert_pem: cert.pem(),
            key_pem: key.serialize_pem(),
            cert_der: cert.der().clone(),
        })
    }

    /// Signs a PEM CSR for `uri` (lcm fake): returns the leaf PEM.
    pub fn sign_csr(&self, csr_pem: &str, lifetime: Duration) -> Result<String, TestError> {
        let mut csr = rcgen::CertificateSigningRequestParams::from_pem(csr_pem).map_err(terr)?;
        let now = SystemTime::now();
        csr.params.not_before = to_offset(now - Duration::from_secs(1));
        csr.params.not_after = to_offset(now + lifetime);
        csr.params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        csr.params.serial_number = Some(SerialNumber::from(
            self.serial.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        ));
        Ok(csr.signed_by(&self.issuer).map_err(terr)?.pem())
    }
}

struct MemState {
    svid: Svid,
    bundle: Arc<Bundle>,
    cred: Credential,
}

/// An in-memory provider whose identity is replaced with [`MemoryProvider::set`].
pub struct MemoryProvider {
    st: RwLock<Option<MemState>>,
    subs: Subscribers,
    version: std::sync::atomic::AtomicU64,
    roots: RwLock<Vec<CertificateDer<'static>>>,
}

impl std::fmt::Debug for MemoryProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemoryProvider").finish_non_exhaustive()
    }
}

impl MemoryProvider {
    /// A provider holding `issued` with `ca`'s root as the bundle.
    pub fn new(ca: &TestCa, issued: &Issued) -> Result<Arc<Self>, TestError> {
        let p = Arc::new(Self {
            st: RwLock::new(None),
            subs: Subscribers::default(),
            version: std::sync::atomic::AtomicU64::new(0),
            roots: RwLock::new(vec![ca.root_der()]),
        });
        p.set(ca.trust_domain(), issued)?;
        Ok(p)
    }

    /// Replaces the identity (same bundle) and notifies watchers.
    pub fn set(&self, trust_domain: &str, issued: &Issued) -> Result<(), TestError> {
        let (cred, leaf) =
            load_certified_key(issued.cert_pem.as_bytes(), issued.key_pem.as_bytes()).map_err(terr)?;
        let uri = leaf.uris.first().cloned().unwrap_or_default();
        let id = SpiffeId::parse(&uri).map_err(terr)?;
        let roots = self.roots.read().map_err(terr)?.clone();
        let mut guard = self.st.write().map_err(terr)?;
        let version = match guard.as_ref() {
            Some(s) if s.bundle.roots == roots => s.bundle.version,
            _ => self.version.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1,
        };
        let svid = Svid {
            id,
            not_before: leaf.not_before,
            not_after: leaf.not_after,
            serial: leaf.serial,
        };
        let bundle = Arc::new(Bundle {
            trust_domain: trust_domain.to_owned(),
            roots,
            version,
        });
        *guard = Some(MemState {
            svid: svid.clone(),
            bundle: Arc::clone(&bundle),
            cred,
        });
        drop(guard);
        self.subs.notify(&Update {
            identity: Some(svid),
            bundle: Some(bundle),
            err: None,
        });
        Ok(())
    }

    /// Replaces the trust roots (takes effect on the next `set`).
    pub fn set_roots(&self, roots: Vec<CertificateDer<'static>>) {
        if let Ok(mut r) = self.roots.write() {
            *r = roots;
        }
    }

    /// Delivers a renewal failure to watchers.
    pub fn fail(&self, msg: &str) {
        let cur = self.current().ok();
        self.subs.notify(&Update {
            identity: cur.as_ref().map(|c| c.0.clone()),
            bundle: cur.map(|c| c.1),
            err: Some(IdentityError(msg.to_owned())),
        });
    }
}

#[async_trait]
impl Provider for MemoryProvider {
    fn current(&self) -> Result<(Svid, Arc<Bundle>), IdentityError> {
        let g = self.st.read().map_err(|_| IdentityError::new("poisoned"))?;
        let s = g
            .as_ref()
            .ok_or_else(|| IdentityError::new("memory: no identity"))?;
        Ok((s.svid.clone(), Arc::clone(&s.bundle)))
    }

    fn credential(&self) -> Result<Credential, IdentityError> {
        let g = self.st.read().map_err(|_| IdentityError::new("poisoned"))?;
        g.as_ref()
            .map(|s| s.cred.clone())
            .ok_or_else(|| IdentityError::new("memory: no identity"))
    }

    fn watch(&self) -> Result<mpsc::Receiver<Update>, IdentityError> {
        Ok(self.subs.subscribe(8))
    }

    async fn close(&self) {
        self.subs.close();
    }
}
