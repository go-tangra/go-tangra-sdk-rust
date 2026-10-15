//! Certificate and key parsing shared by the providers and the TLS layer.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use rustls::sign::CertifiedKey;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::{FromDer, X509Certificate};

use super::{Credential, IdentityError};

/// What the SDK needs from a leaf certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeafInfo {
    /// URI SANs, in order.
    pub uris: Vec<String>,
    /// Start of validity.
    pub not_before: SystemTime,
    /// End of validity.
    pub not_after: SystemTime,
    /// Serial number in decimal.
    pub serial: String,
}

fn to_system_time(secs: i64) -> SystemTime {
    if secs >= 0 {
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs.unsigned_abs())
    } else {
        SystemTime::UNIX_EPOCH - Duration::from_secs(secs.unsigned_abs())
    }
}

/// Parses a DER certificate.
pub fn parse_leaf(der: &[u8]) -> Result<LeafInfo, IdentityError> {
    let (_, cert) = X509Certificate::from_der(der)
        .map_err(|e| IdentityError(format!("x509: malformed certificate: {e}")))?;
    let mut uris = Vec::new();
    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for name in &san.value.general_names {
            if let GeneralName::URI(u) = name {
                uris.push((*u).to_owned());
            }
        }
    } else if cert.subject_alternative_name().is_err() {
        return Err(IdentityError::new("x509: malformed subject alternative name"));
    }
    Ok(LeafInfo {
        uris,
        not_before: to_system_time(cert.validity().not_before.timestamp()),
        not_after: to_system_time(cert.validity().not_after.timestamp()),
        serial: cert.tbs_certificate.serial.to_string(),
    })
}

/// All CERTIFICATE blocks of a PEM document (other block types are skipped).
pub fn parse_certs_pem(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>, IdentityError> {
    let mut out = Vec::new();
    for c in CertificateDer::pem_slice_iter(pem) {
        let c = c.map_err(|e| IdentityError(format!("pem: {e}")))?;
        X509Certificate::from_der(&c).map_err(|e| IdentityError(format!("x509: {e}")))?;
        out.push(c);
    }
    Ok(out)
}

/// The process-wide rustls crypto provider (ring).
pub(crate) fn crypto() -> Arc<rustls::crypto::CryptoProvider> {
    static P: std::sync::OnceLock<Arc<rustls::crypto::CryptoProvider>> = std::sync::OnceLock::new();
    Arc::clone(P.get_or_init(|| Arc::new(rustls::crypto::ring::default_provider())))
}

/// Builds a credential from a certificate chain PEM and a private key PEM
/// (PKCS#8, PKCS#1 or SEC1), checking that the key matches the leaf
/// (Go `tls.X509KeyPair`).
pub fn load_certified_key(cert_pem: &[u8], key_pem: &[u8]) -> Result<(Credential, LeafInfo), IdentityError> {
    let chain = parse_certs_pem(cert_pem)?;
    let leaf_der = chain
        .first()
        .ok_or_else(|| IdentityError::new("tls: failed to find any PEM data in certificate input"))?;
    let leaf = parse_leaf(leaf_der)?;
    let key = PrivateKeyDer::from_pem_slice(key_pem).map_err(|e| IdentityError(format!("tls: key: {e}")))?;
    certified_from_parts(chain, key, leaf)
}

/// Builds a credential from DER parts.
pub(crate) fn certified_from_parts(
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    leaf: LeafInfo,
) -> Result<(Credential, LeafInfo), IdentityError> {
    let signing = crypto()
        .key_provider
        .load_private_key(key)
        .map_err(|e| IdentityError(format!("tls: key: {e}")))?;
    let ck = CertifiedKey::new(chain, signing);
    ck.keys_match()
        .map_err(|_| IdentityError::new("tls: private key does not match public key"))?;
    Ok((
        Credential {
            certified: Arc::new(ck),
            not_before: leaf.not_before,
            not_after: leaf.not_after,
        },
        leaf,
    ))
}
