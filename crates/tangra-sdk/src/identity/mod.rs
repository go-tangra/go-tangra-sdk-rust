//! Service identity: SPIFFE IDs, the [`Provider`] contract, the identity
//! [`lifecycle`] and the providers (go-tangra `identity/`).
//!
//! A provider supplies the local SVID (certificate chain + key) and the trust
//! bundle and reports changes. The private key never leaves the provider
//! except as a rustls [`CertifiedKey`] handed to the TLS layer per handshake.
//!
//! Providers: [`file`] (PEM files polled every 2s), [`lcm`] (network
//! enrolment with lcm). The SPIFFE Workload API provider is not implemented
//! yet (feature `spiffe`; see the `spiffe` module docs).

mod spiffeid;
pub(crate) mod x509;

pub mod file;
pub mod lcm;
pub mod lifecycle;
#[cfg(feature = "spiffe")]
pub mod spiffe;

use std::sync::Arc;
use std::time::SystemTime;

use async_trait::async_trait;
use rustls::sign::CertifiedKey;
use rustls_pki_types::CertificateDer;
use tokio::sync::mpsc;

pub use spiffeid::{SpiffeId, SpiffeIdError, valid_service_name, valid_trust_domain};
pub use x509::{LeafInfo, load_certified_key, parse_certs_pem, parse_leaf};

/// The read-only view of a service's own identity (no key material).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Svid {
    /// The SPIFFE ID.
    pub id: SpiffeId,
    /// Start of validity.
    pub not_before: SystemTime,
    /// End of validity.
    pub not_after: SystemTime,
    /// Serial number in decimal (Go `big.Int.String`).
    pub serial: String,
}

/// The trust roots of one trust domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bundle {
    /// Trust domain.
    pub trust_domain: String,
    /// DER root certificates.
    pub roots: Vec<CertificateDer<'static>>,
    /// Increases monotonically on every change.
    pub version: u64,
}

/// The TLS credential: chain + signing key, with the leaf validity so the
/// transport can refuse to present an expired identity.
#[derive(Debug, Clone)]
pub struct Credential {
    /// rustls certificate chain and signing key.
    pub certified: Arc<CertifiedKey>,
    /// Leaf start of validity.
    pub not_before: SystemTime,
    /// Leaf end of validity.
    pub not_after: SystemTime,
}

/// Delivered on every identity or bundle change. `err` is set when a renewal
/// failed; `identity`/`bundle` then hold the last-known-good values.
#[derive(Debug, Clone)]
pub struct Update {
    /// Current identity.
    pub identity: Option<Svid>,
    /// Current bundle.
    pub bundle: Option<Arc<Bundle>>,
    /// Renewal failure.
    pub err: Option<IdentityError>,
}

/// A provider or identity failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct IdentityError(pub String);

impl IdentityError {
    pub(crate) fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
}

/// Supplies the local identity and trust bundle and reports changes
/// (go-tangra `identity.Provider` + the internal `cred.Source`).
#[async_trait]
pub trait Provider: Send + Sync + 'static {
    /// The current identity and bundle, or an error if none is valid.
    fn current(&self) -> Result<(Svid, Arc<Bundle>), IdentityError>;
    /// The current TLS credential (served per handshake).
    fn credential(&self) -> Result<Credential, IdentityError>;
    /// A channel that receives an [`Update`] on every change until the
    /// receiver is dropped or the provider is closed.
    fn watch(&self) -> Result<mpsc::Receiver<Update>, IdentityError>;
    /// Pull-model providers renew on request; push-model ones return None.
    fn renewer(&self) -> Option<&dyn Renewer> {
        None
    }
    /// Stops background work and closes every watch channel.
    async fn close(&self);
}

/// Implemented by providers that renew on request.
#[async_trait]
pub trait Renewer: Send + Sync {
    /// Obtains a fresh identity.
    async fn renew(&self) -> Result<(), IdentityError>;
}

/// Answers whether an identity was revoked inside its validity window. An
/// error is treated as revoked (fail closed).
#[async_trait]
pub trait RevocationChecker: Send + Sync + 'static {
    /// Whether `id` (with certificate `serial`) is revoked.
    async fn is_revoked(&self, id: &SpiffeId, serial: &str) -> Result<bool, IdentityError>;
}

/// The closed vocabulary of verification outcomes (identical to the audit
/// reason strings).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Reason {
    /// `no_identity`
    NoIdentity,
    /// `untrusted`
    Untrusted,
    /// `identity_expired`
    Expired,
    /// `identity_not_yet_valid`
    NotYetValid,
    /// `identity_revoked`
    Revoked,
    /// `name_mismatch`
    NameMismatch,
    /// `downgrade_refused`
    Downgrade,
    /// `provider_unavailable`
    ProviderUnavailable,
    /// `bundle_empty`
    BundleEmpty,
}

impl Reason {
    /// The wire/audit string.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoIdentity => "no_identity",
            Self::Untrusted => "untrusted",
            Self::Expired => "identity_expired",
            Self::NotYetValid => "identity_not_yet_valid",
            Self::Revoked => "identity_revoked",
            Self::NameMismatch => "name_mismatch",
            Self::Downgrade => "downgrade_refused",
            Self::ProviderUnavailable => "provider_unavailable",
            Self::BundleEmpty => "bundle_empty",
        }
    }
}

impl std::fmt::Display for Reason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A peer verification refusal. The message is fixed-vocabulary and never
/// contains certificate material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyError {
    /// The classified reason.
    pub reason: Reason,
    /// A short operator-facing hint; never peer-supplied text.
    pub detail: String,
    /// The SPIFFE ID the peer presented, if it parsed (audit only).
    pub claimed: String,
}

impl VerifyError {
    /// A refusal without detail.
    pub fn new(reason: Reason) -> Self {
        Self {
            reason,
            detail: String::new(),
            claimed: String::new(),
        }
    }

    #[must_use]
    pub(crate) fn detail(mut self, d: impl Into<String>) -> Self {
        self.detail = d.into();
        self
    }

    #[must_use]
    pub(crate) fn claimed(mut self, c: impl Into<String>) -> Self {
        self.claimed = c.into();
        self
    }
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.detail.is_empty() {
            write!(f, "identity: peer refused: {}", self.reason)
        } else {
            write!(f, "identity: peer refused: {} ({})", self.reason, self.detail)
        }
    }
}

impl std::error::Error for VerifyError {}

/// Fan-out of updates to watch channels; a slow subscriber never stalls
/// rotation (updates to a full channel are dropped, as in Go).
#[derive(Debug, Default)]
pub(crate) struct Subscribers {
    subs: std::sync::Mutex<Vec<mpsc::Sender<Update>>>,
}

impl Subscribers {
    pub(crate) fn subscribe(&self, cap: usize) -> mpsc::Receiver<Update> {
        let (tx, rx) = mpsc::channel(cap);
        if let Ok(mut s) = self.subs.lock() {
            s.push(tx);
        }
        rx
    }

    pub(crate) fn notify(&self, u: &Update) {
        if let Ok(mut s) = self.subs.lock() {
            s.retain(|tx| !matches!(tx.try_send(u.clone()), Err(mpsc::error::TrySendError::Closed(_))));
        }
    }

    pub(crate) fn close(&self) {
        if let Ok(mut s) = self.subs.lock() {
            s.clear();
        }
    }
}
