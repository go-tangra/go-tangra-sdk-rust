//! SPIFFE Workload API identity provider (go-tangra `identity/spiffe`), on
//! the maintained `spiffe` crate (rust-spiffe, tonic 0.14). Feature `spiffe`.
//!
//! The provider waits up to `startup_timeout` for the first X.509 context,
//! adopts the default SVID (exactly one SPIFFE URI SAN in the trust domain)
//! and the trust domain's bundle, and follows the context stream. A broken
//! stream is reported as a renewal failure (last-known-good kept) and
//! re-established with backoff (1s doubling to 30s; go-spiffe's watcher
//! retries internally).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use async_trait::async_trait;
use futures_util::StreamExt;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use spiffe::{TrustDomain, WorkloadApiClient, X509Context};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

use super::x509::certified_from_parts;
use super::{Bundle, Credential, IdentityError, Provider, SpiffeId, Subscribers, Svid, Update, parse_leaf};

/// Workload API settings.
#[derive(Debug, Clone)]
pub struct SpiffeConfig {
    /// Socket address, e.g. `unix:///run/spire/sockets/agent.sock`.
    pub socket: String,
    /// The trust domain.
    pub trust_domain: String,
    /// Bound on the wait for the first identity (default 30s).
    pub startup_timeout: Duration,
}

struct State {
    svid: Svid,
    bundle: Arc<Bundle>,
    cred: Credential,
}

/// The Workload API provider.
pub struct SpiffeProvider {
    td: String,
    st: RwLock<Option<State>>,
    roots_seen: Mutex<Option<Vec<CertificateDer<'static>>>>,
    ver: Mutex<u64>,
    subs: Subscribers,
    closed: AtomicBool,
    cancel: CancellationToken,
}

impl std::fmt::Debug for SpiffeProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpiffeProvider")
            .field("td", &self.td)
            .finish_non_exhaustive()
    }
}

impl SpiffeProvider {
    /// Connects and waits for the first identity.
    pub async fn new(cfg: SpiffeConfig) -> Result<Arc<Self>, IdentityError> {
        if cfg.socket.is_empty() {
            return Err(IdentityError::new("identity/spiffe: workload socket is required"));
        }
        if !super::valid_trust_domain(&cfg.trust_domain) {
            return Err(IdentityError::new("identity/spiffe: invalid trust domain"));
        }
        let td = TrustDomain::new(&cfg.trust_domain)
            .map_err(|e| IdentityError(format!("identity/spiffe: {e}")))?;
        let timeout = if cfg.startup_timeout.is_zero() {
            Duration::from_secs(30)
        } else {
            cfg.startup_timeout
        };
        let p = Arc::new(Self {
            td: cfg.trust_domain.clone(),
            st: RwLock::new(None),
            roots_seen: Mutex::new(None),
            ver: Mutex::new(0),
            subs: Subscribers::default(),
            closed: AtomicBool::new(false),
            cancel: CancellationToken::new(),
        });
        let (first_tx, first_rx) = oneshot::channel();
        tokio::spawn(watch_loop(
            Arc::downgrade(&p),
            cfg.socket,
            td,
            p.cancel.clone(),
            first_tx,
        ));
        match tokio::time::timeout(timeout, first_rx).await {
            Ok(Ok(Ok(()))) => Ok(p),
            Ok(Ok(Err(e))) => {
                p.close().await;
                Err(e)
            }
            _ => {
                p.close().await;
                Err(IdentityError::new(
                    "identity/spiffe: no identity from the workload api within the startup timeout",
                ))
            }
        }
    }

    /// Adopts an X.509 context (Go `adopt`).
    pub(crate) fn adopt(&self, c: &X509Context, td: &TrustDomain) -> Result<Update, IdentityError> {
        let svid = c
            .default_svid()
            .ok_or_else(|| IdentityError::new("identity/spiffe: empty SVID"))?;
        let chain: Vec<CertificateDer<'static>> = svid
            .cert_chain()
            .iter()
            .map(|c| CertificateDer::from(c.as_bytes().to_vec()))
            .collect();
        let leaf_der = chain
            .first()
            .ok_or_else(|| IdentityError::new("identity/spiffe: empty SVID"))?;
        let leaf = parse_leaf(leaf_der)?;
        if leaf.uris.len() != 1 {
            return Err(IdentityError::new(
                "identity/spiffe: SVID must carry exactly one URI SAN",
            ));
        }
        let id = SpiffeId::parse(&leaf.uris[0])
            .map_err(|e| IdentityError(format!("identity/spiffe: SVID id: {e}")))?;
        if id.trust_domain() != self.td {
            return Err(IdentityError(format!(
                "identity/spiffe: SVID trust domain {:?} does not match {:?}",
                id.trust_domain(),
                self.td
            )));
        }
        let bundle = c
            .bundle_set()
            .get(td)
            .ok_or_else(|| IdentityError::new("identity/spiffe: bundle: no bundle for the trust domain"))?;
        let roots: Vec<CertificateDer<'static>> = bundle
            .authorities()
            .iter()
            .map(|c| CertificateDer::from(c.as_bytes().to_vec()))
            .collect();
        if roots.is_empty() {
            return Err(IdentityError::new("identity/spiffe: empty trust bundle"));
        }
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(svid.private_key().as_bytes().to_vec()));
        let (cred, leaf) = certified_from_parts(chain, key, leaf)?;
        let version = {
            let mut seen = self
                .roots_seen
                .lock()
                .map_err(|_| IdentityError::new("identity/spiffe: poisoned"))?;
            let mut v = self
                .ver
                .lock()
                .map_err(|_| IdentityError::new("identity/spiffe: poisoned"))?;
            if seen.as_ref() != Some(&roots) {
                *seen = Some(roots.clone());
                *v += 1;
            }
            *v
        };
        let svid = Svid {
            id,
            not_before: leaf.not_before,
            not_after: leaf.not_after,
            serial: leaf.serial,
        };
        let bundle = Arc::new(Bundle {
            trust_domain: self.td.clone(),
            roots,
            version,
        });
        if let Ok(mut g) = self.st.write() {
            *g = Some(State {
                svid: svid.clone(),
                bundle: Arc::clone(&bundle),
                cred,
            });
        }
        Ok(Update {
            identity: Some(svid),
            bundle: Some(bundle),
            err: None,
        })
    }

    fn have(&self) -> bool {
        self.st.read().map(|g| g.is_some()).unwrap_or(false)
    }
}

async fn watch_loop(
    p: std::sync::Weak<SpiffeProvider>,
    socket: String,
    td: TrustDomain,
    cancel: CancellationToken,
    first: oneshot::Sender<Result<(), IdentityError>>,
) {
    let mut first = Some(first);
    let mut backoff = Duration::from_secs(1);
    loop {
        let res = async {
            let client = WorkloadApiClient::connect_to(&socket)
                .await
                .map_err(|e| IdentityError(format!("identity/spiffe: workload api: {e}")))?;
            client
                .stream_x509_contexts()
                .await
                .map_err(|e| IdentityError(format!("identity/spiffe: workload api: {e}")))
        };
        let stream = tokio::select! {
            () = cancel.cancelled() => return,
            r = res => r,
        };
        match stream {
            Err(e) => {
                if let Some(p) = p.upgrade()
                    && p.have()
                {
                    p.subs.notify(&Update {
                        identity: None,
                        bundle: None,
                        err: Some(e),
                    });
                }
            }
            Ok(mut s) => loop {
                let item = tokio::select! {
                    () = cancel.cancelled() => return,
                    i = s.next() => i,
                };
                let Some(p) = p.upgrade() else { return };
                match item {
                    None => break,
                    Some(Err(e)) => {
                        if p.have() {
                            p.subs.notify(&Update {
                                identity: None,
                                bundle: None,
                                err: Some(IdentityError(format!("identity/spiffe: workload api: {e}"))),
                            });
                        }
                        break;
                    }
                    Some(Ok(ctx)) => {
                        backoff = Duration::from_secs(1);
                        match p.adopt(&ctx, &td) {
                            Ok(u) => {
                                if let Some(f) = first.take() {
                                    let _ = f.send(Ok(()));
                                }
                                p.subs.notify(&u);
                            }
                            Err(e) => {
                                if !p.have()
                                    && let Some(f) = first.take()
                                {
                                    let _ = f.send(Err(e.clone()));
                                }
                                p.subs.notify(&Update {
                                    identity: None,
                                    bundle: None,
                                    err: Some(e),
                                });
                            }
                        }
                    }
                }
            },
        }
        tokio::select! {
            () = cancel.cancelled() => return,
            () = tokio::time::sleep(backoff) => {}
        }
        backoff = (backoff * 2).min(Duration::from_secs(30));
    }
}

#[async_trait]
impl Provider for SpiffeProvider {
    fn current(&self) -> Result<(Svid, Arc<Bundle>), IdentityError> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(IdentityError::new("identity/spiffe: provider closed"));
        }
        let g = self
            .st
            .read()
            .map_err(|_| IdentityError::new("identity/spiffe: poisoned"))?;
        let s = g
            .as_ref()
            .ok_or_else(|| IdentityError::new("identity/spiffe: no identity yet"))?;
        Ok((s.svid.clone(), Arc::clone(&s.bundle)))
    }

    fn credential(&self) -> Result<Credential, IdentityError> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(IdentityError::new("identity/spiffe: provider closed"));
        }
        let g = self
            .st
            .read()
            .map_err(|_| IdentityError::new("identity/spiffe: poisoned"))?;
        g.as_ref()
            .map(|s| s.cred.clone())
            .ok_or_else(|| IdentityError::new("identity/spiffe: no identity yet"))
    }

    fn watch(&self) -> Result<mpsc::Receiver<Update>, IdentityError> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(IdentityError::new("identity/spiffe: provider closed"));
        }
        Ok(self.subs.subscribe(8))
    }

    async fn close(&self) {
        if self.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        self.cancel.cancel();
        self.subs.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{IssueOptions, TestCa};
    use spiffe::{X509Bundle, X509BundleSet, X509Svid};

    fn provider() -> SpiffeProvider {
        SpiffeProvider {
            td: "example.org".into(),
            st: RwLock::new(None),
            roots_seen: Mutex::new(None),
            ver: Mutex::new(0),
            subs: Subscribers::default(),
            closed: AtomicBool::new(false),
            cancel: CancellationToken::new(),
        }
    }

    fn context(ca: &TestCa, issued: &crate::testutil::Issued) -> X509Context {
        let key = issued.key_der().expect("key");
        let svid = X509Svid::parse_from_der(issued.cert_der.as_ref(), key.secret_der()).expect("svid");
        let td = TrustDomain::new("example.org").expect("td");
        let bundle = X509Bundle::from_x509_authorities(td, &[ca.root_der().as_ref()]).expect("bundle");
        let mut set = X509BundleSet::new();
        set.add_bundle(bundle);
        X509Context::new([Arc::new(svid)], set)
    }

    #[test]
    fn adopts_the_default_svid_and_bundle() {
        let ca = TestCa::new("example.org").expect("ca");
        let p = provider();
        let td = TrustDomain::new("example.org").expect("td");
        let u = p
            .adopt(&context(&ca, &ca.issue("orders").expect("issue")), &td)
            .expect("adopt");
        assert_eq!(
            u.identity.expect("id").id.to_string(),
            "spiffe://example.org/svc/orders"
        );
        assert_eq!(u.bundle.expect("bundle").version, 1);
        let u2 = p
            .adopt(&context(&ca, &ca.issue("orders").expect("issue")), &td)
            .expect("adopt");
        assert_eq!(
            u2.bundle.expect("bundle").version,
            1,
            "same roots keep the version"
        );
        assert!(p.credential().is_ok());
        // An SVID outside the trust domain is refused.
        let foreign = ca
            .issue_with(
                "x",
                IssueOptions {
                    uris: Some(vec!["spiffe://other.org/svc/x".into()]),
                    ..IssueOptions::default()
                },
            )
            .expect("issue");
        assert!(p.adopt(&context(&ca, &foreign), &td).is_err());
    }
}
