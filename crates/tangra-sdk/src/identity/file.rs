//! File-backed identity provider (go-tangra `identity/file/provider.go`):
//! PEM certificate (+chain), key and trust bundle, polled for changes every
//! 2s. A failed reload keeps the last-known-good identity and is reported as
//! an [`Update`] with `err` set.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock, Weak};
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use super::{
    Bundle, Credential, IdentityError, Provider, SpiffeId, Subscribers, Svid, Update, load_certified_key,
    parse_certs_pem, valid_trust_domain,
};

/// Where the PEM files are.
#[derive(Debug, Clone)]
pub struct FileConfig {
    /// Leaf certificate (and chain) PEM.
    pub cert: PathBuf,
    /// Private key PEM.
    pub key: PathBuf,
    /// Trust bundle PEM.
    pub bundle: PathBuf,
    /// The trust domain the identity must belong to.
    pub trust_domain: String,
    /// Change-detection interval (default 2s).
    pub poll_interval: Duration,
}

struct State {
    cert_key: Vec<u8>,
    bundle_raw: Vec<u8>,
    svid: Svid,
    bundle: Arc<Bundle>,
    cred: Credential,
}

/// The file provider.
pub struct FileProvider {
    cfg: FileConfig,
    cur: RwLock<Arc<State>>,
    ver: AtomicU64,
    subs: Subscribers,
    stop: CancellationToken,
    closed: AtomicBool,
}

impl std::fmt::Debug for FileProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileProvider")
            .field("cert", &self.cfg.cert)
            .finish_non_exhaustive()
    }
}

impl FileProvider {
    /// Loads the files, validates them and starts change polling (requires a
    /// Tokio runtime).
    pub fn new(mut cfg: FileConfig) -> Result<Arc<Self>, IdentityError> {
        if !valid_trust_domain(&cfg.trust_domain) {
            return Err(IdentityError::new("identity/file: trust domain is required"));
        }
        if cfg.poll_interval.is_zero() {
            cfg.poll_interval = Duration::from_secs(2);
        }
        let handle = tokio::runtime::Handle::try_current()
            .map_err(|_| IdentityError::new("identity/file: a Tokio runtime is required"))?;
        let ver = AtomicU64::new(0);
        let st = load(&cfg, None, &ver)?;
        let p = Arc::new(Self {
            cfg,
            cur: RwLock::new(st),
            ver,
            subs: Subscribers::default(),
            stop: CancellationToken::new(),
            closed: AtomicBool::new(false),
        });
        handle.spawn(poll(Arc::downgrade(&p), p.stop.clone(), p.cfg.poll_interval));
        Ok(p)
    }

    fn snapshot(&self) -> Option<Arc<State>> {
        self.cur.read().ok().map(|g| Arc::clone(&g))
    }
}

fn read(p: &PathBuf, what: &str) -> Result<Vec<u8>, IdentityError> {
    std::fs::read(p).map_err(|e| IdentityError(format!("identity/file: {what}: {e}")))
}

fn load(cfg: &FileConfig, prev: Option<&Arc<State>>, ver: &AtomicU64) -> Result<Arc<State>, IdentityError> {
    let cert_pem = read(&cfg.cert, "cert")?;
    let key_pem = read(&cfg.key, "key")?;
    let bundle_pem = read(&cfg.bundle, "bundle")?;
    let mut cert_key = cert_pem.clone();
    cert_key.extend_from_slice(&key_pem);
    if let Some(prev) = prev
        && prev.cert_key == cert_key
        && prev.bundle_raw == bundle_pem
    {
        return Ok(Arc::clone(prev));
    }
    let (cred, leaf) = load_certified_key(&cert_pem, &key_pem)
        .map_err(|e| IdentityError(format!("identity/file: cert/key: {e}")))?;
    if leaf.uris.len() != 1 {
        return Err(IdentityError(format!(
            "identity/file: cert must carry exactly one URI SAN, has {}",
            leaf.uris.len()
        )));
    }
    let id =
        SpiffeId::parse(&leaf.uris[0]).map_err(|e| IdentityError(format!("identity/file: cert SAN: {e}")))?;
    if id.trust_domain() != cfg.trust_domain {
        return Err(IdentityError(format!(
            "identity/file: cert trust domain {:?} does not match configured {:?}",
            id.trust_domain(),
            cfg.trust_domain
        )));
    }
    let roots =
        parse_certs_pem(&bundle_pem).map_err(|e| IdentityError(format!("identity/file: bundle: {e}")))?;
    if roots.is_empty() {
        return Err(IdentityError::new(
            "identity/file: bundle contains no certificates",
        ));
    }
    let version = match prev {
        Some(p) if p.bundle_raw == bundle_pem => ver.load(Ordering::SeqCst),
        _ => ver.fetch_add(1, Ordering::SeqCst) + 1,
    };
    Ok(Arc::new(State {
        cert_key,
        bundle_raw: bundle_pem,
        svid: Svid {
            id,
            not_before: leaf.not_before,
            not_after: leaf.not_after,
            serial: leaf.serial,
        },
        bundle: Arc::new(Bundle {
            trust_domain: cfg.trust_domain.clone(),
            roots,
            version,
        }),
        cred,
    }))
}

async fn poll(p: Weak<FileProvider>, stop: CancellationToken, every: Duration) {
    let mut t = tokio::time::interval_at(tokio::time::Instant::now() + every, every);
    loop {
        tokio::select! {
            () = stop.cancelled() => return,
            _ = t.tick() => {}
        }
        let Some(p) = p.upgrade() else { return };
        let Some(prev) = p.snapshot() else { return };
        match load(&p.cfg, Some(&prev), &p.ver) {
            Err(e) => p.subs.notify(&Update {
                identity: Some(prev.svid.clone()),
                bundle: Some(Arc::clone(&prev.bundle)),
                err: Some(e),
            }),
            Ok(st) if Arc::ptr_eq(&st, &prev) => {}
            Ok(st) => {
                if let Ok(mut g) = p.cur.write() {
                    *g = Arc::clone(&st);
                }
                p.subs.notify(&Update {
                    identity: Some(st.svid.clone()),
                    bundle: Some(Arc::clone(&st.bundle)),
                    err: None,
                });
            }
        }
    }
}

#[async_trait]
impl Provider for FileProvider {
    fn current(&self) -> Result<(Svid, Arc<Bundle>), IdentityError> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(IdentityError::new("identity/file: provider closed"));
        }
        let st = self
            .snapshot()
            .ok_or_else(|| IdentityError::new("identity/file: poisoned"))?;
        Ok((st.svid.clone(), Arc::clone(&st.bundle)))
    }

    fn credential(&self) -> Result<Credential, IdentityError> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(IdentityError::new("identity/file: provider closed"));
        }
        let st = self
            .snapshot()
            .ok_or_else(|| IdentityError::new("identity/file: poisoned"))?;
        Ok(st.cred.clone())
    }

    fn watch(&self) -> Result<mpsc::Receiver<Update>, IdentityError> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(IdentityError::new("identity/file: provider closed"));
        }
        Ok(self.subs.subscribe(8))
    }

    async fn close(&self) {
        if self.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        self.stop.cancel();
        self.subs.close();
    }
}

impl Drop for FileProvider {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{IssueOptions, TestCa};

    fn write_svid(dir: &std::path::Path, ca: &TestCa, name: &str) -> FileConfig {
        let issued = ca.issue(name).expect("issue");
        std::fs::write(dir.join("cert.pem"), &issued.cert_pem).expect("cert");
        std::fs::write(dir.join("key.pem"), &issued.key_pem).expect("key");
        std::fs::write(dir.join("bundle.pem"), ca.bundle_pem()).expect("bundle");
        FileConfig {
            cert: dir.join("cert.pem"),
            key: dir.join("key.pem"),
            bundle: dir.join("bundle.pem"),
            trust_domain: ca.trust_domain().to_owned(),
            poll_interval: Duration::from_millis(30),
        }
    }

    #[tokio::test]
    async fn loads_and_rotates() {
        let dir = tempfile::tempdir().expect("dir");
        let ca = TestCa::new("example.org").expect("ca");
        let cfg = write_svid(dir.path(), &ca, "orders");
        let p = FileProvider::new(cfg).expect("provider");
        let (id, b) = p.current().expect("current");
        assert_eq!(id.id.to_string(), "spiffe://example.org/svc/orders");
        assert_eq!(b.version, 1);
        let mut rx = p.watch().expect("watch");
        // Rotate the leaf: same bundle version, new serial.
        let issued = ca.issue("orders").expect("issue");
        std::fs::write(dir.path().join("key.pem"), &issued.key_pem).expect("key");
        std::fs::write(dir.path().join("cert.pem"), &issued.cert_pem).expect("cert");
        let u = loop {
            let u = tokio::time::timeout(Duration::from_secs(5), rx.recv())
                .await
                .expect("update")
                .expect("open");
            if u.err.is_none() {
                break u;
            }
        };
        let new = u.identity.expect("identity");
        assert_ne!(new.serial, id.serial);
        assert_eq!(u.bundle.expect("bundle").version, 1);
        // A broken rewrite keeps the last-known-good identity.
        std::fs::write(dir.path().join("cert.pem"), "garbage").expect("cert");
        let u = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("update")
            .expect("open");
        assert!(u.err.is_some());
        assert_eq!(p.current().expect("lkg").0.serial, new.serial);
        p.close().await;
        assert!(p.current().is_err());
    }

    #[tokio::test]
    async fn rejects_bad_identities() {
        let dir = tempfile::tempdir().expect("dir");
        let ca = TestCa::new("example.org").expect("ca");
        let mut cfg = write_svid(dir.path(), &ca, "orders");
        cfg.trust_domain = "other.org".into();
        let e = FileProvider::new(cfg.clone()).expect_err("td");
        assert!(e.0.contains("does not match"), "{e}");
        cfg.trust_domain = "example.org".into();
        let two = ca
            .issue_with(
                "x",
                IssueOptions {
                    uris: Some(vec![
                        "spiffe://example.org/svc/a".into(),
                        "spiffe://example.org/svc/b".into(),
                    ]),
                    ..IssueOptions::default()
                },
            )
            .expect("issue");
        std::fs::write(&cfg.cert, &two.cert_pem).expect("cert");
        std::fs::write(&cfg.key, &two.key_pem).expect("key");
        let e = FileProvider::new(cfg.clone()).expect_err("two");
        assert!(e.0.contains("exactly one URI SAN"), "{e}");
        let other = ca.issue("y").expect("issue");
        std::fs::write(&cfg.key, &other.key_pem).expect("key");
        let e = FileProvider::new(cfg.clone()).expect_err("mismatch");
        assert!(e.0.contains("cert/key"), "{e}");
        std::fs::write(&cfg.bundle, "").expect("bundle");
        std::fs::write(&cfg.cert, &other.cert_pem).expect("cert");
        let e = FileProvider::new(cfg).expect_err("empty bundle");
        assert!(e.0.contains("no certificates"), "{e}");
    }
}
