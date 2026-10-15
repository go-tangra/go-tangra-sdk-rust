use super::*;
use crate::identity::Credential;
use crate::identity::Renewer;
use crate::testutil::{IssueOptions, MemoryProvider, TestCa};
use async_trait::async_trait;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};

type Events = Arc<Mutex<Vec<State>>>;

fn recorder() -> (Events, LifecycleConfig) {
    let ev: Events = Arc::default();
    let e2 = Arc::clone(&ev);
    let cfg = LifecycleConfig {
        on_event: Arc::new(move |e: LifecycleEvent| {
            if let Ok(mut v) = e2.lock() {
                v.push(e.state);
            }
        }),
        ..LifecycleConfig::default()
    };
    (ev, cfg)
}

fn events(ev: &Events) -> Vec<State> {
    ev.lock().map(|v| v.clone()).unwrap_or_default()
}

async fn wait_for(ev: &Events, s: State) {
    for _ in 0..200 {
        if events(ev).contains(&s) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("no {s:?} event in {:?}", events(ev));
}

#[test]
fn renew_time_is_within_the_jittered_window() {
    let nb = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
    let na = nb + Duration::from_secs(1000);
    for _ in 0..100 {
        let t = renew_time(nb, na, 0.5, 0.1);
        let off = t.duration_since(nb).unwrap_or_default().as_secs_f64();
        assert!((450.0..=550.0).contains(&off), "{off}");
    }
    assert_eq!(renew_time(nb, na, 0.5, 0.0), nb + Duration::from_secs(500));
}

#[test]
fn defaults() {
    let c = LifecycleConfig {
        renew_at: 0.9,
        jitter: 0.0,
        min_backoff: Duration::ZERO,
        max_backoff: Duration::ZERO,
        ..LifecycleConfig::default()
    }
    .with_defaults();
    assert!((c.renew_at - 0.5).abs() < f64::EPSILON);
    assert!((c.jitter - 0.1).abs() < f64::EPSILON);
    assert_eq!(
        (c.min_backoff, c.max_backoff),
        (Duration::from_secs(1), Duration::from_secs(60))
    );
}

#[tokio::test]
async fn adopts_updates_and_bundle_changes() {
    let ca = TestCa::new("example.org").expect("ca");
    let p = MemoryProvider::new(&ca, &ca.issue("orders").expect("issue")).expect("provider");
    let (ev, cfg) = recorder();
    let lc = Lifecycle::new(p.clone(), cfg);
    let cancel = CancellationToken::new();
    lc.start(cancel.clone()).expect("start");
    assert_eq!(lc.state(), State::Valid);
    assert_eq!(events(&ev), vec![State::Valid]);
    // A renewed leaf (push model) is adopted.
    p.set("example.org", &ca.issue("orders").expect("issue"))
        .expect("set");
    for _ in 0..100 {
        if events(&ev).len() >= 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(events(&ev), vec![State::Valid, State::Valid]);
    // A failure keeps the last-known-good identity.
    p.fail("boom");
    wait_for(&ev, State::RenewFailed).await;
    assert_eq!(lc.state(), State::Valid);
    // A new root set fires BundleUpdated.
    let ca2 = TestCa::new("example.org").expect("ca2");
    p.set_roots(vec![ca.root_der(), ca2.root_der()]);
    p.set("example.org", &ca.issue("orders").expect("issue"))
        .expect("set");
    wait_for(&ev, State::BundleUpdated).await;
    cancel.cancel();
}

#[tokio::test]
async fn expires_without_renewal() {
    let ca = TestCa::new("example.org").expect("ca");
    let now = SystemTime::now();
    let short = ca
        .issue_with(
            "orders",
            IssueOptions {
                not_before: Some(now - Duration::from_secs(10)),
                not_after: Some(now + Duration::from_secs(2)),
                ..IssueOptions::default()
            },
        )
        .expect("issue");
    let p = MemoryProvider::new(&ca, &short).expect("provider");
    let (ev, cfg) = recorder();
    let lc = Lifecycle::new(p, cfg);
    lc.start(CancellationToken::new()).expect("start");
    assert_eq!(lc.state(), State::Valid);
    wait_for(&ev, State::Expired).await;
    assert_eq!(lc.state(), State::Expired);
}

/// A pull-model provider: renews on request, failing the first `fail` times.
struct Pull {
    ca: TestCa,
    inner: Arc<MemoryProvider>,
    fail: AtomicU32,
    calls: AtomicU32,
}

#[async_trait]
impl Renewer for Pull {
    async fn renew(&self) -> Result<(), IdentityError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail.load(Ordering::SeqCst) > 0 {
            self.fail.fetch_sub(1, Ordering::SeqCst);
            return Err(IdentityError::new("ca unavailable"));
        }
        let fresh = self
            .ca
            .issue("orders")
            .map_err(|e| IdentityError(e.to_string()))?;
        self.inner
            .set("example.org", &fresh)
            .map_err(|e| IdentityError(e.to_string()))
    }
}

#[async_trait]
impl Provider for Pull {
    fn current(&self) -> Result<(Svid, Arc<Bundle>), IdentityError> {
        self.inner.current()
    }
    fn credential(&self) -> Result<Credential, IdentityError> {
        self.inner.credential()
    }
    fn watch(&self) -> Result<mpsc::Receiver<Update>, IdentityError> {
        self.inner.watch()
    }
    fn renewer(&self) -> Option<&dyn Renewer> {
        Some(self)
    }
    async fn close(&self) {}
}

#[tokio::test]
async fn renews_with_backoff_on_failure() {
    let ca = TestCa::new("example.org").expect("ca");
    let now = SystemTime::now();
    // Renewal point (50%) is 2s after not_before; the floor is remaining/4.
    let first = ca
        .issue_with(
            "orders",
            IssueOptions {
                not_before: Some(now - Duration::from_secs(1)),
                not_after: Some(now + Duration::from_secs(4)),
                ..IssueOptions::default()
            },
        )
        .expect("issue");
    let inner = MemoryProvider::new(&ca, &first).expect("mem");
    let p = Arc::new(Pull {
        ca,
        inner,
        fail: AtomicU32::new(1),
        calls: AtomicU32::new(0),
    });
    let (ev, mut cfg) = recorder();
    cfg.jitter = 0.0001;
    cfg.min_backoff = Duration::from_millis(100);
    let lc = Lifecycle::new(p.clone(), cfg);
    let serial0 = p.current().expect("cur").0.serial;
    lc.start(CancellationToken::new()).expect("start");
    wait_for(&ev, State::RenewFailed).await;
    for _ in 0..200 {
        if p.current().expect("cur").0.serial != serial0 && lc.state() == State::Valid {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_ne!(p.current().expect("cur").0.serial, serial0);
    assert_eq!(lc.state(), State::Valid);
    assert!(p.calls.load(Ordering::SeqCst) >= 2);
    let evs = events(&ev);
    assert!(evs.contains(&State::Renewing), "{evs:?}");
    assert!(!evs.contains(&State::Expired), "{evs:?}");
}
