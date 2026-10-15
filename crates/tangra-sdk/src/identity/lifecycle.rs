//! The identity state machine (go-tangra `identity/lifecycle.go`): schedules
//! renewal at `renew_at` of the validity window (with jitter), retries with
//! backoff, detects expiry, keeps the last-known-good identity on a failed
//! renewal and reports every transition.

use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};

use tokio::sync::mpsc;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use super::{Bundle, IdentityError, Provider, Svid, Update};

/// Lifecycle state, and the kinds of lifecycle events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum State {
    /// No identity adopted yet.
    Pending,
    /// A valid identity is held.
    Valid,
    /// A renewal is in progress (the current identity is still valid).
    Renewing,
    /// Event only: a renewal failed; the state stays as it was.
    RenewFailed,
    /// The identity expired with no renewal: every call is refused.
    Expired,
    /// Revoked.
    Revoked,
    /// Event only: the trust bundle changed.
    BundleUpdated,
}

impl State {
    /// The Go string form (`valid`, `renewing`, ...).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Valid => "valid",
            Self::Renewing => "renewing",
            Self::RenewFailed => "renew_failed",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
            Self::BundleUpdated => "bundle_updated",
        }
    }
}

/// Delivered to [`LifecycleConfig::on_event`].
#[derive(Debug, Clone)]
pub struct LifecycleEvent {
    /// The transition.
    pub state: State,
    /// The identity it concerns, if any.
    pub identity: Option<Svid>,
    /// The bundle, if any.
    pub bundle: Option<Arc<Bundle>>,
    /// The failure, for `RenewFailed`.
    pub err: Option<IdentityError>,
}

type Now = Arc<dyn Fn() -> SystemTime + Send + Sync>;
type OnEvent = Arc<dyn Fn(LifecycleEvent) + Send + Sync>;

/// Renewal scheduling.
#[derive(Clone)]
pub struct LifecycleConfig {
    /// Fraction of the validity window at which renewal starts (0.3..0.8, default 0.5).
    pub renew_at: f64,
    /// Relative random spread of the renewal time (default 0.1).
    pub jitter: f64,
    /// Retry bounds after a failed renewal (defaults 1s / 1m).
    pub min_backoff: Duration,
    /// Upper retry bound.
    pub max_backoff: Duration,
    /// Clock (tests).
    pub now: Now,
    /// Transition callback.
    pub on_event: OnEvent,
}

impl std::fmt::Debug for LifecycleConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LifecycleConfig")
            .field("renew_at", &self.renew_at)
            .field("jitter", &self.jitter)
            .field("min_backoff", &self.min_backoff)
            .field("max_backoff", &self.max_backoff)
            .finish_non_exhaustive()
    }
}

impl Default for LifecycleConfig {
    fn default() -> Self {
        Self {
            renew_at: 0.5,
            jitter: 0.1,
            min_backoff: Duration::from_secs(1),
            max_backoff: Duration::from_secs(60),
            now: Arc::new(SystemTime::now),
            on_event: Arc::new(|_| {}),
        }
    }
}

impl LifecycleConfig {
    /// Fills out-of-range/zero fields with the defaults (Go `WithDefaults`).
    #[must_use]
    pub fn with_defaults(mut self) -> Self {
        if !(0.3..=0.8).contains(&self.renew_at) {
            self.renew_at = 0.5;
        }
        if self.jitter == 0.0 {
            self.jitter = 0.1;
        }
        if self.min_backoff.is_zero() {
            self.min_backoff = Duration::from_secs(1);
        }
        if self.max_backoff.is_zero() {
            self.max_backoff = Duration::from_secs(60);
        }
        self
    }
}

/// Signed difference `a - b` in nanoseconds.
fn diff_nanos(a: SystemTime, b: SystemTime) -> i128 {
    match a.duration_since(b) {
        Ok(d) => i128::try_from(d.as_nanos()).unwrap_or(i128::MAX),
        Err(e) => -i128::try_from(e.duration().as_nanos()).unwrap_or(i128::MAX),
    }
}

fn add_nanos(t: SystemTime, n: i128) -> SystemTime {
    let d = Duration::from_nanos(u64::try_from(n.unsigned_abs()).unwrap_or(u64::MAX));
    if n >= 0 { t + d } else { t - d }
}

/// The instant at which renewal should start: `renew_at` of the window, with
/// a uniform random spread of ±`jitter` of that point.
pub fn renew_time(not_before: SystemTime, not_after: SystemTime, at: f64, jitter: f64) -> SystemTime {
    #[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]
    let mut point = (diff_nanos(not_after, not_before) as f64 * at) as i128;
    if jitter > 0.0 {
        #[allow(clippy::cast_precision_loss)]
        let spread = point as f64 * jitter;
        let u: f64 = rand::random();
        #[allow(clippy::cast_possible_truncation)]
        let delta = ((u * 2.0 - 1.0) * spread) as i128;
        point += delta;
    }
    add_nanos(not_before, point)
}

struct Shared {
    state: State,
    serial: String,
    bundle_version: u64,
}

/// Drives the identity state machine for one provider.
pub struct Lifecycle {
    p: Arc<dyn Provider>,
    cfg: LifecycleConfig,
    shared: Arc<RwLock<Shared>>,
}

impl std::fmt::Debug for Lifecycle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Lifecycle")
            .field("state", &self.state())
            .finish_non_exhaustive()
    }
}

impl Lifecycle {
    /// A lifecycle for `p`; call [`Lifecycle::start`].
    pub fn new(p: Arc<dyn Provider>, cfg: LifecycleConfig) -> Self {
        Self {
            p,
            cfg: cfg.with_defaults(),
            shared: Arc::new(RwLock::new(Shared {
                state: State::Pending,
                serial: String::new(),
                bundle_version: 0,
            })),
        }
    }

    /// The current state.
    pub fn state(&self) -> State {
        self.shared.read().map_or(State::Pending, |s| s.state)
    }

    /// Subscribes to the provider, adopts the current identity synchronously
    /// (so `state` is meaningful on return) and runs the state machine in
    /// the background until `cancel` fires or the watch closes.
    pub fn start(&self, cancel: CancellationToken) -> Result<(), IdentityError> {
        let rx = self.p.watch()?;
        let mut rt = Runtime {
            p: Arc::clone(&self.p),
            cfg: self.cfg.clone(),
            shared: Arc::clone(&self.shared),
            renew: None,
            expire: None,
            backoff: self.cfg.min_backoff,
        };
        rt.initial();
        tokio::spawn(rt.run(rx, cancel));
        Ok(())
    }
}

struct Runtime {
    p: Arc<dyn Provider>,
    cfg: LifecycleConfig,
    shared: Arc<RwLock<Shared>>,
    renew: Option<Instant>,
    expire: Option<Instant>,
    backoff: Duration,
}

impl Runtime {
    fn set(&self, s: State) {
        if let Ok(mut g) = self.shared.write() {
            g.state = s;
        }
    }

    fn state(&self) -> State {
        self.shared.read().map_or(State::Pending, |s| s.state)
    }

    fn emit(
        &self,
        state: State,
        identity: Option<Svid>,
        bundle: Option<Arc<Bundle>>,
        err: Option<IdentityError>,
    ) {
        (self.cfg.on_event)(LifecycleEvent {
            state,
            identity,
            bundle,
            err,
        });
    }

    fn arm(&mut self, id: &Svid) {
        let now = (self.cfg.now)();
        if now >= id.not_after {
            self.set(State::Expired);
            self.emit(State::Expired, Some(id.clone()), None, None);
            return;
        }
        let remaining = diff_nanos(id.not_after, now);
        let to_dur = |n: i128| Duration::from_nanos(u64::try_from(n.max(0)).unwrap_or(u64::MAX));
        self.expire = Some(Instant::now() + to_dur(remaining));
        if self.p.renewer().is_some() {
            let mut d = diff_nanos(
                renew_time(id.not_before, id.not_after, self.cfg.renew_at, self.cfg.jitter),
                now,
            );
            // Certificates have one-second granularity; never spin on a
            // renewal point that already passed for a fresh identity.
            if d < remaining / 4 {
                d = remaining / 4;
            }
            self.renew = Some(Instant::now() + to_dur(d));
        }
    }

    fn adopt(&mut self, id: Svid, b: Option<Arc<Bundle>>) {
        let (new_serial, new_bundle) = {
            let Ok(mut g) = self.shared.write() else { return };
            let first = g.serial.is_empty();
            let new_serial = id.serial != g.serial;
            let new_bundle = !first && b.as_ref().is_some_and(|b| b.version != g.bundle_version);
            g.serial.clone_from(&id.serial);
            if let Some(b) = &b {
                g.bundle_version = b.version;
            }
            (new_serial, new_bundle)
        };
        if new_bundle {
            self.emit(State::BundleUpdated, Some(id.clone()), b.clone(), None);
        }
        if new_serial || self.state() != State::Valid {
            self.backoff = self.cfg.min_backoff;
            self.set(State::Valid);
            self.emit(State::Valid, Some(id.clone()), b, None);
            self.arm(&id);
        }
    }

    fn initial(&mut self) {
        match self.p.current() {
            Ok((id, b)) => self.adopt(id, Some(b)),
            Err(e) => self.emit(State::RenewFailed, None, None, Some(e)),
        }
    }

    async fn run(mut self, mut rx: mpsc::Receiver<Update>, cancel: CancellationToken) {
        loop {
            let renew = self.renew;
            let expire = self.expire;
            tokio::select! {
                () = cancel.cancelled() => return,
                u = rx.recv() => {
                    let Some(u) = u else { return };
                    if let Some(e) = u.err {
                        self.emit(State::RenewFailed, u.identity, u.bundle, Some(e));
                        continue;
                    }
                    if let Some(id) = u.identity {
                        self.adopt(id, u.bundle);
                    }
                }
                () = sleep_opt(renew) => {
                    self.renew = None;
                    self.set(State::Renewing);
                    self.emit(State::Renewing, None, None, None);
                    let res = match self.p.renewer() {
                        Some(r) => r.renew().await,
                        None => Ok(()),
                    };
                    if let Err(e) = res {
                        self.emit(State::RenewFailed, None, None, Some(e));
                        self.renew = Some(Instant::now() + self.backoff);
                        self.backoff = (self.backoff * 2).min(self.cfg.max_backoff);
                        continue;
                    }
                    // The provider reports the new identity through watch; if
                    // it does not, fall back to reading it directly.
                    if let Ok((id, b)) = self.p.current() {
                        self.adopt(id, Some(b));
                    }
                }
                () = sleep_opt(expire) => {
                    self.expire = None;
                    if let Ok((id, _)) = self.p.current()
                        && (self.cfg.now)() < id.not_after
                    {
                        // A newer identity arrived between the timer and now.
                        continue;
                    }
                    self.set(State::Expired);
                    self.emit(State::Expired, None, None, None);
                }
            }
        }
    }
}

async fn sleep_opt(at: Option<Instant>) {
    match at {
        Some(t) => tokio::time::sleep_until(t).await,
        None => std::future::pending().await,
    }
}

#[cfg(test)]
mod tests;
