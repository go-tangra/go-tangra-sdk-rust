//! The offline token verifier (auth `sdk/pkg/authclient/verify.go` at
//! `sdk/v4.3.0`): cached keys, the revocation feed, failing closed when the
//! feed is stale.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime};

use tokio::time::{Instant, MissedTickBehavior};
use tokio_util::sync::CancellationToken;

use super::token::{MAX_SKEW, MAX_TOKEN_LIFETIME, TokenError, verify_token};

/// A key-source, revocation-feed or registration failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct AuthError(pub String);

/// A raw Ed25519 public key (32 bytes).
pub type PublicKey = Vec<u8>;

/// Fetches the current verification keys (authclient `KeySource`).
#[async_trait::async_trait]
pub trait KeySource: Send + Sync {
    /// kid → key.
    async fn keys(&self) -> Result<HashMap<String, PublicKey>, AuthError>;
}

/// One revocation feed entry.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Revocation {
    /// When it was revoked (nanoseconds since the Unix epoch).
    pub ts_unix_nanos: i128,
    /// `session`, `user` or `tenant`.
    pub kind: String,
    /// The revoked session, user or tenant id.
    pub subject_id: String,
    /// The tenant (user revocations; empty = every tenant).
    pub tenant_id: String,
    /// Why (closed vocabulary).
    pub reason: String,
}

impl Revocation {
    /// Go `time.Time.Unix()` (seconds, rounded down).
    fn unix(&self) -> i128 {
        self.ts_unix_nanos.div_euclid(1_000_000_000)
    }
}

/// Pages the revocation feed from a cursor ("" = the retention window).
#[async_trait::async_trait]
pub trait RevocationSource: Send + Sync {
    /// Entries after `cursor` and the next cursor.
    async fn since(&self, cursor: &str) -> Result<(Vec<Revocation>, String), AuthError>;
}

/// Verifier tuning (authclient `Config`).
#[derive(Debug, Clone, Default)]
pub struct Config {
    /// The expected `iss` (config `gateway.issuer`).
    pub issuer: String,
    /// Optional expected `aud`.
    pub audience: String,
    /// Optional: only tokens of this tenant.
    pub tenant_id: String,
    /// Clock skew (≤ 60s; zero means 60s).
    pub skew: Duration,
    /// Key refresh period (default 5m).
    pub key_refresh: Duration,
    /// Minimum gap between unknown-kid refreshes (default 1m).
    pub unknown_kid_cap: Duration,
    /// Revocation feed poll period (default 5s).
    pub revocation_poll: Duration,
    /// Fail closed when the feed is older than this (default 60m).
    pub max_stale: Duration,
    /// Feed window kept in memory (default 60m).
    pub retention: Duration,
}

/// A verified end user (authclient `Identity`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct User {
    /// `sub`.
    pub user_id: String,
    /// `tid`.
    pub tenant_id: String,
    /// `sid`.
    pub session_id: String,
    /// Tenant roles (`owner`, `admin`, `member`, ...).
    pub roles: Vec<String>,
    /// Authentication methods.
    pub amr: Vec<String>,
    /// The first `aud` ("" when none).
    pub audience: String,
    /// `iat` (unix seconds).
    pub issued_at: i64,
    /// `exp` (unix seconds).
    pub expires_at: i64,
    /// `jti`.
    pub jti: String,
}

/// The Go name.
pub type Identity = User;

impl User {
    /// Holds `role` exactly.
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.iter().any(|r| r == role)
    }

    /// Holds the tenant `admin` role (deployer `internal/authz`
    /// `Subjects.IsAdmin`).
    pub fn is_admin(&self) -> bool {
        self.has_role("admin")
    }
}

/// Why verification failed (authclient error values).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VerifyError {
    /// `ErrUnauthenticated` joined with the cause.
    #[error("authclient: unauthenticated\n{0}")]
    Unauthenticated(String),
    /// `ErrRevoked`.
    #[error("authclient: token revoked")]
    Revoked,
    /// `ErrStale`.
    #[error("authclient: revocation feed stale; failing closed")]
    Stale,
    /// `ErrWrongTenant`.
    #[error("authclient: token belongs to another tenant")]
    WrongTenant,
}

/// Reported for background refresh failures.
pub type OnError = Arc<dyn Fn(&AuthError) + Send + Sync>;

type Clock = Arc<dyn Fn() -> SystemTime + Send + Sync>;

#[derive(Default)]
pub(super) struct St {
    key_set: HashMap<String, PublicKey>,
    keys_at: Option<SystemTime>,
    last_unknown: Option<SystemTime>,
    pub(super) entries: Vec<Revocation>,
    pub(super) cursor: String,
    rev_synced_at: Option<SystemTime>,
}

/// Verifies tokens with cached keys and the revocation feed.
pub struct Verifier {
    cfg: Config,
    keys: Arc<dyn KeySource>,
    revs: Option<Arc<dyn RevocationSource>>,
    now: RwLock<Clock>,
    st: Mutex<St>,
}

impl std::fmt::Debug for Verifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Verifier")
            .field("cfg", &self.cfg)
            .finish_non_exhaustive()
    }
}

fn nanos(t: SystemTime) -> i128 {
    match t.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(d) => i128::try_from(d.as_nanos()).unwrap_or(i128::MAX),
        Err(e) => -i128::try_from(e.duration().as_nanos()).unwrap_or(i128::MAX),
    }
}

fn since(now: SystemTime, then: SystemTime) -> Duration {
    now.duration_since(then).unwrap_or(Duration::ZERO)
}

impl Verifier {
    /// Builds a verifier; `revs` may be `None` (no revocation checks — only
    /// for callers that accept a full token lifetime of latency).
    pub fn new(mut cfg: Config, keys: Arc<dyn KeySource>, revs: Option<Arc<dyn RevocationSource>>) -> Self {
        if cfg.skew.is_zero() || cfg.skew > MAX_SKEW {
            cfg.skew = MAX_SKEW;
        }
        let def = |d: &mut Duration, v: Duration| {
            if d.is_zero() {
                *d = v;
            }
        };
        def(&mut cfg.key_refresh, Duration::from_secs(5 * 60));
        def(&mut cfg.unknown_kid_cap, Duration::from_secs(60));
        def(&mut cfg.revocation_poll, Duration::from_secs(5));
        def(&mut cfg.max_stale, Duration::from_secs(60 * 60));
        def(&mut cfg.retention, Duration::from_secs(60 * 60));
        Self {
            cfg,
            keys,
            revs,
            now: RwLock::new(Arc::new(SystemTime::now)),
            st: Mutex::new(St::default()),
        }
    }

    /// The effective configuration (defaults applied).
    pub fn config(&self) -> &Config {
        &self.cfg
    }

    /// Overrides the clock (tests simulate expiry; authclient `SetClock`).
    pub fn set_clock(&self, now: impl Fn() -> SystemTime + Send + Sync + 'static) {
        if let Ok(mut g) = self.now.write() {
            *g = Arc::new(now);
        }
    }

    fn now(&self) -> SystemTime {
        self.now.read().map_or_else(|_| SystemTime::now(), |f| f())
    }

    pub(super) fn st(&self) -> std::sync::MutexGuard<'_, St> {
        self.st.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// When the key set was last fetched.
    pub fn keys_fetched_at(&self) -> Option<SystemTime> {
        self.st().keys_at
    }

    /// Fetches the key set now.
    pub async fn refresh_keys(&self) -> Result<(), AuthError> {
        let set = self.keys.keys().await?;
        let now = self.now();
        let mut st = self.st();
        st.key_set = set;
        st.keys_at = Some(now);
        Ok(())
    }

    /// Pulls the feed once: the first sync loads the whole retention
    /// window, later syncs continue from the cursor (at most 100 pages).
    pub async fn sync_revocations(&self) -> Result<(), AuthError> {
        let Some(revs) = &self.revs else {
            return Ok(());
        };
        let mut cursor = self.st().cursor.clone();
        for _ in 0..100 {
            let (entries, next) = revs.since(&cursor).await?;
            let n = entries.len();
            {
                let now = self.now();
                let mut st = self.st();
                st.entries.extend(entries);
                st.cursor.clone_from(&next);
                let cut = nanos(now) - i128::try_from(self.cfg.retention.as_nanos()).unwrap_or(0);
                st.entries.retain(|e| e.ts_unix_nanos > cut);
            }
            if next == cursor || n == 0 {
                break;
            }
            cursor = next;
        }
        let now = self.now();
        self.st().rev_synced_at = Some(now);
        Ok(())
    }

    /// Runs key refresh and feed polling until `stop` is cancelled. Returns
    /// after the first attempt of each so callers can fail fast on
    /// misconfiguration (authclient `Start`).
    pub async fn start(
        self: &Arc<Self>,
        stop: CancellationToken,
        on_error: Option<OnError>,
    ) -> Result<(), AuthError> {
        self.refresh_keys().await?;
        self.sync_revocations().await?;
        let v = Arc::clone(self);
        spawn_loop(stop.clone(), self.cfg.key_refresh, on_error.clone(), move || {
            let v = Arc::clone(&v);
            async move { v.refresh_keys().await }
        });
        if self.revs.is_some() {
            let v = Arc::clone(self);
            spawn_loop(stop, self.cfg.revocation_poll, on_error, move || {
                let v = Arc::clone(&v);
                async move { v.sync_revocations().await }
            });
        }
        Ok(())
    }

    fn lookup(&self, kid: &str) -> Option<PublicKey> {
        self.st().key_set.get(kid).cloned()
    }

    fn verify_once(&self) -> impl Fn(&str) -> Result<super::Claims, TokenError> + '_ {
        move |token| {
            verify_token(
                token,
                &self.cfg.issuer,
                self.cfg.skew,
                MAX_TOKEN_LIFETIME,
                self.now(),
                |kid| self.lookup(kid),
            )
        }
    }

    /// Checks a bearer token and returns the user it proves.
    pub async fn verify(&self, token: &str) -> Result<User, VerifyError> {
        let mut res = (self.verify_once())(token);
        if matches!(res, Err(TokenError::UnknownKey(_))) {
            // Rotation may have happened: refresh at most once per cap.
            let allowed = {
                let now = self.now();
                let mut st = self.st();
                let ok = st
                    .last_unknown
                    .is_none_or(|t| since(now, t) >= self.cfg.unknown_kid_cap);
                if ok {
                    st.last_unknown = Some(now);
                }
                ok
            };
            if allowed && self.refresh_keys().await.is_ok() {
                res = (self.verify_once())(token);
            }
        }
        let c = res.map_err(|e| VerifyError::Unauthenticated(e.to_string()))?;
        if !self.cfg.audience.is_empty() && !c.audience.contains(&self.cfg.audience) {
            return Err(VerifyError::Unauthenticated("audience mismatch".into()));
        }
        if !self.cfg.tenant_id.is_empty() && c.tenant_id != self.cfg.tenant_id {
            return Err(VerifyError::WrongTenant);
        }
        if self.revs.is_some() {
            let now = self.now();
            let synced = self.st().rev_synced_at;
            match synced {
                Some(at) if since(now, at) <= self.cfg.max_stale => {}
                _ => return Err(VerifyError::Stale),
            }
            if self.revoked(&c) {
                return Err(VerifyError::Revoked);
            }
        }
        Ok(User {
            audience: c.audience.first().cloned().unwrap_or_default(),
            user_id: c.subject,
            tenant_id: c.tenant_id,
            session_id: c.session_id,
            roles: c.roles.unwrap_or_default(),
            amr: c.amr.unwrap_or_default(),
            issued_at: c.issued_at.unwrap_or_default(),
            expires_at: c.expires_at.unwrap_or_default(),
            jti: c.id,
        })
    }

    /// The contract rule: an entry for the session, user or tenant with
    /// `ts ≥ iat` (second granularity) invalidates the token.
    fn revoked(&self, c: &super::Claims) -> bool {
        let iat = i128::from(c.issued_at.unwrap_or_default());
        self.st().entries.iter().any(|e| {
            if e.unix() < iat {
                return false;
            }
            match e.kind.as_str() {
                "session" => e.subject_id == c.session_id,
                "user" => e.subject_id == c.subject && (e.tenant_id.is_empty() || e.tenant_id == c.tenant_id),
                "tenant" => e.subject_id == c.tenant_id,
                _ => false,
            }
        })
    }
}

/// A Go `time.Ticker` loop: first run after `every`, missed ticks skipped.
fn spawn_loop<F, Fut>(stop: CancellationToken, every: Duration, on_error: Option<OnError>, f: F)
where
    F: Fn() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Result<(), AuthError>> + Send,
{
    tokio::spawn(async move {
        let mut t = tokio::time::interval_at(Instant::now() + every, every);
        t.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                () = stop.cancelled() => return,
                _ = t.tick() => {
                    if let Err(e) = f().await
                        && let Some(cb) = &on_error
                    {
                        cb(&e);
                    }
                }
            }
        }
    });
}

/// A fixed key set (tests and pinned deployments; authclient `StaticKeys`).
#[derive(Debug, Clone, Default)]
pub struct StaticKeys(pub HashMap<String, PublicKey>);

#[async_trait::async_trait]
impl KeySource for StaticKeys {
    async fn keys(&self) -> Result<HashMap<String, PublicKey>, AuthError> {
        Ok(self.0.clone())
    }
}
