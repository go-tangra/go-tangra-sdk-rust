//! The application runtime (go-tangra `freya.go`): validates the config,
//! obtains and checks the identity, runs the identity lifecycle, loads the
//! service policy, binds the mTLS listeners and the admin listener, and
//! serves an axum `Router` (HTTP) and tonic services (gRPC) behind the fixed
//! security chain until SIGINT/SIGTERM.
//!
//! ```no_run
//! # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
//! use tangra_sdk::app::{App, Services};
//! use tangra_sdk::config::{Config, NoModule};
//!
//! let cfg = Config::<NoModule>::load("config.yaml")?;
//! let app = App::builder(cfg.framework).build().await?;
//! app.on_ready(|app, stop| async move {
//!     // gateway / auth registration loops start here
//!     let _ = (app, stop);
//! });
//! let router = axum::Router::new().route("/api/x/v1/ping", axum::routing::get(|| async { "pong" }));
//! app.run(Services::new().http(router)).await?;
//! # Ok(()) }
//! ```

pub(crate) mod chain;
mod client;
mod conn;
pub mod endpoint;
mod platform;
pub(crate) mod serve;

pub use chain::PeerIdentity;
pub use client::{ClientError, PeerChannel};
pub use conn::{GrpcChannel, ServiceConn};
pub use platform::GATEWAY_SERVICE;
pub use serve::ConnInfo;

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime};

use axum::Router;
use axum::body::Body;
use http::Response;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tower::ServiceExt;
use tower::util::BoxCloneSyncService;

use crate::admin::{Admin, Metrics};
use crate::audit::{self, Event, Outcome, Type};
use crate::config::{
    AUTHZ_FILE, AUTHZ_PROVIDED, AUTHZ_VALKEY, FrameworkConfig, PROVIDER_FILE, PROVIDER_PROVIDED,
    PROVIDER_SPIFFE,
};
use crate::identity::lifecycle::{Lifecycle, LifecycleConfig, LifecycleEvent, State};
use crate::identity::{Provider, RevocationChecker};
use crate::log::{Logger, attr};
use crate::policy::{AllowAll, Authorizer, DenyAll, FileSource, PolicySource};
use serve::{HandshakeError, HttpService, Proto, ServeOptions};

/// How long `run` waits for in-flight calls after a stop signal (Kratos
/// `StopTimeout`).
pub const STOP_TIMEOUT: Duration = Duration::from_secs(10);

/// How long `run` waits for the ready hooks after a stop signal (the
/// gateway deregistration has a 5s deadline).
pub const HOOK_STOP_TIMEOUT: Duration = Duration::from_secs(6);

/// A startup failure. Never a degraded app: every security prerequisite
/// must be met.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct AppError(pub String);

fn err(e: impl std::fmt::Display) -> AppError {
    AppError(e.to_string())
}

/// What the transports need from the application (go-tangra `transport.Runtime`).
pub(crate) struct Runtime {
    pub(crate) cfg: FrameworkConfig,
    pub(crate) local_id: String,
    pub(crate) logger: Logger,
    pub(crate) provider: Arc<dyn Provider>,
    authorizer: RwLock<Arc<dyn Authorizer>>,
    policy_ok: AtomicBool,
    lifecycle: Mutex<Option<Arc<Lifecycle>>>,
    pub(crate) metrics: Arc<Metrics>,
    pub(crate) revocation: Option<Arc<dyn RevocationChecker>>,
    pub(crate) sample_allowed: bool,
    closed: AtomicBool,
    pool: client::Pool,
}

impl Runtime {
    pub(crate) fn authorizer(&self) -> Arc<dyn Authorizer> {
        self.authorizer
            .read()
            .map(|a| Arc::clone(&a))
            .unwrap_or_else(|_| Arc::new(DenyAll))
    }

    fn set_authorizer(&self, a: Arc<dyn Authorizer>) {
        if let Ok(mut g) = self.authorizer.write() {
            *g = a;
        }
        self.policy_ok.store(true, Ordering::SeqCst);
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    /// go-tangra `transport.LocalIdentityValid`.
    pub(crate) fn local_identity_valid(&self) -> bool {
        let Ok((id, bundle)) = self.provider.current() else {
            return false;
        };
        if bundle.roots.is_empty() {
            return false;
        }
        let now = SystemTime::now();
        let skew = self.cfg.identity.skew_tolerance.to_std();
        now + skew >= id.not_before && now < id.not_after
    }

    pub(crate) fn tls_options(&self) -> crate::tls::Options {
        let mut o = crate::tls::Options::new(self.cfg.trust_domain.clone());
        o.skew_tolerance = self.cfg.identity.skew_tolerance.to_std();
        o
    }

    fn audit(&self, mut e: Event) {
        e.local_id.clone_from(&self.local_id);
        audit::emit(&self.logger, e);
    }

    fn ready(&self) -> bool {
        if self.is_closed() || !self.policy_ok.load(Ordering::SeqCst) {
            return false;
        }
        if let Some(lc) = self.lifecycle.lock().ok().and_then(|g| g.clone())
            && !matches!(lc.state(), State::Valid | State::Renewing)
        {
            return false;
        }
        let Ok((id, bundle)) = self.provider.current() else {
            return false;
        };
        if bundle.roots.is_empty() {
            return false;
        }
        let now = SystemTime::now();
        now >= id.not_before && now < id.not_after
    }

    fn on_identity_event(self: &Arc<Self>, started: &AtomicBool, e: LifecycleEvent) {
        let rfc = |t: SystemTime| {
            chrono::DateTime::<chrono::Utc>::from(t).to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        };
        let mut attrs = std::collections::BTreeMap::new();
        if let Some(id) = &e.identity {
            attrs.insert("serial".to_owned(), id.serial.clone());
            attrs.insert("not_after".to_owned(), rfc(id.not_after));
        }
        let ev = |kind, outcome, reason: &'static str, attrs: &std::collections::BTreeMap<String, String>| {
            let mut ev = Event::new(kind, outcome, reason, &self.local_id);
            ev.attrs.clone_from(attrs);
            ev
        };
        match e.state {
            State::Valid => {
                if started.swap(true, Ordering::SeqCst) {
                    self.logger.info(
                        "identity renewed",
                        vec![
                            attr("serial", attrs.get("serial").cloned().unwrap_or_default()),
                            attr("not_after", attrs.get("not_after").cloned().unwrap_or_default()),
                        ],
                    );
                    self.metrics.identity_renewal("ok");
                    self.audit(ev(Type::IdentityRenewed, Outcome::Ok, "renewed", &attrs));
                }
            }
            State::Renewing => self.logger.debug("identity renewal started", vec![]),
            State::RenewFailed => {
                let msg = e.err.map(|x| x.0).unwrap_or_default();
                self.logger.error(
                    "identity renewal failed; keeping last-known-good until expiry",
                    vec![attr("err", msg)],
                );
                self.metrics.identity_renewal("failed");
                self.audit(ev(
                    Type::IdentityRenewFailed,
                    Outcome::Failed,
                    "provider_unavailable",
                    &attrs,
                ));
            }
            State::Expired => {
                self.logger.error(
                    "identity expired and no renewal available: refusing all calls until renewed",
                    vec![],
                );
                self.audit(ev(
                    Type::IdentityExpired,
                    Outcome::Failed,
                    "identity_expired",
                    &attrs,
                ));
            }
            State::BundleUpdated => {
                if let Some(b) = &e.bundle {
                    attrs.insert("bundle_version".to_owned(), b.version.to_string());
                    attrs.insert("roots".to_owned(), b.roots.len().to_string());
                }
                self.logger.info(
                    "trust bundle updated",
                    vec![
                        attr(
                            "bundle_version",
                            attrs.get("bundle_version").cloned().unwrap_or_default(),
                        ),
                        attr("roots", attrs.get("roots").cloned().unwrap_or_default()),
                    ],
                );
                self.audit(ev(
                    Type::TrustBundleUpdated,
                    Outcome::Ok,
                    "bundle_updated",
                    &attrs,
                ));
                // Only a root change re-verifies peers: drain the pool.
                self.pool.rotate();
            }
            State::Pending | State::Revoked => {}
        }
    }
}

type HookFn = Box<dyn FnOnce(App, CancellationToken) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send>;

/// Configures [`App`] (go-tangra `freya.Option`s).
pub struct AppBuilder {
    cfg: FrameworkConfig,
    provider: Option<Arc<dyn Provider>>,
    policy: Option<Arc<dyn PolicySource>>,
    allow_all: bool,
    logger: Option<Logger>,
    revocation: Option<Arc<dyn RevocationChecker>>,
}

impl std::fmt::Debug for AppBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppBuilder")
            .field("service", &self.cfg.service_name)
            .finish_non_exhaustive()
    }
}

impl AppBuilder {
    /// Supplies the identity provider (config `identity` is then ignored;
    /// e.g. the lcm enrolment provider).
    #[must_use]
    pub fn identity_provider(mut self, p: Arc<dyn Provider>) -> Self {
        self.provider = Some(p);
        self
    }

    /// Supplies the policy source (config `authz` is then ignored).
    #[must_use]
    pub fn policy_source(mut self, s: Arc<dyn PolicySource>) -> Self {
        self.policy = Some(s);
        self
    }

    /// Permits every authenticated caller (development only; refused in
    /// production, logged and audited).
    #[must_use]
    pub fn allow_all_policy(mut self) -> Self {
        self.allow_all = true;
        self
    }

    /// The logger (default: JSON lines on stderr with `service=<name>`).
    #[must_use]
    pub fn logger(mut self, l: Logger) -> Self {
        self.logger = Some(l);
        self
    }

    /// In-lifetime revocation; a checker error counts as revoked.
    #[must_use]
    pub fn revocation_checker(mut self, c: Arc<dyn RevocationChecker>) -> Self {
        self.revocation = Some(c);
        self
    }

    /// Validates, obtains the identity, loads the policy and binds every
    /// listener. Returns an error, never a degraded app.
    pub async fn build(self) -> Result<App, AppError> {
        let mut cfg = self.cfg;
        if self.provider.is_some() {
            cfg.identity.provider = PROVIDER_PROVIDED.to_owned();
        }
        if self.policy.is_some() || self.allow_all {
            cfg.authz.source = AUTHZ_PROVIDED.to_owned();
        }
        cfg.validate().map_err(err)?;
        if cfg.is_production() && self.allow_all {
            return Err(AppError(
                "freya: WithInsecureLocalDev/WithAllowAllPolicy are refused when env is production".into(),
            ));
        }
        // Go: the handler is wrapped by the redactor and given service=<name>.
        let logger = self
            .logger
            .unwrap_or_else(|| Logger::new(std::io::stderr(), crate::log::Level::Info))
            .with(vec![attr("service", cfg.service_name.as_str())]);
        for w in cfg.warnings() {
            logger.warn(
                "insecure configuration override accepted",
                vec![attr("warning", w)],
            );
        }
        let local_id = cfg.local_spiffe_id();

        // Identity.
        let provider: Arc<dyn Provider> = match self.provider {
            Some(p) => p,
            None => match cfg.identity.provider.as_str() {
                PROVIDER_FILE => {
                    crate::identity::file::FileProvider::new(crate::identity::file::FileConfig {
                        cert: cfg.identity.file.cert.clone().into(),
                        key: cfg.identity.file.key.clone().into(),
                        bundle: cfg.identity.file.bundle.clone().into(),
                        trust_domain: cfg.trust_domain.clone(),
                        poll_interval: Duration::ZERO,
                    })
                    .map_err(err)?
                }
                #[cfg(feature = "spiffe")]
                PROVIDER_SPIFFE => {
                    crate::identity::spiffe::SpiffeProvider::new(crate::identity::spiffe::SpiffeConfig {
                        socket: cfg.identity.workload_socket.clone(),
                        trust_domain: cfg.trust_domain.clone(),
                        startup_timeout: cfg.identity.startup_timeout.to_std(),
                    })
                    .await
                    .map_err(err)?
                }
                other => {
                    return Err(AppError(format!(
                        "freya: identity provider {other:?} is not available: supply one with AppBuilder::identity_provider{}",
                        if other == PROVIDER_SPIFFE {
                            " or enable the `spiffe` feature"
                        } else {
                            ""
                        }
                    )));
                }
            },
        };
        let (id, bundle) = provider
            .current()
            .map_err(|e| AppError(format!("freya: identity unavailable: {e}")))?;
        if id.id.service_name() != cfg.service_name || id.id.trust_domain() != cfg.trust_domain {
            return Err(AppError(format!(
                "freya: identity {} does not match configured service {local_id}",
                id.id
            )));
        }
        if bundle.roots.is_empty() {
            return Err(AppError("freya: trust bundle is empty".into()));
        }
        let rfc = |t: SystemTime| {
            chrono::DateTime::<chrono::Utc>::from(t).to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        };
        logger.info(
            "identity ready",
            vec![
                attr("id", id.id.to_string()),
                attr("not_after", rfc(id.not_after)),
                attr("serial", id.serial.as_str()),
            ],
        );
        let mut issued = Event::new(Type::IdentityIssued, Outcome::Ok, "issued", &local_id);
        issued.attrs.insert("serial".into(), id.serial.clone());
        issued.attrs.insert("not_after".into(), rfc(id.not_after));
        audit::emit(&logger, issued);

        if !cfg.discovery.r#static.is_empty() {
            client::validate_static(&cfg.discovery.r#static).map_err(err)?;
        }
        let discovery = (!cfg.discovery.r#static.is_empty()).then(|| cfg.discovery.r#static.clone());
        let rt = Arc::new(Runtime {
            local_id: local_id.clone(),
            logger: logger.clone(),
            provider: Arc::clone(&provider),
            authorizer: RwLock::new(Arc::new(DenyAll)),
            policy_ok: AtomicBool::new(false),
            lifecycle: Mutex::new(None),
            metrics: Metrics::new(),
            revocation: self.revocation,
            sample_allowed: cfg.authz.sample_allowed,
            closed: AtomicBool::new(false),
            pool: client::Pool::new(discovery),
            cfg,
        });
        let stop = CancellationToken::new();

        // Identity lifecycle.
        let started = Arc::new(AtomicBool::new(false));
        let rt_ev = Arc::clone(&rt);
        let st = Arc::clone(&started);
        let lc = Arc::new(Lifecycle::new(
            Arc::clone(&provider),
            LifecycleConfig {
                renew_at: rt.cfg.identity.renew_at,
                on_event: Arc::new(move |e| rt_ev.on_identity_event(&st, e)),
                ..LifecycleConfig::default()
            },
        ));
        lc.start(stop.child_token())
            .map_err(|e| AppError(format!("freya: identity lifecycle: {e}")))?;
        if let Ok(mut g) = rt.lifecycle.lock() {
            *g = Some(lc);
        }

        // Policy.
        let policy_source: Option<Arc<dyn PolicySource>> = if self.allow_all {
            rt.set_authorizer(Arc::new(AllowAll));
            logger.warn(
                "allow-all authorization policy in use: every authenticated caller is permitted",
                vec![],
            );
            rt.audit(Event::new(
                Type::InsecureModeEnabled,
                Outcome::Ok,
                "allow_all",
                &local_id,
            ));
            None
        } else if let Some(s) = self.policy {
            Some(s)
        } else {
            match rt.cfg.authz.source.as_str() {
                AUTHZ_FILE => Some(Arc::new(
                    FileSource::new(&rt.cfg.authz.path, Duration::ZERO).map_err(|e| {
                        rt.audit(Event::new(
                            Type::PolicyLoadFailed,
                            Outcome::Failed,
                            "policy_invalid",
                            &local_id,
                        ));
                        AppError(format!("freya: policy: {e}"))
                    })?,
                )),
                AUTHZ_VALKEY => {
                    return Err(AppError(
                        "authz: valkey source is provided by contrib/policy-valkey; pass it with AppBuilder::policy_source"
                            .into(),
                    ));
                }
                other => return Err(AppError(format!("authz: unsupported policy source {other:?}"))),
            }
        };
        if let Some(src) = &policy_source {
            start_policy(&rt, Arc::clone(src), stop.child_token())?;
        }

        // Listeners.
        let grpc = if rt.cfg.server.grpc_addr.is_empty() {
            None
        } else {
            Some(
                crate::admin::bind_addr(&rt.cfg.server.grpc_addr)
                    .await
                    .map_err(|e| AppError(format!("freya: bind: {e}")))?,
            )
        };
        let http = if rt.cfg.server.http_addr.is_empty() {
            None
        } else {
            Some(
                crate::admin::bind_addr(&rt.cfg.server.http_addr)
                    .await
                    .map_err(|e| AppError(format!("freya: bind: {e}")))?,
            )
        };
        let server_tls = crate::tls::server_config(Arc::clone(&provider), rt.tls_options()).map_err(err)?;
        let rt_ready = Arc::clone(&rt);
        let admin = Admin::bind(
            &rt.cfg.admin,
            Arc::new(move || rt_ready.ready()),
            Arc::clone(&rt.metrics),
            &logger,
            Some(Arc::clone(&server_tls)),
        )
        .await
        .map_err(|e| AppError(format!("freya: admin listener: {e}")))?;
        let grpc_addr = grpc.as_ref().and_then(|l| l.local_addr().ok());
        let http_addr = http.as_ref().and_then(|l| l.local_addr().ok());
        let admin_url = admin.url();
        Ok(App {
            inner: Arc::new(AppInner {
                rt,
                stop,
                server_tls,
                listeners: Mutex::new(Some(Listeners { grpc, http, admin })),
                grpc_addr,
                http_addr,
                admin_url,
                hooks: Mutex::new(Vec::new()),
                policy_source,
            }),
        })
    }
}

fn start_policy(
    rt: &Arc<Runtime>,
    src: Arc<dyn PolicySource>,
    stop: CancellationToken,
) -> Result<(), AppError> {
    let pol = src.load().map_err(|e| {
        rt.audit(Event::new(
            Type::PolicyLoadFailed,
            Outcome::Failed,
            "policy_invalid",
            &rt.local_id,
        ));
        AppError(format!("freya: policy: {e}"))
    })?;
    rt.set_authorizer(Arc::clone(&pol) as Arc<dyn Authorizer>);
    let mut loaded = Event::new(Type::PolicyLoaded, Outcome::Ok, "loaded", &rt.local_id);
    loaded.policy_version.clone_from(&pol.version);
    rt.audit(loaded);
    rt.logger.info(
        "policy loaded",
        vec![
            attr("version", pol.version.as_str()),
            attr("rules", pol.rules.len()),
        ],
    );
    if pol.rules.is_empty() {
        rt.logger.warn(
            "policy has no rules: every call will be denied (deny by default)",
            vec![],
        );
    }
    let (mut ch, mut errs) = src
        .watch()
        .map_err(|e| AppError(format!("freya: policy watch: {e}")))?;
    let rt = Arc::clone(rt);
    tokio::spawn(async move {
        loop {
            tokio::select! {
                () = stop.cancelled() => return,
                p = ch.recv() => {
                    let Some(p) = p else { return };
                    rt.set_authorizer(Arc::clone(&p) as Arc<dyn Authorizer>);
                    let mut e = Event::new(Type::PolicyLoaded, Outcome::Ok, "loaded", &rt.local_id);
                    e.policy_version.clone_from(&p.version);
                    rt.audit(e);
                    rt.logger.info("policy reloaded", vec![attr("version", p.version.as_str()), attr("rules", p.rules.len())]);
                }
                e = errs.recv() => {
                    let Some(e) = e else { continue };
                    rt.audit(Event::new(Type::PolicyLoadFailed, Outcome::Failed, "policy_invalid", &rt.local_id));
                    rt.logger.error("policy reload failed; keeping last-known-good", vec![attr("err", e.0)]);
                }
            }
        }
    });
    Ok(())
}

struct Listeners {
    grpc: Option<TcpListener>,
    http: Option<TcpListener>,
    admin: Admin,
}

struct AppInner {
    rt: Arc<Runtime>,
    stop: CancellationToken,
    server_tls: Arc<rustls::ServerConfig>,
    listeners: Mutex<Option<Listeners>>,
    grpc_addr: Option<SocketAddr>,
    http_addr: Option<SocketAddr>,
    admin_url: String,
    hooks: Mutex<Vec<HookFn>>,
    policy_source: Option<Arc<dyn PolicySource>>,
}

/// A configured application. Clone it freely (handles share state).
#[derive(Clone)]
pub struct App {
    inner: Arc<AppInner>,
}

impl std::fmt::Debug for App {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("App")
            .field("service", &self.inner.rt.cfg.service_name)
            .finish_non_exhaustive()
    }
}

/// The application's services: an axum router (HTTP listener) and tonic
/// services (gRPC listener).
#[derive(Default)]
pub struct Services {
    http: Option<Router>,
    grpc: Option<tonic::service::Routes>,
}

impl std::fmt::Debug for Services {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Services")
            .field("http", &self.http.is_some())
            .field("grpc", &self.grpc.is_some())
            .finish()
    }
}

impl Services {
    /// No services.
    pub fn new() -> Self {
        Self::default()
    }

    /// The HTTP router. Unmatched paths answer net/http's `404 page not
    /// found`, wrong methods `405 method not allowed` (as the go-tangra HTTP
    /// server); install your own fallbacks on the router to change that.
    #[must_use]
    pub fn http(mut self, r: Router) -> Self {
        self.http = Some(r);
        self
    }

    /// The gRPC services (`tonic::service::Routes::new(FooServer::new(..))
    /// .add_service(...)`). Set each generated server's
    /// `max_decoding_message_size` to `limits.max_request_bytes` to mirror
    /// grpc-go's `MaxRecvMsgSize`.
    #[must_use]
    pub fn grpc(mut self, r: tonic::service::Routes) -> Self {
        self.grpc = Some(r);
        self
    }
}

fn http_service(r: Router, max_body: usize) -> HttpService {
    let r = r
        .method_not_allowed_fallback(|| async {
            let mut resp = Response::new(Body::from("405 method not allowed\n"));
            *resp.status_mut() = http::StatusCode::METHOD_NOT_ALLOWED;
            resp.headers_mut().insert(
                http::header::CONTENT_TYPE,
                http::HeaderValue::from_static("text/plain; charset=utf-8"),
            );
            resp.headers_mut().insert(
                "x-content-type-options",
                http::HeaderValue::from_static("nosniff"),
            );
            resp
        })
        .fallback(|| async { crate::admin::not_found() })
        .layer(axum::extract::DefaultBodyLimit::max(max_body));
    BoxCloneSyncService::new(r.into_service::<Body>())
}

fn grpc_service(r: tonic::service::Routes) -> HttpService {
    BoxCloneSyncService::new(ServiceExt::<http::Request<Body>>::map_response(
        r,
        |resp: Response<tonic::body::Body>| resp.map(Body::new),
    ))
}

impl App {
    /// Starts configuring an app for `cfg`.
    pub fn builder(cfg: FrameworkConfig) -> AppBuilder {
        AppBuilder {
            cfg,
            provider: None,
            policy: None,
            allow_all: false,
            logger: None,
            revocation: None,
        }
    }

    /// The validated framework configuration.
    pub fn config(&self) -> &FrameworkConfig {
        &self.inner.rt.cfg
    }

    /// The logger (JSON lines, redacting, `service` attribute).
    pub fn logger(&self) -> &Logger {
        &self.inner.rt.logger
    }

    /// The metrics registry (add module counters next to `freya_*`).
    pub fn metrics(&self) -> Arc<Metrics> {
        Arc::clone(&self.inner.rt.metrics)
    }

    /// The identity provider.
    pub fn provider(&self) -> Arc<dyn Provider> {
        Arc::clone(&self.inner.rt.provider)
    }

    /// The current local identity (no key material).
    pub fn identity(&self) -> Option<crate::identity::Svid> {
        self.inner.rt.provider.current().ok().map(|(i, _)| i)
    }

    /// The lifecycle state (`valid`, `renewing`, `expired`, ...).
    pub fn identity_state(&self) -> State {
        self.inner
            .rt
            .lifecycle
            .lock()
            .ok()
            .and_then(|g| g.as_ref().map(|l| l.state()))
            .unwrap_or(State::Pending)
    }

    /// Identity valid (or renewing), trust bundle non-empty and a policy
    /// loaded (go-tangra `App.Ready`).
    pub fn ready(&self) -> bool {
        self.inner.rt.ready()
    }

    /// The pooled, mutually authenticated channel to `service` (discovered
    /// via `discovery.static`, verified as `spiffe://<td>/svc/<service>`).
    pub fn client(&self, service: &str) -> Result<PeerChannel, ClientError> {
        self.inner.rt.pool.client(&self.inner.rt, service)
    }

    /// The mTLS server configuration (for extra listeners).
    pub fn server_tls(&self) -> Arc<rustls::ServerConfig> {
        Arc::clone(&self.inner.server_tls)
    }

    /// The bound gRPC address.
    pub fn grpc_local_addr(&self) -> Option<SocketAddr> {
        self.inner.grpc_addr
    }

    /// The bound HTTP address.
    pub fn http_local_addr(&self) -> Option<SocketAddr> {
        self.inner.http_addr
    }

    /// The advertised HTTP backend URL (`https://host:port`; honours
    /// `FREYA_ADVERTISE_HOST`).
    pub fn http_url(&self) -> Option<String> {
        self.inner.http_addr.map(|a| {
            format!(
                "https://{}",
                endpoint::resolve_endpoint(&self.inner.rt.cfg.server.http_addr, a)
            )
        })
    }

    /// The advertised gRPC target (`host:port`).
    pub fn grpc_target(&self) -> Option<String> {
        self.inner
            .grpc_addr
            .map(|a| endpoint::extract_endpoint(&self.inner.rt.cfg.server.grpc_addr, a))
    }

    /// The admin listener base URL.
    pub fn admin_url(&self) -> &str {
        &self.inner.admin_url
    }

    /// Registers a background task that starts once the app is ready
    /// (gateway registration, auth permission registration). The token is
    /// cancelled on shutdown.
    pub fn on_ready<F, Fut>(&self, f: F)
    where
        F: FnOnce(App, CancellationToken) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        if let Ok(mut h) = self.inner.hooks.lock() {
            h.push(Box::new(move |app, tok| Box::pin(f(app, tok))));
        }
    }

    /// Serves until SIGINT or SIGTERM.
    pub async fn run(&self, services: Services) -> Result<(), AppError> {
        self.run_until(services, shutdown_signal()).await
    }

    /// Serves until `stop` completes, then shuts down gracefully (in-flight
    /// calls get [`STOP_TIMEOUT`], the admin listener 5s).
    pub async fn run_until(
        &self,
        services: Services,
        stop: impl Future<Output = ()>,
    ) -> Result<(), AppError> {
        let lis = self
            .inner
            .listeners
            .lock()
            .ok()
            .and_then(|mut g| g.take())
            .ok_or_else(|| AppError("freya: app already running".into()))?;
        let rt = Arc::clone(&self.inner.rt);
        let shutdown = CancellationToken::new();
        let force = CancellationToken::new();
        let tracker = TaskTracker::new();
        let limits = &rt.cfg.limits;
        let opts = |proto| ServeOptions {
            proto,
            handshake_timeout: limits.handshake_timeout.to_std(),
            idle_timeout: limits.idle_timeout.to_std(),
            max_connection_age: Some(limits.max_connection_age.to_std()),
            age_grace: limits.request_timeout.to_std(),
            max_concurrent_streams: limits.max_concurrent_streams,
            max_header_bytes: u32::try_from(limits.max_header_bytes.clamp(1, 1 << 20)).unwrap_or(8 << 10),
        };
        let rt_hs = Arc::clone(&rt);
        let on_err: serve::OnHandshakeError = Arc::new(move |e, remote| audit_handshake(&rt_hs, e, remote));
        let mut servers = Vec::new();
        if let Some(l) = lis.grpc {
            let inner = services
                .grpc
                .map_or_else(|| grpc_service(tonic::service::Routes::default()), grpc_service);
            let svc = BoxCloneSyncService::new(chain::Secure {
                rt: Arc::clone(&rt),
                inner,
                flavor: chain::Flavor::Grpc,
            });
            servers.push(tokio::spawn(serve::serve_tls(
                l,
                Some(Arc::clone(&self.inner.server_tls)),
                svc,
                opts(Proto::Grpc),
                Arc::clone(&on_err),
                shutdown.clone(),
                force.clone(),
                tracker.clone(),
            )));
        }
        if let Some(l) = lis.http {
            let max_body = usize::try_from(limits.max_request_bytes).unwrap_or(usize::MAX);
            let inner = http_service(services.http.unwrap_or_default(), max_body);
            let svc = BoxCloneSyncService::new(chain::Secure {
                rt: Arc::clone(&rt),
                inner,
                flavor: chain::Flavor::Http,
            });
            servers.push(tokio::spawn(serve::serve_tls(
                l,
                Some(Arc::clone(&self.inner.server_tls)),
                svc,
                opts(Proto::Http),
                Arc::clone(&on_err),
                shutdown.clone(),
                force.clone(),
                tracker.clone(),
            )));
        }
        let admin_stop = CancellationToken::new();
        let admin = tokio::spawn(lis.admin.serve(admin_stop.clone()));

        // Ready hooks.
        let hooks: Vec<HookFn> = self
            .inner
            .hooks
            .lock()
            .map(|mut h| std::mem::take(&mut *h))
            .unwrap_or_default();
        let app = self.clone();
        let hook_stop = self.inner.stop.child_token();
        // Ready hooks are awaited on shutdown (bounded) so a gateway lease is
        // withdrawn before the pool closes.
        let hook_tracker = TaskTracker::new();
        let ht = hook_tracker.clone();
        let hook_task = tokio::spawn(async move {
            while !app.ready() {
                tokio::select! {
                    () = hook_stop.cancelled() => return,
                    () = tokio::time::sleep(Duration::from_millis(100)) => {}
                }
            }
            for h in hooks {
                ht.spawn(h(app.clone(), hook_stop.clone()));
            }
        });

        stop.await;
        self.inner.rt.logger.info("shutting down", vec![]);
        self.inner.stop.cancel();
        hook_task.abort();
        let _ = hook_task.await;
        hook_tracker.close();
        let hooks_done = tokio::spawn(async move {
            let _ = tokio::time::timeout(HOOK_STOP_TIMEOUT, hook_tracker.wait()).await;
        });
        shutdown.cancel();
        for s in servers {
            let _ = s.await;
        }
        tracker.close();
        if tokio::time::timeout(STOP_TIMEOUT, tracker.wait()).await.is_err() {
            force.cancel();
        }
        admin_stop.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(6), admin).await;
        let _ = hooks_done.await;
        self.close().await;
        Ok(())
    }

    /// Releases the provider, the policy source and the client pool.
    pub async fn close(&self) {
        if self.inner.rt.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        self.inner.stop.cancel();
        self.inner.rt.pool.rotate();
        if let Some(s) = &self.inner.policy_source {
            s.close();
        }
        self.inner.rt.provider.close().await;
    }
}

/// go-tangra `transport.AuditHandshakeRefusal`.
fn audit_handshake(rt: &Arc<Runtime>, e: HandshakeError, remote: SocketAddr) {
    let short = || {
        let b: [u8; 8] = rand::random();
        b.iter().map(|x| format!("{x:02x}")).collect::<String>()
    };
    match e {
        HandshakeError::Timeout => {
            let mut ev = Event::new(
                Type::LimitExceeded,
                Outcome::Refused,
                "limit_exceeded",
                &rt.local_id,
            );
            ev.operation = "tls handshake".into();
            ev.remote_addr = remote.to_string();
            ev.attrs.insert("limit".into(), "handshake_timeout".into());
            rt.audit(ev);
        }
        HandshakeError::Tls(io) => {
            let reason = crate::tls::classify(&io);
            let mut claimed = String::new();
            let mut detail = String::new();
            if let Some(re) = io.get_ref().and_then(|e| e.downcast_ref::<rustls::Error>())
                && let Some(ve) = crate::tls::verify_error(re)
            {
                claimed.clone_from(&ve.claimed);
                detail.clone_from(&ve.detail);
            }
            let kind = if reason == crate::identity::Reason::Downgrade {
                Type::ChannelRefusedDowngrade
            } else {
                Type::AuthnRefused
            };
            let mut ev = Event::new(kind, Outcome::Refused, reason.as_str(), &rt.local_id);
            ev.claimed_peer_id = claimed;
            ev.remote_addr = remote.to_string();
            ev.correlation_id = format!("handshake-{}", short());
            if !detail.is_empty() {
                ev.attrs.insert("detail".into(), detail);
            }
            rt.audit(ev);
        }
    }
}

/// Resolves on SIGINT or SIGTERM.
pub async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => {}
        () = term => {}
    }
}
