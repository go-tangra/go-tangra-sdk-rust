//! Wires the notes module (deployer `internal/app`): configuration ->
//! identity -> the SDK [`App`] -> token verifier, auth registration and
//! gateway lease -> event bus -> the HTTP API, help bundle and UI remote.

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use tangra_sdk::app::{App, ServiceConn, Services};
use tangra_sdk::auth::{self, AuthzClient, Verifier};
use tangra_sdk::events::{Client, Publisher};
use tangra_sdk::gateway;
use tangra_sdk::helpdocs::{self, AllowServices};
use tangra_sdk::identity::Provider;
use tangra_sdk::identity::lcm::{LcmProvider, NetConfig};
use tangra_sdk::log::{Level, Logger, attr};

use crate::api::{self, ApiState};
use crate::config::NotesFile;
#[cfg(feature = "ui")]
use crate::remote;
use crate::store::Store;
use crate::{docs, manifest};

/// A start-up failure (the module never runs degraded).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct BuildError(pub String);

fn fail(ctx: &str) -> impl Fn(&dyn std::fmt::Display) -> BuildError + '_ {
    move |e| BuildError(format!("notes: {ctx}: {e}"))
}

/// Infrastructure overrides (tests).
#[derive(Default)]
pub struct Options {
    /// The logger (default: JSON lines on stderr).
    pub logger: Option<Logger>,
    /// The identity provider; overrides `identity` and `enroll` (tests: an
    /// in-memory SVID).
    pub identity: Option<Arc<dyn Provider>>,
    /// Auth registration cadence `(retry, period)` (default 5s / 5 min).
    pub registration_every: Option<(Duration, Duration)>,
}

/// The wired module.
pub struct Notes {
    /// The SDK runtime.
    pub app: App,
    /// The platform token verifier.
    pub verifier: Arc<Verifier>,
    /// The help bundle digest announced at gateway registration.
    pub docs_digest: String,
    /// Whether this binary serves the UI remote.
    pub serves_ui: bool,
    router: Router,
}

impl std::fmt::Debug for Notes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Notes")
            .field("app", &self.app)
            .finish_non_exhaustive()
    }
}

/// Builds the module from a validated configuration. Binds every listener;
/// the platform loops start once the app is ready.
pub async fn build(cfg: NotesFile, o: Options) -> Result<Notes, BuildError> {
    // The help pages ship in the binary and CI lints them: a bundle that
    // does not load is a broken build.
    let docs = docs::bundle().map_err(|e| fail("help docs")(&e))?;
    let manifest = manifest::manifest().map_err(|e| fail("manifest")(&e))?;
    let registration = manifest::registration();
    let m = &cfg.module;

    let mut b = App::builder(cfg.framework.clone()).logger(
        o.logger
            .unwrap_or_else(|| Logger::new(std::io::stderr(), Level::Info)),
    );
    // Identity: an injected provider (tests); lcm network enrolment
    // (production: `identity.provider: provided` + `enroll.enabled`); else
    // the framework's own `identity` (file for development).
    if let Some(p) = o.identity {
        b = b.identity_provider(p);
    } else if m.enroll.enabled {
        let net = NetConfig::from_config(&cfg.framework, &m.enroll).map_err(|e| fail("enroll")(&e))?;
        let p = LcmProvider::new(net).await.map_err(|e| fail("enroll")(&e))?;
        b = b.identity_provider(p);
    }
    let app = b.build().await.map_err(|e| BuildError(e.0))?;
    let log = app.logger().clone();
    for w in m.warnings() {
        log.warn(
            "insecure configuration override accepted",
            vec![attr("warning", w)],
        );
    }

    // Platform: token verification, auth registration, gateway lease.
    let verifier = app
        .user_auth(auth::Config {
            issuer: m.gateway.issuer.clone(),
            ..auth::Config::default()
        })
        .map_err(|e| BuildError(e.0))?;
    match o.registration_every {
        Some((retry, period)) => {
            registration.validate().map_err(|e| fail("registration")(&e))?;
            app.auth_registration_every(registration, retry, period);
        }
        None => app.auth_registration(registration).map_err(|e| BuildError(e.0))?,
    }
    app.gateway_registration_with(
        &m.gateway.service,
        gateway::Options {
            manifest,
            // The gateway fetches the help bundle when the digest changes.
            docs_digest: docs.digest().to_owned(),
            ..gateway::Options::default()
        },
    )
    .map_err(|e| BuildError(e.0))?;

    // Event bus.
    let events = match (&m.valkey, m.events.enabled) {
        (Some(v), true) => {
            let c = Client::connect(v).await.map_err(|e| fail("event bus")(&e))?;
            Some(Arc::new(Publisher::new(c)))
        }
        _ => None,
    };

    // HTTP: the API, the help bundle for the gateway only, the UI remote.
    let state = ApiState::new(
        Arc::new(Store::new(m.limits_notes.max_notes_per_tenant)),
        events,
        AuthzClient::new(ServiceConn::app(&app, "auth")),
        log.clone(),
        crate::VERSION,
    );
    let docs_digest = docs.digest().to_owned();
    #[cfg_attr(not(feature = "ui"), allow(unused_mut))]
    let mut router = api::router(state, Arc::clone(&verifier)).merge(helpdocs::router(
        docs,
        AllowServices::new([m.gateway.service.clone()]),
    ));
    #[cfg(feature = "ui")]
    let serves_ui = match remote::remote() {
        Some(r) => {
            router = router.merge(tangra_sdk::ui::router(r));
            true
        }
        None => false,
    };
    #[cfg(not(feature = "ui"))]
    let serves_ui = false;
    if !serves_ui {
        log.warn(
            "ui: this binary has no built remote; the portal shows no notes UI",
            vec![],
        );
    }
    Ok(Notes {
        app,
        verifier,
        docs_digest,
        serves_ui,
        router,
    })
}

impl Notes {
    /// Serves until SIGINT/SIGTERM.
    pub async fn run(self) -> Result<(), BuildError> {
        self.app
            .run(Services::new().http(self.router))
            .await
            .map_err(|e| BuildError(e.0))
    }

    /// Serves until `stop` completes.
    pub async fn run_until(self, stop: impl std::future::Future<Output = ()>) -> Result<(), BuildError> {
        self.app
            .run_until(Services::new().http(self.router), stop)
            .await
            .map_err(|e| BuildError(e.0))
    }
}
