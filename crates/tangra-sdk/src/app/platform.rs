//! Platform wiring on [`App`]: end-user token verification, auth
//! registration and gateway registration, started and stopped with the app
//! the way the deployer does it (`internal/app/app.go` `Run`/`register`,
//! `internal/app/permissions.go`).

use std::sync::Arc;
use std::time::Duration;

use super::{App, AppError, ServiceConn};
use crate::auth::{self, GrpcKeys, GrpcRevocations, Registration, Verifier};
use crate::gateway::{self, State};
use crate::log::attr;
use crate::manifest::Manifest;

/// The gateway's service name (deployer config `gateway.service` default).
pub const GATEWAY_SERVICE: &str = "gateway";
/// The auth service name.
const AUTH_SERVICE: &str = "auth";
/// Retry gap for the verifier start and the gateway channel (deployer).
const RETRY: Duration = Duration::from_secs(2);

impl App {
    /// A token verifier fed by `auth.v1.Keys/List` and
    /// `auth.v1.Sessions/RevokedSince` over this app's mTLS channel to
    /// `auth`. Its key refresh and feed polling start now, retried every 2s
    /// until the first fetch succeeds, and stop with the app (deployer
    /// `Run`). Until then every token is refused.
    ///
    /// Must be called inside a Tokio runtime.
    pub fn user_auth(&self, cfg: auth::Config) -> Result<Arc<Verifier>, AppError> {
        let handle =
            tokio::runtime::Handle::try_current().map_err(|e| AppError(format!("user_auth: {e}")))?;
        let conn = ServiceConn::app(self, AUTH_SERVICE);
        let v = Arc::new(Verifier::new(
            cfg,
            Arc::new(GrpcKeys { conn: conn.clone() }),
            Some(Arc::new(GrpcRevocations { conn, limit: 0 })),
        ));
        let stop = self.inner.stop.child_token();
        let log = self.logger().clone();
        let v2 = Arc::clone(&v);
        handle.spawn(async move {
            let log2 = log.clone();
            let on_error: auth::OnError = Arc::new(move |e: &auth::AuthError| {
                log2.warn("verifier", vec![attr("err", e.0.as_str())]);
            });
            while !stop.is_cancelled() {
                if v2.start(stop.clone(), Some(Arc::clone(&on_error))).await.is_ok() {
                    return;
                }
                tokio::select! {
                    () = stop.cancelled() => return,
                    () = tokio::time::sleep(RETRY) => {}
                }
            }
        });
        Ok(v)
    }

    /// Registers `reg` with auth once the app is ready, retrying every 5s
    /// until auth accepts, then every 5 minutes (deployer `seedLoop`). The
    /// registration is validated now.
    pub fn auth_registration(&self, reg: Registration) -> Result<(), AppError> {
        reg.validate().map_err(|e| AppError(e.to_string()))?;
        self.auth_registration_every(reg, auth::REGISTER_RETRY, auth::REGISTER_PERIOD);
        Ok(())
    }

    /// [`App::auth_registration`] with explicit cadences (tests).
    #[doc(hidden)]
    pub fn auth_registration_every(&self, reg: Registration, retry: Duration, period: Duration) {
        self.on_ready(move |app, stop| async move {
            let conn = ServiceConn::app(&app, AUTH_SERVICE);
            auth::registration_loop(&reg, &conn, app.logger(), retry, period, &stop).await;
        });
    }

    /// Keeps a gateway lease for `manifest` (service `gateway`, the app's
    /// advertised HTTP/gRPC endpoints, the process build version and docs
    /// digest). See [`App::gateway_registration_with`].
    pub fn gateway_registration(&self, manifest: Manifest) -> Result<(), AppError> {
        self.gateway_registration_with(
            GATEWAY_SERVICE,
            gateway::Options {
                manifest,
                ..gateway::Options::default()
            },
        )
    }

    /// Keeps a gateway lease once the app is ready (deployer `register`):
    /// empty `http_url`/`grpc_target` default to this app's advertised
    /// endpoints, the logger to the app's, `on_state` to the deployer's
    /// `gateway lease` log line. The lease is withdrawn on shutdown.
    ///
    /// The manifest is checked now with the gateway's own validation
    /// ([`Manifest::validate`]) and the docs digest with
    /// [`gateway::validate_docs_digest`]; a manifest the gateway would refuse
    /// fails here instead of retrying at the maximum backoff forever.
    pub fn gateway_registration_with(
        &self,
        service: &str,
        mut opts: gateway::Options,
    ) -> Result<(), AppError> {
        opts.manifest.validate().map_err(|e| AppError(e.0))?;
        if opts.http_url.is_empty()
            && let Some(u) = self.http_url()
        {
            opts.http_url = u;
        }
        if opts.grpc_target.is_empty()
            && let Some(t) = self.grpc_target()
        {
            opts.grpc_target = t;
        }
        if opts.logger.is_none() {
            opts.logger = Some(self.logger().clone());
        }
        if opts.on_state.is_none() {
            let log = self.logger().clone();
            opts.on_state = Some(Arc::new(move |s: &State| {
                log.info(
                    "gateway lease",
                    vec![
                        attr("registered", s.registered),
                        attr("lease", s.lease_id.as_str()),
                        attr("err", s.err.as_ref().map(ToString::to_string).unwrap_or_default()),
                    ],
                );
            }));
        }
        // gatewayclient.New's checks, now rather than after ready.
        let probe =
            gateway::Client::new(ServiceConn::app(self, service), opts.clone()).map_err(|e| AppError(e.0))?;
        let opts = probe.options().clone();
        let service = service.to_owned();
        self.on_ready(move |app, stop| async move {
            // The deployer retries the channel every 2s before starting.
            while app.client(&service).is_err() {
                tokio::select! {
                    () = stop.cancelled() => return,
                    () = tokio::time::sleep(RETRY) => {}
                }
            }
            let log = app.logger().clone();
            match gateway::Client::new(ServiceConn::app(&app, &service), opts) {
                Ok(c) => {
                    if let Err(e) = c.run(stop).await {
                        log.error("gateway registration", vec![attr("err", e.0)]);
                    }
                }
                Err(e) => log.error("gateway client", vec![attr("err", e.0)]),
            }
        });
        Ok(())
    }
}
