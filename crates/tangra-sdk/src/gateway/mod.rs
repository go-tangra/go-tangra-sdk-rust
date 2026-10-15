//! Registration with the application gateway (portal
//! `sdk/pkg/gatewayclient`, tag `sdk/v4.2.0`): Register, then Renew every
//! `renew_every` (±10 % jitter) until shutdown, then Deregister.
//!
//! - Register failures back off from 1s doubling to `max_backoff` (30s);
//!   `PermissionDenied`, `InvalidArgument`, `FailedPrecondition` and
//!   `Unauthenticated` are permanent refusals ([`State::err`] has
//!   `refused`) and jump straight to `max_backoff` (client.go:123-142,210-216).
//! - A renewal that is refused, answers `NotFound`, or keeps failing for the
//!   lease TTL loses the lease: the loop registers again (client.go:163-197).
//! - On shutdown the lease is withdrawn with a 5s deadline (client.go:146-152).

use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use tangra_proto::gateway::v1 as pb;
use tangra_proto::gateway::v1::registry_client::RegistryClient;
use tokio_util::sync::CancellationToken;

use crate::app::ServiceConn;
use crate::log::{Logger, attr};
use crate::manifest::Manifest;

/// A setup error (gatewayclient `New` / `Run` refusals).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct GatewayError(pub String);

/// A failed gateway call as the loop reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallError {
    /// The gRPC status code.
    pub code: tonic::Code,
    /// The status message (the gateway's reason, e.g. `identity_not_allowed`).
    pub message: String,
    /// A permanent refusal (gatewayclient `ErrRefused`).
    pub refused: bool,
}

impl std::fmt::Display for CallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = format!(
            "rpc error: code = {} desc = {}",
            code_name(self.code),
            self.message
        );
        if self.refused {
            write!(f, "gatewayclient: registration refused: {s}")
        } else {
            f.write_str(&s)
        }
    }
}

/// grpc-go's `codes.Code.String()`.
fn code_name(c: tonic::Code) -> &'static str {
    use tonic::Code::*;
    match c {
        Ok => "OK",
        Cancelled => "Canceled",
        Unknown => "Unknown",
        InvalidArgument => "InvalidArgument",
        DeadlineExceeded => "DeadlineExceeded",
        NotFound => "NotFound",
        AlreadyExists => "AlreadyExists",
        PermissionDenied => "PermissionDenied",
        ResourceExhausted => "ResourceExhausted",
        FailedPrecondition => "FailedPrecondition",
        Aborted => "Aborted",
        OutOfRange => "OutOfRange",
        Unimplemented => "Unimplemented",
        Internal => "Internal",
        Unavailable => "Unavailable",
        DataLoss => "DataLoss",
        Unauthenticated => "Unauthenticated",
    }
}

/// The lease state visible to the module (gatewayclient `State`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct State {
    /// A lease is held.
    pub registered: bool,
    /// The lease id.
    pub lease_id: String,
    /// The module the lease is for.
    pub module: String,
    /// The registry version.
    pub version: u64,
    /// The last failure.
    pub err: Option<CallError>,
}

/// Called on every state change.
pub type OnState = Arc<dyn Fn(&State) + Send + Sync>;

/// Registration options (gatewayclient `Options`).
#[derive(Clone, Default)]
pub struct Options {
    /// The manifest.
    pub manifest: Manifest,
    /// Stable per process; generated (32 hex characters) when empty.
    pub instance_id: String,
    /// `https://host:port` of the module's HTTP server.
    pub http_url: String,
    /// `host:port` of the module's gRPC server.
    pub grpc_target: String,
    /// Logger (default: JSON on stderr).
    pub logger: Option<Logger>,
    /// Cap of the re-registration delay (default 30s).
    pub max_backoff: Duration,
    /// Called on every transition.
    pub on_state: Option<OnState>,
    /// The release this process runs; empty means [`build_version`].
    pub build_version: String,
    /// The help-docs digest (64 lowercase hex or empty); empty means
    /// [`docs_digest`].
    pub docs_digest: String,
}

impl std::fmt::Debug for Options {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Options")
            .field("module", &self.manifest.module)
            .field("instance_id", &self.instance_id)
            .field("http_url", &self.http_url)
            .field("grpc_target", &self.grpc_target)
            .field("max_backoff", &self.max_backoff)
            .field("build_version", &self.build_version)
            .field("docs_digest", &self.docs_digest)
            .finish_non_exhaustive()
    }
}

static BUILD_VERSION: RwLock<String> = RwLock::new(String::new());
static DOCS_DIGEST: RwLock<String> = RwLock::new(String::new());

/// Records the release this process runs (trimmed); sent with every
/// registration whose `build_version` is empty (gatewayclient
/// `SetBuildVersion`). Typically `set_build_version(env!("CARGO_PKG_VERSION"))`.
pub fn set_build_version(v: &str) {
    if let Ok(mut g) = BUILD_VERSION.write() {
        *g = v.trim().to_owned();
    }
}

/// The process build version ("" when unset). Go falls back to the main
/// module version from the build info; Rust has no equivalent the SDK can
/// read, so modules set it explicitly.
pub fn build_version() -> String {
    BUILD_VERSION.read().map(|g| g.clone()).unwrap_or_default()
}

/// Records the process help-docs digest (gatewayclient `SetDocsDigest`).
pub fn set_docs_digest(d: &str) {
    if let Ok(mut g) = DOCS_DIGEST.write() {
        *g = d.to_owned();
    }
}

/// The process help-docs digest ("" when unset).
pub fn docs_digest() -> String {
    DOCS_DIGEST.read().map(|g| g.clone()).unwrap_or_default()
}

/// Accepts "" or exactly 64 lowercase hex characters (gatewayclient
/// `ValidateDocsDigest`; the gateway refuses anything else with
/// `docs_digest_invalid`).
pub fn validate_docs_digest(d: &str) -> Result<(), GatewayError> {
    if d.is_empty() {
        return Ok(());
    }
    if d.len() != 64 {
        return Err(GatewayError(format!(
            "gatewayclient: docs digest {d:?} must be 64 lowercase hex characters (sha256) or empty, got {} characters",
            d.len()
        )));
    }
    if !d
        .bytes()
        .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err(GatewayError(format!(
            "gatewayclient: docs digest {d:?} must be 64 lowercase hex characters (sha256) or empty"
        )));
    }
    Ok(())
}

/// A uniform float in [0, 1) from 53 random bits (client.go `jitter`).
fn jitter() -> f64 {
    let b: u64 = rand::random();
    (b >> 11) as f64 / (1u64 << 53) as f64
}

/// 16 random bytes as 32 lowercase hex characters (client.go `newInstanceID`).
pub fn new_instance_id() -> String {
    let b: [u8; 16] = rand::random();
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn permanent(code: tonic::Code) -> bool {
    matches!(
        code,
        tonic::Code::PermissionDenied
            | tonic::Code::InvalidArgument
            | tonic::Code::FailedPrecondition
            | tonic::Code::Unauthenticated
    )
}

fn nanos(d: Duration) -> i64 {
    i64::try_from(d.as_nanos()).unwrap_or(i64::MAX)
}

/// durationpb `AsDuration` (negative clamps to zero here: Go treats
/// `every <= 0` as 10s and compares TTLs with `>=`).
fn as_std(d: Option<&prost_types::Duration>) -> Duration {
    let Some(d) = d else { return Duration::ZERO };
    if d.seconds < 0 || (d.seconds == 0 && d.nanos <= 0) {
        return Duration::ZERO;
    }
    Duration::new(
        u64::try_from(d.seconds).unwrap_or(0),
        u32::try_from(d.nanos.max(0)).unwrap_or(0),
    )
}

/// Drives Register, Renew, Deregister (gatewayclient `Client`).
pub struct Client {
    conn: ServiceConn,
    opts: Options,
    logger: Logger,
    st: Mutex<State>,
    rand: fn() -> f64,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("opts", &self.opts)
            .finish_non_exhaustive()
    }
}

fn status_err(s: &tonic::Status) -> CallError {
    CallError {
        code: s.code(),
        message: s.message().to_owned(),
        refused: false,
    }
}

impl Client {
    /// Validates the options (gatewayclient `New`).
    pub fn new(conn: ServiceConn, mut o: Options) -> Result<Self, GatewayError> {
        if o.manifest.module.is_empty() {
            return Err(GatewayError("gatewayclient: manifest module is required".into()));
        }
        if o.http_url.is_empty() && o.grpc_target.is_empty() {
            return Err(GatewayError(
                "gatewayclient: a backend address is required".into(),
            ));
        }
        if o.instance_id.is_empty() {
            o.instance_id = new_instance_id();
        }
        if o.max_backoff.is_zero() {
            o.max_backoff = Duration::from_secs(30);
        }
        if o.build_version.is_empty() {
            o.build_version = build_version();
        }
        if o.docs_digest.is_empty() {
            o.docs_digest = docs_digest();
        }
        validate_docs_digest(&o.docs_digest)?;
        let logger = o
            .logger
            .clone()
            .unwrap_or_else(|| Logger::new(std::io::stderr(), crate::log::Level::Info));
        Ok(Self {
            conn,
            opts: o,
            logger,
            st: Mutex::new(State::default()),
            rand: jitter,
        })
    }

    /// The options in effect (generated instance id, defaults applied).
    pub fn options(&self) -> &Options {
        &self.opts
    }

    /// The current lease state.
    pub fn state(&self) -> State {
        self.st.lock().map(|g| g.clone()).unwrap_or_default()
    }

    fn set(&self, st: State) {
        if let Ok(mut g) = self.st.lock() {
            *g = st.clone();
        }
        if let Some(f) = &self.opts.on_state {
            f(&st);
        }
    }

    fn client(&self) -> Result<RegistryClient<crate::app::GrpcChannel>, tonic::Status> {
        self.conn
            .get()
            .map(RegistryClient::new)
            .map_err(|e| tonic::Status::unavailable(e.0))
    }

    async fn register(&self, req: pb::RegisterRequest) -> Result<pb::Lease, tonic::Status> {
        Ok(self.client()?.register(req).await?.into_inner())
    }

    async fn renew(&self, lease_id: &str, timeout: Duration) -> Result<pb::Lease, tonic::Status> {
        let mut c = self.client()?;
        let req = pb::RenewRequest {
            lease_id: lease_id.to_owned(),
        };
        match tokio::time::timeout(timeout, c.renew(req)).await {
            Ok(r) => Ok(r?.into_inner()),
            Err(_) => Err(tonic::Status::deadline_exceeded("context deadline exceeded")),
        }
    }

    /// Registers and renews until `stop` is cancelled, then deregisters.
    /// Errors only when the manifest cannot be encoded.
    pub async fn run(&self, stop: CancellationToken) -> Result<(), GatewayError> {
        let pm = self.opts.manifest.to_proto().map_err(|e| GatewayError(e.0))?;
        let req = pb::RegisterRequest {
            manifest: Some(pm),
            instance_id: self.opts.instance_id.clone(),
            backend: Some(pb::Backend {
                http_url: self.opts.http_url.clone(),
                grpc_target: self.opts.grpc_target.clone(),
            }),
            build_version: self.opts.build_version.clone(),
            docs_digest: self.opts.docs_digest.clone(),
        };
        let module = self.opts.manifest.module.clone();
        let mut backoff = Duration::from_secs(1);
        loop {
            let res = tokio::select! {
                () = stop.cancelled() => return Ok(()),
                r = self.register(req.clone()) => r,
            };
            let lease = match res {
                Ok(l) => l,
                Err(s) => {
                    let mut e = status_err(&s);
                    if permanent(s.code()) {
                        e.refused = true;
                        backoff = self.opts.max_backoff;
                    }
                    self.set(State {
                        err: Some(e.clone()),
                        ..State::default()
                    });
                    self.logger.warn(
                        "gateway registration failed",
                        vec![
                            attr("module", module.as_str()),
                            attr("err", status_err(&s).to_string()),
                            attr("retry_in", nanos(backoff)),
                        ],
                    );
                    if !sleep(&stop, backoff).await {
                        return Ok(());
                    }
                    backoff = (backoff * 2).min(self.opts.max_backoff);
                    continue;
                }
            };
            backoff = Duration::from_secs(1);
            self.set(State {
                registered: true,
                lease_id: lease.lease_id.clone(),
                module: lease.module.clone(),
                version: lease.registry_version,
                err: None,
            });
            self.logger.info(
                "registered with gateway",
                vec![
                    attr("module", lease.module.as_str()),
                    attr("lease", lease.lease_id.as_str()),
                ],
            );
            if !self.renew_loop(&stop, lease.clone()).await {
                // Cancelled: withdraw immediately.
                if let Ok(mut c) = self.client() {
                    let req = pb::DeregisterRequest {
                        lease_id: lease.lease_id.clone(),
                    };
                    let _ = tokio::time::timeout(Duration::from_secs(5), c.deregister(req)).await;
                }
                self.set(State::default());
                return Ok(());
            }
            // Lease lost: re-register after a short pause.
            if !sleep(&stop, backoff).await {
                return Ok(());
            }
        }
    }

    /// Renews until cancelled (false) or the lease is lost (true).
    async fn renew_loop(&self, stop: &CancellationToken, mut lease: pb::Lease) -> bool {
        let mut every = as_std(lease.renew_every.as_ref());
        if every.is_zero() {
            every = Duration::from_secs(10);
        }
        let ttl = as_std(lease.ttl.as_ref());
        let mut failures: u32 = 0;
        loop {
            let wait = every.mul_f64(0.9 + 0.2 * (self.rand)());
            if !sleep(stop, wait).await {
                return false;
            }
            let res = tokio::select! {
                () = stop.cancelled() => return false,
                r = self.renew(&lease.lease_id, every) => r,
            };
            match res {
                Err(s) => {
                    failures += 1;
                    self.logger.warn(
                        "gateway lease renewal failed",
                        vec![
                            attr("module", self.opts.manifest.module.as_str()),
                            attr("err", status_err(&s).to_string()),
                            attr("failures", u64::from(failures)),
                        ],
                    );
                    if permanent(s.code()) || s.code() == tonic::Code::NotFound || every * failures >= ttl {
                        self.set(State {
                            err: Some(status_err(&s)),
                            ..State::default()
                        });
                        return true;
                    }
                }
                Ok(renewed) => {
                    failures = 0;
                    let version = renewed.registry_version;
                    if !renewed.lease_id.is_empty() {
                        lease = renewed;
                    }
                    self.set(State {
                        registered: true,
                        lease_id: lease.lease_id.clone(),
                        module: lease.module.clone(),
                        version,
                        err: None,
                    });
                }
            }
        }
    }
}

async fn sleep(stop: &CancellationToken, d: Duration) -> bool {
    tokio::select! {
        () = stop.cancelled() => false,
        () = tokio::time::sleep(d) => true,
    }
}

#[cfg(test)]
mod tests;
