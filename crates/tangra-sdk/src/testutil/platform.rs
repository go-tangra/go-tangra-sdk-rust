//! In-process fakes of the platform services a module talks to, for module
//! integration tests: `gateway` (`gateway.v1.Registry`) and `auth`
//! (`auth.v1.Keys`, `Sessions`, `Authorization`, `Profiles`). Each runs as a
//! real [`App`] with its own SPIFFE identity from a [`TestCa`], so the module
//! under test reaches them over the same mTLS it uses in production; point
//! its `discovery.static` at [`Platform::discovery`].
//!
//! ```no_run
//! # async fn demo() -> Result<(), tangra_sdk::testutil::TestError> {
//! use tangra_sdk::testutil::platform::Platform;
//!
//! let mut p = Platform::start("example.org", "https://portal.example.org").await?;
//! // build the module's App with p.discovery() and an identity from p.ca ...
//! let token = p.token("u1", "t1", &["member"]);
//! // call the module as the gateway: p.call(addr, "orders", "GET", "/api/orders/v1/x", &[("authorization", &format!("Bearer {token}"))], "").await?
//! p.stop().await;
//! # Ok(()) }
//! ```
//!
//! Not for production use.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tangra_proto::auth::v1 as apb;
use tangra_proto::auth::v1::authorization_server::{Authorization, AuthorizationServer};
use tangra_proto::auth::v1::keys_server::{Keys, KeysServer};
use tangra_proto::auth::v1::profiles_server::{Profiles, ProfilesServer};
use tangra_proto::auth::v1::sessions_server::{Sessions, SessionsServer};
use tangra_proto::gateway::v1 as gpb;
use tangra_proto::gateway::v1::registry_server::{Registry, RegistryServer};
use tokio::sync::oneshot;

use super::{MemoryProvider, TestCa, TestError, terr};
use crate::app::{App, PeerIdentity, Services};
use crate::auth::TestSigner;
use crate::config::{Config, FrameworkConfig, NoModule};
use crate::identity::SpiffeId;
use crate::log::{Capture, Level, Logger};

type Reply<T> = Result<tonic::Response<T>, tonic::Status>;

fn peer<T>(r: &tonic::Request<T>) -> String {
    PeerIdentity::of(r).map(|p| p.id.to_string()).unwrap_or_default()
}

fn proto_duration(d: Duration) -> Option<prost_types::Duration> {
    Some(prost_types::Duration {
        seconds: i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
        nanos: i32::try_from(d.subsec_nanos()).unwrap_or(0),
    })
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

// --- gateway ----------------------------------------------------------------

/// What the fake gateway saw, and how it answers.
#[derive(Debug, Clone)]
pub struct GatewayState {
    /// `Register` calls.
    pub registers: u32,
    /// `Renew` calls.
    pub renews: u32,
    /// `Deregister` calls.
    pub deregisters: u32,
    /// Refuse every `Register` with this status.
    pub refuse: Option<tonic::Status>,
    /// Fail every `Renew` with this status.
    pub renew_err: Option<tonic::Status>,
    /// The last `RegisterRequest`.
    pub last: Option<gpb::RegisterRequest>,
    /// The verified SPIFFE ID of each `Register` caller.
    pub peers: Vec<String>,
    /// Lease TTL handed out (default 600ms).
    pub ttl: Duration,
    /// Renewal cadence handed out (default 100ms).
    pub renew_every: Duration,
}

impl Default for GatewayState {
    fn default() -> Self {
        Self {
            registers: 0,
            renews: 0,
            deregisters: 0,
            refuse: None,
            renew_err: None,
            last: None,
            peers: Vec::new(),
            ttl: Duration::from_millis(600),
            renew_every: Duration::from_millis(100),
        }
    }
}

/// A fake `gateway.v1.Registry` (leases `L<n>`, no admission rules).
#[derive(Debug, Clone, Default)]
pub struct FakeGateway(pub Arc<Mutex<GatewayState>>);

impl FakeGateway {
    /// The state (lock held while the guard lives).
    pub fn state(&self) -> MutexGuard<'_, GatewayState> {
        lock(&self.0)
    }

    /// `(registers, renews, deregisters)`.
    pub fn counts(&self) -> (u32, u32, u32) {
        let g = self.state();
        (g.registers, g.renews, g.deregisters)
    }

    /// The last registration request.
    pub fn last(&self) -> Option<gpb::RegisterRequest> {
        self.state().last.clone()
    }
}

#[tonic::async_trait]
impl Registry for FakeGateway {
    async fn register(&self, r: tonic::Request<gpb::RegisterRequest>) -> Reply<gpb::Lease> {
        let mut g = self.state();
        g.registers += 1;
        g.peers.push(peer(&r));
        let r = r.into_inner();
        let module = r.manifest.as_ref().map(|m| m.module.clone()).unwrap_or_default();
        g.last = Some(r);
        if let Some(s) = &g.refuse {
            return Err(s.clone());
        }
        Ok(tonic::Response::new(gpb::Lease {
            lease_id: format!("L{}", g.registers),
            ttl: proto_duration(g.ttl),
            renew_every: proto_duration(g.renew_every),
            module,
            registry_version: 1,
        }))
    }

    async fn renew(&self, r: tonic::Request<gpb::RenewRequest>) -> Reply<gpb::Lease> {
        let mut g = self.state();
        g.renews += 1;
        if let Some(s) = &g.renew_err {
            return Err(s.clone());
        }
        let module = g
            .last
            .as_ref()
            .and_then(|l| l.manifest.as_ref())
            .map(|m| m.module.clone())
            .unwrap_or_default();
        Ok(tonic::Response::new(gpb::Lease {
            lease_id: r.into_inner().lease_id,
            ttl: proto_duration(g.ttl),
            renew_every: proto_duration(g.renew_every),
            module,
            registry_version: 2,
        }))
    }

    async fn deregister(&self, _: tonic::Request<gpb::DeregisterRequest>) -> Reply<gpb::DeregisterResponse> {
        self.state().deregisters += 1;
        Ok(tonic::Response::new(gpb::DeregisterResponse {}))
    }

    type WatchStream = futures_util::stream::Empty<Result<gpb::RegistryEvent, tonic::Status>>;

    async fn watch(&self, _: tonic::Request<gpb::WatchRequest>) -> Reply<Self::WatchStream> {
        Err(tonic::Status::unimplemented("watch"))
    }
}

// --- auth -------------------------------------------------------------------

/// What the fake auth service saw, and how it answers.
#[derive(Debug, Clone)]
pub struct AuthState {
    /// Signing keys `Keys/List` returns.
    pub keys: Vec<apb::Key>,
    /// `Keys/List` calls.
    pub key_calls: u32,
    /// The revocation feed (`RevokedSince` cursor = index).
    pub revocations: Vec<apb::Revocation>,
    /// `RevokedSince` calls.
    pub rev_calls: u32,
    /// Fail `RevokedSince` (feed down).
    pub rev_fail: bool,
    /// Fail this many `RegisterPermissions` calls before accepting.
    pub register_fail_first: u32,
    /// Every `RegisterPermissions` request with its caller's SPIFFE ID.
    pub registers: Vec<(String, apb::RegisterPermissionsRequest)>,
    /// Every `Authorization/Check` request.
    pub checks: Vec<apb::CheckRequest>,
    /// `Check` decisions: `Some(user -> ["resource:action"])` allows exactly
    /// those; `None` allows every user except `u-denied`.
    pub grants: Option<BTreeMap<String, Vec<String>>>,
    /// The tenant members `Profiles/ListMembers` pages through (two a page).
    pub members: Vec<String>,
}

impl Default for AuthState {
    fn default() -> Self {
        Self {
            keys: Vec::new(),
            key_calls: 0,
            revocations: Vec::new(),
            rev_calls: 0,
            rev_fail: false,
            register_fail_first: 0,
            registers: Vec::new(),
            checks: Vec::new(),
            grants: None,
            members: ["u1", "u2", "u3", "u4", "u5"].map(String::from).to_vec(),
        }
    }
}

/// A fake auth service (`Keys`, `Sessions`, `Authorization`, `Profiles`).
#[derive(Debug, Clone, Default)]
pub struct FakeAuth(pub Arc<Mutex<AuthState>>);

impl FakeAuth {
    /// The state (lock held while the guard lives).
    pub fn state(&self) -> MutexGuard<'_, AuthState> {
        lock(&self.0)
    }

    /// Publishes the signers' public keys (state `active`).
    pub fn set_keys(&self, signers: &[&TestSigner]) {
        self.state().keys = signers
            .iter()
            .map(|s| apb::Key {
                kid: s.kid().into(),
                kty: "OKP".into(),
                crv: "Ed25519".into(),
                public_key: s.public_key(),
                state: "active".into(),
                not_after: None,
            })
            .collect();
    }

    /// Appends a revocation (`kind` session, user or tenant) dated now + 1s.
    pub fn revoke(&self, kind: &str, subject: &str, tenant: &str) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        self.state().revocations.push(apb::Revocation {
            ts: Some(prost_types::Timestamp {
                seconds: i64::try_from(now).unwrap_or(i64::MAX) + 1,
                nanos: 0,
            }),
            kind: kind.into(),
            subject_id: subject.into(),
            tenant_id: tenant.into(),
            reason: "logout".into(),
        });
    }

    /// Allows `user` exactly `perms` (`resource:action`) in `Check`.
    pub fn grant(&self, user: &str, perms: &[&str]) {
        let mut a = self.state();
        a.grants
            .get_or_insert_with(BTreeMap::new)
            .insert(user.to_owned(), perms.iter().map(|p| (*p).to_owned()).collect());
    }

    /// The `RegisterPermissions` requests so far.
    pub fn registrations(&self) -> Vec<(String, apb::RegisterPermissionsRequest)> {
        self.state().registers.clone()
    }
}

#[tonic::async_trait]
impl Keys for FakeAuth {
    async fn list(&self, _: tonic::Request<apb::ListKeysRequest>) -> Reply<apb::ListKeysResponse> {
        let mut a = self.state();
        a.key_calls += 1;
        Ok(tonic::Response::new(apb::ListKeysResponse {
            keys: a.keys.clone(),
        }))
    }
}

#[tonic::async_trait]
impl Sessions for FakeAuth {
    async fn revoked_since(
        &self,
        r: tonic::Request<apb::RevokedSinceRequest>,
    ) -> Reply<apb::RevokedSinceResponse> {
        let mut a = self.state();
        a.rev_calls += 1;
        if a.rev_fail {
            return Err(tonic::Status::unavailable("feed down"));
        }
        let from = r
            .into_inner()
            .cursor
            .parse::<usize>()
            .unwrap_or(0)
            .min(a.revocations.len());
        Ok(tonic::Response::new(apb::RevokedSinceResponse {
            revocations: a.revocations[from..].to_vec(),
            next_cursor: a.revocations.len().to_string(),
        }))
    }

    type WatchStream = futures_util::stream::Empty<Result<apb::Revocation, tonic::Status>>;

    async fn watch(&self, _: tonic::Request<apb::WatchRequest>) -> Reply<Self::WatchStream> {
        Err(tonic::Status::unimplemented(""))
    }
    async fn introspect(&self, _: tonic::Request<apb::IntrospectRequest>) -> Reply<apb::IntrospectResponse> {
        Err(tonic::Status::unimplemented(""))
    }
    async fn exchange(&self, _: tonic::Request<apb::ExchangeRequest>) -> Reply<apb::ExchangeResponse> {
        Err(tonic::Status::unimplemented(""))
    }
    async fn mint_token(&self, _: tonic::Request<apb::MintTokenRequest>) -> Reply<apb::MintTokenResponse> {
        Err(tonic::Status::unimplemented(""))
    }
}

#[tonic::async_trait]
impl Authorization for FakeAuth {
    async fn check(&self, r: tonic::Request<apb::CheckRequest>) -> Reply<apb::CheckResponse> {
        let r = r.into_inner();
        let mut a = self.state();
        let allowed = match &a.grants {
            None => r.user_id != "u-denied",
            Some(g) => {
                let want = format!("{}:{}", r.resource, r.action);
                g.get(&r.user_id).is_some_and(|p| p.contains(&want))
            }
        };
        a.checks.push(r);
        Ok(tonic::Response::new(apb::CheckResponse {
            allowed,
            reason: if allowed { "role:admin" } else { "no_permission" }.into(),
            policy_version: "7".into(),
        }))
    }

    async fn batch_check(&self, r: tonic::Request<apb::BatchCheckRequest>) -> Reply<apb::BatchCheckResponse> {
        // Alternating decisions: allowed, denied, allowed, ...
        let n = r.into_inner().permissions.len();
        Ok(tonic::Response::new(apb::BatchCheckResponse {
            results: (0..n)
                .map(|i| apb::CheckResponse {
                    allowed: i % 2 == 0,
                    ..Default::default()
                })
                .collect(),
        }))
    }

    async fn register_permissions(
        &self,
        r: tonic::Request<apb::RegisterPermissionsRequest>,
    ) -> Reply<apb::RegisterPermissionsResponse> {
        let mut a = self.state();
        let p = peer(&r);
        a.registers.push((p, r.into_inner()));
        if a.register_fail_first > 0 {
            a.register_fail_first -= 1;
            return Err(tonic::Status::unavailable("auth starting"));
        }
        Ok(tonic::Response::new(apb::RegisterPermissionsResponse {
            registered: 2,
            skipped_grants: vec![apb::SkippedGrant {
                role: "operator".into(),
                tenants: 3,
                sample_tenant_ids: vec!["t1".into()],
                reason: "role_missing".into(),
            }],
            ..Default::default()
        }))
    }
}

#[tonic::async_trait]
impl Profiles for FakeAuth {
    async fn lookup(
        &self,
        _: tonic::Request<apb::LookupProfilesRequest>,
    ) -> Reply<apb::LookupProfilesResponse> {
        Err(tonic::Status::unimplemented(""))
    }

    async fn list_members(
        &self,
        r: tonic::Request<apb::ListMembersRequest>,
    ) -> Reply<apb::ListMembersResponse> {
        // Pages of two; the cursor is the last id returned.
        let cursor = r.into_inner().cursor;
        let a = self.state();
        let start = if cursor.is_empty() {
            0
        } else {
            a.members
                .iter()
                .position(|m| *m == cursor)
                .map_or(a.members.len(), |i| i + 1)
        };
        let end = (start + 2).min(a.members.len());
        let ids = a.members[start..end].to_vec();
        let next = if end < a.members.len() {
            ids.last().cloned().unwrap_or_default()
        } else {
            String::new()
        };
        Ok(tonic::Response::new(apb::ListMembersResponse {
            user_ids: ids,
            next_cursor: next,
        }))
    }

    async fn contacts(
        &self,
        _: tonic::Request<apb::LookupContactsRequest>,
    ) -> Reply<apb::LookupContactsResponse> {
        Err(tonic::Status::unimplemented(""))
    }
}

// --- running apps -------------------------------------------------------------

/// An [`App`] served in the background until [`Running::stop`].
pub struct Running {
    /// The app.
    pub app: App,
    /// Its log lines.
    pub log: Capture,
    stop: Option<oneshot::Sender<()>>,
    done: Option<tokio::task::JoinHandle<()>>,
}

impl std::fmt::Debug for Running {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Running")
            .field("app", &self.app)
            .finish_non_exhaustive()
    }
}

impl Running {
    /// Serves `services` on `app` (`run_until` a stop signal).
    pub fn spawn(app: App, log: Capture, services: Services) -> Self {
        let (tx, rx) = oneshot::channel::<()>();
        let a = app.clone();
        let done = tokio::spawn(async move {
            let _ = a
                .run_until(services, async {
                    let _ = rx.await;
                })
                .await;
        });
        Self {
            app,
            log,
            stop: Some(tx),
            done: Some(done),
        }
    }

    /// Stops the app and waits (at most 20s) for its shutdown.
    pub async fn stop(&mut self) {
        if let Some(s) = self.stop.take() {
            let _ = s.send(());
        }
        if let Some(d) = self.done.take() {
            let _ = tokio::time::timeout(Duration::from_secs(20), d).await;
        }
    }
}

/// A framework config for `name` on loopback with random ports and the
/// given `discovery.static` (policy and identity are left to the builder).
pub fn loopback_config(
    trust_domain: &str,
    name: &str,
    discovery: &BTreeMap<String, Vec<String>>,
) -> Result<FrameworkConfig, TestError> {
    let yaml = format!(
        "service_name: {name}\ntrust_domain: {trust_domain}\nidentity: {{provider: provided}}\n\
server: {{grpc_addr: \"127.0.0.1:0\", http_addr: \"127.0.0.1:0\"}}\nadmin: {{addr: \"127.0.0.1:0\"}}\n"
    );
    let mut cfg = Config::<NoModule>::from_yaml(yaml.as_bytes())
        .map_err(terr)?
        .framework;
    cfg.discovery.r#static = discovery.clone();
    Ok(cfg)
}

/// An app named `name` with an in-memory SVID from `ca`, the allow-all
/// policy (fakes only) and a captured debug log.
pub async fn fake_app(ca: &TestCa, name: &str) -> Result<(App, Capture), TestError> {
    let cfg = loopback_config(ca.trust_domain(), name, &BTreeMap::new())?;
    let log = Capture::new();
    let app = App::builder(cfg)
        .identity_provider(MemoryProvider::new(ca, &ca.issue(name)?)?)
        .allow_all_policy()
        .logger(Logger::new(log.clone(), Level::Debug))
        .build()
        .await
        .map_err(terr)?;
    Ok((app, log))
}

/// The fake platform: a CA, `gateway` and `auth` serving their fakes, and an
/// Ed25519 signer (`kid` `k1`) whose key auth publishes.
pub struct Platform {
    /// The trust domain's CA (issue the module's SVID from it).
    pub ca: TestCa,
    /// The fake gateway registry.
    pub gateway: FakeGateway,
    /// The fake auth service.
    pub auth: FakeAuth,
    /// Signs platform access tokens ([`Platform::token`]).
    pub signer: TestSigner,
    /// The token issuer (the module's `gateway.issuer`).
    pub issuer: String,
    /// The running `gateway` app.
    pub gateway_app: Running,
    /// The running `auth` app.
    pub auth_app: Running,
}

impl std::fmt::Debug for Platform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Platform")
            .field("trust_domain", &self.ca.trust_domain())
            .field("issuer", &self.issuer)
            .finish_non_exhaustive()
    }
}

impl Platform {
    /// Starts `gateway` and `auth` for `trust_domain`; tokens carry `issuer`.
    pub async fn start(trust_domain: &str, issuer: &str) -> Result<Self, TestError> {
        let ca = TestCa::new(trust_domain)?;
        let gateway = FakeGateway::default();
        let auth = FakeAuth::default();
        let signer = TestSigner::new("k1").map_err(terr)?;
        auth.set_keys(&[&signer]);
        let (gapp, glog) = fake_app(&ca, "gateway").await?;
        let gateway_app = Running::spawn(
            gapp,
            glog,
            Services::new().grpc(tonic::service::Routes::new(RegistryServer::new(gateway.clone()))),
        );
        let (aapp, alog) = fake_app(&ca, "auth").await?;
        let routes = tonic::service::Routes::new(KeysServer::new(auth.clone()))
            .add_service(SessionsServer::new(auth.clone()))
            .add_service(AuthorizationServer::new(auth.clone()))
            .add_service(ProfilesServer::new(auth.clone()));
        let auth_app = Running::spawn(aapp, alog, Services::new().grpc(routes));
        Ok(Self {
            ca,
            gateway,
            auth,
            signer,
            issuer: issuer.to_owned(),
            gateway_app,
            auth_app,
        })
    }

    /// `discovery.static` entries for `gateway` and `auth`.
    pub fn discovery(&self) -> BTreeMap<String, Vec<String>> {
        let mut d = BTreeMap::new();
        for (name, app) in [("gateway", &self.gateway_app.app), ("auth", &self.auth_app.app)] {
            if let Some(a) = app.grpc_local_addr() {
                d.insert(name.to_owned(), vec![a.to_string()]);
            }
        }
        d
    }

    /// A platform access token for `user` in `tenant` with `roles`, valid
    /// for 10 minutes, signed with the key auth publishes.
    pub fn token(&self, user: &str, tenant: &str, roles: &[&str]) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(0));
        let mut c = TestSigner::claims(&self.issuer, user, tenant, &format!("s-{user}"), now, 600);
        c["roles"] = serde_json::json!(roles);
        self.signer.mint(&c)
    }

    /// One HTTP/2 request to the module `module` at `addr` over mTLS, as the
    /// gateway (an SVID `spiffe://<td>/svc/gateway` from [`Platform::ca`]).
    pub async fn call(
        &self,
        addr: SocketAddr,
        module: &str,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: &str,
    ) -> Result<TestResponse, TestError> {
        self.call_as("gateway", addr, module, method, path, headers, body)
            .await
    }

    /// [`Platform::call`] presenting the SVID of service `caller`.
    #[allow(clippy::too_many_arguments)]
    pub async fn call_as(
        &self,
        caller: &str,
        addr: SocketAddr,
        module: &str,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: &str,
    ) -> Result<TestResponse, TestError> {
        let tls = client_tls(&self.ca, caller, module)?;
        h2_request(tls, addr, method, path, headers, Bytes::from(body.to_owned())).await
    }

    /// Stops `gateway` and `auth`.
    pub async fn stop(&mut self) {
        self.gateway_app.stop().await;
        self.auth_app.stop().await;
    }
}

/// An mTLS client configuration presenting a fresh SVID of `caller` and
/// requiring the server to be `spiffe://<td>/svc/<server>`.
pub fn client_tls(ca: &TestCa, caller: &str, server: &str) -> Result<Arc<rustls::ClientConfig>, TestError> {
    let provider = MemoryProvider::new(ca, &ca.issue(caller)?)?;
    let expected = SpiffeId::new(ca.trust_domain(), server).map_err(terr)?;
    crate::tls::client_config(provider, expected, crate::tls::Options::new(ca.trust_domain())).map_err(terr)
}

/// A response read in full.
#[derive(Debug, Clone)]
pub struct TestResponse {
    /// Status code.
    pub status: u16,
    /// Headers.
    pub headers: http::HeaderMap,
    /// Body (lossy UTF-8).
    pub body: String,
}

impl TestResponse {
    /// The body as JSON (`Null` when it is not JSON).
    pub fn json(&self) -> serde_json::Value {
        serde_json::from_str(&self.body).unwrap_or(serde_json::Value::Null)
    }
}

/// One HTTP/2 request over a fresh TLS connection to `addr`.
pub async fn h2_request(
    tls: Arc<rustls::ClientConfig>,
    addr: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Bytes,
) -> Result<TestResponse, TestError> {
    let tcp = tokio::net::TcpStream::connect(addr).await.map_err(terr)?;
    let name = rustls_pki_types::ServerName::try_from("localhost").map_err(terr)?;
    let conn = tokio_rustls::TlsConnector::from(tls)
        .connect(name, tcp)
        .await
        .map_err(terr)?;
    let (mut send, driver) = hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(conn))
        .await
        .map_err(terr)?;
    tokio::spawn(driver);
    let mut req = http::Request::builder()
        .method(method)
        .uri(format!("https://localhost{path}"));
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let req = req.body(Full::new(body)).map_err(terr)?;
    let resp = send.send_request(req).await.map_err(terr)?;
    let status = resp.status().as_u16();
    let headers = resp.headers().clone();
    let body = resp.into_body().collect().await.map_err(terr)?.to_bytes();
    Ok(TestResponse {
        status,
        headers,
        body: String::from_utf8_lossy(&body).into_owned(),
    })
}
