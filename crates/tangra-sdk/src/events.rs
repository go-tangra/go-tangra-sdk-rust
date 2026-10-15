//! The platform event bus (feature `events`): one Valkey stream per tenant,
//! `platform:events:<tenant_id>`, which the gateway fans out to signed-in
//! people over SSE and modules consume.
//!
//! - [`Publisher`] appends events exactly like the deployer's hub
//!   (`internal/stream/hub.go` `PublishID` + `internal/stream/valkeykv`):
//!   `XADD <key> MAXLEN ~ 10000 * at <unix ms> data <json> to <*|ids> type <type>`
//!   (fields sorted), with the same validation and errors: type
//!   `^[a-z][a-z0-9._-]{0,63}$`, module events may not use the reserved
//!   types, 1..1000 user ids without `,`, space or newline (or everyone),
//!   data valid JSON of at most 16 KiB without CR/LF.
//! - [`consume`] is the deployer's `internal/events/consumer.go` loop:
//!   start after each tenant stream's tail, `XREAD COUNT 100 BLOCK 2000`,
//!   skip the module's own events (`module` field, loop guard), keep the
//!   wanted types.
//! - [`ValkeyConfig`] is the module config section `valkey:` with the
//!   deployer's rules: addresses required, TLS 1.3 unless
//!   `allow_plaintext` (refused in production, warned otherwise),
//!   `ca_file` for a private CA (system roots otherwise), ACL user and
//!   password.

use std::collections::BTreeMap;
use std::sync::{Arc, LazyLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use redis::aio::MultiplexedConnection;
use regex::Regex;
use rustls_pki_types::ServerName;
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

/// Largest `data` payload.
pub const MAX_PAYLOAD: usize = 16 << 10;
/// Most user ids per event.
pub const MAX_TARGETS: usize = 1000;
/// The approximate stream length kept (`MAXLEN ~`).
pub const DEFAULT_MAX_LEN: i64 = 10000;
/// Event types only the platform publishes (`issued`, `renewed`,
/// `revoked`: certificate lifecycle; `reset`, `bye`: SSE control).
pub const RESERVED: [&str; 5] = ["issued", "renewed", "revoked", "reset", "bye"];

/// The stream of a tenant.
pub fn key(tenant_id: &str) -> String {
    format!("platform:events:{tenant_id}")
}

/// A refused publish or a bus failure. The four refusals carry the Go
/// error texts.
#[derive(Debug, thiserror::Error)]
pub enum EventsError {
    /// `stream: invalid event type`
    #[error("stream: invalid event type")]
    Type,
    /// `stream: payload too large or not JSON-safe`
    #[error("stream: payload too large or not JSON-safe")]
    Payload,
    /// `stream: 1..1000 user ids or all=true`
    #[error("stream: 1..1000 user ids or all=true")]
    Targets,
    /// `stream: reserved event type`
    #[error("stream: reserved event type")]
    Reserved,
    /// Configuration (`config: valkey...`, `valkey: ...`).
    #[error("{0}")]
    Config(String),
    /// Connecting or a command failed.
    #[error("valkey: {0}")]
    Bus(String),
}

impl From<redis::RedisError> for EventsError {
    fn from(e: redis::RedisError) -> Self {
        EventsError::Bus(e.to_string())
    }
}

#[allow(clippy::expect_used)]
static TYPE_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[a-z][a-z0-9._-]{0,63}$").expect("regex"));

/// Checks an event type; `module` events may not use [`RESERVED`] types.
pub fn validate_type(typ: &str, module: bool) -> Result<(), EventsError> {
    if !TYPE_RE.is_match(typ) {
        return Err(EventsError::Type);
    }
    if module && RESERVED.contains(&typ) {
        return Err(EventsError::Reserved);
    }
    Ok(())
}

/// Who an event is for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// Everyone in the tenant (`to: *`).
    All,
    /// These user ids (1..1000).
    Users(Vec<String>),
}

/// The stream fields of one event, sorted by name (`at`, `data`, `to`,
/// `type`) as the deployer's client writes them. `now_ms` is `at`.
pub fn encode(
    to: &Target,
    typ: &str,
    data: &[u8],
    module: bool,
    now_ms: i64,
) -> Result<Vec<(String, String)>, EventsError> {
    validate_type(typ, module)?;
    if let Target::Users(u) = to
        && (u.is_empty() || u.len() > MAX_TARGETS)
    {
        return Err(EventsError::Targets);
    }
    let json_ok = serde_json::from_slice::<serde::de::IgnoredAny>(data).is_ok();
    if data.len() > MAX_PAYLOAD || !json_ok || data.contains(&b'\n') || data.contains(&b'\r') {
        return Err(EventsError::Payload);
    }
    let target = match to {
        Target::All => "*".to_owned(),
        Target::Users(u) => {
            if u.iter().any(|id| id.is_empty() || id.contains([',', ' ', '\n'])) {
                return Err(EventsError::Targets);
            }
            u.join(",")
        }
    };
    let data = String::from_utf8(data.to_vec()).map_err(|_| EventsError::Payload)?;
    Ok(vec![
        ("at".to_owned(), now_ms.to_string()),
        ("data".to_owned(), data),
        ("to".to_owned(), target),
        ("type".to_owned(), typ.to_owned()),
    ])
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

/// The module config section `valkey:` (deployer `config.Valkey`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ValkeyConfig {
    /// `host:port` endpoints, tried in order.
    pub addresses: Vec<String>,
    /// ACL user.
    pub username: String,
    /// ACL password.
    pub password: String,
    /// Connect without TLS (development only; refused in production).
    pub allow_plaintext: bool,
    /// PEM CA bundle verifying the server (system roots when empty).
    pub ca_file: String,
}

impl ValkeyConfig {
    /// The deployer's checks (`config.Validate`).
    pub fn validate(&self, production: bool) -> Result<(), EventsError> {
        if self.addresses.is_empty() {
            return Err(EventsError::Config("config: valkey.addresses is required".into()));
        }
        if production && self.allow_plaintext {
            return Err(EventsError::Config(
                "config: valkey.allow_plaintext is not permitted in production".into(),
            ));
        }
        Ok(())
    }

    /// Accepted deviations to log at start (`config.Warnings`).
    pub fn warnings(&self) -> Vec<String> {
        if self.allow_plaintext {
            vec!["valkey.allow_plaintext: event-bus traffic without TLS (development only)".into()]
        } else {
            Vec::new()
        }
    }

    fn tls(&self) -> Result<Option<Arc<rustls::ClientConfig>>, EventsError> {
        if self.allow_plaintext {
            return Ok(None);
        }
        let mut roots = rustls::RootCertStore::empty();
        if self.ca_file.is_empty() {
            for c in rustls_native_certs::load_native_certs().certs {
                let _ = roots.add(c);
            }
        } else {
            let pem =
                std::fs::read(&self.ca_file).map_err(|e| EventsError::Config(format!("valkey ca: {e}")))?;
            let mut n = 0;
            for c in rustls_pki_types::pem::PemObject::pem_slice_iter(&pem).flatten() {
                if roots.add(c).is_ok() {
                    n += 1;
                }
            }
            if n == 0 {
                return Err(EventsError::Config("valkey: ca is not valid PEM".into()));
            }
        }
        let cfg =
            rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .map_err(|e| EventsError::Config(format!("valkey: {e}")))?
                .with_root_certificates(roots)
                .with_no_client_auth();
        Ok(Some(Arc::new(cfg)))
    }
}

/// A Valkey connection (TLS 1.3 unless plaintext is allowed) that
/// reconnects on the next command after a connection failure.
#[derive(Clone)]
pub struct Client {
    cfg: ValkeyConfig,
    tls: Option<Arc<rustls::ClientConfig>>,
    conn: Arc<Mutex<Option<MultiplexedConnection>>>,
    timeout: Option<Duration>,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("addresses", &self.cfg.addresses)
            .field("tls", &self.tls.is_some())
            .finish_non_exhaustive()
    }
}

const DIAL_TIMEOUT: Duration = Duration::from_secs(5);
const COMMAND_TIMEOUT: Duration = Duration::from_secs(10);

impl Client {
    /// Validates the configuration (addresses, CA) and connects.
    pub async fn connect(cfg: &ValkeyConfig) -> Result<Self, EventsError> {
        let c = Self::new(cfg, Some(COMMAND_TIMEOUT))?;
        c.conn().await?;
        Ok(c)
    }

    fn new(cfg: &ValkeyConfig, timeout: Option<Duration>) -> Result<Self, EventsError> {
        if cfg.addresses.is_empty() {
            return Err(EventsError::Config("valkey: addresses required".into()));
        }
        Ok(Self {
            tls: cfg.tls()?,
            cfg: cfg.clone(),
            conn: Arc::new(Mutex::new(None)),
            timeout,
        })
    }

    /// A second connection for blocking reads (a blocked `XREAD` would
    /// stall every command pipelined behind it).
    fn dedicated(&self) -> Self {
        Self {
            cfg: self.cfg.clone(),
            tls: self.tls.clone(),
            conn: Arc::new(Mutex::new(None)),
            timeout: None,
        }
    }

    async fn dial(&self, addr: &str) -> Result<MultiplexedConnection, EventsError> {
        let mut info = redis::RedisConnectionInfo::default();
        if !self.cfg.username.is_empty() {
            info = info.set_username(&self.cfg.username);
        }
        if !self.cfg.password.is_empty() {
            info = info.set_password(&self.cfg.password);
        }
        let cfg = redis::AsyncConnectionConfig::new().set_response_timeout(self.timeout);
        let tcp = tokio::time::timeout(DIAL_TIMEOUT, TcpStream::connect(addr))
            .await
            .map_err(|_| EventsError::Bus(format!("dial {addr}: timeout")))?
            .map_err(|e| EventsError::Bus(format!("dial {addr}: {e}")))?;
        let conn = match &self.tls {
            None => {
                let (conn, driver) = MultiplexedConnection::new_with_config(&info, tcp, cfg).await?;
                tokio::spawn(driver);
                conn
            }
            Some(tls) => {
                let (host, _) = crate::config::split_host_port(addr).map_err(EventsError::Bus)?;
                let name = ServerName::try_from(host.clone())
                    .map_err(|e| EventsError::Bus(format!("{host}: {e}")))?;
                let stream = tokio::time::timeout(
                    DIAL_TIMEOUT,
                    tokio_rustls::TlsConnector::from(Arc::clone(tls)).connect(name, tcp),
                )
                .await
                .map_err(|_| EventsError::Bus(format!("tls {addr}: timeout")))?
                .map_err(|e| EventsError::Bus(format!("tls {addr}: {e}")))?;
                let (conn, driver) = MultiplexedConnection::new_with_config(&info, stream, cfg).await?;
                tokio::spawn(driver);
                conn
            }
        };
        Ok(conn)
    }

    async fn conn(&self) -> Result<MultiplexedConnection, EventsError> {
        let mut g = self.conn.lock().await;
        if let Some(c) = g.as_ref() {
            return Ok(c.clone());
        }
        let mut last = EventsError::Bus("no address".into());
        for addr in &self.cfg.addresses {
            match self.dial(addr).await {
                Ok(c) => {
                    *g = Some(c.clone());
                    return Ok(c);
                }
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    async fn query<T: redis::FromRedisValue>(&self, cmd: &redis::Cmd) -> Result<T, EventsError> {
        let mut c = self.conn().await?;
        match cmd.query_async::<T>(&mut c).await {
            Ok(v) => Ok(v),
            Err(e) => {
                if e.is_io_error()
                    || e.is_connection_dropped()
                    || e.is_unrecoverable_error()
                    || e.is_timeout()
                {
                    *self.conn.lock().await = None;
                }
                Err(e.into())
            }
        }
    }

    /// `PING`.
    pub async fn ping(&self) -> Result<(), EventsError> {
        self.query::<String>(&redis::cmd("PING")).await.map(drop)
    }

    /// `XADD key MAXLEN ~ max_len * <fields>`; returns the entry id.
    pub async fn xadd(
        &self,
        key: &str,
        fields: &[(String, String)],
        max_len: i64,
    ) -> Result<String, EventsError> {
        let mut cmd = redis::cmd("XADD");
        cmd.arg(key).arg("MAXLEN").arg("~").arg(max_len).arg("*");
        for (k, v) in fields {
            cmd.arg(k).arg(v);
        }
        self.query(&cmd).await
    }

    /// `XREAD COUNT count BLOCK block STREAMS key after` (`$` when `after`
    /// is empty); an expired block is no entries.
    pub async fn xread(
        &self,
        key: &str,
        after: &str,
        block: Duration,
        count: usize,
    ) -> Result<Vec<Entry>, EventsError> {
        let after = if after.is_empty() { "$" } else { after };
        let mut cmd = redis::cmd("XREAD");
        cmd.arg("COUNT")
            .arg(count)
            .arg("BLOCK")
            .arg(u64::try_from(block.as_millis()).unwrap_or(u64::MAX))
            .arg("STREAMS")
            .arg(key)
            .arg(after);
        let r: Option<redis::streams::StreamReadReply> = self.query(&cmd).await?;
        Ok(r.into_iter()
            .flat_map(|r| r.keys)
            .filter(|k| k.key == key)
            .flat_map(|k| k.ids)
            .map(Entry::from)
            .collect())
    }

    /// The id of the newest entry ("" for an empty stream).
    pub async fn xlast(&self, key: &str) -> Result<String, EventsError> {
        let mut cmd = redis::cmd("XREVRANGE");
        cmd.arg(key).arg("+").arg("-").arg("COUNT").arg(1);
        let r: redis::streams::StreamRangeReply = self.query(&cmd).await?;
        Ok(r.ids.into_iter().next().map(|e| e.id).unwrap_or_default())
    }
}

/// One stream entry.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Entry {
    /// `<ms>-<seq>`.
    pub id: String,
    /// The fields (`to`, `type`, `data`, `at`, ...).
    pub fields: BTreeMap<String, String>,
}

impl From<redis::streams::StreamId> for Entry {
    fn from(s: redis::streams::StreamId) -> Self {
        let fields = s
            .map
            .into_iter()
            .filter_map(|(k, v)| redis::from_redis_value::<String>(v).ok().map(|v| (k, v)))
            .collect();
        Entry { id: s.id, fields }
    }
}

/// Publishes events of a module.
#[derive(Debug, Clone)]
pub struct Publisher {
    client: Client,
    max_len: i64,
    module: bool,
}

impl Publisher {
    /// A publisher refusing the [`RESERVED`] types (`PublishID(...,
    /// module=true)`), trimming to [`DEFAULT_MAX_LEN`].
    pub fn new(client: Client) -> Self {
        Self {
            client,
            max_len: DEFAULT_MAX_LEN,
            module: true,
        }
    }

    /// Allows the reserved types too (the deployer's own hub publishes with
    /// `module=false`).
    #[must_use]
    pub fn allow_reserved(mut self) -> Self {
        self.module = false;
        self
    }

    /// The `MAXLEN ~` trim length.
    #[must_use]
    pub fn max_len(mut self, n: i64) -> Self {
        self.max_len = n;
        self
    }

    /// Publishes `data` encoded as Go's `json.Marshal` would (HTML-safe
    /// escaping); returns the entry id.
    pub async fn publish<T: Serialize + ?Sized>(
        &self,
        tenant_id: &str,
        to: &Target,
        typ: &str,
        data: &T,
    ) -> Result<String, EventsError> {
        let raw = crate::gofmt::json_html_escaped(data);
        self.publish_raw(tenant_id, to, typ, raw.as_bytes()).await
    }

    /// Publishes already-encoded JSON (`[]byte`/`json.RawMessage`/`string`
    /// in Go; empty means `{}`).
    pub async fn publish_raw(
        &self,
        tenant_id: &str,
        to: &Target,
        typ: &str,
        data: &[u8],
    ) -> Result<String, EventsError> {
        let data = if data.is_empty() { b"{}" } else { data };
        let fields = encode(to, typ, data, self.module, now_ms())?;
        self.client.xadd(&key(tenant_id), &fields, self.max_len).await
    }
}

/// What [`consume`] delivers.
#[derive(Debug, Clone)]
pub struct ConsumeOptions {
    /// This module's name: entries whose `module` field equals it are
    /// skipped (loop guard). Empty: none skipped.
    pub own_module: String,
    /// Wanted types (compared after trimming spaces); empty: every type.
    pub types: Vec<String>,
    /// `XREAD BLOCK` (2s).
    pub block: Duration,
    /// `XREAD COUNT` (100).
    pub count: usize,
    /// Pause after a failed read (Go retries at once).
    pub retry_delay: Duration,
}

impl Default for ConsumeOptions {
    fn default() -> Self {
        Self {
            own_module: String::new(),
            types: Vec::new(),
            block: Duration::from_secs(2),
            count: 100,
            retry_delay: Duration::from_secs(1),
        }
    }
}

/// Consumes the tenants' streams until `stop`, calling `handler(tenant,
/// entry)` for each wanted entry in order. It starts after each stream's
/// current tail, so a restart does not replay old events (deployer
/// `events.Consumer.Run`). Reads use a dedicated connection.
pub async fn consume<F, Fut>(
    client: &Client,
    tenants: &[String],
    opts: ConsumeOptions,
    stop: CancellationToken,
    mut handler: F,
) where
    F: FnMut(String, Entry) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let reader = client.dedicated();
    let mut last: BTreeMap<String, String> = BTreeMap::new();
    for t in tenants {
        let id = match reader.xlast(&key(t)).await {
            Ok(id) if !id.is_empty() => id,
            _ => "0-0".to_owned(),
        };
        last.insert(t.clone(), id);
    }
    while !stop.is_cancelled() {
        for t in tenants {
            let after = last.get(t).cloned().unwrap_or_else(|| "0-0".to_owned());
            let k = key(t);
            let read = tokio::select! {
                () = stop.cancelled() => return,
                r = reader.xread(&k, &after, opts.block, opts.count) => r,
            };
            let entries = match read {
                Ok(e) => e,
                Err(_) => {
                    tokio::select! {
                        () = stop.cancelled() => return,
                        () = tokio::time::sleep(opts.retry_delay) => {}
                    }
                    continue;
                }
            };
            for e in entries {
                last.insert(t.clone(), e.id.clone());
                if !opts.own_module.is_empty() && e.fields.get("module") == Some(&opts.own_module) {
                    continue;
                }
                let typ = e.fields.get("type").map_or("", |s| s.trim());
                if !opts.types.is_empty() && !opts.types.iter().any(|w| w == typ) {
                    continue;
                }
                handler(t.clone(), e).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn users(n: usize) -> Target {
        Target::Users((0..n).map(|i| format!("u{i}")).collect())
    }

    #[test]
    fn encodes_like_the_deployer_hub() {
        let f = encode(
            &Target::All,
            "job.done",
            br#"{"id":"1"}"#,
            true,
            1_700_000_000_123,
        )
        .expect("ok");
        assert_eq!(
            f,
            vec![
                ("at".into(), "1700000000123".into()),
                ("data".into(), r#"{"id":"1"}"#.into()),
                ("to".into(), "*".into()),
                ("type".into(), "job.done".into()),
            ]
        );
        let f = encode(&users(3), "x", b"{}", true, 1).expect("ok");
        assert_eq!(f[2].1, "u0,u1,u2");
        assert_eq!(key("t1"), "platform:events:t1");
    }

    #[test]
    fn refuses_like_the_deployer_hub() {
        let e = |to: &Target, t: &str, d: &[u8], m: bool| encode(to, t, d, m, 0).err().map(|e| e.to_string());
        let ty = Some("stream: invalid event type".to_owned());
        let payload = Some("stream: payload too large or not JSON-safe".to_owned());
        let targets = Some("stream: 1..1000 user ids or all=true".to_owned());
        assert_eq!(e(&Target::All, "Job", b"{}", true), ty);
        assert_eq!(e(&Target::All, "1x", b"{}", true), ty);
        assert_eq!(e(&Target::All, &format!("a{}", "b".repeat(64)), b"{}", true), ty);
        assert_eq!(
            e(&Target::All, &format!("a{}", "b".repeat(63)), b"{}", true),
            None
        );
        assert_eq!(
            e(&Target::All, "revoked", b"{}", true),
            Some("stream: reserved event type".into())
        );
        assert_eq!(e(&Target::All, "revoked", b"{}", false), None);
        assert_eq!(e(&users(0), "x", b"{}", true), targets);
        assert_eq!(e(&users(1001), "x", b"{}", true), targets);
        assert_eq!(e(&users(1000), "x", b"{}", true), None);
        for bad in ["", "a,b", "a b", "a\nb"] {
            assert_eq!(
                e(&Target::Users(vec![bad.into()]), "x", b"{}", true),
                targets,
                "{bad:?}"
            );
        }
        assert_eq!(e(&Target::All, "x", b"{\"a\":\n1}", true), payload);
        assert_eq!(e(&Target::All, "x", b"{\"a\":\r1}", true), payload);
        assert_eq!(e(&Target::All, "x", b"{nope", true), payload);
        let big = format!("\"{}\"", "a".repeat(MAX_PAYLOAD - 1));
        assert_eq!(e(&Target::All, "x", big.as_bytes(), true), payload);
        let fits = format!("\"{}\"", "a".repeat(MAX_PAYLOAD - 2));
        assert_eq!(e(&Target::All, "x", fits.as_bytes(), true), None);
        // The type is checked before the targets, the targets before the data.
        assert_eq!(e(&users(0), "BAD", b"{", true), ty);
        assert_eq!(e(&users(0), "x", b"{", true), targets);
    }

    #[test]
    fn config_rules() {
        let mut c = ValkeyConfig::default();
        assert_eq!(
            c.validate(false).err().map(|e| e.to_string()),
            Some("config: valkey.addresses is required".into())
        );
        c.addresses = vec!["valkey:6379".into()];
        c.allow_plaintext = true;
        assert!(c.validate(false).is_ok());
        assert_eq!(
            c.validate(true).err().map(|e| e.to_string()),
            Some("config: valkey.allow_plaintext is not permitted in production".into())
        );
        assert_eq!(c.warnings().len(), 1);
        let y: ValkeyConfig = serde_norway::from_str(
            "addresses: [a:1]\nusername: u\npassword: p\nallow_plaintext: false\nca_file: /x\n",
        )
        .expect("yaml");
        assert_eq!(y.ca_file, "/x");
        assert!(serde_norway::from_str::<ValkeyConfig>("nope: 1\n").is_err());
        let bad = ValkeyConfig {
            addresses: vec!["a:1".into()],
            ca_file: "/nonexistent/ca.pem".into(),
            ..ValkeyConfig::default()
        };
        assert!(Client::new(&bad, None).is_err_and(|e| e.to_string().starts_with("valkey ca: ")));
        let dir = tempfile::tempdir().expect("dir");
        let junk = dir.path().join("ca.pem");
        std::fs::write(&junk, "not pem").expect("write");
        let bad = ValkeyConfig {
            ca_file: junk.display().to_string(),
            ..bad
        };
        assert_eq!(
            Client::new(&bad, None).err().map(|e| e.to_string()),
            Some("valkey: ca is not valid PEM".into())
        );
    }
}
