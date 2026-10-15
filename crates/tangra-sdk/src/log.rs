//! Structured JSON logs in the shape of Go's `slog.NewJSONHandler(os.Stderr)`
//! wrapped in `audit.NewRedactingHandler` with a `service` attribute
//! (go-tangra `freya.go` `New`, `audit/redact.go`).
//!
//! Every line is one JSON object: `time` (RFC 3339, milliseconds, local
//! offset), `level` (`DEBUG|INFO|WARN|ERROR`), `msg`, then the logger's own
//! attributes (`service`) and the record's attributes in order. Attributes
//! whose key looks sensitive, whose value is bytes, or whose string holds a
//! PEM header are replaced by `[REDACTED]`.
//!
//! Framework lines (`request`, `audit`, lifecycle) are written through
//! [`Logger`]; application code can use `tracing` macros after installing
//! [`Logger::layer`] (or calling [`init`]), which renders events the same way.

use std::fmt::{self, Write as _};
use std::io::Write;
use std::sync::{Arc, Mutex};

use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Subscriber};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;

use crate::gofmt::json_float;

/// The value that replaces anything the redactor refuses to log.
pub const REDACTED: &str = "[REDACTED]";

/// Key substrings (case-insensitive) that are never logged.
const FORBIDDEN_KEY_PARTS: [&str; 7] = [
    "key",
    "private",
    "secret",
    "token",
    "password",
    "authorization",
    "phone",
];

/// Log severity (slog levels).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    /// `DEBUG`
    Debug,
    /// `INFO`
    Info,
    /// `WARN`
    Warn,
    /// `ERROR`
    Error,
}

impl Level {
    fn as_str(self) -> &'static str {
        match self {
            Self::Debug => "DEBUG",
            Self::Info => "INFO",
            Self::Warn => "WARN",
            Self::Error => "ERROR",
        }
    }

    fn from_tracing(l: tracing::Level) -> Self {
        match l {
            tracing::Level::ERROR => Self::Error,
            tracing::Level::WARN => Self::Warn,
            tracing::Level::INFO => Self::Info,
            _ => Self::Debug,
        }
    }
}

/// An attribute value.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// A string.
    Str(String),
    /// A signed integer.
    I64(i64),
    /// An unsigned integer.
    U64(u64),
    /// A float (encoded like `encoding/json`).
    F64(f64),
    /// A boolean.
    Bool(bool),
    /// Raw bytes: always redacted.
    Bytes,
}

impl From<&str> for Value {
    fn from(s: &str) -> Self {
        Self::Str(s.to_owned())
    }
}
impl From<String> for Value {
    fn from(s: String) -> Self {
        Self::Str(s)
    }
}
impl From<&String> for Value {
    fn from(s: &String) -> Self {
        Self::Str(s.clone())
    }
}
impl From<i64> for Value {
    fn from(v: i64) -> Self {
        Self::I64(v)
    }
}
impl From<u64> for Value {
    fn from(v: u64) -> Self {
        Self::U64(v)
    }
}
impl From<usize> for Value {
    fn from(v: usize) -> Self {
        Self::U64(v as u64)
    }
}
impl From<f64> for Value {
    fn from(v: f64) -> Self {
        Self::F64(v)
    }
}
impl From<bool> for Value {
    fn from(v: bool) -> Self {
        Self::Bool(v)
    }
}

/// One key/value attribute.
#[derive(Debug, Clone, PartialEq)]
pub struct Attr {
    /// Key.
    pub key: String,
    /// Value.
    pub value: Value,
}

/// Builds an attribute.
pub fn attr(key: impl Into<String>, value: impl Into<Value>) -> Attr {
    Attr {
        key: key.into(),
        value: value.into(),
    }
}

fn forbidden_key(k: &str) -> bool {
    let lk = k.to_ascii_lowercase();
    FORBIDDEN_KEY_PARTS.iter().any(|p| lk.contains(p))
}

/// Applies the redaction rules of `audit.NewRedactingHandler`.
pub fn redact(a: Attr) -> Attr {
    let sensitive = match &a.value {
        Value::Str(s) => s.contains("-----BEGIN"),
        Value::Bytes => true,
        _ => false,
    };
    if forbidden_key(&a.key) || sensitive {
        return Attr {
            key: a.key,
            value: Value::Str(REDACTED.to_owned()),
        };
    }
    a
}

fn write_json_str(out: &mut String, s: &str) {
    // slog's JSON handler does not escape HTML characters.
    out.push_str(&serde_json::to_string(s).unwrap_or_else(|_| "\"\"".to_owned()));
}

fn write_value(out: &mut String, v: &Value) {
    match v {
        Value::Str(s) => write_json_str(out, s),
        Value::I64(n) => {
            let _ = write!(out, "{n}");
        }
        Value::U64(n) => {
            let _ = write!(out, "{n}");
        }
        Value::F64(f) => out.push_str(&json_float(*f)),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Bytes => write_json_str(out, REDACTED),
    }
}

fn now_rfc3339_millis() -> String {
    let now = chrono::Local::now();
    let s = now.format("%Y-%m-%dT%H:%M:%S%.3f%:z").to_string();
    match s.strip_suffix("+00:00") {
        Some(base) => format!("{base}Z"),
        None => s,
    }
}

type Sink = Box<dyn Write + Send>;

struct Inner {
    sink: Mutex<Sink>,
    min: Level,
}

/// A JSON line logger with fixed attributes (`slog.Logger`).
#[derive(Clone)]
pub struct Logger {
    inner: Arc<Inner>,
    base: Arc<Vec<Attr>>,
}

impl fmt::Debug for Logger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Logger").field("attrs", &self.base).finish()
    }
}

impl Logger {
    /// A logger writing to stderr at INFO with `service=<service>`.
    pub fn stderr(service: &str) -> Self {
        Self::new(std::io::stderr(), Level::Info).with(vec![attr("service", service)])
    }

    /// A logger writing JSON lines to `w`, dropping records below `min`.
    pub fn new(w: impl Write + Send + 'static, min: Level) -> Self {
        Self {
            inner: Arc::new(Inner {
                sink: Mutex::new(Box::new(w)),
                min,
            }),
            base: Arc::new(Vec::new()),
        }
    }

    /// A child logger with extra fixed attributes (`slog.Logger.With`).
    #[must_use]
    pub fn with(&self, attrs: Vec<Attr>) -> Self {
        let mut base = (*self.base).clone();
        base.extend(attrs.into_iter().map(redact));
        Self {
            inner: Arc::clone(&self.inner),
            base: Arc::new(base),
        }
    }

    /// Whether records at `level` are written.
    pub fn enabled(&self, level: Level) -> bool {
        level >= self.inner.min
    }

    /// Writes one record.
    pub fn log(&self, level: Level, msg: &str, attrs: Vec<Attr>) {
        if !self.enabled(level) {
            return;
        }
        let mut line = String::with_capacity(256);
        line.push_str("{\"time\":");
        write_json_str(&mut line, &now_rfc3339_millis());
        line.push_str(",\"level\":");
        write_json_str(&mut line, level.as_str());
        line.push_str(",\"msg\":");
        write_json_str(&mut line, msg);
        for a in self.base.iter().cloned().chain(attrs.into_iter().map(redact)) {
            line.push(',');
            write_json_str(&mut line, &a.key);
            line.push(':');
            write_value(&mut line, &a.value);
        }
        line.push_str("}\n");
        if let Ok(mut w) = self.inner.sink.lock() {
            let _ = w.write_all(line.as_bytes());
            let _ = w.flush();
        }
    }

    /// `log(Level::Debug, ..)`.
    pub fn debug(&self, msg: &str, attrs: Vec<Attr>) {
        self.log(Level::Debug, msg, attrs);
    }
    /// `log(Level::Info, ..)`.
    pub fn info(&self, msg: &str, attrs: Vec<Attr>) {
        self.log(Level::Info, msg, attrs);
    }
    /// `log(Level::Warn, ..)`.
    pub fn warn(&self, msg: &str, attrs: Vec<Attr>) {
        self.log(Level::Warn, msg, attrs);
    }
    /// `log(Level::Error, ..)`.
    pub fn error(&self, msg: &str, attrs: Vec<Attr>) {
        self.log(Level::Error, msg, attrs);
    }

    /// A `tracing` layer that renders events through this logger: the event
    /// `message` becomes `msg`, span fields (outermost first) and event fields
    /// become attributes.
    pub fn layer(&self) -> SlogLayer {
        SlogLayer { logger: self.clone() }
    }
}

/// Installs `logger.layer()` as the global `tracing` subscriber.
pub fn init(logger: &Logger) -> Result<(), tracing::subscriber::SetGlobalDefaultError> {
    use tracing_subscriber::layer::SubscriberExt;
    let min = match logger.inner.min {
        Level::Debug => tracing::level_filters::LevelFilter::DEBUG,
        Level::Info => tracing::level_filters::LevelFilter::INFO,
        Level::Warn => tracing::level_filters::LevelFilter::WARN,
        Level::Error => tracing::level_filters::LevelFilter::ERROR,
    };
    let sub = tracing_subscriber::registry().with(logger.layer().with_filter(min));
    tracing::subscriber::set_global_default(sub)
}

/// The `tracing` layer of a [`Logger`].
#[derive(Debug, Clone)]
pub struct SlogLayer {
    logger: Logger,
}

#[derive(Default)]
struct Fields {
    message: Option<String>,
    attrs: Vec<Attr>,
}

impl Visit for Fields {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        let s = format!("{value:?}");
        if field.name() == "message" {
            self.message = Some(s);
        } else {
            self.attrs.push(attr(field.name(), s));
        }
    }
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message = Some(value.to_owned());
        } else {
            self.attrs.push(attr(field.name(), value));
        }
    }
    fn record_i64(&mut self, field: &Field, value: i64) {
        self.attrs.push(attr(field.name(), value));
    }
    fn record_u64(&mut self, field: &Field, value: u64) {
        self.attrs.push(attr(field.name(), value));
    }
    fn record_f64(&mut self, field: &Field, value: f64) {
        self.attrs.push(attr(field.name(), value));
    }
    fn record_bool(&mut self, field: &Field, value: bool) {
        self.attrs.push(attr(field.name(), value));
    }
    fn record_bytes(&mut self, field: &Field, _value: &[u8]) {
        self.attrs.push(Attr {
            key: field.name().to_owned(),
            value: Value::Bytes,
        });
    }
    fn record_error(&mut self, field: &Field, value: &(dyn std::error::Error + 'static)) {
        self.attrs.push(attr(field.name(), value.to_string()));
    }
}

struct SpanAttrs(Vec<Attr>);

impl<S> Layer<S> for SlogLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        let mut f = Fields::default();
        attrs.record(&mut f);
        if let Some(span) = ctx.span(id) {
            span.extensions_mut().insert(SpanAttrs(f.attrs));
        }
    }

    fn on_record(&self, id: &Id, values: &Record<'_>, ctx: Context<'_, S>) {
        let mut f = Fields::default();
        values.record(&mut f);
        if let Some(span) = ctx.span(id) {
            let mut ext = span.extensions_mut();
            if let Some(sa) = ext.get_mut::<SpanAttrs>() {
                sa.0.extend(f.attrs);
            } else {
                ext.insert(SpanAttrs(f.attrs));
            }
        }
    }

    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        let level = Level::from_tracing(*event.metadata().level());
        if !self.logger.enabled(level) {
            return;
        }
        let mut f = Fields::default();
        event.record(&mut f);
        let mut attrs = Vec::new();
        if let Some(scope) = ctx.event_scope(event) {
            for span in scope.from_root() {
                if let Some(sa) = span.extensions().get::<SpanAttrs>() {
                    attrs.extend(sa.0.iter().cloned());
                }
            }
        }
        attrs.extend(f.attrs);
        self.logger.log(level, f.message.as_deref().unwrap_or(""), attrs);
    }
}

/// An in-memory writer for tests: clones share the buffer.
#[derive(Clone, Default)]
pub struct Capture(Arc<Mutex<Vec<u8>>>);

impl Capture {
    /// A new, empty capture.
    pub fn new() -> Self {
        Self::default()
    }

    /// Everything written so far.
    pub fn contents(&self) -> String {
        self.0
            .lock()
            .map(|b| String::from_utf8_lossy(&b).into_owned())
            .unwrap_or_default()
    }

    /// The written lines parsed as JSON objects (unparseable lines skipped).
    pub fn lines(&self) -> Vec<serde_json::Value> {
        self.contents()
            .lines()
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect()
    }
}

impl Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if let Ok(mut b) = self.0.lock() {
            b.extend_from_slice(buf);
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn logger() -> (Logger, Capture) {
        let cap = Capture::new();
        let l = Logger::new(cap.clone(), Level::Info).with(vec![attr("service", "orders")]);
        (l, cap)
    }

    #[test]
    fn slog_json_shape() {
        let (l, cap) = logger();
        l.info(
            "request",
            vec![
                attr("caller", "gateway"),
                attr("caller_id", "spiffe://example.org/svc/gateway"),
                attr("duration_ms", 1.25),
                attr("n", 3i64),
                attr("ok", true),
            ],
        );
        let raw = cap.contents();
        assert!(raw.ends_with("}\n"));
        // Key order: time, level, msg, service, record attrs.
        let keys: Vec<&str> = raw
            .trim_end()
            .trim_start_matches('{')
            .split(",\"")
            .map(|kv| kv.trim_start_matches('"').split('"').next().unwrap_or(""))
            .collect();
        assert_eq!(
            keys,
            [
                "time",
                "level",
                "msg",
                "service",
                "caller",
                "caller_id",
                "duration_ms",
                "n",
                "ok"
            ]
        );
        let v = &cap.lines()[0];
        assert_eq!(v["level"], "INFO");
        assert_eq!(v["msg"], "request");
        assert_eq!(v["service"], "orders");
        assert_eq!(v["duration_ms"], 1.25);
        let t = v["time"].as_str().unwrap_or("");
        assert!(chrono::DateTime::parse_from_rfc3339(t).is_ok(), "{t}");
        assert_eq!(
            t.split('.')
                .nth(1)
                .map(|f| f.chars().take_while(char::is_ascii_digit).count()),
            Some(3)
        );
    }

    #[test]
    fn levels_filter() {
        let (l, cap) = logger();
        l.debug("hidden", vec![]);
        l.warn("shown", vec![]);
        let lines = cap.lines();
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0]["level"], "WARN");
    }

    #[test]
    fn redaction_like_go() {
        let (l, cap) = logger();
        l.info(
            "x",
            vec![
                attr("api_key", "k"),
                attr("Authorization", "Bearer x"),
                attr("PASSWORD", "p"),
                attr("phone_number", "1"),
                attr("cert", "-----BEGIN CERTIFICATE-----\nAAA"),
                Attr {
                    key: "blob".into(),
                    value: Value::Bytes,
                },
                attr("plain", "fine"),
            ],
        );
        let v = &cap.lines()[0];
        for k in [
            "api_key",
            "Authorization",
            "PASSWORD",
            "phone_number",
            "cert",
            "blob",
        ] {
            assert_eq!(v[k], REDACTED, "{k}");
        }
        assert_eq!(v["plain"], "fine");
        // Fixed attributes are redacted too.
        let l2 = l.with(vec![attr("token", "t")]);
        l2.info("y", vec![]);
        assert_eq!(cap.lines()[1]["token"], REDACTED);
    }

    #[test]
    fn tracing_layer_renders_events() {
        use tracing_subscriber::layer::SubscriberExt;
        let (l, cap) = logger();
        let sub = tracing_subscriber::registry().with(l.layer());
        tracing::subscriber::with_default(sub, || {
            let span = tracing::info_span!("op", tenant = "t1");
            let _g = span.enter();
            tracing::info!(count = 2u64, secret = "s", "hello {}", "world");
            tracing::debug!("dropped");
        });
        let lines = cap.lines();
        assert_eq!(lines.len(), 1);
        let v = &lines[0];
        assert_eq!(v["msg"], "hello world");
        assert_eq!(v["tenant"], "t1");
        assert_eq!(v["count"], 2);
        assert_eq!(v["secret"], REDACTED);
        assert_eq!(v["service"], "orders");
    }
}
