//! The gateway's manifest validation (portal `internal/manifest/manifest.go`
//! and `convert.go`): `FromProto` renders the wire manifest as JSON and runs
//! `Parse` on it (size limit, JSON Schema, then the semantic rules).

use std::collections::HashSet;
use std::sync::OnceLock;
use std::time::Duration;

use regex::Regex;
use serde_json::{Map, Value};
use tangra_proto::gateway::v1 as pb;

use super::ManifestError;
use super::gojson::{J, Obj, marshal};
use crate::GoDuration;

/// Largest accepted manifest JSON (manifest.go:90).
pub const MAX_MANIFEST_BYTES: usize = 256 << 10;
/// Largest serialised ability conditions (manifest.go:91).
pub const MAX_CONDITION_BYTES: usize = 4096;
/// Longest route timeout (manifest.go:92).
pub const MAX_DURATION_ROUTE: Duration = Duration::from_secs(5 * 60);

fn invalid(msg: impl std::fmt::Display) -> ManifestError {
    ManifestError(format!("manifest: invalid: {msg}"))
}

fn perm_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r"^[a-z0-9][a-z0-9_.-]{0,63}:[a-z0-9][a-z0-9_.-]{0,63}$")
            .unwrap_or_else(|_| unreachable!())
    })
}

fn param_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"^\{[a-z][a-z0-9_]*(\.\.\.)?\}$").unwrap_or_else(|_| unreachable!()))
}

const ALLOW_OPS: &[&str] = &[
    "$eq", "$ne", "$in", "$nin", "$lt", "$lte", "$gt", "$gte", "$exists",
];

/// A validated manifest as the gateway stores it (portal `manifest.Manifest`):
/// prefixes normalised and sorted, durations in the schema grammar.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct GatewayManifest {
    /// Module name.
    pub module: String,
    /// Display name.
    pub display_name: String,
    /// Version.
    pub version: String,
    /// Owned prefixes (normalised, sorted).
    pub prefixes: Vec<String>,
    /// Routes.
    pub routes: Vec<GwRoute>,
    /// gRPC methods.
    pub methods: Vec<GwMethod>,
    /// Permissions.
    pub permissions: Vec<GwPermission>,
    /// Abilities.
    pub abilities: Vec<GwAbility>,
    /// Remote.
    pub remote: GwRemote,
    /// Navigation.
    pub nav: Vec<GwNav>,
}

/// A route (`timeout` in the schema grammar, e.g. `5s`).
#[allow(missing_docs)]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GwRoute {
    pub method: String,
    pub path: String,
    pub permission: String,
    pub public: bool,
    pub max_body_bytes: i64,
    pub timeout: String,
    pub client_address: bool,
}

/// A gRPC method.
#[allow(missing_docs)]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GwMethod {
    pub full_method: String,
    pub permission: String,
    pub public: bool,
    pub streaming: bool,
    pub max_stream_duration: String,
}

/// A permission.
#[allow(missing_docs)]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GwPermission {
    pub resource: String,
    pub action: String,
    pub description: String,
}

/// An ability (`None` lists are Go nil slices).
#[allow(missing_docs)]
#[derive(Debug, Clone, Default, PartialEq)]
pub struct GwAbility {
    pub action: Option<Vec<String>>,
    pub subject: Option<Vec<String>>,
    pub fields: Vec<String>,
    pub conditions: Map<String, Value>,
    pub inverted: bool,
    pub reason: String,
    pub requires: String,
}

/// The remote.
#[allow(missing_docs)]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GwRemote {
    pub entry: String,
    pub exposes: Vec<String>,
    pub integrity: String,
}

/// A navigation entry.
#[allow(missing_docs)]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GwNav {
    pub title: String,
    pub path: String,
    pub icon: String,
    pub order: i64,
    pub requires: String,
}

impl GatewayManifest {
    /// Go `json.Marshal(m)` of the portal struct.
    fn to_j(&self) -> J {
        let routes = self
            .routes
            .iter()
            .map(|r| {
                Obj::default()
                    .field("method", J::str(&r.method))
                    .field("path", J::str(&r.path))
                    .omit_str("permission", &r.permission)
                    .omit_bool("public", r.public)
                    .omit_int("max_body_bytes", r.max_body_bytes)
                    .omit_str("timeout", &r.timeout)
                    .omit_bool("client_address", r.client_address)
                    .build()
            })
            .collect();
        let methods = self
            .methods
            .iter()
            .map(|m| {
                Obj::default()
                    .field("full_method", J::str(&m.full_method))
                    .omit_str("permission", &m.permission)
                    .omit_bool("public", m.public)
                    .omit_bool("streaming", m.streaming)
                    .omit_str("max_stream_duration", &m.max_stream_duration)
                    .build()
            })
            .collect();
        let permissions = self
            .permissions
            .iter()
            .map(|p| {
                Obj::default()
                    .field("resource", J::str(&p.resource))
                    .field("action", J::str(&p.action))
                    .omit_str("description", &p.description)
                    .build()
            })
            .collect();
        let abilities = self
            .abilities
            .iter()
            .map(|a| {
                let mut o = Obj::default()
                    .field("action", J::opt_strs(a.action.as_ref()))
                    .field("subject", J::opt_strs(a.subject.as_ref()))
                    .omit_strs("fields", &a.fields);
                if !a.conditions.is_empty() {
                    o = o.field("conditions", J::Map(a.conditions.clone()));
                }
                o.omit_bool("inverted", a.inverted)
                    .omit_str("reason", &a.reason)
                    .field("requires", J::str(&a.requires))
                    .build()
            })
            .collect();
        let nav = self
            .nav
            .iter()
            .map(|n| {
                Obj::default()
                    .field("title", J::str(&n.title))
                    .field("path", J::str(&n.path))
                    .omit_str("icon", &n.icon)
                    .field("order", J::Int(n.order))
                    .field("requires", J::str(&n.requires))
                    .build()
            })
            .collect();
        Obj::default()
            .field("module", J::str(&self.module))
            .field("display_name", J::str(&self.display_name))
            .field("version", J::str(&self.version))
            .field("prefixes", J::strs(&self.prefixes))
            .field("routes", J::Arr(routes))
            .field("methods", J::Arr(methods))
            .field("permissions", J::Arr(permissions))
            .field("abilities", J::Arr(abilities))
            .field(
                "remote",
                Obj::default()
                    .field("entry", J::str(&self.remote.entry))
                    .field("exposes", J::strs(&self.remote.exposes))
                    .omit_str("integrity", &self.remote.integrity)
                    .build(),
            )
            .field("nav", J::Arr(nav))
            .build()
    }

    /// The JSON the gateway stores (Go `json.Marshal` bytes).
    pub fn to_json(&self) -> String {
        marshal(&self.to_j())
    }

    /// The gateway's content hash (portal `registry.hashManifest`: lowercase
    /// hex SHA-256 of the JSON).
    pub fn content_hash(&self) -> String {
        let d = ring::digest::digest(&ring::digest::SHA256, self.to_json().as_bytes());
        d.as_ref().iter().map(|b| format!("{b:02x}")).collect()
    }

    /// The CASL subjects the manifest claims (sorted, unique).
    pub fn subjects(&self) -> Vec<String> {
        let mut s: Vec<String> = self
            .abilities
            .iter()
            .flat_map(|a| a.subject.iter().flatten().cloned())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        s.sort();
        s
    }

    /// The semantic rules the schema cannot express (manifest.go:162-254).
    pub(crate) fn check(&mut self) -> Result<(), ManifestError> {
        for p in &mut self.prefixes {
            let n = normalize_prefix(p).ok_or_else(|| invalid(format!("prefix {}", goq(p))))?;
            *p = n;
        }
        self.prefixes.sort();
        for i in 0..self.prefixes.len() {
            for j in i + 1..self.prefixes.len() {
                if overlaps(&self.prefixes[i], &self.prefixes[j]) {
                    return Err(invalid(format!(
                        "prefixes {} and {} overlap",
                        goq(&self.prefixes[i]),
                        goq(&self.prefixes[j])
                    )));
                }
            }
        }
        let mut perms = HashSet::new();
        for p in &self.permissions {
            let r = format!("{}:{}", p.resource, p.action);
            if !perm_re().is_match(&r) || perms.contains(&r) {
                return Err(invalid(format!("permission {}", goq(&r))));
            }
            perms.insert(r);
        }
        let mut seen = HashSet::new();
        for r in &self.routes {
            if r.public == !r.permission.is_empty() {
                return Err(invalid(format!(
                    "route {} {} must be public or carry a permission",
                    r.method, r.path
                )));
            }
            if !r.permission.is_empty() && !perms.contains(&r.permission) {
                return Err(invalid(format!(
                    "route {} {} requires undeclared permission {}",
                    r.method,
                    r.path,
                    goq(&r.permission)
                )));
            }
            if !self.under_prefix(&r.path) {
                return Err(invalid(format!(
                    "route {} {} outside the owned prefixes",
                    r.method, r.path
                )));
            }
            let segs: Vec<&str> = r.path.strip_prefix('/').unwrap_or(&r.path).split('/').collect();
            for (i, seg) in segs.iter().enumerate() {
                if seg.starts_with('{') && !param_re().is_match(seg) {
                    return Err(invalid(format!("route path parameter {}", goq(seg))));
                }
                if seg.ends_with("...}") && i != segs.len() - 1 {
                    return Err(invalid(format!("catch-all parameter {} must be last", goq(seg))));
                }
            }
            if !r.timeout.is_empty() {
                let ok = GoDuration::parse(&r.timeout)
                    .is_ok_and(|d| d.as_nanos() > 0 && d.to_std() <= MAX_DURATION_ROUTE);
                if !ok {
                    return Err(invalid(format!("route timeout {}", goq(&r.timeout))));
                }
            }
            let key = format!("{} {}", r.method, r.path);
            if !seen.insert(key.clone()) {
                return Err(invalid(format!("duplicate route {key}")));
            }
        }
        let mut seen = HashSet::new();
        for m in &self.methods {
            if m.public == !m.permission.is_empty() {
                return Err(invalid(format!(
                    "method {} must be public or carry a permission",
                    m.full_method
                )));
            }
            if !m.permission.is_empty() && !perms.contains(&m.permission) {
                return Err(invalid(format!(
                    "method {} requires undeclared permission {}",
                    m.full_method,
                    goq(&m.permission)
                )));
            }
            if !m.max_stream_duration.is_empty() {
                let ok = GoDuration::parse(&m.max_stream_duration)
                    .is_ok_and(|d| d.as_nanos() > 0 && d.as_nanos() <= GoDuration::HOUR * 24);
                if !ok {
                    return Err(invalid(format!(
                        "max_stream_duration {}",
                        goq(&m.max_stream_duration)
                    )));
                }
            }
            if !seen.insert(m.full_method.clone()) {
                return Err(invalid(format!("duplicate method {}", m.full_method)));
            }
        }
        for a in &self.abilities {
            if !perms.contains(&a.requires) {
                return Err(invalid(format!(
                    "ability requires undeclared permission {}",
                    goq(&a.requires)
                )));
            }
            validate_conditions(&a.conditions)?;
        }
        for n in &self.nav {
            if !perms.contains(&n.requires) {
                return Err(invalid(format!(
                    "nav entry {} requires undeclared permission {}",
                    goq(&n.title),
                    goq(&n.requires)
                )));
            }
        }
        let want = format!("/m/{}/mf-manifest.json", self.module);
        if self.remote.entry != want {
            return Err(invalid(format!("remote entry must be {want}")));
        }
        Ok(())
    }

    fn under_prefix(&self, path: &str) -> bool {
        self.prefixes
            .iter()
            .any(|p| path == p || path.strip_prefix(p.as_str()).is_some_and(|r| r.starts_with('/')))
    }
}

/// Canonicalises an owned prefix (manifest.go `NormalizePrefix`): absolute,
/// no trailing slash, no empty/dot segments, no parameters, no
/// percent-encoding.
pub fn normalize_prefix(p: &str) -> Option<String> {
    if p.is_empty()
        || !p.starts_with('/')
        || p.len() > 128
        || p.contains(['%', '?', '#', '\\', ' ', '\t', '\r', '\n'])
    {
        return None;
    }
    let p = p.strip_suffix('/').unwrap_or(p);
    if p.is_empty() {
        return None;
    }
    for seg in p[1..].split('/') {
        if seg.is_empty() || seg == "." || seg == ".." || seg.starts_with('{') {
            return None;
        }
    }
    Some(p.to_owned())
}

/// Whether one prefix contains the other (manifest.go `Overlaps`).
pub fn overlaps(a: &str, b: &str) -> bool {
    a == b
        || a.strip_prefix(b).is_some_and(|r| r.starts_with('/'))
        || b.strip_prefix(a).is_some_and(|r| r.starts_with('/'))
}

/// Bounds CASL conditions to the documented MongoDB-style subset
/// (manifest.go `ValidateConditions`).
pub fn validate_conditions(c: &Map<String, Value>) -> Result<(), ManifestError> {
    if c.is_empty() {
        return Ok(());
    }
    if marshal(&J::Map(c.clone())).len() > MAX_CONDITION_BYTES {
        return Err(invalid(format!(
            "conditions larger than {MAX_CONDITION_BYTES} bytes"
        )));
    }
    walk_conditions(&Value::Object(c.clone()), 0)
}

fn walk_conditions(v: &Value, depth: usize) -> Result<(), ManifestError> {
    if depth > 6 {
        return Err(invalid("conditions nested too deeply"));
    }
    match v {
        Value::Object(m) => {
            for (k, val) in m {
                if k.starts_with('$') && !ALLOW_OPS.contains(&k.as_str()) {
                    return Err(invalid(format!("condition operator {} not allowed", goq(k))));
                }
                if !k.starts_with('$')
                    && (k.is_empty() || k.len() > 64 || k.contains([' ', '\t', '\r', '\n']))
                {
                    return Err(invalid(format!("condition field {}", goq(k))));
                }
                walk_conditions(val, depth + 1)?;
            }
        }
        Value::Array(a) => {
            if a.len() > 100 {
                return Err(invalid("condition list too long"));
            }
            for e in a {
                walk_conditions(e, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Validates the wire manifest exactly as the gateway's `Register` does
/// (convert.go `FromProto`: JSON round trip, then [`parse`]).
pub fn validate(p: &pb::Manifest) -> Result<GatewayManifest, ManifestError> {
    let m = from_proto_no_validate(p);
    parse(m.to_json().as_bytes())
}

/// Validates manifest JSON (manifest.go `Parse`): size limit, JSON Schema,
/// then the semantic rules.
pub fn parse(raw: &[u8]) -> Result<GatewayManifest, ManifestError> {
    if raw.len() > MAX_MANIFEST_BYTES {
        return Err(invalid(format!(
            "manifest larger than {MAX_MANIFEST_BYTES} bytes"
        )));
    }
    let doc: Value = serde_json::from_slice(raw).map_err(invalid)?;
    super::schema::validate(&doc).map_err(|e| invalid(format!("schema: {e}")))?;
    let mut m = decode(&doc);
    m.check()?;
    Ok(m)
}

fn s(v: Option<&Value>) -> String {
    v.and_then(Value::as_str).unwrap_or_default().to_owned()
}

fn b(v: Option<&Value>) -> bool {
    v.and_then(Value::as_bool).unwrap_or(false)
}

/// Go json.Unmarshal into an int field: a fractional or exponent literal is
/// a type error that leaves the field zero.
fn i(v: Option<&Value>) -> i64 {
    v.and_then(Value::as_i64).unwrap_or(0)
}

fn strs(v: Option<&Value>) -> Option<Vec<String>> {
    v.and_then(Value::as_array).map(|a| {
        a.iter()
            .map(|x| x.as_str().unwrap_or_default().to_owned())
            .collect()
    })
}

fn objs(v: Option<&Value>) -> Vec<&Map<String, Value>> {
    v.and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_object).collect())
        .unwrap_or_default()
}

/// Go json.Unmarshal into the portal struct (after the schema has refused
/// wrong types and unknown fields).
fn decode(doc: &Value) -> GatewayManifest {
    let remote = doc.get("remote").and_then(Value::as_object);
    GatewayManifest {
        module: s(doc.get("module")),
        display_name: s(doc.get("display_name")),
        version: s(doc.get("version")),
        prefixes: strs(doc.get("prefixes")).unwrap_or_default(),
        routes: objs(doc.get("routes"))
            .into_iter()
            .map(|r| GwRoute {
                method: s(r.get("method")),
                path: s(r.get("path")),
                permission: s(r.get("permission")),
                public: b(r.get("public")),
                max_body_bytes: i(r.get("max_body_bytes")),
                timeout: s(r.get("timeout")),
                client_address: b(r.get("client_address")),
            })
            .collect(),
        methods: objs(doc.get("methods"))
            .into_iter()
            .map(|m| GwMethod {
                full_method: s(m.get("full_method")),
                permission: s(m.get("permission")),
                public: b(m.get("public")),
                streaming: b(m.get("streaming")),
                max_stream_duration: s(m.get("max_stream_duration")),
            })
            .collect(),
        permissions: objs(doc.get("permissions"))
            .into_iter()
            .map(|p| GwPermission {
                resource: s(p.get("resource")),
                action: s(p.get("action")),
                description: s(p.get("description")),
            })
            .collect(),
        abilities: objs(doc.get("abilities"))
            .into_iter()
            .map(|a| GwAbility {
                action: strs(a.get("action")),
                subject: strs(a.get("subject")),
                fields: strs(a.get("fields")).unwrap_or_default(),
                conditions: a
                    .get("conditions")
                    .and_then(Value::as_object)
                    .cloned()
                    .unwrap_or_default(),
                inverted: b(a.get("inverted")),
                reason: s(a.get("reason")),
                requires: s(a.get("requires")),
            })
            .collect(),
        remote: GwRemote {
            entry: s(remote.and_then(|r| r.get("entry"))),
            exposes: strs(remote.and_then(|r| r.get("exposes"))).unwrap_or_default(),
            integrity: s(remote.and_then(|r| r.get("integrity"))),
        },
        nav: objs(doc.get("nav"))
            .into_iter()
            .map(|n| GwNav {
                title: s(n.get("title")),
                path: s(n.get("path")),
                icon: s(n.get("icon")),
                order: i(n.get("order")),
                requires: s(n.get("requires")),
            })
            .collect(),
    }
}

/// durationpb `AsDuration` (saturating), in nanoseconds.
fn as_duration(d: Option<&prost_types::Duration>) -> i128 {
    let Some(d) = d else { return 0 };
    let n = i128::from(d.seconds) * 1_000_000_000 + i128::from(d.nanos);
    n.clamp(i128::from(i64::MIN), i128::from(i64::MAX))
}

/// convert.go `dur`: the schema grammar (`^[0-9]+(ms|s|m)$`).
pub(crate) fn dur(n: i128) -> String {
    const SEC: i128 = 1_000_000_000;
    const MIN: i128 = 60 * SEC;
    if n <= 0 {
        String::new()
    } else if n % MIN == 0 {
        format!("{}m", n / MIN)
    } else if n % SEC == 0 {
        format!("{}s", n / SEC)
    } else {
        format!("{}ms", n / 1_000_000)
    }
}

/// structpb `AsMap`.
fn struct_map(s: &prost_types::Struct) -> Map<String, Value> {
    s.fields.iter().map(|(k, v)| (k.clone(), pb_value(v))).collect()
}

fn pb_value(v: &prost_types::Value) -> Value {
    use prost_types::value::Kind;
    match &v.kind {
        None | Some(Kind::NullValue(_)) => Value::Null,
        Some(Kind::BoolValue(b)) => Value::Bool(*b),
        Some(Kind::NumberValue(n)) => serde_json::Number::from_f64(*n).map_or(Value::Null, Value::Number),
        Some(Kind::StringValue(s)) => Value::String(s.clone()),
        Some(Kind::ListValue(l)) => Value::Array(l.values.iter().map(pb_value).collect()),
        Some(Kind::StructValue(s)) => Value::Object(struct_map(s)),
    }
}

/// convert.go `fromProtoNoValidate`.
fn from_proto_no_validate(p: &pb::Manifest) -> GatewayManifest {
    let nil = |v: &Vec<String>| (!v.is_empty()).then(|| v.clone());
    GatewayManifest {
        module: p.module.clone(),
        display_name: p.display_name.clone(),
        version: p.version.clone(),
        prefixes: p
            .prefixes
            .iter()
            .map(|pf| normalize_prefix(pf).unwrap_or_else(|| pf.clone()))
            .collect(),
        routes: p
            .routes
            .iter()
            .map(|r| GwRoute {
                method: r.method.clone(),
                path: r.path.clone(),
                permission: r.permission.clone(),
                public: r.public,
                // int64(uint64): wraps like Go (convert.go:28).
                max_body_bytes: r.max_body_bytes as i64,
                timeout: dur(as_duration(r.timeout.as_ref())),
                client_address: r.client_address,
            })
            .collect(),
        methods: p
            .methods
            .iter()
            .map(|m| GwMethod {
                full_method: m.full_method.clone(),
                permission: m.permission.clone(),
                public: m.public,
                streaming: m.streaming,
                max_stream_duration: dur(as_duration(m.max_stream_duration.as_ref())),
            })
            .collect(),
        permissions: p
            .permissions
            .iter()
            .map(|x| GwPermission {
                resource: x.resource.clone(),
                action: x.action.clone(),
                description: x.description.clone(),
            })
            .collect(),
        abilities: p
            .abilities
            .iter()
            .map(|a| GwAbility {
                action: nil(&a.action),
                subject: nil(&a.subject),
                fields: a.fields.clone(),
                conditions: a.conditions.as_ref().map(struct_map).unwrap_or_default(),
                inverted: a.inverted,
                reason: a.reason.clone(),
                requires: a.requires.clone(),
            })
            .collect(),
        remote: p
            .remote
            .as_ref()
            .map(|r| GwRemote {
                entry: r.entry.clone(),
                exposes: r.exposes.clone(),
                integrity: r.integrity.clone(),
            })
            .unwrap_or_default(),
        nav: p
            .nav
            .iter()
            .map(|n| GwNav {
                title: n.title.clone(),
                path: n.path.clone(),
                icon: n.icon.clone(),
                order: i64::from(n.order),
                requires: n.requires.clone(),
            })
            .collect(),
    }
}

/// Go `%q` (strconv.Quote) for the strings that appear in messages.
pub(crate) fn goq(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{7}' => out.push_str("\\a"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{b}' => out.push_str("\\v"),
            c if (c as u32) < 0x20 || c == '\u{7f}' => out.push_str(&format!("\\x{:02x}", c as u32)),
            c if c.is_control() => {
                if (c as u32) <= 0xffff {
                    out.push_str(&format!("\\u{:04x}", c as u32));
                } else {
                    out.push_str(&format!("\\U{:08x}", c as u32));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}
