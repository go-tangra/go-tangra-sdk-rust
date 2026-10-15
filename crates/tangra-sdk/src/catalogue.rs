//! How a module describes itself to the gateway's module catalogue (spec
//! 035; go-tangra `catalogue/catalogue.go`): the `tangra-module.yaml`
//! descriptor (schema 1), decoded strictly and validated with the Go rules
//! and messages.
//!
//! Releases keep using the Go tooling: the `catalogue-entry` action
//! (`go-tangra/go-tangra/.github/actions/catalogue-entry`) runs
//! `tangra-catalogue build`, which validates the descriptor again, packs
//! `deploy/bundle` into `bundle.zip`, writes `catalogue-entry.json` and
//! attests both. The action needs a `permissions-command` printing the
//! module's permissions as a JSON array; a Rust module provides it with a
//! tiny binary calling [`print_permissions`]:
//!
//! ```no_run
//! // src/bin/orders-catalogue-permissions.rs
//! fn main() -> std::io::Result<()> {
//!     tangra_sdk::catalogue::print_permissions(["orders:read", "orders:write"])
//! }
//! ```
//!
//! with `permissions-command: cargo run -q --bin orders-catalogue-permissions`.

use std::collections::{BTreeMap, HashSet};
use std::sync::LazyLock;

use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::gocompat::{self, quote};
use crate::goyaml::{self, Kind as NodeKind, Node};

/// The descriptor and entry format version.
pub const SCHEMA: i64 = 1;
const MAX_HOST_INPUTS: usize = 20;
const MAX_TEMPLATES: usize = 20;

/// A refused descriptor (Go wraps every refusal in `catalogue: invalid`).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("catalogue: invalid: {0}")]
pub struct Invalid(pub String);

fn invalid(msg: String) -> Invalid {
    Invalid(msg)
}

/// `tangra-module.yaml`. Field order and `omitempty` follow the Go struct,
/// so the JSON encoding is identical.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Descriptor {
    /// Must be [`SCHEMA`].
    #[serde(default)]
    pub schema: i64,
    /// The module (service) name.
    #[serde(default)]
    pub module: String,
    /// 1-60 characters.
    #[serde(default)]
    pub display_name: String,
    /// At most 40 characters.
    #[serde(default)]
    pub category: String,
    /// At most 200 characters.
    #[serde(default)]
    pub summary: String,
    /// The image repository, without tag or digest.
    #[serde(default)]
    pub image: String,
    /// The allow-list scope the module asks for.
    #[serde(default)]
    pub routes: Routes,
    /// Minimum core versions (`gateway`, `auth`, `lcm` -> `X.Y.Z`).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub min_core: BTreeMap<String, String>,
    /// Where the install bundle lives and which files are templates.
    #[serde(default)]
    pub bundle: BundleSpec,
    /// Values the operator supplies for the target host.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub host_inputs: Vec<HostInput>,
    /// An https URL.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub docs: String,
}

/// The allow-list scope.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Routes {
    /// `/api/<m>`, `/m/<m>`, `/<m>` or paths under them; 1-10.
    #[serde(default)]
    pub prefixes: Vec<String>,
    /// Exactly `[<module>]`.
    #[serde(default)]
    pub names: Vec<String>,
}

/// The install bundle.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleSpec {
    /// A relative path inside the repository.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub dir: String,
    /// 1-20 files of the bundle rendered with the placeholders.
    #[serde(default)]
    pub templates: Vec<String>,
    /// Hosts that get a server certificate from a local CA at join time.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tls_hosts: Vec<String>,
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// A value the operator supplies for the target host. A non-empty value
/// must match `pattern`; an `optional` input may be left empty.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostInput {
    /// `^[A-Z][A-Z0-9_]{1,63}$`, not [`reserved`].
    #[serde(default)]
    pub key: String,
    /// 1-100 characters.
    #[serde(default)]
    pub label: String,
    /// An anchored (`^...$`) regular expression.
    #[serde(default)]
    pub pattern: String,
    /// Must match `pattern` when set.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub default: String,
    /// May be left empty (gateway 4.9.0+).
    #[serde(default, skip_serializing_if = "is_false")]
    pub optional: bool,
}

const MODULE_SRC: &str = r"^[a-z0-9][a-z0-9-]{0,62}$";
const KEY_SRC: &str = r"^[A-Z][A-Z0-9_]{1,63}$";

#[allow(clippy::expect_used)]
fn re(s: &str) -> Regex {
    Regex::new(s).expect("regex")
}

static MODULE_RE: LazyLock<Regex> = LazyLock::new(|| re(MODULE_SRC));
static IMAGE_RE: LazyLock<Regex> = LazyLock::new(|| re(r"^[a-z0-9.-]+(:[0-9]{1,5})?(/[a-z0-9._-]+)+$"));
static VERSION_RE: LazyLock<Regex> =
    LazyLock::new(|| re(r"^(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})$"));
static KEY_RE: LazyLock<Regex> = LazyLock::new(|| re(KEY_SRC));
static HOST_RE: LazyLock<Regex> =
    LazyLock::new(|| re(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$"));
static PERM_RE: LazyLock<Regex> =
    LazyLock::new(|| re(r"^[a-z0-9][a-z0-9_.-]{0,63}:[a-z0-9][a-z0-9_.-]{0,63}$"));

/// Whether `key` is a placeholder the gateway fills itself (core values,
/// `MODULE`, `MODULE_VERSION`, `MODULE_IMAGE`, and every `GEN_*` value).
pub fn reserved(key: &str) -> bool {
    matches!(
        key,
        "TRUST_DOMAIN"
            | "GATEWAY_ISSUER"
            | "LCM_ENROLL_URL"
            | "AUTH_GRPC"
            | "GATEWAY_GRPC"
            | "LCM_GRPC"
            | "MESH_TENANT_ID"
            | "MODULE_VERSION"
            | "MODULE_IMAGE"
            | "MODULE"
    ) || key.starts_with("GEN_")
}

/// Whether `v` is a release version `X.Y.Z` (no `v`, no pre-release).
pub fn valid_version(v: &str) -> bool {
    VERSION_RE.is_match(v)
}

/// Whether `p` is a `resource:action` permission.
pub fn valid_permission(p: &str) -> bool {
    PERM_RE.is_match(p)
}

/// Decodes `tangra-module.yaml` strictly (unknown fields are refused) and
/// validates it (Go `ParseDescriptor`). Decoding follows yaml.v3 with
/// `KnownFields(true)`: scalars of any type decode into strings with their
/// source text, and every type error, unknown or duplicate key is reported
/// in yaml.v3's words.
pub fn parse_descriptor(raw: &[u8]) -> Result<Descriptor, Invalid> {
    let decode_err = |e: &str| invalid(format!("tangra-module.yaml: {e}"));
    let src = std::str::from_utf8(raw).map_err(|_| decode_err("yaml: invalid leading UTF-8 octet"))?;
    let root = goyaml::parse(src)
        .map_err(|e| decode_err(&format!("yaml: {e}")))?
        .ok_or_else(|| decode_err("EOF"))?;
    let mut dec = Dec::default();
    let mut d = Descriptor::default();
    dec.descriptor(&root, &mut d);
    if !dec.errs.is_empty() {
        return Err(decode_err(&format!(
            "yaml: unmarshal errors:\n  {}",
            dec.errs.join("\n  ")
        )));
    }
    d.validate()?;
    Ok(d)
}

/// yaml.v3's struct decoder over [`goyaml`] nodes, collecting type errors.
#[derive(Default)]
struct Dec {
    errs: Vec<String>,
}

impl Dec {
    fn string(&mut self, n: &Node, out: &mut String) {
        if goyaml::decode_string(n, out).is_err() {
            self.errs.push(goyaml::terror(n, "string"));
        }
    }

    fn int(&mut self, n: &Node, out: &mut i64) {
        if goyaml::decode_int(n, out).is_err() {
            self.errs.push(goyaml::terror(n, "int"));
        }
    }

    fn bool(&mut self, n: &Node, out: &mut bool) {
        if goyaml::decode_bool(n, out).is_err() {
            self.errs.push(goyaml::terror(n, "bool"));
        }
    }

    fn strings(&mut self, n: &Node, out: &mut Vec<String>) {
        match &n.kind {
            NodeKind::Seq(items) => {
                let mut good = Vec::with_capacity(items.len());
                for it in items {
                    let mut s = String::new();
                    match goyaml::decode_string(it, &mut s) {
                        Ok(true) => good.push(s),
                        Ok(false) => {}
                        Err(()) => self.errs.push(goyaml::terror(it, "string")),
                    }
                }
                *out = good;
            }
            _ if goyaml::is_null(n) => out.clear(),
            _ => self.errs.push(goyaml::terror(n, "[]string")),
        }
    }

    /// The pairs of a mapping decoded into the Go type `ty` (yaml.v3
    /// `mapping`): duplicate keys are reported and stop that mapping; a
    /// non-mapping is a type error (null leaves the target unchanged).
    fn mapping<'n>(&mut self, n: &'n Node, ty: &str) -> Vec<&'n (Node, Node)> {
        let NodeKind::Map(pairs) = &n.kind else {
            if !goyaml::is_null(n) {
                self.errs.push(goyaml::terror(n, ty));
            }
            return Vec::new();
        };
        let before = self.errs.len();
        for (i, (ki, _)) in pairs.iter().enumerate() {
            for (kj, _) in &pairs[i + 1..] {
                if std::mem::discriminant(&ki.kind) == std::mem::discriminant(&kj.kind)
                    && ki.key_text() == kj.key_text()
                {
                    self.errs.push(format!(
                        "line {}: mapping key {} already defined at line {}",
                        kj.line,
                        quote(kj.key_text()),
                        ki.line
                    ));
                }
            }
        }
        if self.errs.len() > before {
            return Vec::new();
        }
        pairs.iter().collect()
    }

    /// `KnownFields(true)`: a key that names no field of `ty`.
    fn unknown(&mut self, k: &Node, ty: &str) {
        self.errs.push(format!(
            "line {}: field {} not found in type {ty}",
            k.line,
            k.key_text()
        ));
    }

    fn descriptor(&mut self, n: &Node, d: &mut Descriptor) {
        const TY: &str = "catalogue.Descriptor";
        for (k, v) in self.mapping(n, TY) {
            match k.key_text() {
                "schema" => self.int(v, &mut d.schema),
                "module" => self.string(v, &mut d.module),
                "display_name" => self.string(v, &mut d.display_name),
                "category" => self.string(v, &mut d.category),
                "summary" => self.string(v, &mut d.summary),
                "image" => self.string(v, &mut d.image),
                "routes" => {
                    for (k, v) in self.mapping(v, "catalogue.Routes") {
                        match k.key_text() {
                            "prefixes" => self.strings(v, &mut d.routes.prefixes),
                            "names" => self.strings(v, &mut d.routes.names),
                            _ => self.unknown(k, "catalogue.Routes"),
                        }
                    }
                }
                "min_core" => {
                    if goyaml::is_null(v) {
                        d.min_core.clear();
                    }
                    for (k, v) in self.mapping(v, "map[string]string") {
                        let mut key = String::new();
                        self.string(k, &mut key);
                        let mut val = String::new();
                        self.string(v, &mut val);
                        d.min_core.insert(key, val);
                    }
                }
                "bundle" => {
                    for (k, v) in self.mapping(v, "catalogue.BundleSpec") {
                        match k.key_text() {
                            "dir" => self.string(v, &mut d.bundle.dir),
                            "templates" => self.strings(v, &mut d.bundle.templates),
                            "tls_hosts" => self.strings(v, &mut d.bundle.tls_hosts),
                            _ => self.unknown(k, "catalogue.BundleSpec"),
                        }
                    }
                }
                "host_inputs" => self.host_inputs(v, &mut d.host_inputs),
                "docs" => self.string(v, &mut d.docs),
                _ => self.unknown(k, TY),
            }
        }
    }

    fn host_inputs(&mut self, n: &Node, out: &mut Vec<HostInput>) {
        let items = match &n.kind {
            NodeKind::Seq(items) => items,
            _ if goyaml::is_null(n) => {
                out.clear();
                return;
            }
            _ => {
                self.errs.push(goyaml::terror(n, "[]catalogue.HostInput"));
                return;
            }
        };
        out.clear();
        for it in items {
            // A null element does not decode into a struct and is dropped.
            if goyaml::is_null(it) {
                continue;
            }
            if !matches!(it.kind, NodeKind::Map(_)) {
                self.errs.push(goyaml::terror(it, "catalogue.HostInput"));
                continue;
            }
            let mut h = HostInput::default();
            for (k, v) in self.mapping(it, "catalogue.HostInput") {
                match k.key_text() {
                    "key" => self.string(v, &mut h.key),
                    "label" => self.string(v, &mut h.label),
                    "pattern" => self.string(v, &mut h.pattern),
                    "default" => self.string(v, &mut h.default),
                    "optional" => self.bool(v, &mut h.optional),
                    _ => self.unknown(k, "catalogue.HostInput"),
                }
            }
            out.push(h);
        }
    }
}

impl Descriptor {
    /// Checks every field (Go `Descriptor.Validate`).
    pub fn validate(&self) -> Result<(), Invalid> {
        if self.schema != SCHEMA {
            return Err(invalid(format!("schema must be {SCHEMA}")));
        }
        validate_common(self)?;
        if self.bundle.dir.is_empty() || !local(&self.bundle.dir) {
            return Err(invalid(
                "bundle.dir must be a relative path inside the repository".to_owned(),
            ));
        }
        validate_bundle_spec(&self.bundle.templates, &self.bundle.tls_hosts)
    }
}

fn validate_common(d: &Descriptor) -> Result<(), Invalid> {
    let m = &d.module;
    if !MODULE_RE.is_match(m) {
        return Err(invalid(format!("module {} must match {MODULE_SRC}", quote(m))));
    }
    if d.display_name.is_empty() || d.display_name.len() > 60 {
        return Err(invalid("display_name must be 1-60 characters".to_owned()));
    }
    if d.category.len() > 40 {
        return Err(invalid("category must be at most 40 characters".to_owned()));
    }
    if d.summary.len() > 200 {
        return Err(invalid("summary must be at most 200 characters".to_owned()));
    }
    if !IMAGE_RE.is_match(&d.image) {
        return Err(invalid(format!(
            "image {} must be a repository without tag or digest",
            quote(&d.image)
        )));
    }
    let r = &d.routes;
    if r.prefixes.is_empty() || r.prefixes.len() > 10 {
        return Err(invalid("routes.prefixes must list 1-10 prefixes".to_owned()));
    }
    for p in &r.prefixes {
        if !in_scope(p, m) {
            return Err(invalid(format!(
                "routes.prefixes: {} is outside /api/{m}, /m/{m} and /{m}",
                quote(p)
            )));
        }
    }
    if r.names.len() != 1 || r.names[0] != *m {
        return Err(invalid(format!("routes.names must be [{m}]")));
    }
    for (k, v) in &d.min_core {
        if k != "gateway" && k != "auth" && k != "lcm" {
            return Err(invalid(format!(
                "min_core: unknown component {} (gateway, auth, lcm)",
                quote(k)
            )));
        }
        if !valid_version(v) {
            return Err(invalid(format!("min_core.{k}: {} is not X.Y.Z", quote(v))));
        }
    }
    if d.host_inputs.len() > MAX_HOST_INPUTS {
        return Err(invalid(format!("at most {MAX_HOST_INPUTS} host_inputs")));
    }
    let mut seen = HashSet::new();
    for i in &d.host_inputs {
        let k = &i.key;
        if !KEY_RE.is_match(k) {
            return Err(invalid(format!(
                "host_inputs: key {} must match {KEY_SRC}",
                quote(k)
            )));
        }
        if reserved(k) {
            return Err(invalid(format!("host_inputs: {k} is filled by the gateway")));
        }
        if seen.contains(k.as_str()) {
            return Err(invalid(format!("host_inputs: {k} twice")));
        }
        if i.label.is_empty() || i.label.len() > 100 {
            return Err(invalid(format!(
                "host_inputs.{k}: label must be 1-100 characters"
            )));
        }
        if !i.pattern.starts_with('^') || !i.pattern.ends_with('$') {
            return Err(invalid(format!(
                "host_inputs.{k}: pattern must be anchored (^...$)"
            )));
        }
        seen.insert(k.as_str());
        let pat = Regex::new(&i.pattern)
            .map_err(|e| invalid(format!("host_inputs.{k}: pattern: {}", regex_error(&e))))?;
        if !i.default.is_empty() && !pat.is_match(&i.default) {
            return Err(invalid(format!(
                "host_inputs.{k}: default does not match the pattern"
            )));
        }
    }
    if !d.docs.is_empty() && !https_url(&d.docs) {
        return Err(invalid("docs must be an https URL".to_owned()));
    }
    Ok(())
}

/// The first line of a regex syntax error (the `regex` crate's wording;
/// Go's reads `error parsing regexp: ...`).
fn regex_error(e: &regex::Error) -> String {
    let s = e.to_string();
    let last = s.lines().rfind(|l| !l.trim().is_empty()).unwrap_or("");
    format!(
        "error parsing regexp: {}",
        last.trim().trim_start_matches("error: ")
    )
}

fn validate_bundle_spec(templates: &[String], tls_hosts: &[String]) -> Result<(), Invalid> {
    if templates.is_empty() || templates.len() > MAX_TEMPLATES {
        return Err(invalid(format!(
            "bundle.templates must list 1-{MAX_TEMPLATES} files"
        )));
    }
    for t in templates {
        if !local(t) {
            return Err(invalid(format!(
                "bundle.templates: {} must be a relative path inside the bundle",
                quote(t)
            )));
        }
    }
    for h in tls_hosts {
        if !HOST_RE.is_match(h) {
            return Err(invalid(format!(
                "bundle.tls_hosts: {} is not a host name",
                quote(h)
            )));
        }
    }
    Ok(())
}

/// `p` is `/api/<m>`, `/m/<m>` or `/<m>`, or a path under one of them.
fn in_scope(p: &str, module: &str) -> bool {
    if p != gocompat::clean(p) {
        return false;
    }
    [
        format!("/api/{module}"),
        format!("/m/{module}"),
        format!("/{module}"),
    ]
    .iter()
    .any(|root| p == root || p.starts_with(&format!("{root}/")))
}

/// A clean relative path that stays inside its root.
fn local(p: &str) -> bool {
    !p.is_empty() && !p.contains('\\') && gocompat::valid_path(p) && p != "."
}

/// `url.Parse(s)` succeeds with scheme `https` and a non-empty host.
fn https_url(s: &str) -> bool {
    if s.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return false;
    }
    let Some((scheme, rest)) = s.split_once(':') else {
        return false;
    };
    let valid_scheme = scheme
        .bytes()
        .enumerate()
        .all(|(i, b)| b.is_ascii_alphabetic() || (i > 0 && (b.is_ascii_digit() || b"+-.".contains(&b))));
    if scheme.is_empty() || !valid_scheme || !scheme.eq_ignore_ascii_case("https") {
        return false;
    }
    let rest = rest.split_once('#').map_or(rest, |(a, _)| a);
    let rest = rest.split_once('?').map_or(rest, |(a, _)| a);
    let Some(auth) = rest.strip_prefix("//") else {
        return false;
    };
    let auth = auth.split_once('/').map_or(auth, |(a, _)| a);
    let host = auth.rsplit_once('@').map_or(auth, |(_, h)| h);
    if host.contains('%') && gocompat::path_unescape(host).is_err() {
        return false;
    }
    // validOptionalPort.
    let port = if host.starts_with('[') {
        host.rsplit_once(']').map_or("", |(_, p)| p)
    } else {
        host.rsplit_once(':').map_or("", |(_, p)| p)
    };
    let has_port = host.starts_with('[') && !port.is_empty() || !host.starts_with('[') && host.contains(':');
    if has_port {
        let digits = port.strip_prefix(':').unwrap_or(port);
        if !digits.bytes().all(|b| b.is_ascii_digit()) {
            return false;
        }
    }
    !host.is_empty()
}

/// The module's permissions as Go's `json.Encoder` writes a `[]string`
/// (one line, newline-terminated): the output the catalogue action's
/// `permissions-command` must print.
pub fn permissions_json<I, S>(perms: I) -> String
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let v: Vec<String> = perms.into_iter().map(|p| p.as_ref().to_owned()).collect();
    let mut s = crate::gofmt::json_html_escaped(&v);
    s.push('\n');
    s
}

/// Prints [`permissions_json`] on stdout.
pub fn print_permissions<I, S>(perms: I) -> std::io::Result<()>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    use std::io::Write as _;
    std::io::stdout().write_all(permissions_json(perms).as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    /// Every fixture against go-tangra's verdict (`<name>.golden`): `ok` +
    /// Go's JSON of the descriptor, or `error: ` + Go's message.
    #[test]
    fn descriptors_match_go() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/catalogue");
        let mut names: Vec<String> = std::fs::read_dir(&dir)
            .expect("fixtures")
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter_map(|n| n.strip_suffix(".yaml").map(str::to_owned))
            .collect();
        names.sort();
        assert!(names.len() >= 45, "{names:?}");
        let (mut ok, mut bad) = (0, 0);
        for name in names {
            let raw = std::fs::read(dir.join(format!("{name}.yaml"))).expect("yaml");
            let golden = std::fs::read_to_string(dir.join(format!("{name}.golden"))).expect("golden");
            match (parse_descriptor(&raw), golden.strip_prefix("ok\n")) {
                (Ok(d), Some(json)) => {
                    assert_eq!(crate::gofmt::json_html_escaped(&d), json.trim_end(), "{name}");
                    ok += 1;
                }
                (Err(e), None) => {
                    let want = golden.strip_prefix("error: ").expect("format").trim_end();
                    let got = e.to_string();
                    // Regex syntax errors are worded by Go's regexp; the
                    // refusal and its field match.
                    let p = "catalogue: invalid: host_inputs.VALKEY_CA_FILE: pattern: error parsing regexp: ";
                    if want.starts_with(p) {
                        assert!(got.starts_with(p), "{name}: {got}");
                    } else {
                        assert_eq!(got, want, "{name}");
                    }
                    bad += 1;
                }
                (got, _) => panic!("{name}: got {got:?}, Go said {golden}"),
            }
        }
        assert!(ok >= 10 && bad >= 35, "{ok} ok, {bad} refused");
    }

    #[test]
    fn scalars_decode_like_yaml_v3() {
        let base = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/catalogue/warden.yaml"),
        )
        .expect("fixture");
        let v = base
            .replace("category: Security", "category: 12.5")
            .replace("    default: warden", "    default: 0x1f\n    optional: yes");
        let d = parse_descriptor(v.as_bytes()).expect("valid");
        assert_eq!(d.category, "12.5");
        let mount = d
            .host_inputs
            .iter()
            .find(|h| h.key == "VAULT_MOUNT")
            .expect("input");
        assert_eq!((mount.default.as_str(), mount.optional), ("0x1f", true));
    }

    #[test]
    fn helpers() {
        assert!(reserved("GEN_X") && reserved("MODULE") && !reserved("MODULE_ADVERTISE_HOST"));
        assert!(valid_version("4.10.0") && !valid_version("v4.10.0") && !valid_version("01.1.1"));
        assert_eq!(
            permissions_json(["orders:read", "orders:write"]),
            "[\"orders:read\",\"orders:write\"]\n"
        );
        assert_eq!(permissions_json(Vec::<String>::new()), "[]\n");
        assert!(valid_permission("a-b.c_d:read.all") && !valid_permission("a:B"));
        for (u, want) in [
            ("https://github.com/x#readme", true),
            ("HTTPS://h:443/p", true),
            ("https://h:x/", false),
            ("https:///p", false),
            ("https:h", false),
            ("http://h", false),
            ("https://u@h", true),
            ("https://[::1]:8443", true),
            ("https://h/\u{1}", false),
        ] {
            assert_eq!(https_url(u), want, "{u}");
        }
    }
}
