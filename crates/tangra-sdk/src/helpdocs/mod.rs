//! A module's user documentation (go-tangra `helpdocs/`): Markdown pages
//! with YAML front-matter plus images, kept under `docs/help`, embedded in
//! the binary, loaded once at start-up and served to the gateway as one
//! bundle at `GET /docs/v1/bundle`.
//!
//! ```no_run
//! # fn demo(app: &tangra_sdk::app::App) -> Result<(), tangra_sdk::helpdocs::Problems> {
//! use tangra_sdk::fstree::FileTree;
//! use tangra_sdk::helpdocs::{self, AllowServices};
//!
//! static HELP: include_dir::Dir<'static> = include_dir::include_dir!("$CARGO_MANIFEST_DIR/src");
//! let bundle = helpdocs::load(&FileTree::from_embedded(&HELP), "orders")?;
//! let digest = bundle.digest().to_owned(); // announce at gateway registration
//! let router = axum::Router::new().merge(helpdocs::router(bundle, AllowServices::new(["gateway"])));
//! # let _ = (app, digest, router); Ok(()) }
//! ```
//!
//! Everything is strict, with the Go loader's rules and messages: unknown
//! front-matter keys, unresolved relative links, SVG and unsniffable images,
//! oversize trees are refused, and every problem is reported (as
//! [`Problems`]), not just the first. The bundle JSON is byte-identical to
//! Go's `json.Marshal` and [`compute_digest`] is the Go `ComputeDigest`.

mod cli;
mod frontmatter;
mod handler;
mod links;

#[cfg(test)]
mod tests;

pub use cli::cli;
pub use handler::{AllowServices, Authorizer, BUNDLE_PATH, DEFAULT_GATEWAY_SERVICE, handler, router};

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::sync::LazyLock;

use base64::Engine as _;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::fstree::FileTree;
use crate::gocompat::{self, quote};
use crate::identity::valid_service_name;

/// The bundle wire format version.
pub const SCHEMA: i64 = 1;
/// Where a module repository keeps its help pages.
pub const DEFAULT_DIR: &str = "docs/help";
/// At most this many pages.
pub const MAX_PAGES: usize = 500;
/// Per-page byte limit.
pub const MAX_PAGE_BYTES: usize = 256 << 10;
/// Per-image byte limit.
pub const MAX_ASSET_BYTES: usize = 512 << 10;
/// Limit of pages and images together.
pub const MAX_TOTAL_BYTES: usize = 4 << 20;

/// Page kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// `guide`
    Guide,
    /// `example`
    Example,
    /// `reference`
    Reference,
    /// `faq`
    Faq,
}

impl Kind {
    /// The wire string.
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Guide => "guide",
            Kind::Example => "example",
            Kind::Reference => "reference",
            Kind::Faq => "faq",
        }
    }

    /// Parses a wire string.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "guide" => Some(Kind::Guide),
            "example" => Some(Kind::Example),
            "reference" => Some(Kind::Reference),
            "faq" => Some(Kind::Faq),
            _ => None,
        }
    }
}

/// Who a page is written for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Audience {
    /// `user` (default)
    User,
    /// `operator`
    Operator,
}

impl Audience {
    /// The wire string.
    pub fn as_str(self) -> &'static str {
        match self {
            Audience::User => "user",
            Audience::Operator => "operator",
        }
    }

    /// Parses a wire string.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "user" => Some(Audience::User),
            "operator" => Some(Audience::Operator),
            _ => None,
        }
    }
}

fn is_empty_vec(v: &[String]) -> bool {
    v.is_empty()
}

/// One help page. `markdown` is the page source without its front-matter;
/// the gateway renders and sanitizes it. Field order and `omitempty` follow
/// the Go struct, so the JSON is identical.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Page {
    /// Path without `.md`; `x/index.md` is `x`.
    pub slug: String,
    /// One line, at most 200 characters.
    pub title: String,
    /// At most 500 characters.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub summary: String,
    /// `guide`, `example`, `reference` or `faq` ([`Kind`]).
    pub kind: String,
    /// Sort order (default 0).
    pub order: i64,
    /// At most 20 tags of `[a-z0-9-]`.
    #[serde(default, skip_serializing_if = "is_empty_vec")]
    pub tags: Vec<String>,
    /// A `resource:action` permission gating the page.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub requires: String,
    /// `user` or `operator` ([`Audience`]).
    pub audience: String,
    /// Only `en`.
    pub lang: String,
    /// The Markdown body.
    pub markdown: String,
}

mod b64 {
    use base64::Engine as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&base64::engine::general_purpose::STANDARD.encode(v))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        base64::engine::general_purpose::STANDARD
            .decode(s)
            .map_err(serde::de::Error::custom)
    }
}

/// An image referenced by pages; `data` is base64 on the wire.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Asset {
    /// Relative to the docs root, `/`-separated.
    pub path: String,
    /// The sniffed type (`image/png`, `image/jpeg`, `image/gif`, `image/webp`).
    pub mime: String,
    /// Byte length.
    pub size: i64,
    /// Hex SHA-256 of `data`.
    pub sha256: String,
    /// The image bytes.
    #[serde(with = "b64")]
    pub data: Vec<u8>,
}

/// A module's complete help content as served to the gateway. Pages are
/// sorted by slug and assets by path.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bundle {
    /// [`SCHEMA`].
    pub schema: i64,
    /// The module (service) name.
    pub module: String,
    /// [`compute_digest`] of the content; "" for an empty bundle.
    pub digest: String,
    /// Pages by slug.
    pub pages: Vec<Page>,
    /// Images by path.
    pub assets: Vec<Asset>,
}

impl Bundle {
    /// An empty bundle (a module without docs; digest "").
    pub fn empty(module: &str) -> Self {
        Self {
            schema: SCHEMA,
            module: module.to_owned(),
            ..Self::default()
        }
    }

    /// No pages.
    pub fn is_empty(&self) -> bool {
        self.pages.is_empty()
    }

    /// The digest to announce at gateway registration (`docs_digest`; ""
    /// for a module without docs).
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// The JSON encoding, byte-identical to Go's `json.Marshal(bundle)`
    /// (HTML-safe escaping of `<`, `>`, `&`, U+2028, U+2029).
    pub fn marshal(&self) -> Vec<u8> {
        crate::gofmt::json_html_escaped(self).into_bytes()
    }
}

/// The SHA-256 (hex) of the bundle's canonical encoding (Go
/// `ComputeDigest`): every string as u64-BE length + bytes, counts as u64
/// BE; `"tangra-helpdocs"`, schema, module, the pages sorted by slug, then
/// the assets sorted by path (asset bytes enter via their sha256). Empty
/// bundle: "".
pub fn compute_digest(b: &Bundle) -> String {
    if b.is_empty() {
        return String::new();
    }
    let mut pages: Vec<&Page> = b.pages.iter().collect();
    pages.sort_by(|x, y| x.slug.cmp(&y.slug));
    let mut assets: Vec<&Asset> = b.assets.iter().collect();
    assets.sort_by(|x, y| x.path.cmp(&y.path));
    let mut h = Sha256::new();
    let num = |h: &mut Sha256, n: usize| h.update((n as u64).to_be_bytes());
    let st = |h: &mut Sha256, s: &str| {
        num(h, s.len());
        h.update(s.as_bytes());
    };
    st(&mut h, "tangra-helpdocs");
    st(&mut h, &b.schema.to_string());
    st(&mut h, &b.module);
    num(&mut h, pages.len());
    for p in pages {
        st(&mut h, &p.slug);
        st(&mut h, &p.title);
        st(&mut h, &p.summary);
        st(&mut h, &p.kind);
        st(&mut h, &p.order.to_string());
        num(&mut h, p.tags.len());
        for t in &p.tags {
            st(&mut h, t);
        }
        st(&mut h, &p.requires);
        st(&mut h, &p.audience);
        st(&mut h, &p.lang);
        st(&mut h, &p.markdown);
    }
    num(&mut h, assets.len());
    for a in assets {
        st(&mut h, &a.path);
        st(&mut h, &a.mime);
        st(&mut h, &hex::encode(Sha256::digest(&a.data)));
    }
    hex::encode(h.finalize())
}

/// One validation finding. `line` is 1-based; 0 means the whole file (or,
/// with `file` "", the whole tree).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Problem {
    /// Path relative to the docs root ("" for the tree).
    pub file: String,
    /// 1-based line, 0 for none.
    pub line: usize,
    /// What is wrong.
    pub message: String,
}

impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.file.is_empty(), self.line) {
            (true, _) => f.write_str(&self.message),
            (false, 0) => write!(f, "{}: {}", self.file, self.message),
            (false, l) => write!(f, "{}:{l}: {}", self.file, self.message),
        }
    }
}

/// Every finding of a load or lint, sorted by file and line; one per line
/// as `file:line: message` when displayed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Problems(pub Vec<Problem>);

impl fmt::Display for Problems {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, p) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str("\n")?;
            }
            write!(f, "{p}")?;
        }
        Ok(())
    }
}

impl std::error::Error for Problems {}

#[allow(clippy::expect_used)]
static SEGMENT_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[a-z0-9][a-z0-9-]*$").expect("regex"));
#[allow(clippy::expect_used)]
static ASSET_SEG_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z0-9][a-z0-9_.-]*$").expect("regex"));

fn valid_slug(s: &str) -> bool {
    !s.is_empty() && s.len() <= 255 && !reserved_slug(s) && s.split('/').all(|seg| SEGMENT_RE.is_match(seg))
}

/// A slug the gateway's asset route (`<module>/assets/...`) would shadow.
fn reserved_slug(s: &str) -> bool {
    s == "assets" || s.starts_with("assets/")
}

fn valid_asset_path(p: &str) -> bool {
    !p.is_empty()
        && p.len() <= 255
        && p.split('/')
            .all(|seg| ASSET_SEG_RE.is_match(seg) && !seg.contains(".."))
}

/// `index.md` -> `index`, `guides/index.md` -> `guides`, `guides/a.md` -> `guides/a`.
fn slug_of(file: &str) -> String {
    let s = file.strip_suffix(".md").unwrap_or(file);
    if s == "index" {
        return s.to_owned();
    }
    s.strip_suffix("/index").unwrap_or(s).to_owned()
}

/// The MIME type an image must have, by extension. SVG is refused: it can
/// carry script.
fn image_type(name: &str) -> Result<&'static str, String> {
    let ext = gocompat::ext(name).to_lowercase();
    match ext.as_str() {
        ".svg" | ".svgz" => {
            Err("SVG images are not allowed (they can carry script); use png, jpg, webp or gif".to_owned())
        }
        ".png" => Ok("image/png"),
        ".jpg" | ".jpeg" => Ok("image/jpeg"),
        ".gif" => Ok("image/gif"),
        ".webp" => Ok("image/webp"),
        _ => Err(format!(
            "unsupported file type {} (pages are .md; images png, jpg, webp or gif)",
            quote(&ext)
        )),
    }
}

/// The MIME type of an allowed image, by extension, confirmed by sniffing.
fn sniff_image(name: &str, data: &[u8]) -> Result<&'static str, String> {
    let want = image_type(name)?;
    let got = gocompat::detect_content_type(data);
    if got != want {
        return Err(format!("content is {got}, not {want}"));
    }
    Ok(want)
}

/// Reads a docs tree (the contents of `docs/help`), validates it and
/// returns the bundle for `module`. An empty tree yields an empty bundle
/// with digest "".
pub fn load(tree: &FileTree, module: &str) -> Result<Bundle, Problems> {
    run(Some(tree), module, true)
}

/// [`load`] from a directory on disk; a missing directory is an empty
/// bundle (Go `os.DirFS` of a missing root).
pub fn load_dir(dir: impl AsRef<std::path::Path>, module: &str) -> Result<Bundle, Problems> {
    match FileTree::from_dir(dir.as_ref()) {
        Ok(t) => load(&t, module),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => run(None, module, true),
        Err(e) => Err(Problems(vec![Problem {
            file: String::new(),
            line: 0,
            message: format!("walk: {e}"),
        }])),
    }
}

/// Validates a docs tree like [`load`], without a module name.
pub fn lint(tree: &FileTree) -> Result<(), Problems> {
    run(Some(tree), "", false).map(drop)
}

/// The text-body of a page for link checks.
struct Body {
    text: String,
    line: usize,
}

pub(crate) struct Loader {
    ps: Vec<Problem>,
    pages: HashMap<String, Page>,
    files: BTreeSet<String>,
    assets: BTreeMap<String, Asset>,
    bodies: BTreeMap<String, Body>,
    total: usize,
}

impl Loader {
    fn add(&mut self, file: &str, line: usize, msg: String) {
        self.ps.push(Problem {
            file: file.to_owned(),
            line,
            message: msg,
        });
    }

    fn file(&mut self, p: &str, data: &[u8]) {
        let is_page = p.ends_with(".md");
        let limit = if is_page { MAX_PAGE_BYTES } else { MAX_ASSET_BYTES };
        if data.len() > limit {
            self.add(
                p,
                0,
                format!("{} bytes exceed the per-file limit of {limit}", data.len()),
            );
            return;
        }
        if !is_page && let Err(e) = image_type(p) {
            self.add(p, 0, e); // refuse by extension before reading
            return;
        }
        self.total += data.len();
        if is_page {
            self.page(p, data);
            return;
        }
        if !valid_asset_path(p) {
            self.add(
                p,
                0,
                "image path segments must be lowercase [a-z0-9_.-]".to_owned(),
            );
            return;
        }
        match sniff_image(p, data) {
            Err(e) => self.add(p, 0, e),
            Ok(mime) => {
                self.assets.insert(
                    p.to_owned(),
                    Asset {
                        path: p.to_owned(),
                        mime: mime.to_owned(),
                        size: i64::try_from(data.len()).unwrap_or(i64::MAX),
                        sha256: hex::encode(Sha256::digest(data)),
                        data: data.to_vec(),
                    },
                );
            }
        }
    }

    fn page(&mut self, p: &str, data: &[u8]) {
        let slug = slug_of(p);
        if reserved_slug(&slug) {
            self.add(
                p,
                0,
                format!(
                    "slug {} is reserved: the gateway serves images under assets/",
                    quote(&slug)
                ),
            );
            return;
        }
        if !valid_slug(&slug) {
            self.add(
                p,
                0,
                format!(
                    "page path segments must be lowercase [a-z0-9-] (slug {})",
                    quote(&slug)
                ),
            );
            return;
        }
        self.files.insert(p.to_owned());
        let data = data.strip_prefix(b"\xef\xbb\xbf").unwrap_or(data);
        let Ok(text) = std::str::from_utf8(data) else {
            self.add(p, 0, "not valid UTF-8".to_owned());
            return;
        };
        let src = text.replace("\r\n", "\n");
        let (pg, body_line, ps) = frontmatter::parse_page(p, &src);
        let clean = ps.is_empty();
        self.ps.extend(ps);
        let Some(mut pg) = pg else {
            return;
        };
        pg.slug = slug;
        self.bodies.insert(
            p.to_owned(),
            Body {
                text: pg.markdown.clone(),
                line: body_line,
            },
        );
        if clean {
            self.pages.insert(p.to_owned(), pg);
        }
    }

    /// Pages that map to the same slug (`a.md` and `a/index.md`).
    fn check_slugs(&mut self) {
        let mut by: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for f in &self.files {
            by.entry(slug_of(f)).or_default().push(f.clone());
        }
        for (slug, mut files) in by {
            if files.len() > 1 {
                files.sort();
                for f in &files[1..] {
                    let msg = format!("duplicate slug {} (also {})", quote(&slug), files[0]);
                    self.add(f, 0, msg);
                }
            }
        }
    }

    fn check_links(&mut self) {
        let mut found = Vec::new();
        for (f, b) in &self.bodies {
            for r in links::scan_refs(&b.text, b.line) {
                if let Some(msg) = self.resolve(f, &r) {
                    found.push((f.clone(), r.line, msg));
                }
            }
        }
        for (f, l, m) in found {
            self.add(&f, l, m);
        }
    }
}

fn run(tree: Option<&FileTree>, module: &str, check_module: bool) -> Result<Bundle, Problems> {
    if check_module && !valid_service_name(module) {
        return Err(Problems(vec![Problem {
            file: String::new(),
            line: 0,
            message: format!("module name {} is not a valid service name", quote(module)),
        }]));
    }
    let Some(tree) = tree else {
        return Ok(Bundle::empty(module));
    };
    let mut l = Loader {
        ps: Vec::new(),
        pages: HashMap::new(),
        files: BTreeSet::new(),
        assets: BTreeMap::new(),
        bodies: BTreeMap::new(),
        total: 0,
    };
    let mut files = 0usize;
    for (p, e) in tree.walk() {
        files += 1;
        if !e.regular {
            l.add(p, 0, "not a regular file (symlinks are not allowed)".to_owned());
            continue;
        }
        l.file(p, &e.data);
    }
    if files == 0 && l.ps.is_empty() {
        return Ok(Bundle::empty(module));
    }
    if !l.files.contains("index.md") {
        l.add("index.md", 0, "a root index.md is required".to_owned());
    }
    l.check_slugs();
    l.check_links();
    if l.files.len() > MAX_PAGES {
        let msg = format!("{} pages exceed the limit of {MAX_PAGES}", l.files.len());
        l.add("", 0, msg);
    }
    if l.total > MAX_TOTAL_BYTES {
        let msg = format!(
            "{} bytes of pages and images exceed the limit of {MAX_TOTAL_BYTES}",
            l.total
        );
        l.add("", 0, msg);
    }
    if !l.ps.is_empty() {
        let mut ps = l.ps;
        ps.sort_by(|a, b| a.file.cmp(&b.file).then(a.line.cmp(&b.line)));
        return Err(Problems(ps));
    }
    let mut b = Bundle {
        schema: SCHEMA,
        module: module.to_owned(),
        digest: String::new(),
        pages: l.pages.into_values().collect(),
        assets: l.assets.into_values().collect(),
    };
    b.pages.sort_by(|x, y| x.slug.cmp(&y.slug));
    b.digest = compute_digest(&b);
    Ok(b)
}

/// Why a received bundle was refused (Go `ErrInvalidBundle`).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("helpdocs: invalid bundle: {0}")]
pub struct InvalidBundle(pub String);

/// Parses and checks a bundle received over the wire (Go `Decode`): schema,
/// limits, asset sizes and hashes, sniffed image types, and that the digest
/// is the digest of the content. It does not re-run the authoring lint.
pub fn decode(data: &[u8]) -> Result<Bundle, InvalidBundle> {
    let bad = |m: String| InvalidBundle(m);
    if data.len() > 2 * MAX_TOTAL_BYTES {
        return Err(bad(format!("{} bytes", data.len())));
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Wire {
        #[serde(default)]
        schema: i64,
        #[serde(default)]
        module: String,
        #[serde(default)]
        digest: String,
        #[serde(default)]
        pages: Option<Vec<WirePage>>,
        #[serde(default)]
        assets: Option<Vec<WireAsset>>,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct WirePage {
        #[serde(default)]
        slug: String,
        #[serde(default)]
        title: String,
        #[serde(default)]
        summary: String,
        #[serde(default)]
        kind: String,
        #[serde(default)]
        order: i64,
        #[serde(default)]
        tags: Option<Vec<String>>,
        #[serde(default)]
        requires: String,
        #[serde(default)]
        audience: String,
        #[serde(default)]
        lang: String,
        #[serde(default)]
        markdown: String,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct WireAsset {
        #[serde(default)]
        path: String,
        #[serde(default)]
        mime: String,
        #[serde(default)]
        size: i64,
        #[serde(default)]
        sha256: String,
        #[serde(default)]
        data: Option<String>,
    }
    let w: Wire = serde_json::from_slice(data).map_err(|e| bad(e.to_string()))?;
    if w.schema != SCHEMA {
        return Err(bad(format!("schema {} (want {SCHEMA})", w.schema)));
    }
    let pages = w.pages.unwrap_or_default();
    if pages.len() > MAX_PAGES {
        return Err(bad(format!("{} pages (max {MAX_PAGES})", pages.len())));
    }
    if !valid_service_name(&w.module) {
        return Err(bad(format!("module {}", quote(&w.module))));
    }
    let mut total = 0usize;
    let mut slugs = BTreeSet::new();
    let mut b = Bundle {
        schema: w.schema,
        module: w.module,
        digest: w.digest,
        pages: Vec::with_capacity(pages.len()),
        assets: Vec::new(),
    };
    for (i, p) in pages.into_iter().enumerate() {
        if !valid_slug(&p.slug)
            || slugs.contains(&p.slug)
            || p.title.is_empty()
            || Kind::parse(&p.kind).is_none()
        {
            return Err(bad(format!(
                "page {i} ({}) is malformed or duplicate",
                quote(&p.slug)
            )));
        }
        slugs.insert(p.slug.clone());
        if p.markdown.len() > MAX_PAGE_BYTES {
            return Err(bad(format!("page {} exceeds {MAX_PAGE_BYTES} bytes", p.slug)));
        }
        total += p.markdown.len();
        b.pages.push(Page {
            slug: p.slug,
            title: p.title,
            summary: p.summary,
            kind: p.kind,
            order: p.order,
            tags: p.tags.unwrap_or_default(),
            requires: p.requires,
            audience: p.audience,
            lang: p.lang,
            markdown: p.markdown,
        });
    }
    for a in w.assets.unwrap_or_default() {
        let data = match a.data {
            None => Vec::new(),
            Some(s) => base64::engine::general_purpose::STANDARD
                .decode(s)
                .map_err(|e| bad(e.to_string()))?,
        };
        let size_ok = i64::try_from(data.len()).is_ok_and(|n| n == a.size);
        if !valid_asset_path(&a.path) || !size_ok || data.len() > MAX_ASSET_BYTES {
            return Err(bad(format!("asset {} is malformed", quote(&a.path))));
        }
        if hex::encode(Sha256::digest(&data)) != a.sha256 {
            return Err(bad(format!("asset {}: sha256 mismatch", a.path)));
        }
        if sniff_image(&a.path, &data).ok() != Some(a.mime.as_str()) {
            return Err(bad(format!("asset {}: not an allowed image", a.path)));
        }
        total += data.len();
        b.assets.push(Asset {
            path: a.path,
            mime: a.mime,
            size: a.size,
            sha256: a.sha256,
            data,
        });
    }
    if total > MAX_TOTAL_BYTES {
        return Err(bad(format!("{total} bytes of content (max {MAX_TOTAL_BYTES})")));
    }
    if compute_digest(&b) != b.digest {
        return Err(bad("digest mismatch".to_owned()));
    }
    Ok(b)
}
