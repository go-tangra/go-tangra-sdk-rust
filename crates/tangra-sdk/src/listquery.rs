//! The platform list contract (go-tangra `listquery`): numbered pages with an
//! exact total, and server-side sorting restricted to a per-list allow-list.
//!
//! A list declares a [`Spec`] once. [`parse`] turns the untrusted `page`,
//! `page_size`, `sort` and `order` query parameters into a validated
//! [`Request`] or a [`ListError`] naming the offending parameter (answer it
//! with `ApiError::invalid_param`). [`Request::order_by`] builds ORDER BY only
//! from the spec's constants. [`Page`] is the response shape.

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::time::SystemTime;

use serde::Serialize;

/// Sort direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Dir {
    /// `asc`
    Asc,
    /// `desc`
    Desc,
}

impl Dir {
    /// The wire form.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Asc => "asc",
            Self::Desc => "desc",
        }
    }

    /// Parses `asc`/`desc` exactly (case-sensitive, as Go).
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "asc" => Some(Self::Asc),
            "desc" => Some(Self::Desc),
            _ => None,
        }
    }
}

/// Largest page size any list accepts.
pub const MAX_PAGE_SIZE: i64 = 200;
/// Page size when none is requested.
pub const DEFAULT_PAGE_SIZE: i64 = 25;
const MAX_INT32: i64 = i32::MAX as i64;

/// A public sort name mapped to a constant SQL expression.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Field {
    /// Column or expression, a constant in module code.
    pub expr: &'static str,
    /// Order case-insensitively, by `lower(expr)`.
    pub text: bool,
    /// Direction when a request names the field without an order (None = asc).
    pub default_dir: Option<Dir>,
    /// `expr` never yields NULL: ORDER BY omits `NULLS LAST`.
    pub not_null: bool,
}

impl Field {
    fn dir_of(&self) -> Dir {
        self.default_dir.unwrap_or(Dir::Asc)
    }
}

/// One list's definition.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Spec {
    /// Sortable fields by public name.
    pub fields: BTreeMap<&'static str, Field>,
    /// Field used when no sort is requested.
    pub default: &'static str,
    /// Constant unique column appended to every ORDER BY.
    pub tie_break: &'static str,
    /// Page size when none is requested (0 = 25, capped to `max_size`).
    pub default_size: i64,
    /// Page size cap (0 = 200; never above 200).
    pub max_size: i64,
}

/// A malformed [`Spec`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("listquery: {0}")]
pub struct SpecError(String);

impl Spec {
    /// Reports a malformed spec.
    pub fn validate(&self) -> Result<(), SpecError> {
        if self.fields.is_empty() {
            return Err(SpecError("spec has no fields".into()));
        }
        if !self.fields.contains_key(self.default) {
            return Err(SpecError(format!(
                "default sort {:?} is not a field",
                self.default
            )));
        }
        if self.tie_break.is_empty() {
            return Err(SpecError("spec has no tie-breaker".into()));
        }
        for (name, f) in &self.fields {
            if f.expr.is_empty() {
                return Err(SpecError(format!("field {name:?} has no expression")));
            }
        }
        if !(0..=MAX_PAGE_SIZE).contains(&self.max_size) {
            return Err(SpecError(format!("max size must be 0..{MAX_PAGE_SIZE}")));
        }
        if self.default_size < 0 || (self.max_size > 0 && self.default_size > self.max_size) {
            return Err(SpecError("default size must be 0..max size".into()));
        }
        Ok(())
    }

    fn max(&self) -> i64 {
        if self.max_size > 0 {
            self.max_size
        } else {
            MAX_PAGE_SIZE
        }
    }

    fn default_page_size(&self) -> i64 {
        let d = if self.default_size == 0 {
            DEFAULT_PAGE_SIZE
        } else {
            self.default_size
        };
        d.min(self.max())
    }
}

/// A validated page request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// 1-based page.
    pub page: i64,
    /// Page size.
    pub page_size: i64,
    /// Sort field (public name).
    pub sort: String,
    /// Direction.
    pub order: Dir,
}

/// Names the request parameter that failed validation (never its value).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("listquery: invalid {param}")]
pub struct ListError {
    /// `page`, `page_size`, `sort`, `order` or `cursor`.
    pub param: &'static str,
}

fn err(param: &'static str) -> ListError {
    ListError { param }
}

/// Parsed query parameters (`url.Values`): every value of every key, in order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Query(BTreeMap<String, Vec<String>>);

impl Query {
    /// Parses a raw query string (`a=1&b=2`), percent- and `+`-decoding.
    pub fn parse(raw: &str) -> Self {
        let mut m: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (k, v) in form_urlencoded::parse(raw.as_bytes()) {
            m.entry(k.into_owned()).or_default().push(v.into_owned());
        }
        Self(m)
    }

    /// Builds from pairs (tests, internal callers).
    pub fn from_pairs<'a>(pairs: impl IntoIterator<Item = (&'a str, &'a str)>) -> Self {
        let mut m: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (k, v) in pairs {
            m.entry(k.to_owned()).or_default().push(v.to_owned());
        }
        Self(m)
    }

    /// Whether the key is present (`url.Values.Has`).
    pub fn has(&self, k: &str) -> bool {
        self.0.contains_key(k)
    }

    /// The first value of `k`, or "" (`url.Values.Get`).
    pub fn get(&self, k: &str) -> &str {
        self.0.get(k).and_then(|v| v.first()).map_or("", String::as_str)
    }
}

/// `strconv.Atoi` for the page parameters.
fn atoi(s: &str) -> Option<i64> {
    crate::config::go_atoi(s)
}

/// Reads `page`, `page_size`, `sort` and `order` from `q` against `s`.
/// Absent values take the spec's defaults; any present but invalid value is
/// an error. Mixing the legacy `cursor`/`limit` parameters with the page
/// parameters is an error on `cursor`.
pub fn parse(q: &Query, s: &Spec) -> Result<Request, ListError> {
    if has_legacy(q) && has_page(q) {
        return Err(err("cursor"));
    }
    let mut page = 0;
    let mut size = 0;
    if q.has("page") {
        match atoi(q.get("page")) {
            Some(n) if (1..=MAX_INT32).contains(&n) => page = n,
            _ => return Err(err("page")),
        }
    }
    if q.has("page_size") {
        match atoi(q.get("page_size")) {
            Some(n) if n >= 1 => size = n,
            _ => return Err(err("page_size")),
        }
    }
    let mut sort = s.default.to_owned();
    if q.has("sort") {
        sort = q.get("sort").to_owned();
        if !s.fields.contains_key(sort.as_str()) {
            return Err(err("sort"));
        }
    }
    let mut order = None;
    if q.has("order") {
        order = Some(Dir::parse(q.get("order")).ok_or_else(|| err("order"))?);
    }
    new(page, size, &sort, order, s)
}

/// Builds a request from typed values: zero page/size, empty sort and `None`
/// order take the spec's defaults; other invalid values are errors.
pub fn new(
    page: i64,
    page_size: i64,
    sort: &str,
    order: Option<Dir>,
    s: &Spec,
) -> Result<Request, ListError> {
    let page = if page == 0 { 1 } else { page };
    if page < 1 {
        return Err(err("page"));
    }
    let page_size = if page_size == 0 {
        s.default_page_size()
    } else {
        page_size
    };
    if page_size < 1 || page_size > s.max() {
        return Err(err("page_size"));
    }
    let sort = if sort.is_empty() { s.default } else { sort };
    let f = s.fields.get(sort).ok_or_else(|| err("sort"))?;
    Ok(Request {
        page,
        page_size,
        sort: sort.to_owned(),
        order: order.unwrap_or_else(|| f.dir_of()),
    })
}

/// Whether `q` uses only the old `cursor`/`limit` style.
pub fn legacy(q: &Query) -> bool {
    has_legacy(q) && !has_page(q)
}

fn has_legacy(q: &Query) -> bool {
    q.has("cursor") || q.has("limit")
}

fn has_page(q: &Query) -> bool {
    q.has("page") || q.has("page_size") || q.has("sort") || q.has("order")
}

impl Request {
    /// The ORDER BY body, built only from the spec's constants: the sort
    /// expression (lower() for text) with NULLS LAST unless `not_null`, then
    /// the tie-breaker in the same direction. An unknown field falls back to
    /// the default field.
    pub fn order_by(&self, s: &Spec) -> String {
        let fallback = Field::default();
        let f = s
            .fields
            .get(self.sort.as_str())
            .or_else(|| s.fields.get(s.default))
            .unwrap_or(&fallback);
        let expr = if f.text {
            format!("lower({})", f.expr)
        } else {
            f.expr.to_owned()
        };
        let dir = match self.order {
            Dir::Desc => "DESC",
            Dir::Asc => "ASC",
        };
        let nulls = if f.not_null { "" } else { " NULLS LAST" };
        format!("{expr} {dir}{nulls}, {} {dir}", s.tie_break)
    }

    /// LIMIT.
    pub fn limit(&self) -> i64 {
        self.page_size
    }

    /// OFFSET (never negative).
    pub fn offset(&self) -> i64 {
        if self.page < 1 {
            return 0;
        }
        (self.page - 1) * self.page_size
    }

    /// Moves a page beyond the end to the last page (page 1 when empty).
    #[must_use]
    pub fn clamp(&self, total: i64) -> Self {
        let mut r = self.clone();
        if r.page_size < 1 {
            return r;
        }
        let last = ((total + r.page_size - 1) / r.page_size).max(1);
        if r.page > last {
            r.page = last;
        }
        r
    }
}

/// The list response shape shared by every module.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Page<T> {
    /// The page's items (never null).
    pub items: Vec<T>,
    /// Exact total.
    pub total: i64,
    /// Page number.
    pub page: i64,
    /// Page size.
    pub page_size: i64,
    /// Sort field.
    pub sort: String,
    /// Direction.
    pub order: Dir,
}

impl<T> Page<T> {
    /// Shapes a response for `r`.
    pub fn new(items: Vec<T>, total: i64, r: &Request) -> Self {
        Self {
            items,
            total,
            page: r.page,
            page_size: r.page_size,
            sort: r.sort.clone(),
            order: r.order,
        }
    }
}

/// A sort key for in-memory lists ([`sort_slice`]).
#[derive(Debug, Clone, PartialEq)]
pub enum SortKey {
    /// NULL: sorts last in both directions.
    Null,
    /// Compared case-insensitively.
    Str(String),
    /// Integer.
    Int(i64),
    /// Float.
    Float(f64),
    /// Instant.
    Time(SystemTime),
    /// Boolean (compared by its text form against other kinds).
    Bool(bool),
}

impl SortKey {
    fn text(&self) -> String {
        match self {
            Self::Null => String::new(),
            Self::Str(s) => s.to_lowercase(),
            Self::Int(n) => n.to_string(),
            Self::Float(f) => crate::gofmt::format_g(*f),
            Self::Time(t) => chrono::DateTime::<chrono::Utc>::from(*t).to_rfc3339(),
            Self::Bool(b) => b.to_string(),
        }
    }

    fn compare(&self, o: &Self) -> Ordering {
        match (self, o) {
            (Self::Str(a), Self::Str(b)) => a.to_lowercase().cmp(&b.to_lowercase()),
            (Self::Int(a), Self::Int(b)) => a.cmp(b),
            (Self::Float(a), Self::Float(b)) => a.partial_cmp(b).unwrap_or(Ordering::Equal),
            (Self::Time(a), Self::Time(b)) => a.cmp(b),
            _ => self.text().cmp(&o.text()),
        }
    }
}

/// Orders `items` with the semantics of `order_by` (go-tangra
/// `listquery.SortSlice`): strings case-insensitively, NULL keys last in both
/// directions, equal keys broken by `tie` in the requested direction.
pub fn sort_slice<T>(
    items: &mut [T],
    r: &Request,
    key: impl Fn(&T, &str) -> SortKey,
    tie: impl Fn(&T) -> String,
) {
    let desc = r.order == Dir::Desc;
    items.sort_by(|a, b| {
        let (ka, kb) = (key(a, &r.sort), key(b, &r.sort));
        match (&ka, &kb) {
            (SortKey::Null, SortKey::Null) => {}
            (SortKey::Null, _) => return Ordering::Greater,
            (_, SortKey::Null) => return Ordering::Less,
            _ => {
                let c = ka.compare(&kb);
                if c != Ordering::Equal {
                    return if desc { c.reverse() } else { c };
                }
            }
        }
        let c = tie(a).cmp(&tie(b));
        if desc { c.reverse() } else { c }
    });
}

/// The requested page of already-sorted items, the total and the request
/// clamped to the last page.
pub fn window<'a, T>(items: &'a [T], r: &Request) -> (&'a [T], i64, Request) {
    let total = i64::try_from(items.len()).unwrap_or(i64::MAX);
    let applied = r.clamp(total);
    let len = items.len();
    let start = usize::try_from(applied.offset()).unwrap_or(usize::MAX).min(len);
    let end = start
        .saturating_add(usize::try_from(applied.limit()).unwrap_or(0))
        .min(len);
    (&items[start..end], total, applied)
}

#[cfg(test)]
mod tests;
