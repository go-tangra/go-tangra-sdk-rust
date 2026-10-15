//! Serves the module's built module-federation remote (`ui/dist`) at
//! `GET /ui/<asset>` on the mTLS HTTP server; the gateway relays
//! `/m/<module>/<asset>` to it. Behind the cargo feature `ui`, mirroring the
//! Go build tag `ui` (deployer `ui/embed.go`): without it a module serves no
//! remote.
//!
//! The behaviour is deployer `internal/httpapi/server.go` (`remoteHandler`
//! under `GET /ui/`, the `secure` headers and the `{"reason":"not_found"}`
//! catch-all) over Go's `http.FileServerFS` of an `embed.FS`:
//!
//! - `assets/*`: `Cache-Control: public, max-age=31536000, immutable`;
//!   every other file `no-cache`; `nosniff`, `Referrer-Policy: no-referrer`,
//!   `X-Frame-Options: DENY` on everything.
//! - No directory listings: `/ui/`, `/ui/<dir>/` and unknown paths are
//!   `404 {"reason":"not_found"}`; `/ui/<dir>` redirects to `<dir>/` and
//!   `/ui/.../index.html` to `./` (301, as `FileServer`).
//! - `Content-Type` from Go's built-in extension table, else sniffed from the
//!   first 512 bytes; `Accept-Ranges: bytes` with single and multipart
//!   ranges; `If-None-Match: *` -> 304, `If-Match` -> 412 (an embedded file
//!   has no ETag and no modification time, so no `Last-Modified`).
//! - HEAD is answered like GET without a body; other methods get the 404.
//!
//! ```no_run
//! # fn demo() -> Result<(), tangra_sdk::ui::UiError> {
//! static DIST: include_dir::Dir<'static> = include_dir::include_dir!("$CARGO_MANIFEST_DIR/src");
//! let remote = tangra_sdk::ui::Remote::from_embedded(&DIST)?;
//! let router = axum::Router::new().merge(tangra_sdk::ui::router(remote));
//! # let _ = router; Ok(()) }
//! ```

use std::sync::Arc;

use axum::body::Body;
use axum::extract::Request;
use axum::response::IntoResponse;
use axum::routing::any;
use http::{HeaderMap, HeaderValue, Method, Response, StatusCode, header};

use crate::error::{ApiError, set_secure_headers};
use crate::fstree::FileTree;
use crate::gocompat;

/// Where the remote is served (deployer `httpapi.RemotePrefix`).
pub const REMOTE_PREFIX: &str = "/ui";

/// The module-federation manifest every remote has at its root.
pub const MANIFEST: &str = "mf-manifest.json";

const IMMUTABLE: &str = "public, max-age=31536000, immutable";

/// A remote without `mf-manifest.json` (Go `ui.Remote` returns `false`).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("ui: the remote has no {MANIFEST} at its root (run the UI build first)")]
pub struct UiError;

/// A built remote, rooted at `dist/`.
#[derive(Debug, Clone)]
pub struct Remote {
    tree: Arc<FileTree>,
}

impl Remote {
    /// The remote in `tree`; it must hold `mf-manifest.json` at its root.
    pub fn new(tree: FileTree) -> Result<Self, UiError> {
        if !tree.get(MANIFEST).is_some_and(|e| e.regular) {
            return Err(UiError);
        }
        Ok(Self { tree: Arc::new(tree) })
    }

    /// The remote embedded with `include_dir!("$CARGO_MANIFEST_DIR/ui/dist")`.
    pub fn from_embedded(dir: &'static include_dir::Dir<'static>) -> Result<Self, UiError> {
        Self::new(FileTree::from_embedded(dir))
    }

    /// The remote in a directory on disk (read once).
    pub fn from_dir(dir: impl AsRef<std::path::Path>) -> Result<Self, UiError> {
        Self::new(FileTree::from_dir(dir).map_err(|_| UiError)?)
    }

    /// The files.
    pub fn tree(&self) -> &FileTree {
        &self.tree
    }
}

/// A router serving the remote under `/ui/`; merge it into the module's
/// router (before any catch-all route).
pub fn router(remote: Remote) -> axum::Router {
    let tree = remote.tree;
    let h = move |req: Request| {
        let tree = Arc::clone(&tree);
        async move { serve(&tree, &req) }
    };
    axum::Router::new()
        .route("/ui/", any(h.clone()))
        .route("/ui/{*path}", any(h))
}

/// `WriteError(w, 404, "not_found")` behind the `secure` headers.
fn not_found(base: &HeaderMap) -> Response<Body> {
    let mut r = ApiError::not_found().into_response();
    merge(&mut r, base);
    // WriteJSON sets no-store last.
    r.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r
}

fn merge(r: &mut Response<Body>, base: &HeaderMap) {
    for (k, v) in base {
        r.headers_mut().insert(k.clone(), v.clone());
    }
}

fn respond(status: StatusCode, headers: HeaderMap, body: Body) -> Response<Body> {
    let mut r = Response::new(body);
    *r.status_mut() = status;
    *r.headers_mut() = headers;
    r
}

/// Go `http.Error` after `serveError` dropped the caching headers.
fn serve_error(mut h: HeaderMap, text: &str, status: StatusCode) -> Response<Body> {
    for k in [
        header::CACHE_CONTROL,
        header::CONTENT_ENCODING,
        header::ETAG,
        header::LAST_MODIFIED,
    ] {
        h.remove(k);
    }
    h.remove(header::CONTENT_LENGTH);
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    h.insert("x-content-type-options", HeaderValue::from_static("nosniff"));
    respond(status, h, Body::from(format!("{text}\n")))
}

fn local_redirect(mut h: HeaderMap, req: &Request, to: &str) -> Response<Body> {
    let loc = match req.uri().query() {
        Some(q) if !q.is_empty() => format!("{to}?{q}"),
        _ => to.to_owned(),
    };
    if let Ok(v) = HeaderValue::from_str(&loc) {
        h.insert(header::LOCATION, v);
    }
    respond(StatusCode::MOVED_PERMANENTLY, h, Body::empty())
}

fn serve(tree: &FileTree, req: &Request) -> Response<Body> {
    let mut h = HeaderMap::new();
    set_secure_headers(&mut h);
    // "GET /ui/" also matches HEAD; anything else falls to the catch-all.
    if req.method() != Method::GET && req.method() != Method::HEAD {
        return not_found(&h);
    }
    // r.URL.Path is the unescaped path.
    let raw = req.uri().path().strip_prefix("/ui/").unwrap_or("");
    let Ok(p) = gocompat::path_unescape(raw).map(String::from_utf8) else {
        return not_found(&h);
    };
    let Ok(p) = p else {
        return not_found(&h);
    };
    if p.is_empty() || p.ends_with('/') {
        return not_found(&h);
    }
    // fs.Stat(dist, p): only valid paths of existing files or directories.
    let file = tree.get(&p).filter(|e| e.regular);
    let is_dir = tree.is_dir(&p);
    if !gocompat::valid_path(&p) || (file.is_none() && !is_dir) {
        return not_found(&h);
    }
    let cc = if p.starts_with("assets/") {
        IMMUTABLE
    } else {
        "no-cache"
    };
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static(cc));

    // http.FileServerFS under StripPrefix("/ui"): URL path "/"+p.
    let url = format!("/{p}");
    if url.ends_with("/index.html") {
        return local_redirect(h, req, "./");
    }
    let Some(file) = file else {
        // A directory without a trailing slash.
        return local_redirect(h, req, &format!("{}/", gocompat::base(&url)));
    };
    serve_content(h, req, &gocompat::base(&url), &file.data)
}

/// Go `scanETag`.
fn scan_etag(s: &str) -> Option<(&str, &str)> {
    let s = s.trim_matches([' ', '\t']);
    let start = if s.starts_with("W/") { 2 } else { 0 };
    let b = s.as_bytes();
    if b.len() < start + 2 || b[start] != b'"' {
        return None;
    }
    for (i, &c) in b.iter().enumerate().skip(start + 1) {
        match c {
            b'"' => return Some((&s[..=i], &s[i + 1..])),
            0x21 | 0x23..=0x7e | 0x80..=0xff => {}
            _ => return None,
        }
    }
    None
}

#[derive(PartialEq)]
enum Cond {
    None,
    True,
    False,
}

/// Go `checkIfMatch` / `checkIfNoneMatch` against a response with no ETag:
/// only `*` matches.
fn star_match(v: Option<&HeaderValue>, if_match: bool) -> Cond {
    let Some(v) = v.and_then(|v| v.to_str().ok()).filter(|v| !v.is_empty()) else {
        return Cond::None;
    };
    let mut buf = v;
    loop {
        buf = buf.trim_matches([' ', '\t']);
        if buf.is_empty() {
            break;
        }
        if let Some(rest) = buf.strip_prefix(',') {
            buf = rest;
            continue;
        }
        if buf.starts_with('*') {
            return if if_match { Cond::True } else { Cond::False };
        }
        match scan_etag(buf) {
            Some((_, rest)) => buf = rest,
            None => break,
        }
    }
    if if_match { Cond::False } else { Cond::True }
}

#[derive(Clone, Copy)]
struct Range {
    start: usize,
    length: usize,
}

impl Range {
    fn content_range(self, size: usize) -> String {
        format!("bytes {}-{}/{size}", self.start, self.start + self.length - 1)
    }
}

enum RangeError {
    Invalid,
    NoOverlap,
}

/// Go `parseRange`.
fn parse_range(s: &str, size: usize) -> Result<Vec<Range>, RangeError> {
    let Some(spec) = s.strip_prefix("bytes=") else {
        return Err(RangeError::Invalid);
    };
    let int = |t: &str| -> Option<i64> {
        let digits = t.strip_prefix(['+', '-']).unwrap_or(t);
        if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        t.parse().ok()
    };
    let size_i = i64::try_from(size).unwrap_or(i64::MAX);
    let mut out = Vec::new();
    let mut no_overlap = false;
    for ra in spec.split(',') {
        let ra = ra.trim_matches([' ', '\t']);
        if ra.is_empty() {
            continue;
        }
        let Some((start, end)) = ra.split_once('-') else {
            return Err(RangeError::Invalid);
        };
        let (start, end) = (start.trim_matches([' ', '\t']), end.trim_matches([' ', '\t']));
        let (rs, rl) = if start.is_empty() {
            if end.is_empty() || end.starts_with('-') {
                return Err(RangeError::Invalid);
            }
            let i = int(end)
                .filter(|i| *i >= 0)
                .ok_or(RangeError::Invalid)?
                .min(size_i);
            (size_i - i, i)
        } else {
            let i = int(start).filter(|i| *i >= 0).ok_or(RangeError::Invalid)?;
            if i >= size_i {
                no_overlap = true;
                continue;
            }
            if end.is_empty() {
                (i, size_i - i)
            } else {
                let e = int(end).filter(|e| i <= *e).ok_or(RangeError::Invalid)?;
                let e = e.min(size_i - 1);
                (i, e - i + 1)
            }
        };
        out.push(Range {
            start: usize::try_from(rs).unwrap_or(0),
            length: usize::try_from(rl).unwrap_or(0),
        });
    }
    if no_overlap && out.is_empty() {
        return Err(RangeError::NoOverlap);
    }
    Ok(out)
}

/// Go `serveContent` with a zero modification time and no ETag.
fn serve_content(mut h: HeaderMap, req: &Request, name: &str, data: &[u8]) -> Response<Body> {
    let headers = req.headers();
    // checkPreconditions.
    if star_match(headers.get(header::IF_MATCH), true) == Cond::False {
        return respond(StatusCode::PRECONDITION_FAILED, h, Body::empty());
    }
    if star_match(headers.get(header::IF_NONE_MATCH), false) == Cond::False {
        h.remove(header::CONTENT_TYPE);
        h.remove(header::CONTENT_LENGTH);
        h.remove(header::CONTENT_ENCODING);
        return respond(StatusCode::NOT_MODIFIED, h, Body::empty());
    }
    // If-Range can only match an ETag or a modification time: none here.
    let range = headers
        .get(header::RANGE)
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.is_empty() && headers.get(header::IF_RANGE).is_none_or(|v| v.is_empty()));

    let ctype = gocompat::type_by_extension(gocompat::ext(name))
        .unwrap_or_else(|| gocompat::detect_content_type(data));
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static(ctype));
    let size = data.len();
    let mut ranges = match range.map(|r| parse_range(r, size)) {
        None => Vec::new(),
        Some(Ok(r)) => r,
        Some(Err(RangeError::NoOverlap)) if size == 0 => Vec::new(),
        Some(Err(RangeError::NoOverlap)) => {
            if let Ok(v) = HeaderValue::from_str(&format!("bytes */{size}")) {
                h.insert(header::CONTENT_RANGE, v);
            }
            return serve_error(
                h,
                "invalid range: failed to overlap",
                StatusCode::RANGE_NOT_SATISFIABLE,
            );
        }
        Some(Err(RangeError::Invalid)) => {
            return serve_error(h, "invalid range", StatusCode::RANGE_NOT_SATISFIABLE);
        }
    };
    if ranges.iter().map(|r| r.length).sum::<usize>() > size {
        ranges.clear();
    }
    let (status, body): (StatusCode, Vec<u8>) = match ranges.as_slice() {
        [] => (StatusCode::OK, data.to_vec()),
        [r] => {
            if let Ok(v) = HeaderValue::from_str(&r.content_range(size)) {
                h.insert(header::CONTENT_RANGE, v);
            }
            (
                StatusCode::PARTIAL_CONTENT,
                data[r.start..r.start + r.length].to_vec(),
            )
        }
        many => {
            let boundary = hex::encode(rand::random::<[u8; 30]>());
            if let Ok(v) = HeaderValue::from_str(&format!("multipart/byteranges; boundary={boundary}")) {
                h.insert(header::CONTENT_TYPE, v);
            }
            let mut out = Vec::new();
            for (i, r) in many.iter().enumerate() {
                let lead = if i == 0 { "" } else { "\r\n" };
                out.extend_from_slice(
                    format!(
                        "{lead}--{boundary}\r\nContent-Range: {}\r\nContent-Type: {ctype}\r\n\r\n",
                        r.content_range(size)
                    )
                    .as_bytes(),
                );
                out.extend_from_slice(&data[r.start..r.start + r.length]);
            }
            out.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
            (StatusCode::PARTIAL_CONTENT, out)
        }
    };
    h.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    h.insert(header::CONTENT_LENGTH, HeaderValue::from(body.len()));
    let body = if req.method() == Method::HEAD {
        Body::empty()
    } else {
        Body::from(body)
    };
    respond(status, h, body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn remote() -> Remote {
        let mut t = FileTree::new();
        t.insert(MANIFEST, r#"{"name":"orders"}"#)
            .insert("remoteEntry.js", "export const x = 1;")
            .insert("assets/app-1a2b.js", "console.log(1)")
            .insert("assets/style.css", "body{}")
            .insert("assets/font.woff2", b"wOF2\x00\x01".to_vec())
            .insert("assets/data.map", "{\"version\":3}")
            .insert("assets/blob", vec![0u8, 1, 2, 3])
            .insert("sub/index.html", "<html>")
            .insert("digits.txt", "0123456789");
        Remote::new(t).expect("remote")
    }

    async fn get(method: &str, path: &str, hdrs: &[(&str, &str)]) -> (StatusCode, HeaderMap, Vec<u8>) {
        let mut b = http::Request::builder().method(method).uri(path);
        for (k, v) in hdrs {
            b = b.header(*k, *v);
        }
        let resp = router(remote())
            .oneshot(b.body(Body::empty()).expect("req"))
            .await
            .expect("infallible");
        let (p, body) = resp.into_parts();
        (
            p.status,
            p.headers,
            body.collect().await.expect("body").to_bytes().to_vec(),
        )
    }

    #[test]
    fn manifest_is_required() {
        assert_eq!(Remote::new(FileTree::new()).err(), Some(UiError));
    }

    #[tokio::test]
    async fn serves_like_the_deployer() {
        let (st, h, body) = get("GET", "/ui/remoteEntry.js", &[]).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(body, b"export const x = 1;");
        assert_eq!(h["content-type"], "text/javascript; charset=utf-8");
        assert_eq!(h["cache-control"], "no-cache");
        assert_eq!(h["x-content-type-options"], "nosniff");
        assert_eq!(h["referrer-policy"], "no-referrer");
        assert_eq!(h["x-frame-options"], "DENY");
        assert_eq!(h["accept-ranges"], "bytes");
        assert_eq!(h["content-length"], "19");
        assert!(h.get("last-modified").is_none() && h.get("etag").is_none());

        let (st, h, _) = get("GET", "/ui/assets/app-1a2b.js", &[]).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(h["cache-control"], IMMUTABLE);
        for (p, ct) in [
            ("/ui/assets/style.css", "text/css; charset=utf-8"),
            ("/ui/assets/font.woff2", "font/woff2"),
            ("/ui/assets/data.map", "text/plain; charset=utf-8"),
            ("/ui/assets/blob", "application/octet-stream"),
            ("/ui/mf-manifest.json", "application/json"),
        ] {
            let (st, h, _) = get("GET", p, &[]).await;
            assert_eq!(
                (st, h["content-type"].to_str().expect("ct")),
                (StatusCode::OK, ct),
                "{p}"
            );
        }

        let (st, h, body) = get("HEAD", "/ui/remoteEntry.js", &[]).await;
        assert_eq!(st, StatusCode::OK);
        assert!(body.is_empty());
        assert_eq!(h["content-length"], "19");

        for p in [
            "/ui/",
            "/ui/nope.js",
            "/ui/assets/",
            "/ui/sub/",
            "/ui/../mf-manifest.json",
            "/ui/a//b",
            "/ui/%zz",
        ] {
            let (st, h, body) = get("GET", p, &[]).await;
            assert_eq!(st, StatusCode::NOT_FOUND, "{p}");
            assert_eq!(body, b"{\"reason\":\"not_found\"}\n", "{p}");
            assert_eq!(h["cache-control"], "no-store", "{p}");
            assert_eq!(h["content-type"], "application/json", "{p}");
        }
        let (st, _, _) = get("POST", "/ui/remoteEntry.js", &[]).await;
        assert_eq!(st, StatusCode::NOT_FOUND);

        let (st, h, _) = get("GET", "/ui/assets?x=1", &[]).await;
        assert_eq!(
            (st, &h["location"]),
            (
                StatusCode::MOVED_PERMANENTLY,
                &HeaderValue::from_static("assets/?x=1")
            )
        );
        assert_eq!(h["cache-control"], "no-cache");
        let (st, h, _) = get("GET", "/ui/sub/index.html", &[]).await;
        assert_eq!(
            (st, &h["location"]),
            (StatusCode::MOVED_PERMANENTLY, &HeaderValue::from_static("./"))
        );
        // Escapes are decoded like r.URL.Path.
        let (st, _, _) = get("GET", "/ui/remote%45ntry.js", &[]).await;
        assert_eq!(st, StatusCode::OK);
    }

    #[tokio::test]
    async fn conditional_and_range_requests() {
        let (st, h, body) = get("GET", "/ui/digits.txt", &[("if-none-match", "*")]).await;
        assert_eq!(st, StatusCode::NOT_MODIFIED);
        assert!(body.is_empty() && h.get("content-type").is_none());
        let (st, _, _) = get("GET", "/ui/digits.txt", &[("if-none-match", "\"abc\"")]).await;
        assert_eq!(st, StatusCode::OK);
        let (st, _, _) = get("GET", "/ui/digits.txt", &[("if-match", "\"abc\"")]).await;
        assert_eq!(st, StatusCode::PRECONDITION_FAILED);
        let (st, _, _) = get("GET", "/ui/digits.txt", &[("if-match", "*")]).await;
        assert_eq!(st, StatusCode::OK);

        let (st, h, body) = get("GET", "/ui/digits.txt", &[("range", "bytes=2-4")]).await;
        assert_eq!((st, body.as_slice()), (StatusCode::PARTIAL_CONTENT, &b"234"[..]));
        assert_eq!(h["content-range"], "bytes 2-4/10");
        assert_eq!(h["content-length"], "3");
        let (_, h, body) = get("GET", "/ui/digits.txt", &[("range", "bytes=-3")]).await;
        assert_eq!(
            (body.as_slice(), &h["content-range"]),
            (&b"789"[..], &HeaderValue::from_static("bytes 7-9/10"))
        );
        let (st, _, body) = get(
            "GET",
            "/ui/digits.txt",
            &[("range", "bytes=2-4"), ("if-range", "\"x\"")],
        )
        .await;
        assert_eq!((st, body.len()), (StatusCode::OK, 10));
        let (st, h, body) = get("GET", "/ui/digits.txt", &[("range", "bytes=20-")]).await;
        assert_eq!(st, StatusCode::RANGE_NOT_SATISFIABLE);
        assert_eq!(h["content-range"], "bytes */10");
        assert_eq!(body, b"invalid range: failed to overlap\n");
        assert!(h.get("cache-control").is_none());
        let (st, _, body) = get("GET", "/ui/digits.txt", &[("range", "items=1-2")]).await;
        assert_eq!(
            (st, body.as_slice()),
            (StatusCode::RANGE_NOT_SATISFIABLE, &b"invalid range\n"[..])
        );
        // Overlapping ranges larger than the file are ignored.
        let (st, _, _) = get("GET", "/ui/digits.txt", &[("range", "bytes=0-9,0-9")]).await;
        assert_eq!(st, StatusCode::OK);
        let (st, h, body) = get("GET", "/ui/digits.txt", &[("range", "bytes=0-1,8-9")]).await;
        assert_eq!(st, StatusCode::PARTIAL_CONTENT);
        let ct = h["content-type"].to_str().expect("ct").to_owned();
        let boundary = ct
            .strip_prefix("multipart/byteranges; boundary=")
            .expect("multipart");
        let want = format!(
            "--{boundary}\r\nContent-Range: bytes 0-1/10\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n01\
             \r\n--{boundary}\r\nContent-Range: bytes 8-9/10\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n89\
             \r\n--{boundary}--\r\n"
        );
        assert_eq!(String::from_utf8_lossy(&body), want);
        assert_eq!(h["content-length"], want.len().to_string().as_str());
    }

    /// Replays `tests/fixtures/ui/requests.txt` and compares with what the
    /// deployer's Go stack (secure -> ServeMux -> StripPrefix ->
    /// remoteHandler -> http.FileServerFS) answered (`golden.txt`).
    #[tokio::test]
    async fn matches_the_go_stack() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ui");
        let r = router(Remote::from_dir(root.join("dist")).expect("remote"));
        let reqs = std::fs::read_to_string(root.join("requests.txt")).expect("requests");
        let golden = std::fs::read_to_string(root.join("golden.txt")).expect("golden");
        let mut out = String::new();
        for line in reqs.trim().lines() {
            let mut parts = line.split('|');
            let (method, path) = parts.next().and_then(|m| m.split_once(' ')).expect("line");
            let mut b = http::Request::builder().method(method).uri(path);
            for hv in parts {
                let (k, v) = hv.split_once(": ").expect("header");
                b = b.header(k, v);
            }
            let resp = r
                .clone()
                .oneshot(b.body(Body::empty()).expect("req"))
                .await
                .expect("infallible");
            let (p, body) = resp.into_parts();
            let mut body = body.collect().await.expect("body").to_bytes().to_vec();
            let boundary = p
                .headers
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.strip_prefix("multipart/byteranges; boundary="))
                .map(str::to_owned);
            let fix = |s: String| match &boundary {
                Some(b) => s.replace(b.as_str(), "BOUNDARY"),
                None => s,
            };
            out.push_str(&format!("== {line}\nstatus {}\n", p.status.as_u16()));
            let mut names: Vec<&str> = p.headers.keys().map(http::HeaderName::as_str).collect();
            names.sort_unstable();
            names.dedup();
            for k in names {
                // Go's recorder sees the handler's headers; the length of an
                // error/redirect body is added by the server (both sides).
                if k == "content-length" && !matches!(p.status.as_u16(), 200 | 206) {
                    continue;
                }
                let v: Vec<&str> = p
                    .headers
                    .get_all(k)
                    .iter()
                    .filter_map(|v| v.to_str().ok())
                    .collect();
                out.push_str(&fix(format!("{k}: {}\n", v.join(", "))));
            }
            if method == "HEAD" {
                body.clear();
            }
            let body = match &boundary {
                Some(_) => gocompat::quote(&fix(String::from_utf8_lossy(&body).into_owned())),
                None => gocompat::quote_bytes(&body),
            };
            out.push_str(&format!("body {body}\n"));
        }
        let (got, want): (Vec<&str>, Vec<&str>) = (out.lines().collect(), golden.lines().collect());
        for (i, (g, w)) in got.iter().zip(&want).enumerate() {
            assert_eq!(g, w, "line {} of golden.txt", i + 1);
        }
        assert_eq!(got.len(), want.len());
    }
}
