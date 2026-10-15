//! Link and image reference checks (go-tangra `helpdocs/links.go`). The Go
//! regular expressions are RE2; the `regex` crate has the same semantics
//! (leftmost-first, no backtracking). Go's `\s` and `\b` are ASCII-only, so
//! they are spelled out here (`[\t\n\f\r ]`, `(?-u:\b)`).

use std::sync::LazyLock;

use regex::Regex;

use super::Loader;
use crate::gocompat;

/// A link or image target found in a page's Markdown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Ref {
    pub(crate) target: String,
    pub(crate) line: usize,
    pub(crate) image: bool,
}

#[allow(clippy::expect_used)]
fn re(s: &str) -> Regex {
    Regex::new(s).expect("regex")
}

const WS: &str = r"[\t\n\x0C\r ]";
const NWS: &str = r"[^\t\n\x0C\r ]";

// [text](target) not preceded by "!"; text may hold one level of brackets.
static LINK_RE: LazyLock<Regex> = LazyLock::new(|| {
    re(&format!(
        r"(^|[^!\\])\[(?:[^\[\]]|\[[^\[\]]*\])*\]\({WS}*(<[^>]*>|[^\t\n\x0C\r )]*)"
    ))
});
static IMAGE_RE: LazyLock<Regex> = LazyLock::new(|| {
    re(&format!(
        r"!\[(?:[^\[\]]|\[[^\[\]]*\])*\]\({WS}*(<[^>]*>|[^\t\n\x0C\r )]*)"
    ))
});
// [label]: target
static REF_DEF_RE: LazyLock<Regex> =
    LazyLock::new(|| re(&format!(r"^ {{0,3}}\[[^\]]+\]:{WS}*(<[^>]*>|{NWS}+)")));
// <scheme:...>
static AUTO_RE: LazyLock<Regex> = LazyLock::new(|| re(r"<([A-Za-z][A-Za-z0-9+.-]{1,31}:[^\t\n\x0C\r <>]*)>"));
// raw HTML href="..." / src="..."
static ATTR_RE: LazyLock<Regex> = LazyLock::new(|| {
    re(&format!(
        r#"(?i)(?-u:\b)(href|src){WS}*={WS}*("[^"]*"|'[^']*'|[^\t\n\x0C\r >]+)"#
    ))
});
static CODE_RE: LazyLock<Regex> = LazyLock::new(|| re(r"``.*?``|`[^`]*`"));
static SCHEME_RE: LazyLock<Regex> = LazyLock::new(|| re(r"^([a-z][a-z0-9+.-]*):"));

/// Returns the link and image targets of `body` (whose first line is file
/// line `first`), skipping fenced code blocks and inline code spans.
pub(crate) fn scan_refs(body: &str, first: usize) -> Vec<Ref> {
    let mut out = Vec::new();
    let mut fence = String::new();
    for (i, line) in body.split('\n').enumerate() {
        let n = first + i;
        let t = line.trim_start_matches(' ');
        if line.len() - t.len() <= 3 {
            if fence.is_empty() && (t.starts_with("```") || t.starts_with("~~~")) {
                fence = t[..3].to_owned();
                continue;
            }
            if !fence.is_empty() && t.starts_with(fence.as_str()) {
                fence.clear();
                continue;
            }
        }
        if !fence.is_empty() {
            continue;
        }
        let line = CODE_RE.replace_all(line, "");
        for c in IMAGE_RE.captures_iter(&line) {
            out.push(Ref {
                target: unangle(c.get(1).map_or("", |m| m.as_str())),
                line: n,
                image: true,
            });
        }
        for c in LINK_RE.captures_iter(&line) {
            out.push(Ref {
                target: unangle(c.get(2).map_or("", |m| m.as_str())),
                line: n,
                image: false,
            });
        }
        if let Some(c) = REF_DEF_RE.captures(&line) {
            out.push(Ref {
                target: unangle(c.get(1).map_or("", |m| m.as_str())),
                line: n,
                image: false,
            });
        }
        for c in AUTO_RE.captures_iter(&line) {
            out.push(Ref {
                target: c.get(1).map_or("", |m| m.as_str()).to_owned(),
                line: n,
                image: false,
            });
        }
        for c in ATTR_RE.captures_iter(&line) {
            let v = c.get(2).map_or("", |m| m.as_str()).trim_matches(['"', '\'']);
            out.push(Ref {
                target: v.to_owned(),
                line: n,
                image: c.get(1).is_some_and(|m| m.as_str().eq_ignore_ascii_case("src")),
            });
        }
    }
    out
}

fn unangle(s: &str) -> String {
    let s = s.strip_prefix('<').unwrap_or(s);
    s.strip_suffix('>').unwrap_or(s).to_owned()
}

/// The lower-cased URL scheme of `target`, ignoring the ASCII whitespace
/// and control characters browsers strip ("java\tscript:").
fn scheme_of(target: &str) -> String {
    let s: String = target.chars().filter(|&r| r > ' ' && r != '\u{7f}').collect();
    SCHEME_RE
        .captures(&s.to_lowercase())
        .and_then(|c| c.get(1).map(|m| m.as_str().to_owned()))
        .unwrap_or_default()
}

impl Loader {
    /// Checks one reference of page `file`: a problem message, or `None`.
    pub(crate) fn resolve(&self, file: &str, r: &Ref) -> Option<String> {
        let t = r.target.trim();
        let what = if r.image { "image" } else { "link" };
        if t.is_empty() {
            return Some(format!("empty {what} target"));
        }
        let s = scheme_of(t);
        if !s.is_empty() {
            if r.image {
                return Some(format!(
                    "image {t}: images must be bundled under docs/help (relative path)"
                ));
            }
            return match s.as_str() {
                "http" | "https" | "mailto" => None,
                _ => Some(format!(
                    "link {t}: scheme {s}: is not allowed (http, https, mailto or a relative path)"
                )),
            };
        }
        if t.starts_with("//") || t.starts_with("\\\\") {
            return Some(format!("{what} {t}: protocol-relative URLs are not allowed"));
        }
        if t.starts_with('/') {
            if r.image {
                return Some(format!("image {t}: images must be referenced by a relative path"));
            }
            return None; // a portal route, e.g. /ipam/subnets
        }
        let p = t.find(['#', '?']).map_or(t, |i| &t[..i]);
        if p.is_empty() {
            if r.image {
                return Some(format!("image {t}: not a file"));
            }
            return None; // same-page anchor
        }
        let Ok(p) = gocompat::path_unescape(p) else {
            return Some(format!("{what} {t}: bad escape"));
        };
        // Go keeps the unescaped bytes as a string; the lookups below only
        // match valid UTF-8 paths, and messages print the bytes lossily.
        let p = String::from_utf8_lossy(&p);
        let resolved = gocompat::join(&gocompat::dir(file), &p);
        if resolved == ".." || resolved.starts_with("../") {
            return Some(format!("{what} {t}: points outside docs/help"));
        }
        if r.image {
            if self.assets.contains_key(&resolved) {
                return None;
            }
            return Some(format!("image {t}: {resolved} not found"));
        }
        if self.files.contains(&resolved) || self.assets.contains_key(&resolved) {
            return None;
        }
        Some(format!(
            "link {t}: {resolved} not found (link to pages by their .md file)"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn targets(s: &str) -> Vec<(String, bool)> {
        scan_refs(s, 1).into_iter().map(|r| (r.target, r.image)).collect()
    }

    #[test]
    fn scans_like_go() {
        assert_eq!(
            targets("[a](x.md) ![i](y.png) [![b](z.gif)](w.md)"),
            vec![
                ("y.png".into(), true),
                ("z.gif".into(), true),
                ("x.md".into(), false),
                ("w.md".into(), false)
            ]
        );
        assert_eq!(
            targets("[js](javascript:alert(1))"),
            vec![("javascript:alert(1".into(), false)]
        );
        assert_eq!(targets("`[x](no.md)` \\[y](no.md)"), vec![]);
        assert_eq!(
            targets("```\n[x](no.md)\n```\n[y](yes.md)"),
            vec![("yes.md".into(), false)]
        );
        assert_eq!(
            targets("<a HREF=\"p.md\"> <img src='i.png'> <ftp://x>"),
            vec![
                ("ftp://x".into(), false),
                ("p.md".into(), false),
                ("i.png".into(), true)
            ]
        );
        assert_eq!(scheme_of("JAVA\tSCRIPT:x"), "javascript");
        assert_eq!(scheme_of("a.md"), "");
    }
}
