//! Front-matter parsing and validation (go-tangra `helpdocs/frontmatter.go`).

use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

use regex::Regex;

use super::{Audience, Kind, Page, Problem};
use crate::gocompat::quote;
use crate::goyaml::{self as yaml, Kind as NodeKind};

const MAX_TITLE_RUNES: usize = 200;
const MAX_SUMMARY_RUNES: usize = 500;
const MAX_TAGS: usize = 20;

#[allow(clippy::expect_used)]
static TAG_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[a-z0-9][a-z0-9-]{0,31}$").expect("regex"));
/// The gateway manifest's bare "resource:action" grammar.
#[allow(clippy::expect_used)]
pub(crate) static PERM_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z0-9][a-z0-9_.-]{0,63}:[a-z0-9][a-z0-9_.-]{0,63}$").expect("regex"));

/// Go `strings.SplitAfter(s, "\n")`.
pub(crate) fn split_after_newline(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut rest = s;
    while let Some(i) = rest.find('\n') {
        out.push(&rest[..=i]);
        rest = &rest[i + 1..];
    }
    out.push(rest);
    out
}

/// Splits `src` into front-matter and Markdown and validates the
/// front-matter. Returns the page (`None` only when there is no front-matter
/// to split off; with problems its fields may be partial), the 1-based line
/// where the Markdown starts, and the problems.
pub(crate) fn parse_page(file: &str, src: &str) -> (Option<Page>, usize, Vec<Problem>) {
    let mut ps = Vec::new();
    let add = |ps: &mut Vec<Problem>, line: usize, msg: String| {
        ps.push(Problem {
            file: file.to_owned(),
            line,
            message: msg,
        });
    };
    let lines = split_after_newline(src);
    if lines[0].trim_end_matches('\n') != "---" {
        add(
            &mut ps,
            1,
            "a page must start with YAML front-matter (a line \"---\")".to_owned(),
        );
        return (None, 0, ps);
    }
    let Some(end) = (1..lines.len()).find(|&i| lines[i].trim_end_matches([' ', '\t', '\n']) == "---") else {
        add(
            &mut ps,
            1,
            "front-matter is not closed (no second \"---\" line)".to_owned(),
        );
        return (None, 0, ps);
    };
    let yaml_src = lines[1..end].concat();
    let body = lines[end + 1..].concat();
    let body_line = end + 2;

    let mut pg = Page {
        audience: Audience::User.as_str().to_owned(),
        lang: "en".to_owned(),
        markdown: body.clone(),
        ..Page::default()
    };
    let mut key_line: HashMap<String, usize> = HashMap::new();
    let fm_line = |yl: usize| yl + 1;

    let doc = match yaml::parse(&yaml_src) {
        Ok(d) => d,
        Err(e) => {
            add(&mut ps, 2, format!("front-matter: {e}"));
            return (Some(pg), body_line, ps);
        }
    };
    if let Some(m) = doc {
        let NodeKind::Map(pairs) = &m.kind else {
            add(
                &mut ps,
                fm_line(m.line),
                "front-matter must be a mapping of fields".to_owned(),
            );
            return (Some(pg), body_line, ps);
        };
        for (k, v) in pairs {
            let line = fm_line(k.line);
            let key = k.key_text();
            key_line.insert(key.to_owned(), line);
            let res = match key {
                "title" => yaml::decode_string(v, &mut pg.title).map(drop),
                "summary" => yaml::decode_string(v, &mut pg.summary).map(drop),
                "kind" => yaml::decode_string(v, &mut pg.kind).map(drop),
                "order" => yaml::decode_int(v, &mut pg.order),
                "tags" => yaml::decode_strings(v, &mut pg.tags),
                "requires" => yaml::decode_string(v, &mut pg.requires).map(drop),
                "audience" => yaml::decode_string(v, &mut pg.audience).map(drop),
                "lang" => yaml::decode_string(v, &mut pg.lang).map(drop),
                _ => {
                    add(
                        &mut ps,
                        line,
                        format!(
                            "unknown front-matter field {} (title, summary, kind, order, tags, requires, audience, lang)",
                            quote(key)
                        ),
                    );
                    continue;
                }
            };
            let wrong_kind = match &v.kind {
                NodeKind::Map(_) => true,
                NodeKind::Seq(_) => key != "tags",
                NodeKind::Scalar { .. } => false,
            };
            if res.is_err() || wrong_kind {
                add(&mut ps, line, format!("front-matter: {key} has the wrong type"));
            }
        }
    }
    let at = |key: &str| key_line.get(key).copied().unwrap_or(1);

    pg.title = pg.title.trim().to_owned();
    if pg.title.is_empty() {
        add(&mut ps, at("title"), "title is required".to_owned());
    } else if pg.title.chars().count() > MAX_TITLE_RUNES || pg.title.contains(['\r', '\n']) {
        add(
            &mut ps,
            at("title"),
            format!("title must be one line of at most {MAX_TITLE_RUNES} characters"),
        );
    }
    pg.summary = pg.summary.trim().to_owned();
    if pg.summary.chars().count() > MAX_SUMMARY_RUNES {
        add(
            &mut ps,
            at("summary"),
            format!("summary exceeds {MAX_SUMMARY_RUNES} characters"),
        );
    }
    if pg.kind.is_empty() {
        add(
            &mut ps,
            at("kind"),
            "kind is required (guide, example, reference, faq)".to_owned(),
        );
    } else if Kind::parse(&pg.kind).is_none() {
        add(
            &mut ps,
            at("kind"),
            format!(
                "kind {} is not one of guide, example, reference, faq",
                quote(&pg.kind)
            ),
        );
    }
    if pg.tags.len() > MAX_TAGS {
        add(&mut ps, at("tags"), format!("at most {MAX_TAGS} tags"));
    }
    let mut seen = HashSet::new();
    for t in &pg.tags {
        if !TAG_RE.is_match(t) {
            add(
                &mut ps,
                at("tags"),
                format!(
                    "tag {} must be lowercase [a-z0-9-], at most 32 characters",
                    quote(t)
                ),
            );
        }
        if !seen.insert(t.as_str()) {
            add(&mut ps, at("tags"), format!("duplicate tag {}", quote(t)));
        }
    }
    if !pg.requires.is_empty() && !PERM_RE.is_match(&pg.requires) {
        add(
            &mut ps,
            at("requires"),
            format!(
                "requires {} is not a resource:action permission",
                quote(&pg.requires)
            ),
        );
    }
    if Audience::parse(&pg.audience).is_none() {
        add(
            &mut ps,
            at("audience"),
            format!("audience {} is not one of user, operator", quote(&pg.audience)),
        );
    }
    if pg.lang != "en" {
        add(
            &mut ps,
            at("lang"),
            format!("lang {} is not supported (only en)", quote(&pg.lang)),
        );
    }
    if body.trim().is_empty() {
        add(
            &mut ps,
            body_line,
            "page has no content after the front-matter".to_owned(),
        );
    }
    (Some(pg), body_line, ps)
}
