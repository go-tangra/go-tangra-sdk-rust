//! The slice of `gopkg.in/yaml.v3` the help-docs front-matter needs: a node
//! tree with 1-based lines (`yaml.Node`), and decoding into `string`, `int`
//! and `[]string` with yaml.v3's resolution rules (`resolve.go`,
//! `decode.go` `scalar`/`sequence`/`null`).
//!
//! Parsing uses `yaml-rust2` (a YAML 1.2 parser ported from libyaml, like
//! yaml.v3's). Only the first document is read, as `yaml.Unmarshal` does.

use std::collections::HashMap;

use base64::Engine as _;
use yaml_rust2::parser::{Event, Parser, Tag};
use yaml_rust2::scanner::{Marker, TScalarStyle};

/// A parsed node.
#[derive(Debug, Clone)]
pub(crate) struct Node {
    pub(crate) kind: Kind,
    /// 1-based line of the node's first token.
    pub(crate) line: usize,
}

#[derive(Debug, Clone)]
pub(crate) enum Kind {
    Scalar {
        value: String,
        plain: bool,
        /// The explicit tag in yaml.v3's short form ("" when untagged).
        tag: String,
    },
    Seq(Vec<Node>),
    Map(Vec<(Node, Node)>),
}

impl Node {
    /// yaml.v3 `Node.Value` of a key (a scalar's text; "" otherwise).
    pub(crate) fn key_text(&self) -> &str {
        match &self.kind {
            Kind::Scalar { value, .. } => value,
            _ => "",
        }
    }
}

/// yaml.v3 `shortTag`.
fn short_tag(handle: &str, suffix: &str) -> String {
    const LONG: &str = "tag:yaml.org,2002:";
    let full = format!("{handle}{suffix}");
    match full.strip_prefix(LONG) {
        Some(rest) => format!("!!{rest}"),
        None => full,
    }
}

fn tag_of(t: Option<&Tag>) -> String {
    match t {
        None => String::new(),
        Some(t) => match short_tag(&t.handle, &t.suffix) {
            // The non-specific tag "!" resolves like an untagged node.
            s if s == "!" => String::new(),
            s => s,
        },
    }
}

/// Parses the first YAML document of `src`. `Ok(None)` for a stream with no
/// document (empty or comments only). The error is yaml.v3-like
/// (`line N: <problem>`).
pub(crate) fn parse(src: &str) -> Result<Option<Node>, String> {
    let mut p = Parser::new_from_str(src);
    let mut anchors: HashMap<usize, Node> = HashMap::new();
    let err = |e: yaml_rust2::ScanError| format!("line {}: {}", e.marker().line(), e.info());
    loop {
        let (ev, _) = p.next_token().map_err(err)?;
        match ev {
            Event::StreamStart => {}
            Event::StreamEnd => return Ok(None),
            Event::DocumentStart => {
                let (ev, mark) = p.next_token().map_err(err)?;
                let node = build(&mut p, ev, mark, &mut anchors).map_err(|e| match e {
                    BuildError::Scan(e) => err(e),
                    BuildError::Msg(m) => m,
                })?;
                return Ok(Some(node));
            }
            _ => return Err("line 1: unexpected event".to_owned()),
        }
    }
}

enum BuildError {
    Scan(yaml_rust2::ScanError),
    Msg(String),
}

fn build(
    p: &mut Parser<std::str::Chars<'_>>,
    ev: Event,
    mark: Marker,
    anchors: &mut HashMap<usize, Node>,
) -> Result<Node, BuildError> {
    let line = mark.line();
    let (node, anchor) = match ev {
        Event::Scalar(value, style, anchor, tag) => (
            Node {
                kind: Kind::Scalar {
                    value,
                    plain: style == TScalarStyle::Plain,
                    tag: tag_of(tag.as_ref()),
                },
                line,
            },
            anchor,
        ),
        Event::SequenceStart(anchor, _) => {
            let mut items = Vec::new();
            loop {
                let (ev, m) = p.next_token().map_err(BuildError::Scan)?;
                if matches!(ev, Event::SequenceEnd) {
                    break;
                }
                items.push(build(p, ev, m, anchors)?);
            }
            (
                Node {
                    kind: Kind::Seq(items),
                    line,
                },
                anchor,
            )
        }
        Event::MappingStart(anchor, _) => {
            let mut pairs = Vec::new();
            loop {
                let (ev, m) = p.next_token().map_err(BuildError::Scan)?;
                if matches!(ev, Event::MappingEnd) {
                    break;
                }
                let k = build(p, ev, m, anchors)?;
                let (ev, m) = p.next_token().map_err(BuildError::Scan)?;
                let v = build(p, ev, m, anchors)?;
                pairs.push((k, v));
            }
            (
                Node {
                    kind: Kind::Map(pairs),
                    line,
                },
                anchor,
            )
        }
        Event::Alias(id) => {
            let mut n = anchors
                .get(&id)
                .cloned()
                .ok_or_else(|| BuildError::Msg(format!("line {line}: unknown anchor referenced")))?;
            n.line = line;
            return Ok(n);
        }
        _ => return Err(BuildError::Msg(format!("line {line}: unexpected event"))),
    };
    if anchor > 0 {
        anchors.insert(anchor, node.clone());
    }
    Ok(node)
}

/// A resolved scalar (yaml.v3 `resolve`).
#[derive(Debug, Clone, PartialEq)]
enum Resolved {
    Null,
    Bool,
    Int(i64),
    Uint(u64),
    Float(f64),
    Str,
    Binary(Vec<u8>),
    Other,
}

const RESOLVABLE: [&str; 7] = ["", "!!str", "!!bool", "!!int", "!!float", "!!null", "!!timestamp"];

/// Go `strconv.ParseInt(s, 0, 64)` (underscores already removed).
fn parse_int0(s: &str) -> Option<i64> {
    let (neg, body) = match s.as_bytes().first() {
        Some(b'+') => (false, &s[1..]),
        Some(b'-') => (true, &s[1..]),
        _ => (false, s),
    };
    let u = parse_uint0(body)?;
    if neg {
        if u <= 1u64 << 63 {
            Some((u as i128).wrapping_neg() as i64)
        } else {
            None
        }
    } else {
        i64::try_from(u).ok()
    }
}

/// Go `strconv.ParseUint(s, 0, 64)`.
fn parse_uint0(s: &str) -> Option<u64> {
    let lower = s.to_ascii_lowercase();
    let (radix, digits) = if let Some(d) = lower.strip_prefix("0x") {
        (16, d)
    } else if let Some(d) = lower.strip_prefix("0b") {
        (2, d)
    } else if let Some(d) = lower.strip_prefix("0o") {
        (8, d)
    } else if lower.len() > 1 && lower.starts_with('0') {
        (8, &lower[1..])
    } else {
        (10, lower.as_str())
    };
    if digits.is_empty() || !digits.chars().all(|c| c.is_digit(radix)) {
        return None;
    }
    u64::from_str_radix(digits, radix).ok()
}

fn yaml_style_float(s: &str) -> bool {
    // ^[-+]?(\.[0-9]+|[0-9]+(\.[0-9]*)?)([eE][-+]?[0-9]+)?$
    let b = s.as_bytes();
    let mut i = 0;
    if matches!(b.first(), Some(b'+' | b'-')) {
        i += 1;
    }
    let digits = |i: &mut usize| {
        let st = *i;
        while *i < b.len() && b[*i].is_ascii_digit() {
            *i += 1;
        }
        *i - st
    };
    if b.get(i) == Some(&b'.') {
        i += 1;
        if digits(&mut i) == 0 {
            return false;
        }
    } else {
        if digits(&mut i) == 0 {
            return false;
        }
        if b.get(i) == Some(&b'.') {
            i += 1;
            digits(&mut i);
        }
    }
    if matches!(b.get(i), Some(b'e' | b'E')) {
        i += 1;
        if matches!(b.get(i), Some(b'+' | b'-')) {
            i += 1;
        }
        if digits(&mut i) == 0 {
            return false;
        }
    }
    i == b.len()
}

/// yaml.v3 `resolve(tag, in)`; `Err` where yaml.v3 fails ("cannot decode").
fn resolve(tag: &str, s: &str) -> Result<Resolved, ()> {
    if tag == "!!binary" {
        return base64::engine::general_purpose::STANDARD
            .decode(s)
            .map(Resolved::Binary)
            .map_err(|_| ());
    }
    if !RESOLVABLE.contains(&tag) {
        return Ok(Resolved::Other);
    }
    let (rtag, out) = resolve_plain(tag, s);
    match tag {
        "" | "!!str" => Ok(out),
        t if t == rtag => Ok(out),
        #[allow(clippy::cast_precision_loss)]
        "!!float" if rtag == "!!int" => match out {
            Resolved::Int(i) => Ok(Resolved::Float(i as f64)),
            _ => Err(()),
        },
        _ => Err(()),
    }
}

fn resolve_plain(tag: &str, s: &str) -> (&'static str, Resolved) {
    let hint = match s.as_bytes().first() {
        None => b'N',
        Some(b'+' | b'-') => b'S',
        Some(b'0'..=b'9') => b'D',
        Some(b'y' | b'Y' | b'n' | b'N' | b't' | b'T' | b'f' | b'F' | b'o' | b'O' | b'~') => b'M',
        Some(b'.') => b'.',
        Some(_) => 0,
    };
    if hint != 0 && tag != "!!str" {
        match s {
            "true" | "True" | "TRUE" | "false" | "False" | "FALSE" => return ("!!bool", Resolved::Bool),
            "" | "~" | "null" | "Null" | "NULL" => return ("!!null", Resolved::Null),
            ".nan" | ".NaN" | ".NAN" => return ("!!float", Resolved::Float(f64::NAN)),
            ".inf" | ".Inf" | ".INF" | "+.inf" | "+.Inf" | "+.INF" => {
                return ("!!float", Resolved::Float(f64::INFINITY));
            }
            "-.inf" | "-.Inf" | "-.INF" => return ("!!float", Resolved::Float(f64::NEG_INFINITY)),
            "<<" => return ("!!merge", Resolved::Str),
            _ => {}
        }
        match hint {
            b'.' => {
                if let Ok(f) = s.parse::<f64>() {
                    return ("!!float", Resolved::Float(f));
                }
            }
            b'D' | b'S' => {
                if (tag.is_empty() || tag == "!!timestamp") && is_timestamp(s) {
                    return ("!!timestamp", Resolved::Other);
                }
                let plain = s.replace('_', "");
                if let Some(i) = parse_int0(&plain) {
                    return ("!!int", Resolved::Int(i));
                }
                if let Some(u) = parse_uint0(&plain) {
                    return ("!!int", Resolved::Uint(u));
                }
                if yaml_style_float(&plain)
                    && let Ok(f) = plain.parse::<f64>()
                {
                    return ("!!float", Resolved::Float(f));
                }
            }
            _ => {}
        }
    }
    ("!!str", Resolved::Str)
}

/// yaml.v3 `parseTimestamp` (only whether it is one matters here: a
/// timestamp never decodes into an int or a string differently).
fn is_timestamp(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() < 6 || !b[..4].iter().all(u8::is_ascii_digit) || b[4] != b'-' {
        return false;
    }
    // "2006-1-2" with optional time: the date part is YYYY-M(M)-D(D).
    let date_end = s.find(['T', 't', ' ']).unwrap_or(s.len());
    let parts: Vec<&str> = s[..date_end].split('-').collect();
    if parts.len() != 3
        || !parts
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|c| c.is_ascii_digit()))
    {
        return false;
    }
    let (Ok(m), Ok(d)) = (parts[1].parse::<u32>(), parts[2].parse::<u32>()) else {
        return false;
    };
    if parts[1].len() > 2 || parts[2].len() > 2 || !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return false;
    }
    date_end == s.len() || s.len() > date_end + 1
}

fn indicated_string(plain: bool, tag: &str) -> bool {
    tag == "!!str" || (tag.is_empty() && !plain)
}

/// `Node.Decode(&string)`: `Ok(true)` set, `Ok(false)` null (unchanged).
pub(crate) fn decode_string(n: &Node, out: &mut String) -> Result<bool, ()> {
    let Kind::Scalar { value, plain, tag } = &n.kind else {
        return Err(());
    };
    if indicated_string(*plain, tag) {
        value.clone_into(out);
        return Ok(true);
    }
    match resolve(tag, value)? {
        Resolved::Null => Ok(false),
        Resolved::Binary(b) => {
            *out = String::from_utf8_lossy(&b).into_owned();
            Ok(true)
        }
        _ => {
            value.clone_into(out);
            Ok(true)
        }
    }
}

/// `Node.Decode(&int)` (Go `int` is 64-bit).
pub(crate) fn decode_int(n: &Node, out: &mut i64) -> Result<(), ()> {
    let Kind::Scalar { value, plain, tag } = &n.kind else {
        return Err(());
    };
    if indicated_string(*plain, tag) {
        return Err(());
    }
    match resolve(tag, value)? {
        Resolved::Null => Ok(()),
        Resolved::Int(i) => {
            *out = i;
            Ok(())
        }
        Resolved::Uint(u) => i64::try_from(u).map(|i| *out = i).map_err(|_| ()),
        #[allow(clippy::cast_possible_truncation, clippy::cast_precision_loss)]
        Resolved::Float(f) if f <= i64::MAX as f64 => {
            // Go int64(f) truncates toward zero.
            *out = f as i64;
            Ok(())
        }
        _ => Err(()),
    }
}

/// `Node.Decode(&[]string)`: null elements are dropped; a failing element
/// is dropped and makes the whole decode an error (the good ones stay).
pub(crate) fn decode_strings(n: &Node, out: &mut Vec<String>) -> Result<(), ()> {
    match &n.kind {
        Kind::Scalar { value, plain, tag } => {
            if !indicated_string(*plain, tag) && resolve(tag, value)? == Resolved::Null {
                out.clear();
                return Ok(());
            }
            Err(())
        }
        Kind::Map(_) => Err(()),
        Kind::Seq(items) => {
            let mut good = Vec::with_capacity(items.len());
            let mut failed = false;
            for it in items {
                let mut s = String::new();
                match decode_string(it, &mut s) {
                    Ok(true) => good.push(s),
                    Ok(false) => {}
                    Err(()) => failed = true,
                }
            }
            *out = good;
            if failed { Err(()) } else { Ok(()) }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(src: &str) -> Node {
        let n = parse(src).expect("parse").expect("doc");
        match n.kind {
            Kind::Map(mut m) => m.remove(0).1,
            _ => panic!("not a map"),
        }
    }

    #[test]
    fn scalars_resolve_like_yaml_v3() {
        let int = |s: &str| {
            let mut v = -99;
            decode_int(&one(&format!("k: {s}\n")), &mut v).map(|()| v)
        };
        assert_eq!(int("0x1F"), Ok(31));
        assert_eq!(int("0o17"), Ok(15));
        assert_eq!(int("017"), Ok(15));
        assert_eq!(int("08"), Ok(8));
        assert_eq!(int("0b101"), Ok(5));
        assert_eq!(int("1_000"), Ok(1000));
        assert_eq!(int("+7"), Ok(7));
        assert_eq!(int("-3"), Ok(-3));
        assert_eq!(int("1.9"), Ok(1));
        assert_eq!(int("-1.9"), Ok(-1));
        assert_eq!(int("2.5e1"), Ok(25));
        assert_eq!(int("~"), Ok(-99));
        assert_eq!(int("!!float 3"), Ok(3));
        assert!(int("abc").is_err() && int("true").is_err() && int("'5'").is_err());
        assert!(int(".nan").is_err() && int("2024-01-01").is_err() && int("!!int x").is_err());
        assert!(int("18446744073709551615").is_err());
        let s = |src: &str| {
            let mut v = "default".to_owned();
            decode_string(&one(&format!("k: {src}\n")), &mut v).map(|_| v)
        };
        assert_eq!(s("0x10"), Ok("0x10".into()));
        assert_eq!(s("~"), Ok("default".into()));
        assert_eq!(s("''"), Ok(String::new()));
        assert_eq!(s("!!binary aGk="), Ok("hi".into()));
        assert_eq!(s("!foo bar"), Ok("bar".into()));
        assert!(s("[a]").is_err() && s("!!int x").is_err());
        let list = |src: &str| {
            let mut v = vec!["x".to_owned()];
            let r = decode_strings(&one(&format!("k: {src}\n")), &mut v);
            (r, v)
        };
        assert_eq!(list("[a, ~, 1]"), (Ok(()), vec!["a".into(), "1".into()]));
        assert_eq!(list("~"), (Ok(()), vec![]));
        assert_eq!(list("[b, [c]]"), (Err(()), vec!["b".into()]));
        assert!(list("a").0.is_err());
    }

    #[test]
    fn lines_and_documents() {
        let n = parse("# c\na: 1\nb:\n  - x\n").expect("ok").expect("doc");
        let Kind::Map(m) = n.kind else { panic!() };
        assert_eq!((m[0].0.line, m[1].0.line), (2, 3));
        assert!(parse("").expect("ok").is_none());
        assert!(parse("# only\n").expect("ok").is_none());
        let e = parse("a: [x\n").expect_err("syntax");
        assert!(e.starts_with("line "), "{e}");
    }
}
