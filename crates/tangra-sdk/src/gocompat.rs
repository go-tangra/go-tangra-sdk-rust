//! Ports of the small Go standard-library routines whose exact behaviour the
//! help-docs loader, the UI file server and the catalogue validation depend
//! on: `strconv.Quote` (`%q`), `path.{Clean,Join,Dir,Base,Ext}`,
//! `io/fs.ValidPath`, `net/url.PathUnescape`, `net/http.DetectContentType`
//! and the built-in table of `mime.TypeByExtension`.

use std::fmt::Write as _;

/// Go `strconv.Quote` (what `fmt`'s `%q` prints for a string).
pub(crate) fn quote(s: &str) -> String {
    quote_bytes(s.as_bytes())
}

/// Go `strconv.Quote` over raw bytes (invalid UTF-8 becomes `\xNN`).
pub(crate) fn quote_bytes(b: &[u8]) -> String {
    let mut out = String::with_capacity(b.len() + 2);
    out.push('"');
    let mut rest = b;
    while !rest.is_empty() {
        let (c, n) = match decode_rune(rest) {
            Some(x) => x,
            None => {
                let _ = write!(out, "\\x{:02x}", rest[0]);
                rest = &rest[1..];
                continue;
            }
        };
        rest = &rest[n..];
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if is_print(c) => out.push(c),
            '\u{7}' => out.push_str("\\a"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{b}' => out.push_str("\\v"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                let _ = write!(out, "\\x{:02x}", c as u32);
            }
            c if (c as u32) < 0x10000 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => {
                let _ = write!(out, "\\U{:08x}", c as u32);
            }
        }
    }
    out.push('"');
    out
}

fn decode_rune(b: &[u8]) -> Option<(char, usize)> {
    let n = match b[0] {
        0x00..=0x7f => 1,
        0xc2..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf4 => 4,
        _ => return None,
    };
    let s = std::str::from_utf8(b.get(..n)?).ok()?;
    s.chars().next().map(|c| (c, n))
}

/// Go `strconv.IsPrint`, approximated without the Unicode category tables:
/// controls, non-ASCII spaces, format characters, private use and
/// non-characters are not printable.
pub(crate) fn is_print(c: char) -> bool {
    let u = c as u32;
    if u < 0x80 {
        return (0x20..0x7f).contains(&u);
    }
    if c.is_control() || c.is_whitespace() {
        return false;
    }
    !matches!(u,
        0xad | 0x600..=0x605 | 0x61c | 0x6dd | 0x70f | 0x890..=0x891 | 0x8e2 | 0x180e
        | 0x200b..=0x200f | 0x202a..=0x202e | 0x2060..=0x2064 | 0x2066..=0x206f
        | 0xd800..=0xf8ff | 0xfdd0..=0xfdef | 0xfeff | 0xfff0..=0xfffb | 0xfffe..=0xffff
        | 0x110bd | 0x110cd | 0x13430..=0x1343f | 0x1bca0..=0x1bca3 | 0x1d173..=0x1d17a
        | 0xe0000..=0xe0fff | 0xf0000..)
        && (u & 0xfffe) != 0xfffe
}

/// Go `path.Clean`.
pub(crate) fn clean(p: &str) -> String {
    if p.is_empty() {
        return ".".to_owned();
    }
    let rooted = p.starts_with('/');
    let mut parts: Vec<&str> = Vec::new();
    for seg in p.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                if parts.last().is_some_and(|l| *l != "..") {
                    parts.pop();
                } else if !rooted {
                    parts.push("..");
                }
            }
            s => parts.push(s),
        }
    }
    let joined = parts.join("/");
    match (rooted, joined.is_empty()) {
        (true, _) => format!("/{joined}"),
        (false, true) => ".".to_owned(),
        (false, false) => joined,
    }
}

/// Go `path.Join` of two elements.
pub(crate) fn join(a: &str, b: &str) -> String {
    match (a.is_empty(), b.is_empty()) {
        (true, true) => String::new(),
        (true, false) => clean(b),
        (false, true) => clean(a),
        (false, false) => clean(&format!("{a}/{b}")),
    }
}

/// Go `path.Dir`.
pub(crate) fn dir(p: &str) -> String {
    let d = match p.rfind('/') {
        Some(i) => &p[..=i],
        None => "",
    };
    clean(d)
}

/// Go `path.Base`.
#[cfg_attr(not(feature = "ui"), allow(dead_code))]
pub(crate) fn base(p: &str) -> String {
    if p.is_empty() {
        return ".".to_owned();
    }
    let t = p.trim_end_matches('/');
    if t.is_empty() {
        return "/".to_owned();
    }
    match t.rfind('/') {
        Some(i) => t[i + 1..].to_owned(),
        None => t.to_owned(),
    }
}

/// Go `path.Ext`: the suffix from the final dot of the final element.
pub(crate) fn ext(p: &str) -> &str {
    for (i, b) in p.bytes().enumerate().rev() {
        match b {
            b'/' => return "",
            b'.' => return &p[i..],
            _ => {}
        }
    }
    ""
}

/// Go `io/fs.ValidPath`: unrooted, slash-separated, no empty, `.` or `..`
/// elements (the root itself is `.`).
#[cfg_attr(not(feature = "ui"), allow(dead_code))]
pub(crate) fn valid_path(p: &str) -> bool {
    if p == "." {
        return true;
    }
    !p.is_empty() && p.split('/').all(|e| !e.is_empty() && e != "." && e != "..")
}

/// Go `net/url.PathUnescape`: `%XX` escapes only; a malformed escape is an
/// error. The result may be any bytes.
pub(crate) fn path_unescape(s: &str) -> Result<Vec<u8>, ()> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let hi = b.get(i + 1).and_then(|c| (*c as char).to_digit(16));
            let lo = b.get(i + 2).and_then(|c| (*c as char).to_digit(16));
            match (hi, lo) {
                (Some(h), Some(l)) => {
                    out.push(u8::try_from(h * 16 + l).map_err(|_| ())?);
                    i += 3;
                }
                _ => return Err(()),
            }
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    Ok(out)
}

/// Go `net/http.DetectContentType` (WHATWG MIME sniffing over the first 512
/// bytes).
pub(crate) fn detect_content_type(data: &[u8]) -> &'static str {
    let data = &data[..data.len().min(512)];
    let first_non_ws = data.iter().position(|b| !is_ws(*b)).unwrap_or(data.len());
    for sig in SIGNATURES {
        if let Some(ct) = sig.matches(data, first_non_ws) {
            return ct;
        }
    }
    // textSig, last.
    if data[first_non_ws..]
        .iter()
        .any(|&b| b <= 0x08 || b == 0x0b || (0x0e..=0x1a).contains(&b) || (0x1c..=0x1f).contains(&b))
    {
        "application/octet-stream"
    } else {
        "text/plain; charset=utf-8"
    }
}

fn is_ws(b: u8) -> bool {
    matches!(b, b'\t' | b'\n' | b'\x0c' | b'\r' | b' ')
}

enum Sig {
    Html(&'static [u8]),
    Masked {
        mask: &'static [u8],
        pat: &'static [u8],
        skip_ws: bool,
        ct: &'static str,
    },
    Exact(&'static [u8], &'static str),
    Mp4,
}

impl Sig {
    fn matches(&self, data: &[u8], first_non_ws: usize) -> Option<&'static str> {
        match self {
            Sig::Html(h) => {
                let d = &data[first_non_ws..];
                if d.len() < h.len() + 1 {
                    return None;
                }
                for (i, &b) in h.iter().enumerate() {
                    let mut db = d[i];
                    if b.is_ascii_uppercase() {
                        db &= 0xdf;
                    }
                    if b != db {
                        return None;
                    }
                }
                matches!(d[h.len()], b' ' | b'>').then_some("text/html; charset=utf-8")
            }
            Sig::Masked {
                mask,
                pat,
                skip_ws,
                ct,
            } => {
                let d = if *skip_ws { &data[first_non_ws..] } else { data };
                if d.len() < pat.len() {
                    return None;
                }
                pat.iter()
                    .zip(mask.iter())
                    .enumerate()
                    .all(|(i, (p, m))| d[i] & m == *p)
                    .then_some(*ct)
            }
            Sig::Exact(sig, ct) => data.starts_with(sig).then_some(*ct),
            Sig::Mp4 => {
                if data.len() < 12 {
                    return None;
                }
                let box_size = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
                if data.len() < box_size || box_size % 4 != 0 || &data[4..8] != b"ftyp" {
                    return None;
                }
                let mut st = 8;
                while st < box_size {
                    if st != 12 && &data[st..st + 3] == b"mp4" {
                        return Some("video/mp4");
                    }
                    st += 4;
                }
                None
            }
        }
    }
}

const ALL: &[u8] = b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF";

const SIGNATURES: &[Sig] = &[
    Sig::Html(b"<!DOCTYPE HTML"),
    Sig::Html(b"<HTML"),
    Sig::Html(b"<HEAD"),
    Sig::Html(b"<SCRIPT"),
    Sig::Html(b"<IFRAME"),
    Sig::Html(b"<H1"),
    Sig::Html(b"<DIV"),
    Sig::Html(b"<FONT"),
    Sig::Html(b"<TABLE"),
    Sig::Html(b"<A"),
    Sig::Html(b"<STYLE"),
    Sig::Html(b"<TITLE"),
    Sig::Html(b"<B"),
    Sig::Html(b"<BODY"),
    Sig::Html(b"<BR"),
    Sig::Html(b"<P"),
    Sig::Html(b"<!--"),
    Sig::Masked {
        mask: b"\xFF\xFF\xFF\xFF\xFF",
        pat: b"<?xml",
        skip_ws: true,
        ct: "text/xml; charset=utf-8",
    },
    Sig::Exact(b"%PDF-", "application/pdf"),
    Sig::Exact(b"%!PS-Adobe-", "application/postscript"),
    Sig::Masked {
        mask: b"\xFF\xFF\x00\x00",
        pat: b"\xFE\xFF\x00\x00",
        skip_ws: false,
        ct: "text/plain; charset=utf-16be",
    },
    Sig::Masked {
        mask: b"\xFF\xFF\x00\x00",
        pat: b"\xFF\xFE\x00\x00",
        skip_ws: false,
        ct: "text/plain; charset=utf-16le",
    },
    Sig::Masked {
        mask: b"\xFF\xFF\xFF\x00",
        pat: b"\xEF\xBB\xBF\x00",
        skip_ws: false,
        ct: "text/plain; charset=utf-8",
    },
    Sig::Exact(b"\x00\x00\x01\x00", "image/x-icon"),
    Sig::Exact(b"\x00\x00\x02\x00", "image/x-icon"),
    Sig::Exact(b"BM", "image/bmp"),
    Sig::Exact(b"GIF87a", "image/gif"),
    Sig::Exact(b"GIF89a", "image/gif"),
    Sig::Masked {
        mask: b"\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF",
        pat: b"RIFF\x00\x00\x00\x00WEBPVP",
        skip_ws: false,
        ct: "image/webp",
    },
    Sig::Exact(b"\x89PNG\x0D\x0A\x1A\x0A", "image/png"),
    Sig::Exact(b"\xFF\xD8\xFF", "image/jpeg"),
    Sig::Masked {
        mask: b"\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF",
        pat: b"FORM\x00\x00\x00\x00AIFF",
        skip_ws: false,
        ct: "audio/aiff",
    },
    Sig::Masked {
        mask: b"\xFF\xFF\xFF",
        pat: b"ID3",
        skip_ws: false,
        ct: "audio/mpeg",
    },
    Sig::Masked {
        mask: b"\xFF\xFF\xFF\xFF\xFF",
        pat: b"OggS\x00",
        skip_ws: false,
        ct: "application/ogg",
    },
    Sig::Masked {
        mask: ALL,
        pat: b"MThd\x00\x00\x00\x06",
        skip_ws: false,
        ct: "audio/midi",
    },
    Sig::Masked {
        mask: b"\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF",
        pat: b"RIFF\x00\x00\x00\x00AVI ",
        skip_ws: false,
        ct: "video/avi",
    },
    Sig::Masked {
        mask: b"\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF",
        pat: b"RIFF\x00\x00\x00\x00WAVE",
        skip_ws: false,
        ct: "audio/wave",
    },
    Sig::Mp4,
    Sig::Exact(b"\x1A\x45\xDF\xA3", "video/webm"),
    Sig::Masked {
        mask: b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF",
        pat: b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00LP",
        skip_ws: false,
        ct: "application/vnd.ms-fontobject",
    },
    Sig::Exact(b"\x00\x01\x00\x00", "font/ttf"),
    Sig::Exact(b"OTTO", "font/otf"),
    Sig::Exact(b"ttcf", "font/collection"),
    Sig::Exact(b"wOFF", "font/woff"),
    Sig::Exact(b"wOF2", "font/woff2"),
    Sig::Exact(b"\x1F\x8B\x08", "application/x-gzip"),
    Sig::Exact(b"PK\x03\x04", "application/zip"),
    Sig::Exact(b"Rar!\x1A\x07\x00", "application/x-rar-compressed"),
    Sig::Exact(b"Rar!\x1A\x07\x01\x00", "application/x-rar-compressed"),
    Sig::Exact(b"\x00\x61\x73\x6D", "application/wasm"),
];

/// Go `mime.TypeByExtension` with only the built-in table (what a distroless
/// or alpine image without `/etc/mime.types` sees). Case-insensitive.
#[cfg_attr(not(feature = "ui"), allow(dead_code))]
pub(crate) fn type_by_extension(ext: &str) -> Option<&'static str> {
    let lower = ext.to_lowercase();
    let t = match lower.as_str() {
        ".ai" | ".eps" | ".ps" => "application/postscript",
        ".apk" => "application/vnd.android.package-archive",
        ".apng" => "image/apng",
        ".avif" => "image/avif",
        ".bin" | ".com" | ".exe" => "application/octet-stream",
        ".bmp" => "image/bmp",
        ".css" => "text/css; charset=utf-8",
        ".csv" => "text/csv; charset=utf-8",
        ".doc" => "application/msword",
        ".docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        ".ehtml" | ".htm" | ".html" | ".shtml" => "text/html; charset=utf-8",
        ".eml" => "message/rfc822",
        ".flac" => "audio/flac",
        ".gif" => "image/gif",
        ".gz" => "application/gzip",
        ".ico" => "image/vnd.microsoft.icon",
        ".ics" => "text/calendar; charset=utf-8",
        ".jfif" | ".jpeg" | ".jpg" | ".pjp" | ".pjpeg" => "image/jpeg",
        ".js" | ".mjs" => "text/javascript; charset=utf-8",
        ".json" => "application/json",
        ".m4a" => "audio/mp4",
        ".mp3" => "audio/mpeg",
        ".mp4" => "video/mp4",
        ".oga" | ".ogg" | ".opus" => "audio/ogg",
        ".ogv" => "video/ogg",
        ".pdf" => "application/pdf",
        ".png" => "image/png",
        ".ppt" => "application/vnd.ms-powerpoint",
        ".pptx" => "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        ".rdf" => "application/rdf+xml",
        ".rtf" => "application/rtf",
        ".svg" => "image/svg+xml",
        ".text" | ".txt" => "text/plain; charset=utf-8",
        ".tif" | ".tiff" => "image/tiff",
        ".vtt" => "text/vtt; charset=utf-8",
        ".wasm" => "application/wasm",
        ".wav" => "audio/wav",
        ".webm" => "audio/webm",
        ".webp" => "image/webp",
        ".xbl" | ".xml" | ".xsl" => "text/xml; charset=utf-8",
        ".xbm" => "image/x-xbitmap",
        ".xht" | ".xhtml" => "application/xhtml+xml",
        ".xls" => "application/vnd.ms-excel",
        ".xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        ".zip" => "application/zip",
        _ => return None,
    };
    Some(t)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quote_matches_strconv() {
        assert_eq!(quote("a\"b\\c"), r#""a\"b\\c""#);
        assert_eq!(quote("tab\there\n"), r#""tab\there\n""#);
        assert_eq!(quote("\u{7f}\u{1}"), r#""\x7f\x01""#);
        assert_eq!(quote("ünï 日本 🎉"), "\"ünï 日本 🎉\"");
        assert_eq!(quote("nb\u{a0}sp\u{200b}"), "\"nb\\u00a0sp\\u200b\"");
        assert_eq!(quote_bytes(b"a\xffb"), r#""a\xffb""#);
    }

    #[test]
    fn paths_match_go() {
        for (i, o) in [
            ("", "."),
            ("a/../..", ".."),
            ("/../a", "/a"),
            ("a//b/./c/", "a/b/c"),
            ("../../x", "../../x"),
            ("/", "/"),
        ] {
            assert_eq!(clean(i), o, "{i}");
        }
        assert_eq!(join(".", "a.md"), "a.md");
        assert_eq!(join("guides", "../index.md"), "index.md");
        assert_eq!(join(".", "../x"), "../x");
        assert_eq!(dir("a/b.md"), "a");
        assert_eq!(dir("b.md"), ".");
        assert_eq!(base("/assets"), "assets");
        assert_eq!(ext("a/b.tar.gz"), ".gz");
        assert_eq!(ext("a.d/b"), "");
        assert_eq!(ext(".hidden"), ".hidden");
        assert!(valid_path("a/b"));
        assert!(!valid_path("a//b") && !valid_path("./a") && !valid_path("a/..") && !valid_path("/a"));
        assert_eq!(path_unescape("a%20b%2F"), Ok(b"a b/".to_vec()));
        assert!(path_unescape("%zz").is_err() && path_unescape("%4").is_err());
    }

    #[test]
    fn sniffing_matches_go() {
        assert_eq!(detect_content_type(b"\x89PNG\r\n\x1a\nxx"), "image/png");
        assert_eq!(detect_content_type(b"\xff\xd8\xff\xe0"), "image/jpeg");
        assert_eq!(detect_content_type(b"GIF89a.."), "image/gif");
        assert_eq!(detect_content_type(b"RIFF\x24\0\0\0WEBPVP8 "), "image/webp");
        assert_eq!(detect_content_type(b"RIFF"), "text/plain; charset=utf-8");
        assert_eq!(detect_content_type(b"  <html>x"), "text/html; charset=utf-8");
        assert_eq!(detect_content_type(b"<svg/>"), "text/plain; charset=utf-8");
        assert_eq!(detect_content_type(b"\x00\x01binary"), "application/octet-stream");
        assert_eq!(detect_content_type(b"wOF2...."), "font/woff2");
        assert_eq!(detect_content_type(b""), "text/plain; charset=utf-8");
        assert_eq!(type_by_extension(".JS"), Some("text/javascript; charset=utf-8"));
        assert_eq!(type_by_extension(".woff2"), None);
    }
}
