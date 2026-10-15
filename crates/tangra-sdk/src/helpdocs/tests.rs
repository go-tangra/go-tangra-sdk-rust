//! Cross-checks against golden files produced by go-tangra v4.10.0
//! (`helpdocs.Load`, `Bundle.Marshal`, `ComputeDigest`, `Problems.Error`)
//! over the fixture trees in `tests/fixtures/helpdocs`; see
//! `tests/fixtures/README.md` for how they were generated.

use std::path::{Path, PathBuf};

use axum::body::Body;
use http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use super::*;
use crate::app::PeerIdentity;
use crate::identity::SpiffeId;

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/helpdocs")
}

fn cases(kind: &str) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(fixtures().join(kind))
        .expect("fixtures")
        .filter_map(Result::ok)
        .filter(|e| e.path().is_dir())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

fn module_for(name: &str) -> &'static str {
    match name {
        "deployer" => "deployer",
        "bad-module" => "Bad_Module",
        _ => "fixture",
    }
}

#[test]
fn valid_trees_match_go_byte_for_byte() {
    let names = cases("valid");
    assert!(names.len() >= 5, "{names:?}");
    for name in names {
        let dir = fixtures().join("valid").join(&name);
        let b = load_dir(&dir, module_for(&name)).unwrap_or_else(|e| panic!("{name}: {e}"));
        let want_json =
            std::fs::read(fixtures().join("valid").join(format!("{name}.bundle.json"))).expect("golden");
        let want_digest =
            std::fs::read_to_string(fixtures().join("valid").join(format!("{name}.digest"))).expect("golden");
        assert_eq!(b.digest(), want_digest.trim_end(), "{name}: digest");
        assert_eq!(compute_digest(&b), b.digest, "{name}");
        let got = b.marshal();
        assert!(
            got == want_json,
            "{name}: JSON differs\n got: {}\nwant: {}",
            String::from_utf8_lossy(&got),
            String::from_utf8_lossy(&want_json)
        );
        assert_eq!(lint(&FileTree::from_dir(&dir).expect("tree")), Ok(()), "{name}");
        // The wire decoder accepts what the loader produced.
        assert_eq!(decode(&got).as_ref(), Ok(&b), "{name}");
    }
}

/// yaml.v3 and yaml-rust2 word syntax errors differently; the problem,
/// its file and line are the same.
fn normalize(s: &str) -> String {
    s.lines()
        .map(|l| match l.find(": front-matter: ") {
            Some(i) if !l.ends_with(" has the wrong type") => {
                format!("{}: front-matter: <yaml syntax error>", &l[..i])
            }
            _ => l.to_owned(),
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn invalid_trees_are_refused_like_go() {
    let names = cases("invalid");
    assert!(names.len() >= 25, "{names:?}");
    for name in names {
        let dir = fixtures().join("invalid").join(&name);
        let golden = std::fs::read_to_string(fixtures().join("invalid").join(format!("{name}.problems.txt")))
            .expect("golden");
        let (load_want, lint_want) = golden
            .strip_prefix("load:\n")
            .and_then(|s| s.split_once("lint:\n"))
            .expect("golden format");
        let got = load_dir(&dir, module_for(&name)).expect_err(&name).to_string();
        assert_eq!(normalize(&got), normalize(load_want.trim_end()), "{name}: load");
        let tree = FileTree::from_dir(&dir).expect("tree");
        let lint_got = match lint(&tree) {
            Ok(()) => "ok".to_owned(),
            Err(p) => p.to_string(),
        };
        assert_eq!(
            normalize(&lint_got),
            normalize(lint_want.trim_end()),
            "{name}: lint"
        );
    }
}

fn page(title: &str) -> Vec<u8> {
    format!("---\ntitle: {title}\nkind: guide\n---\nbody\n").into_bytes()
}

fn png(size: usize) -> Vec<u8> {
    let mut b = vec![0u8; size];
    b[..8].copy_from_slice(b"\x89PNG\r\n\x1a\n");
    for (i, x) in b.iter_mut().enumerate().skip(8) {
        *x = u8::try_from(i % 251).expect("byte");
    }
    b
}

/// The trees go-tangra's checker built in memory (`generated()`), rebuilt
/// here byte for byte.
#[test]
fn generated_cases_match_go() {
    let golden = std::fs::read_to_string(fixtures().join("generated.golden")).expect("golden");
    let mut want = std::collections::BTreeMap::new();
    for chunk in golden.split("== ").filter(|c| !c.is_empty()) {
        let (name, body) = chunk.split_once('\n').expect("format");
        want.insert(name.to_owned(), body.trim_end().to_owned());
    }
    let render = |r: Result<Bundle, Problems>| match r {
        Ok(b) => format!(
            "digest {} pages {} assets {} json {}",
            quote(&b.digest),
            b.pages.len(),
            b.assets.len(),
            String::from_utf8_lossy(&b.marshal())
        ),
        Err(p) => p.to_string(),
    };
    let mut trees: Vec<(&str, Option<FileTree>)> = vec![("empty", Some(FileTree::new())), ("nil", None)];
    let mut many = FileTree::new();
    many.insert("index.md", page("Home"));
    for i in 0..500 {
        many.insert(format!("p{i:03}.md"), page(&format!("P{i}")));
    }
    trees.push(("pages-501", Some(many)));
    let mut big = FileTree::new();
    let mut b = page("Big");
    b.extend(vec![b'a'; MAX_PAGE_BYTES]);
    let mut e = page("Edge");
    e.extend(vec![b'a'; MAX_PAGE_BYTES - page("Edge").len()]);
    big.insert("index.md", page("Home"))
        .insert("big.md", b)
        .insert("edge.md", e);
    trees.push(("page-too-big", Some(big)));
    let mut asset = FileTree::new();
    asset
        .insert("index.md", page("Home"))
        .insert("big.png", png(MAX_ASSET_BYTES + 1))
        .insert("edge.png", png(MAX_ASSET_BYTES))
        .insert("other.svg", vec![b'a'; MAX_ASSET_BYTES + 1]);
    trees.push(("asset-too-big", Some(asset)));
    let mut total = FileTree::new();
    total.insert("index.md", page("Home"));
    for i in 0..9 {
        total.insert(format!("img/{i}.png"), png(500 << 10));
    }
    trees.push(("total-too-big", Some(total)));
    let mut sym = FileTree::new();
    sym.insert("index.md", page("Home")).insert_irregular("link.md");
    trees.push(("symlink", Some(sym)));
    for (name, tree) in trees {
        let got = render(match &tree {
            Some(t) => load(t, "fixture"),
            None => run(None, "fixture", true),
        });
        assert_eq!(Some(&got), want.get(name), "{name}");
    }
    let missing = render(load_dir("/nonexistent/helpdocs", "fixture"));
    assert_eq!(Some(&missing), want.get("missing-root"));
}

#[test]
fn digest_ignores_input_order_and_detects_changes() {
    let b = load_dir(fixtures().join("valid/rich"), "fixture").expect("load");
    let mut shuffled = b.clone();
    shuffled.pages.reverse();
    shuffled.assets.reverse();
    assert_eq!(compute_digest(&shuffled), b.digest);
    let mut changed = b.clone();
    changed.pages[0].order += 1;
    assert_ne!(compute_digest(&changed), b.digest);
    let mut img = b.clone();
    img.assets[0].data.push(0);
    assert_ne!(compute_digest(&img), b.digest);
    assert_eq!(compute_digest(&Bundle::empty("x")), "");
}

#[test]
fn decode_refuses_tampering() {
    let b = load_dir(fixtures().join("valid/rich"), "fixture").expect("load");
    let raw = String::from_utf8(b.marshal()).expect("utf8");
    let tampered = raw.replacen("Orders help", "Orders HELP", 1);
    assert_eq!(
        decode(tampered.as_bytes()),
        Err(InvalidBundle("digest mismatch".into()))
    );
    let unknown = raw.replacen("{\"schema\":1,", "{\"schema\":1,\"x\":1,", 1);
    assert!(decode(unknown.as_bytes()).is_err());
    assert!(decode(raw.replacen("\"schema\":1", "\"schema\":2", 1).as_bytes()).is_err());
}

#[test]
fn embedded_tree_loads_like_the_directory() {
    static DEPLOYER: include_dir::Dir<'static> =
        include_dir::include_dir!("$CARGO_MANIFEST_DIR/tests/fixtures/helpdocs/valid/deployer");
    let a = load(&FileTree::from_embedded(&DEPLOYER), "deployer").expect("embedded");
    let b = load_dir(fixtures().join("valid/deployer"), "deployer").expect("dir");
    assert_eq!(a, b);
}

fn peer(service: &str) -> PeerIdentity {
    PeerIdentity {
        id: SpiffeId::new("example.org", service).expect("id"),
        service_name: service.to_owned(),
        serial: "1".to_owned(),
        verified_at: std::time::SystemTime::now(),
    }
}

async fn call(
    r: &axum::Router,
    method: &str,
    who: Option<&str>,
    inm: Option<&str>,
) -> (StatusCode, http::HeaderMap, Vec<u8>) {
    let mut req = Request::builder().method(method).uri(BUNDLE_PATH);
    if let Some(v) = inm {
        req = req.header("if-none-match", v);
    }
    let mut req = req.body(Body::empty()).expect("req");
    if let Some(s) = who {
        req.extensions_mut().insert(peer(s));
    }
    let resp = r.clone().oneshot(req).await.expect("infallible");
    let (p, b) = resp.into_parts();
    (
        p.status,
        p.headers,
        b.collect().await.expect("body").to_bytes().to_vec(),
    )
}

#[tokio::test]
async fn handler_serves_gateway_only_with_etag() {
    let b = load_dir(fixtures().join("valid/basic"), "fixture").expect("load");
    let etag = format!("\"{}\"", b.digest);
    let r = router(b.clone(), AllowServices::new([DEFAULT_GATEWAY_SERVICE]));
    let (st, h, body) = call(&r, "GET", Some("gateway"), None).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(body, b.marshal());
    assert_eq!(h["etag"], etag.as_str());
    assert_eq!(h["cache-control"], "no-cache");
    assert_eq!(h["content-type"], "application/json");
    assert_eq!(h["x-content-type-options"], "nosniff");
    assert_eq!(h["content-length"], b.marshal().len().to_string().as_str());
    for inm in [
        etag.clone(),
        format!("W/{etag}"),
        "\"x\", *".to_owned(),
        format!("\"a\" , {etag}"),
    ] {
        let (st, h, body) = call(&r, "GET", Some("gateway"), Some(&inm)).await;
        assert_eq!(st, StatusCode::NOT_MODIFIED, "{inm}");
        assert!(body.is_empty() && h.get("content-type").is_none());
        assert_eq!(h["etag"], etag.as_str());
    }
    let (st, _, _) = call(&r, "GET", Some("gateway"), Some("\"other\"")).await;
    assert_eq!(st, StatusCode::OK);
    let (st, h, body) = call(&r, "GET", Some("lcm"), None).await;
    assert_eq!(
        (st, body.as_slice()),
        (StatusCode::FORBIDDEN, &b"forbidden\n"[..])
    );
    assert_eq!(h["cache-control"], "no-cache");
    assert!(h.get("etag").is_none());
    let (st, _, _) = call(&r, "GET", None, None).await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    let (st, h, body) = call(&r, "POST", Some("gateway"), None).await;
    assert_eq!(st, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(h["allow"], "GET, HEAD");
    assert_eq!(body, b"method not allowed\n");
    let (st, h, body) = call(&r, "HEAD", Some("gateway"), None).await;
    assert_eq!(st, StatusCode::OK);
    assert!(body.is_empty());
    assert_eq!(h["content-length"], b.marshal().len().to_string().as_str());
    // An empty bundle has no ETag.
    let r = router(Bundle::empty("fixture"), AllowServices::new(["gateway"]));
    let (st, h, body) = call(&r, "GET", Some("gateway"), Some("*")).await;
    assert_eq!(st, StatusCode::OK);
    assert!(h.get("etag").is_none());
    assert_eq!(
        body,
        br#"{"schema":1,"module":"fixture","digest":"","pages":[],"assets":[]}"#
    );
}

/// Hundreds of front-matter value forms (yaml.v3 resolution, tags, nulls,
/// anchors, block scalars, odd keys) against go-tangra's verdicts.
#[test]
fn frontmatter_matrix_matches_go() {
    let src = std::fs::read_to_string(fixtures().join("frontmatter-cases.txt")).expect("cases");
    let golden = std::fs::read_to_string(fixtures().join("frontmatter.golden")).expect("golden");
    let want: Vec<&str> = golden
        .split("== ")
        .filter(|c| !c.is_empty())
        .map(|c| c.split_once('\n').map_or("", |(_, b)| b).trim_end())
        .collect();
    let cases: Vec<&str> = src.split("\n%%%%\n").collect();
    assert_eq!(cases.len(), want.len());
    let mut mismatches = Vec::new();
    for (i, (case, want)) in cases.iter().zip(want).enumerate() {
        // Known deviation (README): yaml-rust2 refuses a tab after "key:".
        if case.contains(":\t") {
            continue;
        }
        let mut t = FileTree::new();
        t.insert("index.md", case.as_bytes().to_vec());
        let got = match load(&t, "fixture") {
            Ok(b) => crate::gofmt::json_html_escaped(&b.pages[0]),
            Err(p) => p.to_string(),
        };
        if normalize(&got) != normalize(want) {
            mismatches.push(format!("case {i} {case:?}\n got: {got}\nwant: {want}"));
        }
    }
    assert!(
        mismatches.is_empty(),
        "{} mismatches:\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
}
