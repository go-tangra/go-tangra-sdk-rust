//! Mirrors go-tangra `authz/matcher_test.go`, `loader_test.go` and
//! `authz/file/source_test.go`.

use super::*;

fn load(body: &str) -> Policy {
    Policy::load(body.as_bytes()).expect("load")
}

fn id(name: &str) -> SpiffeId {
    SpiffeId::new("example.org", name).expect("id")
}

#[test]
fn decide_matrix() {
    let p = load(
        r#"version: m1
rules:
  - {id: orders-inv, from: ["spiffe://example.org/svc/orders"], to: ["inventory"], operations: ["/inventory.v1.Inventory/Reserve"], effect: allow}
  - {id: any-billing, from: ["spiffe://example.org/svc/*"], to: ["billing"], effect: allow}
  - {id: http-reads, from: ["spiffe://example.org/svc/web-?"], to: ["catalog"], operations: ["GET /v1/items/*"], effect: allow}
  - {id: block-legacy, from: ["spiffe://example.org/svc/legacy-*"], to: ["*"], effect: deny}
  - {id: legacy-billing, from: ["spiffe://example.org/svc/legacy-1"], to: ["billing"], effect: allow}
"#,
    );
    use Reason::*;
    let cases = [
        (
            "orders",
            "inventory",
            "/inventory.v1.Inventory/Reserve",
            true,
            ExplicitAllow,
            "orders-inv",
        ),
        (
            "orders",
            "inventory",
            "/inventory.v1.Inventory/Release",
            false,
            NoMatchingRule,
            "",
        ),
        ("orders", "catalog", "GET /v1/items/1", false, NoMatchingRule, ""),
        (
            "web-a",
            "catalog",
            "GET /v1/items/1",
            true,
            ExplicitAllow,
            "http-reads",
        ),
        ("web-ab", "catalog", "GET /v1/items/1", false, NoMatchingRule, ""),
        ("web-a", "catalog", "POST /v1/items/1", false, NoMatchingRule, ""),
        ("anyone", "billing", "/x.Y/Z", true, ExplicitAllow, "any-billing"),
        (
            "legacy-1",
            "billing",
            "/x.Y/Z",
            false,
            ExplicitDeny,
            "block-legacy",
        ),
        (
            "legacy-9",
            "inventory",
            "/x.Y/Z",
            false,
            ExplicitDeny,
            "block-legacy",
        ),
        (
            "billing",
            "inventory",
            "/inventory.v1.Inventory/Reserve",
            false,
            NoMatchingRule,
            "",
        ),
    ];
    for (peer, callee, op, allowed, reason, rule) in cases {
        let d = p.authorize(&id(peer), callee, op);
        assert_eq!(
            (d.allowed, d.reason, d.rule_id.as_str(), d.policy_version.as_str()),
            (allowed, reason, rule, "m1"),
            "{peer}->{callee} {op}"
        );
    }
    let d = DenyAll.authorize(&id("a"), "b", "c");
    assert!(!d.allowed && d.reason == NoPolicy);
    let empty = load("version: e\nrules: []\n");
    let d = empty.authorize(&id("a"), "b", "c");
    assert!(!d.allowed && d.reason == NoMatchingRule);
    assert!(AllowAll.authorize(&id("a"), "b", "c").allowed);
}

#[test]
fn decisions_do_not_depend_on_rule_order() {
    let base = load(
        r#"version: s
rules:
  - {id: a1, from: ["spiffe://example.org/svc/a"], to: ["b"], effect: allow}
  - {id: a2, from: ["spiffe://example.org/svc/*"], to: ["b"], effect: allow}
  - {id: d1, from: ["spiffe://example.org/svc/a"], to: ["*"], operations: ["/x.Y/Z"], effect: deny}
"#,
    );
    let probe = [
        ("a", "b", "/x.Y/Z"),
        ("a", "b", "/x.Y/W"),
        ("c", "b", "/x.Y/Z"),
        ("a", "c", "/x.Y/Z"),
    ];
    let want: Vec<Decision> = probe
        .iter()
        .map(|(p, c, o)| base.authorize(&id(p), c, o))
        .collect();
    let mut rules = base.rules.clone();
    for i in 0..rules.len() {
        rules.rotate_left(1);
        if i % 2 == 0 {
            rules.reverse();
        }
        let p = Policy::new("s", rules.clone()).expect("policy");
        let got: Vec<Decision> = probe
            .iter()
            .map(|(pe, c, o)| p.authorize(&id(pe), c, o))
            .collect();
        assert_eq!(got, want);
    }
}

#[test]
fn glob_semantics() {
    let cases = [
        ("*", "anything", true),
        ("a*", "abc", true),
        ("a*", "b", false),
        ("a?c", "abc", true),
        ("a?c", "abbc", false),
        ("/x.Y/*", "/x.Y/Z", true),
        ("/x.Y/*", "/x.Z/Z", false),
        ("GET /v1/*", "GET /v1/a/b", true),
        ("GET /v1/*", "POST /v1/a", false),
        ("exact", "exact", true),
        ("exact", "exactly", false),
        ("", "", true),
        ("", "x", false),
        ("a*b*c", "aXbYbZc", true),
        ("*c", "abcabd", false),
    ];
    for (pat, s, m) in cases {
        assert_eq!(glob_match(pat, s), m, "{pat} vs {s}");
    }
}

const GOOD: &str = r#"version: v1
rules:
  - id: a-to-b
    from: ["spiffe://example.org/svc/a"]
    to: ["b"]
    operations: ["/pkg.Svc/Method"]
    effect: allow
  - id: block-legacy
    from: ["spiffe://example.org/svc/legacy-*"]
    to: ["*"]
    effect: deny
"#;

#[test]
fn load_yaml_and_json() {
    let p = load(GOOD);
    assert_eq!(p.version, "v1");
    assert_eq!(p.rules.len(), 2);
    assert_eq!(p.rules[1].operations, vec!["*".to_owned()]);
    let js = r#"{"version":"v2","rules":[{"id":"x","from":["spiffe://example.org/svc/a"],"to":["b"],"effect":"allow"}]}"#;
    let p = load(js);
    assert_eq!(
        (p.version.as_str(), p.rules[0].operations[0].as_str()),
        ("v2", "*")
    );
    // yaml.v3 reads any scalar into a string field.
    assert_eq!(load("version: 3\nrules: []\n").version, "3");
}

#[test]
fn load_rejects() {
    let cases = [
        ("empty", ""),
        ("blank", "  \n"),
        ("no version", "rules: []"),
        ("no rules key", "version: v1"),
        (
            "dup id",
            "version: v1\nrules:\n  - {id: a, from: [\"spiffe://x/svc/a\"], to: [b], effect: allow}\n  - {id: a, from: [\"spiffe://x/svc/a\"], to: [b], effect: allow}\n",
        ),
        (
            "empty from",
            "version: v1\nrules:\n  - {id: a, from: [], to: [b], effect: allow}\n",
        ),
        (
            "empty to",
            "version: v1\nrules:\n  - {id: a, from: [\"spiffe://x/svc/a\"], to: [], effect: allow}\n",
        ),
        (
            "bad effect",
            "version: v1\nrules:\n  - {id: a, from: [\"spiffe://x/svc/a\"], to: [b], effect: maybe}\n",
        ),
        (
            "no effect",
            "version: v1\nrules:\n  - {id: a, from: [\"spiffe://x/svc/a\"], to: [b]}\n",
        ),
        (
            "bad from glob",
            "version: v1\nrules:\n  - {id: a, from: [\"https://x/svc/a\"], to: [b], effect: allow}\n",
        ),
        (
            "bad to glob",
            "version: v1\nrules:\n  - {id: a, from: [\"spiffe://x/svc/a\"], to: [\"B\"], effect: allow}\n",
        ),
        (
            "bad id",
            "version: v1\nrules:\n  - {id: \"a b\", from: [\"spiffe://x/svc/a\"], to: [b], effect: allow}\n",
        ),
        ("unknown field", "version: v1\nextra: 1\nrules: []\n"),
        (
            "unknown rule field",
            "version: v1\nrules:\n  - {id: a, from: [\"spiffe://x/svc/a\"], to: [b], effect: allow, when: never}\n",
        ),
        (
            "empty op",
            "version: v1\nrules:\n  - {id: a, from: [\"spiffe://x/svc/a\"], to: [b], operations: [\"\"], effect: allow}\n",
        ),
        (
            "long version",
            &format!("version: {}\nrules: []\n", "v".repeat(129)),
        ),
        ("not a map", "[1,2]"),
    ];
    for (name, body) in cases {
        assert!(Policy::load(body.as_bytes()).is_err(), "{name}");
    }
    let mut big = String::from("version: v1\nrules:\n");
    for i in 0..10_001 {
        big.push_str(&format!(
            "  - {{id: r{i}, from: [\"spiffe://x/svc/a\"], to: [b], effect: allow}}\n"
        ));
    }
    assert!(Policy::load(big.as_bytes()).is_err());
}

const P1: &str = "version: one\nrules:\n  - {id: a, from: [\"spiffe://x/svc/a\"], to: [b], effect: allow}\n";
const P2: &str = "version: two\nrules:\n  - {id: a, from: [\"spiffe://x/svc/a\"], to: [b], effect: deny}\n";

#[tokio::test]
async fn file_source_loads_and_watches() {
    let dir = tempfile::tempdir().expect("dir");
    let path = dir.path().join("policy.yaml");
    std::fs::write(&path, P1).expect("write");
    let src = FileSource::new(&path, Duration::from_millis(20)).expect("source");
    let pol = src.load().expect("load");
    assert_eq!(pol.version, "one");
    assert_eq!(pol.source, format!("file:{}", path.display()));
    let (mut ch, mut errs) = src.watch().expect("watch");
    tokio::time::sleep(Duration::from_millis(30)).await;
    std::fs::write(&path, P2).expect("write");
    let p = tokio::time::timeout(Duration::from_secs(5), ch.recv())
        .await
        .expect("reload")
        .expect("open");
    assert_eq!(p.version, "two");
    // An invalid rewrite keeps the last-known-good policy and reports it.
    std::fs::write(&path, "version: [broken").expect("write");
    let e = tokio::time::timeout(Duration::from_secs(5), errs.recv())
        .await
        .expect("error")
        .expect("open");
    assert!(!e.0.is_empty());
    assert!(
        tokio::time::timeout(Duration::from_millis(100), ch.recv())
            .await
            .is_err(),
        "an invalid file must not yield a policy"
    );
    assert_eq!(src.load().expect("lkg").version, "two");
    src.close();
}

#[test]
fn file_source_rejects() {
    let dir = tempfile::tempdir().expect("dir");
    assert!(FileSource::new(dir.path().join("missing.yaml"), Duration::ZERO).is_err());
    let path = dir.path().join("bad.yaml");
    std::fs::write(&path, "nope").expect("write");
    assert!(FileSource::new(&path, Duration::ZERO).is_err());
}
