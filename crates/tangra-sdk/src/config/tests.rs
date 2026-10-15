use super::*;

fn valid() -> FrameworkConfig {
    let mut c = FrameworkConfig {
        service_name: "orders".into(),
        trust_domain: "example.org".into(),
        ..FrameworkConfig::default()
    };
    c.identity.provider = PROVIDER_FILE.into();
    c.identity.file = FileIdentity {
        cert: "c.pem".into(),
        key: "k.pem".into(),
        bundle: "b.pem".into(),
    };
    c.authz.source = AUTHZ_FILE.into();
    c.authz.path = "policy.yaml".into();
    c
}

#[test]
fn defaults_match_constitution() {
    let c = FrameworkConfig::default();
    assert_eq!(c.limits.max_request_bytes, 1 << 20);
    assert_eq!(c.limits.max_header_bytes, 8 << 10);
    assert_eq!(c.limits.request_timeout, GoDuration::from_secs(30));
    assert_eq!(c.limits.idle_timeout, GoDuration::from_secs(60));
    assert_eq!(c.limits.handshake_timeout, GoDuration::from_secs(10));
    assert_eq!(c.limits.max_concurrent_streams, 100);
    assert_eq!(c.limits.max_connection_age, GoDuration::from_mins(30));
    assert!((c.identity.renew_at - 0.5).abs() < f64::EPSILON);
    assert_eq!(c.identity.skew_tolerance, GoDuration::from_mins(5));
    assert_eq!(c.identity.max_lifetime, GoDuration::from_hours(1));
    assert_eq!(c.identity.startup_timeout, GoDuration::from_secs(30));
    assert_eq!(c.admin.addr, "127.0.0.1:9090");
    assert!(!c.admin.enable_pprof && !c.admin.allow_non_loopback);
    assert_eq!(c.identity.provider, PROVIDER_SPIFFE);
    assert_eq!(c.identity.workload_socket, "unix:///run/spire/sockets/agent.sock");
    assert_eq!(c.authz.source, AUTHZ_FILE);
    assert_eq!(c.server.grpc_addr, ":9443");
    assert_eq!(c.server.http_addr, "");
}

#[test]
fn validate_ok() {
    let c = valid();
    assert_eq!(c.validate(), Ok(()));
    assert!(c.warnings().is_empty());
}

type Mutator = fn(&mut FrameworkConfig);

#[test]
fn validate_rejects() {
    let cases: Vec<(&str, Mutator, &str)> = vec![
        ("missing service name", |c| c.service_name.clear(), "service_name"),
        (
            "bad service name",
            |c| c.service_name = "Orders_1".into(),
            "service_name",
        ),
        ("missing trust domain", |c| c.trust_domain.clear(), "trust_domain"),
        (
            "bad trust domain",
            |c| c.trust_domain = "Example.ORG/x".into(),
            "trust_domain",
        ),
        ("renew too low", |c| c.identity.renew_at = 0.2, "renew_at"),
        ("renew too high", |c| c.identity.renew_at = 0.9, "renew_at"),
        (
            "skew too large",
            |c| c.identity.skew_tolerance = GoDuration::from_mins(16),
            "skew_tolerance",
        ),
        (
            "skew negative",
            |c| c.identity.skew_tolerance = GoDuration::from_secs(-1),
            "skew_tolerance",
        ),
        (
            "lifetime too long",
            |c| c.identity.max_lifetime = GoDuration::from_hours(25),
            "max_lifetime",
        ),
        (
            "localdev via config",
            |c| c.identity.provider = "localdev".into(),
            "WithInsecureLocalDev",
        ),
        (
            "unknown provider",
            |c| c.identity.provider = "vault".into(),
            "identity.provider",
        ),
        (
            "file provider missing paths",
            |c| c.identity.file.key.clear(),
            "identity.file",
        ),
        (
            "spiffe missing socket",
            |c| {
                c.identity.provider = PROVIDER_SPIFFE.into();
                c.identity.workload_socket.clear();
            },
            "workload_socket",
        ),
        (
            "allow-all via config",
            |c| c.authz.source = "allow-all".into(),
            "WithAllowAllPolicy",
        ),
        (
            "unknown authz source",
            |c| c.authz.source = "opa".into(),
            "authz.source",
        ),
        ("authz file missing path", |c| c.authz.path.clear(), "authz.path"),
        (
            "authz valkey missing key",
            |c| {
                c.authz.source = AUTHZ_VALKEY.into();
                c.authz.valkey_key.clear();
            },
            "authz.valkey_key",
        ),
        (
            "admin non-loopback",
            |c| c.admin.addr = "0.0.0.0:9090".into(),
            "allow_non_loopback",
        ),
        (
            "admin bad addr",
            |c| c.admin.addr = "nonsense".into(),
            "admin.addr",
        ),
        (
            "admin bad port",
            |c| c.admin.addr = "127.0.0.1:http".into(),
            "admin.addr port",
        ),
        ("zero request bytes", |c| c.limits.max_request_bytes = 0, "limits"),
        (
            "zero timeout",
            |c| c.limits.request_timeout = GoDuration(0),
            "limits",
        ),
        ("bad env", |c| c.env = "staging!".into(), "env"),
    ];
    for (name, mutate, want) in cases {
        let mut c = valid();
        mutate(&mut c);
        let err = c.validate().expect_err(name);
        assert!(err.0.contains(want), "{name}: {err} does not mention {want}");
    }
}

#[test]
fn validate_all_reports_every_problem() {
    assert!(valid().validate_all().is_empty());
    let mut c = valid();
    c.trust_domain.clear();
    c.identity.renew_at = 0.9;
    c.identity.max_lifetime = GoDuration(0);
    c.authz.path.clear();
    c.admin.addr = "0.0.0.0:9090".into();
    let errs = c.validate_all();
    let want = [
        "trust_domain",
        "renew_at",
        "max_lifetime",
        "authz.path",
        "allow_non_loopback",
    ];
    assert_eq!(errs.len(), want.len(), "{errs:?}");
    for (e, w) in errs.iter().zip(want) {
        assert!(e.0.contains(w), "{e} vs {w}");
    }
    assert_eq!(c.validate(), Err(errs[0].clone()));
}

#[test]
fn warnings() {
    let mut c = valid();
    c.limits.max_request_bytes = 4 << 20;
    c.limits.request_timeout = GoDuration::from_mins(1);
    c.admin.addr = "0.0.0.0:9090".into();
    c.admin.allow_non_loopback = true;
    c.admin.enable_pprof = true;
    assert_eq!(c.validate(), Ok(()));
    let w = c.warnings();
    assert_eq!(
        w,
        vec![
            "limits.max_request_bytes raised to 4194304 (default 1048576)".to_owned(),
            "limits.request_timeout raised to 1m0s (default 30s)".to_owned(),
            "admin listener allowed on a non-loopback address; health/metrics are reachable from the network"
                .to_owned(),
            "pprof enabled on the admin listener".to_owned(),
        ]
    );
}

#[test]
fn is_production() {
    let mut c = valid();
    assert!(!c.is_production());
    c.env = "production".into();
    assert!(c.is_production());
    c.env = "PRODUCTION".into();
    assert!(c.is_production());
    assert_eq!(c.local_spiffe_id(), "spiffe://example.org/svc/orders");
}

#[test]
fn split_host_port_like_go() {
    let ok = [
        ("127.0.0.1:9090", "127.0.0.1", "9090"),
        (":9443", "", "9443"),
        ("[::1]:80", "::1", "80"),
        ("localhost:http", "localhost", "http"),
        ("host:", "host", ""),
    ];
    for (hp, h, p) in ok {
        assert_eq!(split_host_port(hp), Ok((h.to_owned(), p.to_owned())), "{hp}");
    }
    for bad in ["nonsense", "::1:80", "[::1]", "[::1]x:80", "a]:80", ""] {
        assert!(split_host_port(bad).is_err(), "{bad}");
    }
    assert!(is_loopback_host("::ffff:127.0.0.1"));
    assert!(is_loopback_host("localhost"));
    assert!(!is_loopback_host("10.0.0.1"));
}

// --- loading -----------------------------------------------------------

#[derive(Debug, Default, PartialEq, Deserialize)]
#[serde(default)]
struct DbSection {
    dsn: String,
    max_conns: u32,
}

/// A module section that does NOT opt into deny_unknown_fields: unknown keys
/// must still be refused by the loader.
#[derive(Debug, Default, PartialEq, Deserialize)]
#[serde(default)]
struct Module {
    db: DbSection,
    enroll: EnrollConfig,
}

const DOC: &str = r#"
service_name: deployer
trust_domain: example.org
env: production
identity:
  provider: provided
  skew_tolerance: 2m
enroll:
  enabled: true
  enroll_url: https://gateway:8443/api/lcm/v1/enroll
  lcm_grpc: lcm:9945
  tenant_id: "00000000-0000-0000-0000-000000000001"
  token_file: /tokens/enrollment.token
  state_file: /state/svid.json
authz: { source: file, path: /app/policy.yaml }
server: { grpc_addr: 0.0.0.0:9945, http_addr: 0.0.0.0:9946 }
admin: { addr: 127.0.0.1:9690 }
discovery:
  static:
    gateway: ["gateway:9443"]
limits: { max_request_bytes: 16842752 }
db:
  dsn: postgres://x
"#;

#[test]
fn load_framework_and_module_sections() {
    let c = Config::<Module>::from_yaml(DOC.as_bytes()).expect("load");
    let fw = &c.framework;
    assert_eq!(fw.service_name, "deployer");
    assert_eq!(fw.identity.provider, PROVIDER_PROVIDED);
    assert_eq!(fw.identity.skew_tolerance, GoDuration::from_mins(2));
    // Partially given sections keep the defaults of the absent keys.
    assert!((fw.identity.renew_at - 0.5).abs() < f64::EPSILON);
    assert_eq!(fw.limits.max_request_bytes, 16_842_752);
    assert_eq!(fw.limits.request_timeout, GoDuration::from_secs(30));
    assert_eq!(fw.server.http_addr, "0.0.0.0:9946");
    assert_eq!(fw.discovery.r#static["gateway"], vec!["gateway:9443".to_owned()]);
    assert_eq!(c.module.db.dsn, "postgres://x");
    assert_eq!(c.module.db.max_conns, 0);
    assert!(c.module.enroll.enabled);
    assert_eq!(c.module.enroll.lcm_grpc, "lcm:9945");
    assert_eq!(fw.validate(), Ok(()));
}

#[test]
fn load_rejects_unknown_keys_everywhere() {
    let cases = [
        // Unknown top-level key (neither framework nor module).
        ("service_name: a\nbogus: 1\n", "bogus"),
        // Unknown key inside a framework section.
        ("limits: { max_request_byte: 5 }\n", "max_request_byte"),
        ("identity: { file: { crt: x } }\n", "crt"),
        // Unknown key inside a module section that does not deny unknowns.
        ("db: { dsn: x, extra: y }\n", "db.extra"),
        // Unknown key inside a module section that does deny unknowns.
        ("enroll: { enabled: true, nope: 1 }\n", "nope"),
    ];
    for (doc, want) in cases {
        let err = Config::<Module>::from_yaml(doc.as_bytes()).expect_err(doc);
        assert!(err.0.contains(want), "{doc}: {err} should mention {want}");
    }
    // With no module sections at all, every non-framework key is unknown.
    let err = Config::<NoModule>::from_yaml(b"db: {dsn: x}\n").expect_err("no module");
    assert!(err.0.contains("db"), "{err}");
}

#[test]
fn load_rejects_bad_values() {
    for (doc, want) in [
        ("limits: { request_timeout: 30 }\n", "invalid type"),
        ("limits: { request_timeout: 5 parsecs }\n", "duration"),
        ("service_name: [a]\n", "invalid type"),
        ("", "EOF"),
        ("- a\n", "cannot unmarshal"),
        ("a: 1\na: 2\n", "duplicate"),
    ] {
        let err = Config::<NoModule>::from_yaml(doc.as_bytes()).expect_err(doc);
        assert!(err.0.contains(want), "{doc:?}: {err}");
    }
}

#[test]
fn load_file_errors_name_the_path() {
    let dir = tempfile::tempdir().expect("tempdir");
    let p = dir.path().join("c.yaml");
    std::fs::write(&p, "nope: 1\n").expect("write");
    let err = Config::<NoModule>::load(&p).expect_err("unknown");
    assert!(err.0.starts_with("config: ") && err.0.contains("c.yaml"), "{err}");
    let missing = Config::<NoModule>::load(dir.path().join("missing.yaml")).expect_err("missing");
    assert!(missing.0.starts_with("config: "), "{missing}");
}

#[test]
fn enroll_tls_modes() {
    let td = "example.org";
    let mut e = EnrollTls::default();
    assert_eq!(e.validate(td, true), Ok(()));
    e.insecure = true;
    assert!(
        e.validate(td, true)
            .expect_err("prod")
            .0
            .contains("refused in production")
    );
    assert_eq!(e.validate(td, false), Ok(()));
    assert_eq!(e.warnings().len(), 1);
    e.ca_file = "ca.pem".into();
    assert!(
        e.validate(td, false)
            .expect_err("both")
            .0
            .contains("mutually exclusive")
    );
    e.insecure = false;
    assert_eq!(
        e.server_id(td).expect("id").to_string(),
        "spiffe://example.org/svc/lcm"
    );
    e.server_spiffe_id = "spiffe://other.org/svc/lcm".into();
    assert!(
        e.validate(td, false)
            .expect_err("td")
            .0
            .contains("outside trust domain")
    );
    e.server_spiffe_id = "spiffe://example.org/svc/gateway".into();
    assert_eq!(
        e.server_id(td).expect("id").to_string(),
        "spiffe://example.org/svc/gateway"
    );
    let only_id = EnrollTls {
        server_spiffe_id: "spiffe://example.org/svc/lcm".into(),
        ..EnrollTls::default()
    };
    assert!(
        only_id
            .validate(td, false)
            .expect_err("no ca")
            .0
            .contains("requires enroll.ca_file")
    );
}
