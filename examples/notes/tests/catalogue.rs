//! The catalogue descriptor and the join bundle (deployer
//! `cmd/deployersvc/catalogue_test.go`): `tangra-module.yaml` is valid, its
//! host inputs accept values of the shape operators give, the bundle
//! templates use only placeholders the gateway fills and render to a valid
//! production configuration and policy, and the permissions command prints
//! the manifest's permissions.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::path::Path;

use tangra_notes::config::{self, NotesFile};
use tangra_notes::manifest;
use tangra_sdk::catalogue;
use tangra_sdk::policy::Policy;

const DIR: &str = env!("CARGO_MANIFEST_DIR");

/// Values of the shape the gateway fills in: core values, generated values
/// and the host inputs.
fn join_values() -> BTreeMap<&'static str, String> {
    BTreeMap::from([
        ("TRUST_DOMAIN", "infra.example.org".into()),
        ("GATEWAY_ISSUER", "https://portal.example.org:8443".into()),
        (
            "LCM_ENROLL_URL",
            "https://portal.example.org:8443/api/lcm/v1/enroll".into(),
        ),
        ("LCM_GRPC", "portal.example.org:9945".into()),
        ("GATEWAY_GRPC", "portal.example.org:9643".into()),
        ("AUTH_GRPC", "portal.example.org:9543".into()),
        ("MESH_TENANT_ID", "00000000-0000-0000-0000-000000000001".into()),
        ("MODULE_IMAGE", "ghcr.io/go-tangra/go-tangra-notes".into()),
        ("MODULE_VERSION", "1.0.0".into()),
        ("MODULE_ADVERTISE_HOST", "notes.example.org".into()),
        ("MODULE_BIND_IP", "10.0.0.5".into()),
        ("VALKEY_ADDRESS", "valkey.example.org:6380".into()),
        ("VALKEY_PASSWORD", "c".repeat(32)),
        ("VALKEY_CA_FILE", "/etc/tangra/valkey-ca.pem".into()),
    ])
}

fn render(name: &str) -> String {
    let raw = std::fs::read_to_string(Path::new(DIR).join("deploy/bundle").join(name)).unwrap();
    let re = regex::Regex::new(r"\$\{([A-Z][A-Z0-9_]*)\}").unwrap();
    let values = join_values();
    let mut missing = Vec::new();
    let out = re.replace_all(&raw, |c: &regex::Captures<'_>| {
        let k = &c[1];
        values.get(k).cloned().unwrap_or_else(|| {
            missing.push(k.to_owned());
            String::new()
        })
    });
    assert!(
        missing.is_empty(),
        "{name} uses placeholders the gateway does not fill: {missing:?}"
    );
    out.into_owned()
}

#[test]
fn descriptor_is_valid() {
    let raw = std::fs::read(Path::new(DIR).join("tangra-module.yaml")).unwrap();
    let d = catalogue::parse_descriptor(&raw).unwrap();
    assert_eq!(d.module, manifest::MODULE);
    assert!(d.routes.prefixes[0].starts_with(manifest::PREFIX));
    let values = join_values();
    for i in &d.host_inputs {
        let re = regex::Regex::new(&i.pattern).unwrap();
        assert!(
            re.is_match(&values[i.key.as_str()]),
            "host input {} refuses {:?}",
            i.key,
            values[i.key.as_str()]
        );
        assert!(!catalogue::reserved(&i.key), "{}", i.key);
    }
    for t in &d.bundle.templates {
        assert!(
            Path::new(DIR).join(&d.bundle.dir).join(t).is_file(),
            "template {t}"
        );
    }
}

#[test]
fn join_bundle_renders_to_a_valid_production_config() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.yaml");
    std::fs::write(&path, render("config.yaml")).unwrap();
    render("compose.yaml");
    let cfg: NotesFile = config::load(path.to_str().unwrap()).unwrap();
    assert!(cfg.framework.is_production());
    assert_eq!(cfg.module.gateway.issuer, "https://portal.example.org:8443");
    assert!(cfg.module.events.enabled && cfg.module.enroll.enabled);
    let v = cfg.module.valkey.unwrap();
    assert!(!v.allow_plaintext && v.addresses == ["valkey.example.org:6380"] && !v.ca_file.is_empty());
    let pol = render("policy.yaml");
    Policy::load(pol.as_bytes()).unwrap();
    assert!(pol.contains("spiffe://infra.example.org/svc/gateway"));
}

/// The release job's `permissions-command`.
#[test]
fn permissions_command_prints_the_manifest_permissions() {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_notes-catalogue-permissions"))
        .output()
        .unwrap();
    assert!(out.status.success());
    assert_eq!(
        String::from_utf8(out.stdout).unwrap(),
        catalogue::permissions_json(manifest::permission_refs())
    );
}
