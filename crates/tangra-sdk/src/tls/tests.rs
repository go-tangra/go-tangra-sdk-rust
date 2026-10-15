use super::*;
use crate::testutil::{IssueOptions, TestCa};

fn opts() -> Options {
    Options::new("example.org").normalise().expect("opts")
}

fn verify(
    ca: &TestCa,
    chain: &[CertificateDer<'static>],
    expected: Option<&SpiffeId>,
) -> Result<Peer, VerifyError> {
    let roots = vec![ca.root_der()];
    verify_with(|_| Ok(roots), &opts(), expected, Usage::Any, chain)
}

fn issue(ca: &TestCa, o: IssueOptions) -> CertificateDer<'static> {
    ca.issue_with("orders", o).expect("issue").cert_der
}

#[test]
fn accepts_a_valid_spiffe_leaf() {
    let ca = TestCa::new("example.org").expect("ca");
    let leaf = issue(&ca, IssueOptions::default());
    let p = verify(&ca, std::slice::from_ref(&leaf), None).expect("valid");
    assert_eq!(p.id.to_string(), "spiffe://example.org/svc/orders");
    assert_eq!(p.service_name, "orders");
    let want = SpiffeId::new("example.org", "orders").expect("id");
    assert!(verify(&ca, &[leaf], Some(&want)).is_ok());
}

#[test]
fn refusals_are_classified() {
    let ca = TestCa::new("example.org").expect("ca");
    let other_ca = TestCa::new("example.org").expect("ca2");
    let uris = |u: &[&str]| IssueOptions {
        uris: Some(u.iter().map(|s| (*s).to_owned()).collect()),
        ..IssueOptions::default()
    };
    let now = SystemTime::now();
    let cases: Vec<(CertificateDer<'static>, Option<SpiffeId>, Reason, &str)> = vec![
        (
            issue(&ca, uris(&[])),
            None,
            Reason::Untrusted,
            "exactly one URI SAN",
        ),
        (
            issue(
                &ca,
                uris(&["spiffe://example.org/svc/a", "spiffe://example.org/svc/b"]),
            ),
            None,
            Reason::Untrusted,
            "exactly one URI SAN",
        ),
        (
            issue(&ca, uris(&["https://example.org/a"])),
            None,
            Reason::Untrusted,
            "not a SPIFFE ID",
        ),
        (
            issue(&ca, uris(&["spiffe://evil.org/svc/a"])),
            None,
            Reason::Untrusted,
            "foreign trust domain",
        ),
        (
            issue(&other_ca, IssueOptions::default()),
            None,
            Reason::Untrusted,
            "",
        ),
        (
            issue(&ca, IssueOptions::default()),
            SpiffeId::new("example.org", "billing").ok(),
            Reason::NameMismatch,
            "",
        ),
        (
            issue(
                &ca,
                IssueOptions {
                    not_before: Some(now - Duration::from_secs(7200)),
                    not_after: Some(now - Duration::from_secs(600)),
                    ..IssueOptions::default()
                },
            ),
            None,
            Reason::Expired,
            "beyond clock skew tolerance 5m0s",
        ),
        (
            issue(
                &ca,
                IssueOptions {
                    not_before: Some(now + Duration::from_secs(600)),
                    not_after: Some(now + Duration::from_secs(7200)),
                    ..IssueOptions::default()
                },
            ),
            None,
            Reason::NotYetValid,
            "beyond clock skew tolerance",
        ),
    ];
    for (leaf, expected, reason, detail) in cases {
        let e = verify(&ca, &[leaf], expected.as_ref()).expect_err("must refuse");
        assert_eq!(e.reason, reason, "{e}");
        assert!(e.detail.contains(detail), "{e}");
    }
    assert_eq!(
        verify(&ca, &[], None).expect_err("empty").reason,
        Reason::NoIdentity
    );
    let garbage = CertificateDer::from(vec![1u8, 2, 3]);
    assert_eq!(
        verify(&ca, &[garbage], None).expect_err("garbage").reason,
        Reason::Untrusted
    );
}

#[test]
fn skew_tolerance_widens_validity() {
    let ca = TestCa::new("example.org").expect("ca");
    let now = SystemTime::now();
    let just_expired = issue(
        &ca,
        IssueOptions {
            not_before: Some(now - Duration::from_secs(3600)),
            not_after: Some(now - Duration::from_secs(60)),
            ..IssueOptions::default()
        },
    );
    assert!(verify(&ca, &[just_expired], None).is_ok());
    let soon = issue(
        &ca,
        IssueOptions {
            not_before: Some(now + Duration::from_secs(60)),
            ..IssueOptions::default()
        },
    );
    assert!(verify(&ca, &[soon], None).is_ok());
}

#[test]
fn options_validation() {
    assert!(Options::new("").normalise().is_err());
    let mut o = Options::new("example.org");
    o.skew_tolerance = Duration::from_secs(16 * 60);
    assert!(o.normalise().is_err());
    assert_eq!(
        Options::new("example.org")
            .normalise()
            .expect("ok")
            .skew_tolerance,
        DEFAULT_SKEW
    );
}

#[test]
fn enroll_modes() {
    let ca = TestCa::new("example.org").expect("ca");
    let id = SpiffeId::new("example.org", "lcm").expect("id");
    assert!(
        enroll_client_config(EnrollOptions {
            insecure: true,
            ca_pem: Some(ca.bundle_pem().into_bytes()),
            ..EnrollOptions::default()
        })
        .is_err()
    );
    assert!(
        enroll_client_config(EnrollOptions {
            server_id: Some(id.clone()),
            ..EnrollOptions::default()
        })
        .is_err()
    );
    assert!(
        enroll_client_config(EnrollOptions {
            ca_pem: Some(ca.bundle_pem().into_bytes()),
            ..EnrollOptions::default()
        })
        .is_err()
    );
    let mesh = enroll_client_config(EnrollOptions {
        ca_pem: Some(ca.bundle_pem().into_bytes()),
        server_id: Some(id),
        ..EnrollOptions::default()
    })
    .expect("mesh");
    assert_eq!(mesh.alpn_protocols, vec![b"http/1.1".to_vec()]);
    let public = enroll_client_config(EnrollOptions::default()).expect("public");
    assert!(public.alpn_protocols.len() == 1);
    assert!(
        enroll_client_config(EnrollOptions {
            insecure: true,
            ..EnrollOptions::default()
        })
        .is_ok()
    );
}

#[test]
fn server_auth_usage_for_enroll() {
    let ca = TestCa::new("example.org").expect("ca");
    let client_only = ca
        .issue_with(
            "lcm",
            IssueOptions {
                server_auth: false,
                ..IssueOptions::default()
            },
        )
        .expect("issue")
        .cert_der;
    let roots = vec![ca.root_der()];
    let id = SpiffeId::new("example.org", "lcm").expect("id");
    let e = verify_with(
        |_| Ok(roots.clone()),
        &opts(),
        Some(&id),
        Usage::ServerAuth,
        std::slice::from_ref(&client_only),
    )
    .expect_err("no serverAuth");
    assert_eq!(e.reason, Reason::Untrusted);
    // The mesh accepts any EKU (Go ExtKeyUsageAny).
    assert!(verify_with(|_| Ok(roots), &opts(), Some(&id), Usage::Any, &[client_only]).is_ok());
}
