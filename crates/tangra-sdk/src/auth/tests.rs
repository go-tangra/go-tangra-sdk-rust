//! Ports of authclient `client_test.go` and `registration_test.go`, plus the
//! token acceptance matrix.
#![allow(clippy::type_complexity)]

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

use super::*;

const ISS: &str = "https://auth.example.org";
/// 2026-09-16T12:00:00Z (client_test.go).
const T0: i64 = 1_789_560_000;

fn at(secs: i64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(u64::try_from(secs).unwrap())
}

#[derive(Default)]
struct KeySrc {
    set: Mutex<HashMap<String, PublicKey>>,
    calls: Mutex<u32>,
    fail: Mutex<bool>,
}

#[async_trait::async_trait]
impl KeySource for KeySrc {
    async fn keys(&self) -> Result<HashMap<String, PublicKey>, AuthError> {
        *self.calls.lock().unwrap() += 1;
        if *self.fail.lock().unwrap() {
            return Err(AuthError("down".into()));
        }
        Ok(self.set.lock().unwrap().clone())
    }
}

#[derive(Default)]
struct RevSrc {
    entries: Mutex<Vec<Revocation>>,
    fail: Mutex<bool>,
}

#[async_trait::async_trait]
impl RevocationSource for RevSrc {
    async fn since(&self, cursor: &str) -> Result<(Vec<Revocation>, String), AuthError> {
        if *self.fail.lock().unwrap() {
            return Err(AuthError("feed down".into()));
        }
        let e = self.entries.lock().unwrap();
        let from = cursor.parse::<usize>().unwrap_or(0).min(e.len());
        Ok((e[from..].to_vec(), e.len().to_string()))
    }
}

fn rev(ts: i64, kind: &str, subject: &str, tenant: &str) -> Revocation {
    Revocation {
        ts_unix_nanos: i128::from(ts) * 1_000_000_000,
        kind: kind.into(),
        subject_id: subject.into(),
        tenant_id: tenant.into(),
        reason: String::new(),
    }
}

fn clock(v: &Verifier) -> Arc<Mutex<i64>> {
    let now = Arc::new(Mutex::new(T0));
    let n = Arc::clone(&now);
    v.set_clock(move || at(*n.lock().unwrap()));
    now
}

fn mint(s: &TestSigner, iat: i64, sub: &str, tid: &str, sid: &str, life: i64, aud: &str) -> String {
    let mut c = TestSigner::claims(ISS, sub, tid, sid, iat, life);
    if !aud.is_empty() {
        c["aud"] = json!([aud]);
    }
    s.mint(&c)
}

#[tokio::test]
async fn offline_verify_and_skew() {
    let s = TestSigner::new("k1").unwrap();
    let ks = Arc::new(KeySrc::default());
    ks.set.lock().unwrap().insert("k1".into(), s.public_key());
    let v = Verifier::new(
        Config {
            issuer: ISS.into(),
            audience: "app".into(),
            ..Config::default()
        },
        ks.clone(),
        None,
    );
    let now = clock(&v);
    v.refresh_keys().await.unwrap();
    let tok = mint(&s, T0, "u1", "t1", "s1", 900, "app");
    let id = v.verify(&tok).await.unwrap();
    assert_eq!(
        (id.user_id.as_str(), id.tenant_id.as_str(), id.session_id.as_str()),
        ("u1", "t1", "s1")
    );
    assert_eq!((id.audience.as_str(), id.roles[0].as_str()), ("app", "admin"));
    assert!(id.is_admin() && id.has_role("admin") && !id.has_role("owner"));
    assert!(matches!(
        v.verify(&mint(&s, T0, "u1", "t1", "s1", 900, "other")).await,
        Err(VerifyError::Unauthenticated(_))
    ));
    *now.lock().unwrap() = T0 + 900 + 59;
    v.verify(&tok).await.expect("within skew");
    *now.lock().unwrap() = T0 + 900 + 61;
    assert!(
        matches!(v.verify(&tok).await, Err(VerifyError::Unauthenticated(_))),
        "expired"
    );
    assert!(matches!(v.verify("").await, Err(VerifyError::Unauthenticated(_))));
    let pinned = Verifier::new(
        Config {
            issuer: ISS.into(),
            tenant_id: "t2".into(),
            ..Config::default()
        },
        ks,
        None,
    );
    let _ = clock(&pinned);
    pinned.refresh_keys().await.unwrap();
    assert_eq!(pinned.verify(&tok).await, Err(VerifyError::WrongTenant));
}

#[tokio::test]
async fn unknown_kid_refresh_is_rate_capped() {
    let (s1, s2) = (TestSigner::new("k1").unwrap(), TestSigner::new("k2").unwrap());
    let ks = Arc::new(KeySrc::default());
    ks.set.lock().unwrap().insert("k1".into(), s1.public_key());
    let v = Verifier::new(
        Config {
            issuer: ISS.into(),
            ..Config::default()
        },
        ks.clone(),
        None,
    );
    let now = clock(&v);
    v.refresh_keys().await.unwrap();
    let tok2 = mint(&s2, T0, "u1", "t1", "s1", 60, "");
    assert!(v.verify(&tok2).await.is_err(), "unknown kid accepted");
    let calls = *ks.calls.lock().unwrap();
    // Rotation on the server; within the cap no new fetch happens.
    ks.set.lock().unwrap().insert("k2".into(), s2.public_key());
    *now.lock().unwrap() = T0 + 10;
    assert!(v.verify(&tok2).await.is_err());
    assert_eq!(*ks.calls.lock().unwrap(), calls, "refresh not capped");
    *now.lock().unwrap() = T0 + 70;
    v.verify(&tok2).await.expect("refresh after cap");
    assert_eq!(*ks.calls.lock().unwrap(), calls + 1);
}

#[tokio::test]
async fn revocation_feed_and_fail_closed() {
    let s = TestSigner::new("k1").unwrap();
    let ks = Arc::new(KeySrc::default());
    ks.set.lock().unwrap().insert("k1".into(), s.public_key());
    let rs = Arc::new(RevSrc::default());
    let v = Arc::new(Verifier::new(
        Config {
            issuer: ISS.into(),
            max_stale: Duration::from_secs(3600),
            ..Config::default()
        },
        ks.clone(),
        Some(rs.clone()),
    ));
    let now = clock(&v);
    v.refresh_keys().await.unwrap();
    let tok = mint(&s, T0, "u1", "t1", "s1", 900, "");
    assert_eq!(
        v.verify(&tok).await,
        Err(VerifyError::Stale),
        "never synced must fail closed"
    );
    v.sync_revocations().await.unwrap();
    v.verify(&tok).await.unwrap();
    // Entries before iat do not apply; at/after iat they do, per kind.
    *rs.entries.lock().unwrap() = vec![rev(T0 - 60, "session", "s1", "")];
    v.sync_revocations().await.unwrap();
    v.verify(&tok).await.expect("older entry must not revoke");
    for e in [
        rev(T0, "session", "s1", ""),
        rev(T0 + 1, "user", "u1", "t1"),
        rev(T0 + 1, "user", "u1", ""),
        rev(T0 + 1, "tenant", "t1", ""),
    ] {
        let kind = e.kind.clone();
        *rs.entries.lock().unwrap() = vec![e];
        {
            let mut st = v.st();
            st.entries.clear();
            st.cursor.clear();
        }
        v.sync_revocations().await.unwrap();
        assert_eq!(v.verify(&tok).await, Err(VerifyError::Revoked), "{kind}");
    }
    // A user revocation in another tenant does not apply.
    *rs.entries.lock().unwrap() = vec![rev(T0 + 1, "user", "u1", "t9")];
    {
        let mut st = v.st();
        st.entries.clear();
        st.cursor.clear();
    }
    v.sync_revocations().await.unwrap();
    v.verify(&tok).await.unwrap();
    let other = mint(&s, T0, "u2", "t2", "s2", 900, "");
    v.verify(&other).await.expect("unrelated token");
    // An unreachable feed older than max_stale fails closed.
    *rs.fail.lock().unwrap() = true;
    *now.lock().unwrap() = T0 + 61 * 60;
    assert!(v.sync_revocations().await.is_err());
    let fresh = mint(&s, T0 + 61 * 60, "u2", "t2", "s2", 900, "");
    assert_eq!(v.verify(&fresh).await, Err(VerifyError::Stale));
    *rs.fail.lock().unwrap() = false;
    v.sync_revocations().await.unwrap();
    v.verify(&fresh).await.unwrap();
    // Start runs the loops; it fails fast on key errors.
    let stop = tokio_util::sync::CancellationToken::new();
    v.start(stop.clone(), None).await.unwrap();
    stop.cancel();
    *ks.fail.lock().unwrap() = true;
    let v2 = Arc::new(Verifier::new(
        Config {
            issuer: ISS.into(),
            ..Config::default()
        },
        ks,
        Some(rs),
    ));
    assert!(
        v2.start(tokio_util::sync::CancellationToken::new(), None)
            .await
            .is_err()
    );
}

#[test]
fn retention_forgets_old_entries() {
    let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
    rt.block_on(async {
        let rs = Arc::new(RevSrc::default());
        *rs.entries.lock().unwrap() = vec![
            rev(T0 - 3601, "session", "a", ""),
            rev(T0 - 10, "session", "b", ""),
        ];
        let v = Verifier::new(Config::default(), Arc::new(StaticKeys::default()), Some(rs));
        let _ = clock(&v);
        v.sync_revocations().await.unwrap();
        let st = v.st();
        assert_eq!(st.entries.len(), 1);
        assert_eq!(st.entries[0].subject_id, "b");
        assert_eq!(st.cursor, "2");
    });
}

/// The acceptance matrix: each token variant against a verifier at T0.
#[tokio::test]
async fn token_matrix() {
    let s = TestSigner::new("k1").unwrap();
    let other = TestSigner::new("k1").unwrap();
    let keys: HashMap<String, PublicKey> = [("k1".to_owned(), s.public_key())].into();
    let v = Verifier::new(
        Config {
            issuer: ISS.into(),
            ..Config::default()
        },
        Arc::new(StaticKeys(keys)),
        None,
    );
    let _ = clock(&v);
    v.refresh_keys().await.unwrap();
    let base = || TestSigner::claims(ISS, "u1", "t1", "s1", T0, 900);
    let with = |f: &dyn Fn(&mut Value)| {
        let mut c = base();
        f(&mut c);
        s.mint(&c)
    };
    let hdr = |h: Value| s.sign_raw(&h, &base());
    let cases: Vec<(&str, String, bool)> = vec![
        ("valid", s.mint(&base()), true),
        ("alg HS256", hdr(json!({"alg": "HS256", "kid": "k1"})), false),
        ("alg none", hdr(json!({"alg": "none", "kid": "k1"})), false),
        ("alg missing", hdr(json!({"kid": "k1"})), false),
        ("alg lowercase", hdr(json!({"alg": "eddsa", "kid": "k1"})), false),
        ("kid missing", hdr(json!({"alg": "EdDSA"})), false),
        ("kid empty", hdr(json!({"alg": "EdDSA", "kid": ""})), false),
        ("kid number", hdr(json!({"alg": "EdDSA", "kid": 1})), false),
        ("unknown kid", hdr(json!({"alg": "EdDSA", "kid": "k9"})), false),
        ("wrong key", other.mint(&base()), false),
        ("wrong issuer", with(&|c| c["iss"] = json!("https://evil")), false),
        (
            "issuer missing",
            with(&|c| {
                c.as_object_mut().unwrap().remove("iss");
            }),
            false,
        ),
        (
            "expired",
            with(&|c| {
                c["iat"] = json!(T0 - 1000);
                c["nbf"] = json!(T0 - 1000);
                c["exp"] = json!(T0 - 61);
            }),
            false,
        ),
        (
            "expired within skew",
            with(&|c| {
                c["iat"] = json!(T0 - 900);
                c["nbf"] = json!(T0 - 900);
                c["exp"] = json!(T0 - 59);
            }),
            true,
        ),
        (
            "exp missing",
            with(&|c| {
                c.as_object_mut().unwrap().remove("exp");
            }),
            false,
        ),
        ("nbf future", with(&|c| c["nbf"] = json!(T0 + 61)), false),
        ("nbf within skew", with(&|c| c["nbf"] = json!(T0 + 59)), true),
        (
            "nbf missing",
            with(&|c| {
                c.as_object_mut().unwrap().remove("nbf");
            }),
            false,
        ),
        (
            "iat future",
            with(&|c| {
                c["iat"] = json!(T0 + 61);
                c["exp"] = json!(T0 + 900);
            }),
            false,
        ),
        (
            "iat missing",
            with(&|c| {
                c.as_object_mut().unwrap().remove("iat");
            }),
            false,
        ),
        ("lifetime 15m", with(&|c| c["exp"] = json!(T0 + 900)), true),
        ("lifetime 15m+1s", with(&|c| c["exp"] = json!(T0 + 901)), false),
        (
            "sub missing",
            with(&|c| {
                c.as_object_mut().unwrap().remove("sub");
            }),
            false,
        ),
        ("tid empty", with(&|c| c["tid"] = json!("")), false),
        (
            "sid missing",
            with(&|c| {
                c.as_object_mut().unwrap().remove("sid");
            }),
            false,
        ),
        (
            "jti missing",
            with(&|c| {
                c.as_object_mut().unwrap().remove("jti");
            }),
            false,
        ),
        ("sub number", with(&|c| c["sub"] = json!(5)), false),
        ("sub null keeps nothing", with(&|c| c["sub"] = Value::Null), false),
        ("roles null", with(&|c| c["roles"] = Value::Null), true),
        ("roles number", with(&|c| c["roles"] = json!(1)), false),
        ("aud string", with(&|c| c["aud"] = json!("app")), true),
        ("aud number", with(&|c| c["aud"] = json!(1)), false),
        (
            "exp quoted",
            with(&|c| c["exp"] = json!((T0 + 900).to_string())),
            true,
        ),
        ("exp quoted junk", with(&|c| c["exp"] = json!("soon")), false),
        (
            "exp fractional",
            with(&|c| c["exp"] = json!(T0 as f64 + 900.9)),
            true,
        ),
        (
            "claims array",
            s.sign_raw(&json!({"alg": "EdDSA", "kid": "k1"}), &json!([1])),
            false,
        ),
        (
            "oversized",
            with(&|c| c["pad"] = json!("x".repeat(8 << 10))),
            false,
        ),
    ];
    for (name, tok, ok) in cases {
        let got = v.verify(&tok).await;
        assert_eq!(got.is_ok(), ok, "{name}: {got:?}");
    }
    // Structural refusals.
    let good = s.mint(&base());
    for bad in [
        format!("{good}.x"),
        good.rsplit_once('.').unwrap().0.to_owned(),
        format!("{}.!!!", good.rsplit_once('.').unwrap().0),
        format!("{}=", good),
    ] {
        assert!(v.verify(&bad).await.is_err(), "{bad}");
    }
    // Case-insensitive claim names and last-duplicate-wins, like encoding/json.
    let h = base64_url(r#"{"alg":"EdDSA","kid":"k1"}"#);
    let raw = format!(
        r#"{{"ISS":"{ISS}","Sub":"x","sub":"u1","tid":"t1","sid":"s1","jti":"j","iat":{T0},"nbf":{T0},"exp":{}}}"#,
        T0 + 60
    );
    let id = v.verify(&s.sign_parts(&h, &base64_url(&raw))).await.unwrap();
    assert_eq!(id.user_id, "u1");
}

fn base64_url(s: &str) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(s)
}

#[test]
fn bearer_tokens() {
    assert_eq!(bearer_token("Bearer abc"), "abc");
    assert_eq!(bearer_token("bearer  abc "), "abc");
    assert_eq!(bearer_token("BEARER x"), "x");
    assert_eq!(bearer_token("Bearer "), "");
    assert_eq!(bearer_token("Basic abc"), "");
    assert_eq!(bearer_token("Bearerabc"), "");
}

#[tokio::test]
async fn middleware_and_grpc() {
    use tower::ServiceExt;
    let s = TestSigner::new("k1").unwrap();
    let v = Arc::new(Verifier::new(
        Config {
            issuer: ISS.into(),
            ..Config::default()
        },
        Arc::new(StaticKeys([("k1".to_owned(), s.public_key())].into())),
        None,
    ));
    v.refresh_keys().await.unwrap();
    let now = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()).unwrap();
    let tok = mint(&s, now, "u1", "t1", "s1", 300, "");
    let app = axum::Router::new()
        .route("/", axum::routing::get(|u: User| async move { u.user_id }))
        .layer(UserAuthLayer::new(Arc::clone(&v)));
    let req = |auth: Option<&str>| {
        let mut b = http::Request::get("/");
        if let Some(a) = auth {
            b = b.header("authorization", a);
        }
        b.body(axum::body::Body::empty()).unwrap()
    };
    let r = app.clone().oneshot(req(None)).await.unwrap();
    assert_eq!(r.status(), 401);
    assert_eq!(r.headers()["www-authenticate"], "Bearer realm=\"freya\"");
    assert_eq!(r.headers()["content-type"], "application/json");
    let body = http_body_util::BodyExt::collect(r.into_body())
        .await
        .unwrap()
        .to_bytes();
    assert_eq!(&body[..], br#"{"reason":"unauthenticated"}"#);
    let r = app.oneshot(req(Some(&format!("bearer {tok}")))).await.unwrap();
    assert_eq!(r.status(), 200);
    let body = http_body_util::BodyExt::collect(r.into_body())
        .await
        .unwrap()
        .to_bytes();
    assert_eq!(&body[..], b"u1");
    // The extractor alone (no layer) refuses.
    let bare = axum::Router::new().route("/", axum::routing::get(|u: User| async move { u.user_id }));
    assert_eq!(
        bare.oneshot(req(Some(&format!("Bearer {tok}"))))
            .await
            .unwrap()
            .status(),
        401
    );
    // gRPC.
    let mut r = tonic::Request::new(());
    assert_eq!(
        verify_grpc(&v, &r).await.unwrap_err().code(),
        tonic::Code::Unauthenticated
    );
    r.metadata_mut()
        .insert("authorization", format!("Bearer {tok}").parse().unwrap());
    assert_eq!(verify_grpc(&v, &r).await.unwrap().user_id, "u1");
}

#[test]
fn jwks_parsing() {
    let s = TestSigner::new("k1").unwrap();
    let doc = json!({"keys": [Jwk::new("k1", &s.public_key(), "active")]}).to_string();
    let keys = parse_jwks(doc.as_bytes()).unwrap();
    assert_eq!(keys["k1"], s.public_key());
    assert!(parse_jwks(br#"{"keys":[{"kty":"RSA","kid":"r"}]}"#).is_err());
    assert!(
        parse_jwks(br#"{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"a","x":"AA"},{"kty":"OKP","crv":"Ed25519","kid":"a","x":"AA"}]}"#)
            .is_err()
    );
    let x = Jwk::new("k1", &s.public_key(), "").x;
    let dup = format!(
        r#"{{"keys":[{{"kty":"OKP","crv":"Ed25519","kid":"a","x":"{x}"}},{{"kty":"OKP","crv":"Ed25519","kid":"a","x":"{x}"}}]}}"#
    );
    assert!(parse_jwks(dup.as_bytes()).unwrap_err().0.contains("duplicate"));
    assert!(parse_jwks(&vec![b' '; MAX_JWKS_BYTES + 1]).is_err());
    let alg = format!(r#"{{"keys":[{{"kty":"OKP","crv":"Ed25519","kid":"a","x":"{x}","alg":"ES256"}}]}}"#);
    assert!(parse_jwks(alg.as_bytes()).is_err());
}

#[tokio::test]
async fn http_keys_requires_https() {
    let k = HttpKeys {
        url: "http://plain/jwks".into(),
        tls: None,
    };
    assert!(k.keys().await.unwrap_err().0.contains("https"));
}

fn warden() -> Registration {
    let p = |r: &str, a: &str, d: &str| Permission {
        resource: r.into(),
        action: a.into(),
        description: d.into(),
    };
    let strs = |v: &[&str]| v.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
    Registration {
        module: "warden".into(),
        display_name: "Warden".into(),
        permissions: vec![
            p("secrets", "read", "Read secrets"),
            p("secrets", "write", ""),
            p("backup", "manage", ""),
        ],
        roles: vec![
            ModuleRole {
                slug: "administrator".into(),
                display_name: "Warden administrator".into(),
                description: String::new(),
                permissions: strs(&["secrets:read", "secrets:write", "backup:manage"]),
            },
            ModuleRole {
                slug: "viewer".into(),
                display_name: "Warden viewer".into(),
                description: "Read secrets granted to the user".into(),
                permissions: strs(&["secrets:read"]),
            },
        ],
        builtin_grants: BTreeMap::from([
            ("owner".to_owned(), strs(&["secrets:read", "backup:manage"])),
            ("admin".to_owned(), strs(&["backup:manage"])),
        ]),
        declares_grants: false,
        tenant_ids: vec![],
    }
}

#[test]
fn registration_validate() {
    warden().validate().unwrap();
    let cases: Vec<(&str, Box<dyn Fn(&mut Registration)>)> = vec![
        ("module empty", Box::new(|r| r.module.clear())),
        ("module grammar", Box::new(|r| r.module = "Warden".into())),
        ("module long", Box::new(|r| r.module = "w".repeat(33))),
        ("display long", Box::new(|r| r.display_name = "W".repeat(121))),
        (
            "display control",
            Box::new(|r| r.display_name = "War\nden".into()),
        ),
        (
            "permission grammar",
            Box::new(|r| r.permissions[0].resource = "Secrets".into()),
        ),
        (
            "permission action",
            Box::new(|r| r.permissions[0].action = "read:all".into()),
        ),
        (
            "permission duplicate",
            Box::new(|r| {
                let p = r.permissions[0].clone();
                r.permissions.push(p);
            }),
        ),
        (
            "description long",
            Box::new(|r| r.permissions[0].description = "d".repeat(257)),
        ),
        (
            "too many permissions",
            Box::new(|r| r.permissions = vec![Permission::default(); 201]),
        ),
        (
            "too many roles",
            Box::new(|r| r.roles = vec![ModuleRole::default(); 21]),
        ),
        ("role slug", Box::new(|r| r.roles[0].slug = "Admin".into())),
        ("role slug dot", Box::new(|r| r.roles[0].slug = "a.b".into())),
        ("role slug long", Box::new(|r| r.roles[0].slug = "a".repeat(33))),
        (
            "role duplicate",
            Box::new(|r| r.roles[1].slug = r.roles[0].slug.clone()),
        ),
        (
            "role name empty",
            Box::new(|r| r.roles[0].display_name = " ".into()),
        ),
        (
            "role name long",
            Box::new(|r| r.roles[0].display_name = "n".repeat(121)),
        ),
        (
            "role description",
            Box::new(|r| r.roles[0].description = "d".repeat(257)),
        ),
        (
            "role no permissions",
            Box::new(|r| r.roles[0].permissions.clear()),
        ),
        (
            "role too many",
            Box::new(|r| r.roles[0].permissions = vec!["secrets:read".into(); 201]),
        ),
        (
            "role foreign",
            Box::new(|r| r.roles[1].permissions = vec!["users:manage".into()]),
        ),
        (
            "role other module",
            Box::new(|r| r.roles[1].permissions = vec!["ipam:secrets:read".into()]),
        ),
        (
            "grant role",
            Box::new(|r| {
                r.builtin_grants
                    .insert("viewer".into(), vec!["secrets:read".into()]);
            }),
        ),
        (
            "grant foreign",
            Box::new(|r| {
                r.builtin_grants
                    .insert("member".into(), vec!["users:manage".into()]);
            }),
        ),
        ("tenant id", Box::new(|r| r.tenant_ids = vec!["acme".into()])),
    ];
    for (name, f) in cases {
        let mut r = warden();
        f(&mut r);
        assert!(r.validate().is_err(), "{name}");
    }
    let mut r = warden();
    r.roles[1].permissions = vec!["warden:secrets:read".into()];
    r.validate().expect("qualified own-module reference");
}

#[test]
fn registration_request() {
    let req = warden().request();
    assert_eq!(
        (req.module.as_str(), req.module_display_name.as_str()),
        ("warden", "Warden")
    );
    assert!(req.declares_roles && req.permissions.len() == 3 && req.roles.len() == 2);
    assert_eq!(req.roles[1].description, "Read secrets granted to the user");
    assert_eq!(req.permissions[0].description, "Read secrets");
    assert_eq!(req.builtin_grants.len(), 2);
    assert_eq!(req.builtin_grants[0].role, "admin");
    assert_eq!(req.builtin_grants[1].role, "owner");
    assert_eq!(
        req.builtin_grants[1].permissions.join(","),
        "secrets:read,backup:manage"
    );
    let mut r = warden();
    r.roles[1].permissions = vec!["warden:secrets:read".into()];
    assert_eq!(r.request().roles[1].permissions, ["secrets:read"]);
    r.roles.clear();
    assert!(r.request().declares_roles && r.request().roles.is_empty());
    assert!(!r.request().declares_builtin_grants);
    r.declares_grants = true;
    assert!(r.request().declares_builtin_grants);
}
