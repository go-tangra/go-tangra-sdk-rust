//! Cross-check of `auth::verify_token` against authclient `VerifyToken`
//! (auth `sdk/v4.3.0`, golang-jwt v5.3.1).
//!
//! `tests/fixtures/auth/tokens.json` is written by this file
//! (`TANGRA_WRITE_XCHECK=1 cargo test --test auth_xcheck`); each token is
//! signed with a fixed seed. `tests/fixtures/auth/expected.go.json` is the
//! Go verdict for every token at the same instant (see
//! `tests/fixtures/auth/xcheck/main.go`).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value, json};
use tangra_sdk::auth::{TestSigner, TokenError, verify_token};

const ISS: &str = "https://auth.example.org";
const T0: i64 = 1_789_560_000;
const SEED: [u8; 32] = [7; 32];
const OTHER_SEED: [u8; 32] = [9; 32];

fn dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/auth")
}

fn b64(s: &str) -> String {
    URL_SAFE_NO_PAD.encode(s)
}

fn cases() -> Vec<(String, String)> {
    let s = TestSigner::from_seed("k1", &SEED).unwrap();
    let other = TestSigner::from_seed("k1", &OTHER_SEED).unwrap();
    let base = || TestSigner::claims(ISS, "u1", "t1", "s1", T0, 900);
    let mut out: Vec<(String, String)> = Vec::new();
    let mut add = |n: &str, t: String| out.push((n.to_owned(), t));
    let with = |f: &dyn Fn(&mut Value)| {
        let mut c = base();
        f(&mut c);
        s.mint(&c)
    };
    let rm = |k: &'static str| {
        move |c: &mut Value| {
            c.as_object_mut().unwrap().remove(k);
        }
    };
    let hdr = |h: &str| s.sign_parts(&b64(h), &b64(&base().to_string()));
    let raw_claims = |c: &str| s.sign_parts(&b64(r#"{"alg":"EdDSA","kid":"k1"}"#), &b64(c));
    let claims_str = |extra: &str| {
        format!(
            r#"{{"iss":"{ISS}","sub":"u1","tid":"t1","sid":"s1","jti":"j","iat":{T0},"nbf":{T0},"exp":{}{extra}}}"#,
            T0 + 900
        )
    };

    add("valid", s.mint(&base()));
    add("alg_hs256", hdr(r#"{"alg":"HS256","kid":"k1"}"#));
    add("alg_none", hdr(r#"{"alg":"none","kid":"k1"}"#));
    add("alg_unknown", hdr(r#"{"alg":"XX1","kid":"k1"}"#));
    add("alg_missing", hdr(r#"{"kid":"k1"}"#));
    add("alg_number", hdr(r#"{"alg":1,"kid":"k1"}"#));
    add("alg_lower", hdr(r#"{"alg":"eddsa","kid":"k1"}"#));
    add("kid_missing", hdr(r#"{"alg":"EdDSA"}"#));
    add("kid_empty", hdr(r#"{"alg":"EdDSA","kid":""}"#));
    add("kid_number", hdr(r#"{"alg":"EdDSA","kid":1}"#));
    add("kid_unknown", hdr(r#"{"alg":"EdDSA","kid":"k9"}"#));
    add("header_null", hdr("null"));
    add("header_array", hdr("[]"));
    add(
        "header_dup_alg_last_wins",
        hdr(r#"{"alg":"HS256","alg":"EdDSA","kid":"k1"}"#),
    );
    add(
        "header_dup_alg_last_bad",
        hdr(r#"{"alg":"EdDSA","alg":"HS256","kid":"k1"}"#),
    );
    add("header_trailing", hdr(r#"{"alg":"EdDSA","kid":"k1"} x"#));
    add("wrong_key", other.mint(&base()));
    add("wrong_issuer", with(&|c| c["iss"] = json!("https://evil")));
    add("issuer_missing", with(&rm("iss")));
    add("issuer_empty", with(&|c| c["iss"] = json!("")));
    add(
        "expired_61s",
        with(&|c| {
            c["iat"] = json!(T0 - 1000);
            c["nbf"] = json!(T0 - 1000);
            c["exp"] = json!(T0 - 61);
        }),
    );
    add(
        "expired_60s_boundary",
        with(&|c| {
            c["iat"] = json!(T0 - 900);
            c["nbf"] = json!(T0 - 900);
            c["exp"] = json!(T0 - 60);
        }),
    );
    add(
        "expired_59s_in_skew",
        with(&|c| {
            c["iat"] = json!(T0 - 900);
            c["nbf"] = json!(T0 - 900);
            c["exp"] = json!(T0 - 59);
        }),
    );
    add("exp_missing", with(&rm("exp")));
    add("exp_null", with(&|c| c["exp"] = Value::Null));
    add("exp_quoted", with(&|c| c["exp"] = json!((T0 + 900).to_string())));
    add("exp_quoted_junk", with(&|c| c["exp"] = json!("soon")));
    add(
        "exp_quoted_space",
        with(&|c| c["exp"] = json!(format!(" {}", T0 + 900))),
    );
    add("exp_bool", with(&|c| c["exp"] = json!(true)));
    add("exp_float", with(&|c| c["exp"] = json!(T0 as f64 + 900.9)));
    add(
        "exp_exponent",
        raw_claims(&claims_str("").replace(&format!("\"exp\":{}", T0 + 900), "\"exp\":1.7895609e9")),
    );
    add(
        "exp_huge",
        raw_claims(&claims_str("").replace(&format!("\"exp\":{}", T0 + 900), "\"exp\":\"1e400\"")),
    );
    add("exp_then_null", raw_claims(&claims_str(r#","exp":null"#)));
    add("nbf_61s_future", with(&|c| c["nbf"] = json!(T0 + 61)));
    add("nbf_60s_boundary", with(&|c| c["nbf"] = json!(T0 + 60)));
    add("nbf_missing", with(&rm("nbf")));
    add(
        "iat_61s_future",
        with(&|c| {
            c["iat"] = json!(T0 + 61);
            c["exp"] = json!(T0 + 900);
        }),
    );
    add("iat_missing", with(&rm("iat")));
    add("lifetime_900", with(&|c| c["exp"] = json!(T0 + 900)));
    add("lifetime_901", with(&|c| c["exp"] = json!(T0 + 901)));
    add(
        "lifetime_negative",
        with(&|c| {
            c["iat"] = json!(T0);
            c["exp"] = json!(T0 + 30);
            c["nbf"] = json!(T0 - 5000);
        }),
    );
    add("sub_missing", with(&rm("sub")));
    add("sub_number", with(&|c| c["sub"] = json!(5)));
    add("sub_null", with(&|c| c["sub"] = Value::Null));
    add("tid_empty", with(&|c| c["tid"] = json!("")));
    add("sid_missing", with(&rm("sid")));
    add("jti_missing", with(&rm("jti")));
    add("roles_null", with(&|c| c["roles"] = Value::Null));
    add("roles_null_elem", with(&|c| c["roles"] = json!(["a", null])));
    add("roles_number", with(&|c| c["roles"] = json!(1)));
    add("roles_number_elem", with(&|c| c["roles"] = json!(["a", 1])));
    add("amr_object", with(&|c| c["amr"] = json!({})));
    add("aud_string", with(&|c| c["aud"] = json!("app")));
    add("aud_array", with(&|c| c["aud"] = json!(["a", "b"])));
    add("aud_null_elem", with(&|c| c["aud"] = json!(["a", null])));
    add("aud_number", with(&|c| c["aud"] = json!(1)));
    add(
        "unknown_claim_types_ignored",
        with(&|c| c["extra"] = json!({"x": [1, null]})),
    );
    add("claims_array", raw_claims("[1]"));
    add("claims_null", raw_claims("null"));
    add("claims_trailing", raw_claims(&format!("{} x", claims_str(""))));
    add(
        "key_case_upper",
        raw_claims(&claims_str("").replace("\"sub\":\"u1\"", "\"SUB\":\"u1\"")),
    );
    add(
        "key_long_s",
        raw_claims(&claims_str("").replace("\"sub\":\"u1\"", "\"\u{17f}ub\":\"u1\"")),
    );
    add("key_dup_last_wins", raw_claims(&claims_str(r#","sub":"u2""#)));
    add("key_case_dup_empty_last", raw_claims(&claims_str(r#","Sub":"""#)));
    add("unicode_claim", raw_claims(&claims_str(r#","name":"José  ""#)));
    add("oversized", with(&|c| c["pad"] = json!("x".repeat(8 << 10))));
    let good = s.mint(&base());
    let (signing, sig) = good.rsplit_once('.').unwrap();
    let (h, c) = signing.split_once('.').unwrap();
    add("four_segments", format!("{good}.x"));
    add("two_segments", signing.to_owned());
    add("sig_garbage", format!("{signing}.!!!"));
    add("sig_padded", format!("{good}="));
    add("sig_newline", format!("{signing}.{}\n{}", &sig[..10], &sig[10..]));
    add("header_padded", s.sign_parts(&format!("{h}="), c));
    add(
        "claims_crlf",
        s.sign_parts(h, &format!("{}\r\n{}", &c[..8], &c[8..])),
    );
    add("sig_truncated", format!("{signing}.{}", &sig[..sig.len() - 4]));
    add("empty", String::new());
    out
}

fn verdict(tok: &str) -> (bool, bool) {
    let s = TestSigner::from_seed("k1", &SEED).unwrap();
    let pk = s.public_key();
    let r = verify_token(
        tok,
        ISS,
        Duration::from_secs(60),
        Duration::from_secs(900),
        UNIX_EPOCH + Duration::from_secs(T0 as u64),
        |kid| (kid == "k1").then(|| pk.clone()),
    );
    (r.is_ok(), matches!(r, Err(TokenError::UnknownKey(_))))
}

#[test]
fn token_fixtures_up_to_date() {
    let want: Vec<Value> = cases()
        .into_iter()
        .map(|(n, t)| json!({"name": n, "token": t}))
        .collect();
    let path = dir().join("tokens.json");
    if std::env::var_os("TANGRA_WRITE_XCHECK").is_some() {
        std::fs::create_dir_all(dir()).unwrap();
        std::fs::write(&path, serde_json::to_string_pretty(&want).unwrap() + "\n").unwrap();
        return;
    }
    let got: Vec<Value> = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(
        got, want,
        "fixtures stale: TANGRA_WRITE_XCHECK=1, then rerun the Go cross-check"
    );
}

#[test]
fn verify_token_agrees_with_authclient() {
    let expected: Vec<Value> =
        serde_json::from_slice(&std::fs::read(dir().join("expected.go.json")).unwrap()).unwrap();
    let tokens: Vec<Value> =
        serde_json::from_slice(&std::fs::read(dir().join("tokens.json")).unwrap()).unwrap();
    assert_eq!(expected.len(), tokens.len());
    for (e, t) in expected.iter().zip(&tokens) {
        let name = t["name"].as_str().unwrap();
        assert_eq!(e["name"], t["name"]);
        let (ok, unknown) = verdict(t["token"].as_str().unwrap());
        assert_eq!(ok, e["ok"].as_bool().unwrap(), "{name}: go said {}", e["error"]);
        assert_eq!(
            unknown,
            e["unknown_kid"].as_bool().unwrap(),
            "{name}: unknown-kid classification"
        );
    }
}
