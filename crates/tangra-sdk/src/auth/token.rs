//! Access-token verification (auth `sdk/pkg/authclient/token.go` at
//! `sdk/v4.3.0`, on golang-jwt v5.3.1 `ParseWithClaims` with
//! `WithValidMethods(["EdDSA"])`, `WithIssuer`, `WithLeeway(skew)`,
//! `WithIssuedAt`, `WithExpirationRequired`).
//!
//! Order (each step fails closed):
//! 1. length ≤ 8 KiB;
//! 2. three dot-separated segments; header and claims base64url (raw,
//!    non-strict, CR/LF ignored) and JSON (claims decoded like Go's
//!    `encoding/json` into the claims struct: case-insensitive keys, last
//!    duplicate wins, `null` leaves strings unchanged);
//! 3. `alg` a string naming a known method, and exactly `EdDSA`;
//! 4. signature segment base64url;
//! 5. `kid` a non-empty string, known to the key set (else
//!    [`TokenError::UnknownKey`], which lets the verifier refresh);
//! 6. Ed25519 signature;
//! 7. `exp` required and `now < exp + skew`; `nbf` (when present)
//!    `now >= nbf - skew`; `iat` (when present) `now >= iat - skew`;
//!    `iss` equal to the configured issuer (when one is configured);
//! 8. `iat`, `exp`, `nbf` all present and `exp - iat ≤ max lifetime`;
//! 9. `sub`, `tid`, `sid`, `jti` non-empty.
//!
//! Times are JWT NumericDates truncated to whole seconds (golang-jwt
//! `TimePrecision`).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use serde::de::{Deserializer, MapAccess, Visitor};
use serde_json::Value;

/// The contract ceiling for `exp - iat` (token.go:22).
pub const MAX_TOKEN_LIFETIME: Duration = Duration::from_secs(15 * 60);
/// The longest accepted token (token.go:28).
pub const MAX_TOKEN_BYTES: usize = 8 << 10;
/// The largest clock skew (token.go:31).
pub const MAX_SKEW: Duration = Duration::from_secs(60);

/// The access-token claims (auth `contracts/token.md`; no PII).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Claims {
    /// `iss`.
    pub issuer: String,
    /// `sub`: the user id.
    pub subject: String,
    /// `aud`.
    pub audience: Vec<String>,
    /// `exp` (unix seconds).
    pub expires_at: Option<i64>,
    /// `nbf` (unix seconds).
    pub not_before: Option<i64>,
    /// `iat` (unix seconds).
    pub issued_at: Option<i64>,
    /// `jti`.
    pub id: String,
    /// `tid`: the tenant id.
    pub tenant_id: String,
    /// `sid`: the session id.
    pub session_id: String,
    /// `roles` (`None` = absent or null).
    pub roles: Option<Vec<String>>,
    /// `amr`.
    pub amr: Option<Vec<String>>,
}

/// Why a token was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TokenError {
    /// A `kid` outside the current key set (a refresh may fix it).
    #[error("token: unknown kid {0:?}")]
    UnknownKey(String),
    /// Anything else.
    #[error("token: {0}")]
    Invalid(String),
}

fn invalid(s: impl Into<String>) -> TokenError {
    TokenError::Invalid(s.into())
}

/// Go's `base64.RawURLEncoding` (non-strict): no padding, trailing bits
/// allowed, `\r` and `\n` skipped.
pub(crate) fn decode_raw_url(seg: &str) -> Option<Vec<u8>> {
    const ENGINE: GeneralPurpose = GeneralPurpose::new(
        &base64::alphabet::URL_SAFE,
        GeneralPurposeConfig::new()
            .with_decode_allow_trailing_bits(true)
            .with_decode_padding_mode(DecodePaddingMode::RequireNone),
    );
    let clean: Vec<u8> = seg.bytes().filter(|b| *b != b'\r' && *b != b'\n').collect();
    ENGINE.decode(clean).ok()
}

fn decode_segment(seg: &str) -> Result<Vec<u8>, TokenError> {
    decode_raw_url(seg).ok_or_else(|| invalid("token is malformed: could not base64 decode"))
}

/// The `alg` names golang-jwt registers.
const KNOWN_ALGS: &[&str] = &[
    "EdDSA", "ES256", "ES384", "ES512", "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "PS256",
    "PS384", "PS512", "none",
];

/// A JSON object as an ordered list of entries (duplicates kept).
struct Entries(Option<Vec<(String, Value)>>);

impl<'de> serde::Deserialize<'de> for Entries {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Entries;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a JSON object")
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Entries, E> {
                Ok(Entries(None))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut m: A) -> Result<Entries, A::Error> {
                let mut out = Vec::new();
                while let Some((k, v)) = m.next_entry::<String, Value>()? {
                    out.push((k, v));
                }
                Ok(Entries(Some(out)))
            }
        }
        d.deserialize_any(V)
    }
}

/// Go `encoding/json` key matching (bytes.EqualFold): ASCII case plus the
/// two non-ASCII simple folds of letters that occur in claim names.
fn fold_eq(key: &str, field: &str) -> bool {
    let mut k = key.chars().map(|c| match c {
        '\u{17f}' => 's',
        '\u{212a}' => 'k',
        c => c.to_ascii_lowercase(),
    });
    let mut f = field.chars();
    loop {
        match (k.next(), f.next()) {
            (None, None) => return true,
            (Some(a), Some(b)) if a == b => {}
            _ => return false,
        }
    }
}

/// Go's JSON number grammar (`encoding/json` isValidNumber).
fn valid_number(s: &str) -> bool {
    let b = s.as_bytes();
    let mut i = 0;
    if b.get(i) == Some(&b'-') {
        i += 1;
    }
    match b.get(i) {
        Some(b'0') => i += 1,
        Some(c) if c.is_ascii_digit() => {
            while b.get(i).is_some_and(u8::is_ascii_digit) {
                i += 1;
            }
        }
        _ => return false,
    }
    if b.get(i) == Some(&b'.') {
        i += 1;
        if !b.get(i).is_some_and(u8::is_ascii_digit) {
            return false;
        }
        while b.get(i).is_some_and(u8::is_ascii_digit) {
            i += 1;
        }
    }
    if matches!(b.get(i), Some(b'e' | b'E')) {
        i += 1;
        if matches!(b.get(i), Some(b'+' | b'-')) {
            i += 1;
        }
        if !b.get(i).is_some_and(u8::is_ascii_digit) {
            return false;
        }
        while b.get(i).is_some_and(u8::is_ascii_digit) {
            i += 1;
        }
    }
    i == b.len()
}

/// golang-jwt `NumericDate.UnmarshalJSON` + `newNumericDateFromSeconds`
/// (whole seconds, rounded down). `Ok(None)` is JSON null.
fn numeric_date(v: &Value) -> Result<Option<i64>, TokenError> {
    let f = match v {
        Value::Null => return Ok(None),
        Value::Number(n) => n.as_f64().ok_or_else(|| invalid("could not parse NumericDate"))?,
        // json.Number accepts a quoted number.
        Value::String(s) if valid_number(s) => s
            .parse::<f64>()
            .ok()
            .filter(|f| f.is_finite())
            .ok_or_else(|| invalid("could not convert json number value to float"))?,
        _ => return Err(invalid("could not parse NumericDate")),
    };
    let s = f.floor();
    // int64(round) saturates here; Go's conversion is undefined beyond.
    Ok(Some(if s >= 9.2e18 {
        i64::MAX
    } else if s <= -9.2e18 {
        i64::MIN
    } else {
        s as i64
    }))
}

fn set_string(dst: &mut String, v: &Value) -> Result<(), TokenError> {
    match v {
        Value::Null => Ok(()),
        Value::String(s) => {
            s.clone_into(dst);
            Ok(())
        }
        _ => Err(invalid("cannot unmarshal into string")),
    }
}

fn set_strings(dst: &mut Option<Vec<String>>, v: &Value) -> Result<(), TokenError> {
    match v {
        Value::Null => {
            *dst = None;
            Ok(())
        }
        Value::Array(a) => {
            let mut out = Vec::with_capacity(a.len());
            for x in a {
                match x {
                    Value::String(s) => out.push(s.clone()),
                    Value::Null => out.push(String::new()),
                    _ => return Err(invalid("cannot unmarshal into []string")),
                }
            }
            *dst = Some(out);
            Ok(())
        }
        _ => Err(invalid("cannot unmarshal into []string")),
    }
}

/// golang-jwt `ClaimStrings.UnmarshalJSON`.
fn set_audience(dst: &mut Vec<String>, v: &Value) -> Result<(), TokenError> {
    match v {
        Value::Null => Ok(()),
        Value::String(s) => {
            *dst = vec![s.clone()];
            Ok(())
        }
        Value::Array(a) => {
            let mut out = Vec::with_capacity(a.len());
            for x in a {
                out.push(
                    x.as_str()
                        .ok_or_else(|| invalid("invalid type for claim"))?
                        .to_owned(),
                );
            }
            *dst = out;
            Ok(())
        }
        _ => Err(invalid("invalid type for claim")),
    }
}

/// `json.Unmarshal(claimBytes, &claims)`.
fn decode_claims(raw: &[u8]) -> Result<Claims, TokenError> {
    let Entries(entries) =
        serde_json::from_slice(raw).map_err(|e| invalid(format!("could not JSON decode claim: {e}")))?;
    let mut c = Claims::default();
    let mut failed = false;
    for (k, v) in entries.unwrap_or_default() {
        let r = if fold_eq(&k, "iss") {
            set_string(&mut c.issuer, &v)
        } else if fold_eq(&k, "sub") {
            set_string(&mut c.subject, &v)
        } else if fold_eq(&k, "aud") {
            set_audience(&mut c.audience, &v)
        } else if fold_eq(&k, "exp") {
            numeric_date(&v).map(|d| c.expires_at = d)
        } else if fold_eq(&k, "nbf") {
            numeric_date(&v).map(|d| c.not_before = d)
        } else if fold_eq(&k, "iat") {
            numeric_date(&v).map(|d| c.issued_at = d)
        } else if fold_eq(&k, "jti") {
            set_string(&mut c.id, &v)
        } else if fold_eq(&k, "tid") {
            set_string(&mut c.tenant_id, &v)
        } else if fold_eq(&k, "sid") {
            set_string(&mut c.session_id, &v)
        } else if fold_eq(&k, "roles") {
            set_strings(&mut c.roles, &v)
        } else if fold_eq(&k, "amr") {
            set_strings(&mut c.amr, &v)
        } else {
            Ok(())
        };
        // encoding/json keeps decoding after a type error, then reports it.
        failed |= r.is_err();
    }
    if failed {
        return Err(invalid("could not JSON decode claim"));
    }
    Ok(c)
}

fn unix_nanos(t: SystemTime) -> i128 {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => i128::try_from(d.as_nanos()).unwrap_or(i128::MAX),
        Err(e) => -i128::try_from(e.duration().as_nanos()).unwrap_or(i128::MAX),
    }
}

const NS: i128 = 1_000_000_000;

/// Parses and validates a token (authclient `VerifyToken`). `lookup`
/// returns the raw 32-byte Ed25519 key for a `kid`.
pub fn verify_token(
    s: &str,
    iss: &str,
    skew: Duration,
    max_life: Duration,
    now: SystemTime,
    lookup: impl Fn(&str) -> Option<Vec<u8>>,
) -> Result<Claims, TokenError> {
    if s.len() > MAX_TOKEN_BYTES {
        return Err(invalid("too long"));
    }
    let skew = if skew > MAX_SKEW { MAX_SKEW } else { skew };
    let max_life = if max_life.is_zero() || max_life > MAX_TOKEN_LIFETIME {
        MAX_TOKEN_LIFETIME
    } else {
        max_life
    };
    let mut parts = s.split('.');
    let (Some(h), Some(p), Some(sig), None) = (parts.next(), parts.next(), parts.next(), parts.next()) else {
        return Err(invalid("token contains an invalid number of segments"));
    };
    let header: Value = serde_json::from_slice(&decode_segment(h)?)
        .map_err(|e| invalid(format!("could not JSON decode header: {e}")))?;
    let header = match header {
        Value::Object(m) => m,
        Value::Null => serde_json::Map::new(),
        _ => return Err(invalid("could not JSON decode header")),
    };
    let claims = decode_claims(&decode_segment(p)?)?;
    let alg = header
        .get("alg")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("signing method (alg) is unspecified"))?;
    if !KNOWN_ALGS.contains(&alg) {
        return Err(invalid("signing method (alg) is unavailable"));
    }
    let signature = decode_segment(sig)?;
    if alg != "EdDSA" {
        return Err(invalid(format!("signing method {alg} is invalid")));
    }
    let kid = header.get("kid").and_then(Value::as_str).unwrap_or("");
    if kid.is_empty() {
        return Err(invalid("error while executing keyfunc: kid required"));
    }
    let key = lookup(kid).ok_or_else(|| TokenError::UnknownKey(kid.to_owned()))?;
    if key.len() != 32 {
        return Err(invalid("key is invalid"));
    }
    let signed = &s[..h.len() + 1 + p.len()];
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, &key)
        .verify(signed.as_bytes(), &signature)
        .map_err(|_| invalid("ed25519: verification error"))?;

    // Claims validation (golang-jwt Validator.Validate).
    let now = unix_nanos(now);
    let leeway = i128::try_from(skew.as_nanos()).unwrap_or(0);
    let mut errs = Vec::new();
    match claims.expires_at {
        None => errs.push("exp claim is required"),
        Some(exp) if now >= i128::from(exp) * NS + leeway => errs.push("token is expired"),
        _ => {}
    }
    if let Some(nbf) = claims.not_before
        && now < i128::from(nbf) * NS - leeway
    {
        errs.push("token is not valid yet");
    }
    if let Some(iat) = claims.issued_at
        && now < i128::from(iat) * NS - leeway
    {
        errs.push("token used before issued");
    }
    if !iss.is_empty() {
        if claims.issuer.is_empty() {
            errs.push("iss claim is required");
        } else if claims.issuer != iss {
            errs.push("token has invalid issuer");
        }
    }
    if !errs.is_empty() {
        return Err(invalid(format!("token has invalid claims: {}", errs.join(", "))));
    }
    let max_ns = i128::try_from(max_life.as_nanos()).unwrap_or(i128::MAX);
    match (claims.issued_at, claims.expires_at, claims.not_before) {
        (Some(iat), Some(exp), Some(_)) if (i128::from(exp) - i128::from(iat)) * NS <= max_ns => {}
        _ => return Err(invalid("lifetime exceeds the maximum")),
    }
    if claims.subject.is_empty()
        || claims.tenant_id.is_empty()
        || claims.session_id.is_empty()
        || claims.id.is_empty()
    {
        return Err(invalid("required claims missing"));
    }
    Ok(claims)
}
