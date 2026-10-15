//! Gateway routes derived from an OpenAPI document (deployer
//! `pkg/deployermanifest/manifest.go:110-151`, warden
//! `pkg/wardenmanifest/manifest.go:117-165`).
//!
//! Every operation carries `x-freya-permission` (a declared permission) or
//! `x-freya-public: true`; `x-freya-max-body-bytes` (> 0),
//! `x-freya-timeout-seconds` (1-600) and `x-freya-client-address: true` map
//! to the route fields. An undeclared or missing permission is an error, as
//! is an operation both public and protected (warden's rule; deployer lets
//! `public` win). Routes are sorted by `"METHOD path"`.

use std::collections::HashSet;
use std::time::Duration;

use serde_json::Value;

use super::{ManifestError, Route};

/// `x-freya-permission`.
pub const PERMISSION_EXTENSION: &str = "x-freya-permission";
/// `x-freya-public`.
pub const PUBLIC_EXTENSION: &str = "x-freya-public";
/// `x-freya-max-body-bytes`.
pub const BODY_LIMIT_EXTENSION: &str = "x-freya-max-body-bytes";
/// `x-freya-timeout-seconds`.
pub const TIMEOUT_EXTENSION: &str = "x-freya-timeout-seconds";
/// `x-freya-client-address`.
pub const CLIENT_ADDRESS_EXTENSION: &str = "x-freya-client-address";

/// The operations kin-openapi's `PathItem.Operations` returns.
const METHODS: &[&str] = &[
    "connect", "delete", "get", "head", "options", "patch", "post", "put", "trace",
];

fn err(msg: String) -> ManifestError {
    ManifestError(format!("manifest: {msg}"))
}

/// Parses an OpenAPI document (YAML or JSON) into JSON values; numbers
/// become JSON numbers as kin-openapi's YAML-to-JSON loader yields.
pub fn load(doc: &[u8]) -> Result<Value, ManifestError> {
    let y: serde_norway::Value = serde_norway::from_slice(doc).map_err(|e| err(format!("openapi: {e}")))?;
    Ok(yaml_to_json(y))
}

fn yaml_to_json(y: serde_norway::Value) -> Value {
    use serde_norway::Value as Y;
    match y {
        Y::Null => Value::Null,
        Y::Bool(b) => Value::Bool(b),
        Y::Number(n) => {
            if let Some(i) = n.as_i64() {
                Value::from(i)
            } else if let Some(u) = n.as_u64() {
                Value::from(u)
            } else {
                n.as_f64()
                    .and_then(serde_json::Number::from_f64)
                    .map_or(Value::Null, Value::Number)
            }
        }
        Y::String(s) => Value::String(s),
        Y::Sequence(s) => Value::Array(s.into_iter().map(yaml_to_json).collect()),
        Y::Mapping(m) => Value::Object(
            m.into_iter()
                .map(|(k, v)| {
                    let k = match k {
                        Y::String(s) => s,
                        Y::Number(n) => n.to_string(),
                        Y::Bool(b) => b.to_string(),
                        other => serde_norway::to_string(&other)
                            .unwrap_or_default()
                            .trim()
                            .to_owned(),
                    };
                    (k, yaml_to_json(v))
                })
                .collect(),
        ),
        Y::Tagged(t) => yaml_to_json(t.value),
    }
}

/// Derives the routes of `doc` (an OpenAPI document, YAML or JSON);
/// `permissions` are the declared `resource:action` references.
pub fn routes<S: AsRef<str>>(doc: &[u8], permissions: &[S]) -> Result<Vec<Route>, ManifestError> {
    routes_from_value(&load(doc)?, permissions)
}

/// [`routes`] over an already-parsed document.
pub fn routes_from_value<S: AsRef<str>>(doc: &Value, permissions: &[S]) -> Result<Vec<Route>, ManifestError> {
    let known: HashSet<&str> = permissions.iter().map(AsRef::as_ref).collect();
    let mut out = Vec::new();
    let Some(paths) = doc.get("paths").and_then(Value::as_object) else {
        return Ok(out);
    };
    for (p, item) in paths {
        for m in METHODS {
            let Some(op) = item.get(*m).and_then(Value::as_object) else {
                continue;
            };
            let method = m.to_ascii_uppercase();
            let mut r = Route {
                method: method.clone(),
                path: p.clone(),
                ..Route::default()
            };
            // Go: perm, _ := ext.(string); public, _ := ext.(bool)
            let perm = op.get(PERMISSION_EXTENSION).and_then(Value::as_str).unwrap_or("");
            let public = op.get(PUBLIC_EXTENSION).and_then(Value::as_bool).unwrap_or(false);
            if public && !perm.is_empty() {
                return Err(err(format!("{method} {p} is both public and protected")));
            } else if public {
                r.public = true;
            } else if perm.is_empty() {
                return Err(err(format!("{method} {p} declares no permission")));
            } else if !known.contains(perm) {
                return Err(err(format!(
                    "{method} {p} uses undeclared permission {}",
                    super::validate::goq(perm)
                )));
            } else {
                r.permission = perm.to_owned();
            }
            if let Some(v) = op.get(BODY_LIMIT_EXTENSION) {
                match v.as_f64() {
                    // uint64(n) truncates.
                    Some(n) if n > 0.0 => r.max_body_bytes = n as u64,
                    _ => return Err(err(format!("{method} {p} has a bad body limit"))),
                }
            }
            if op.get(CLIENT_ADDRESS_EXTENSION).and_then(Value::as_bool) == Some(true) {
                r.client_address = true;
            }
            if let Some(v) = op.get(TIMEOUT_EXTENSION) {
                match v.as_f64() {
                    // time.Duration(n) * time.Second truncates n.
                    Some(n) if n > 0.0 && n <= 600.0 => r.timeout = Duration::from_secs(n as u64),
                    _ => return Err(err(format!("{method} {p} has a bad timeout"))),
                }
            }
            out.push(r);
        }
    }
    out.sort_by(|a, b| format!("{} {}", a.method, a.path).cmp(&format!("{} {}", b.method, b.path)));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOC: &str = r#"
openapi: 3.0.3
info: {title: t, version: "1"}
paths:
  /api/x/v1/items:
    get: {x-freya-permission: "items:read", responses: {200: {description: ok}}}
    post: {x-freya-permission: "items:write", x-freya-max-body-bytes: 1048576, x-freya-timeout-seconds: 120}
  /api/x/v1/health:
    get: {x-freya-public: true, x-freya-client-address: true}
"#;

    #[test]
    fn derives_sorted_routes() {
        let r = routes(DOC.as_bytes(), &["items:read", "items:write"]).unwrap();
        let keys: Vec<String> = r.iter().map(|r| format!("{} {}", r.method, r.path)).collect();
        assert_eq!(
            keys,
            [
                "GET /api/x/v1/health",
                "GET /api/x/v1/items",
                "POST /api/x/v1/items"
            ]
        );
        assert!(r[0].public && r[0].client_address);
        assert_eq!(r[2].max_body_bytes, 1_048_576);
        assert_eq!(r[2].timeout, Duration::from_secs(120));
    }

    #[test]
    fn refuses_bad_extensions() {
        let e = routes(DOC.as_bytes(), &["items:read"]).unwrap_err();
        assert_eq!(
            e.0,
            "manifest: POST /api/x/v1/items uses undeclared permission \"items:write\""
        );
        for (doc, want) in [
            (
                "paths: {/a: {get: {}}}",
                "manifest: GET /a declares no permission",
            ),
            (
                "paths: {/a: {get: {x-freya-public: true, x-freya-permission: p:r}}}",
                "manifest: GET /a is both public and protected",
            ),
            (
                "paths: {/a: {get: {x-freya-public: true, x-freya-max-body-bytes: \"1\"}}}",
                "manifest: GET /a has a bad body limit",
            ),
            (
                "paths: {/a: {get: {x-freya-public: true, x-freya-max-body-bytes: 0}}}",
                "manifest: GET /a has a bad body limit",
            ),
            (
                "paths: {/a: {get: {x-freya-public: true, x-freya-timeout-seconds: 601}}}",
                "manifest: GET /a has a bad timeout",
            ),
            // A string "true" is not a boolean: the operation is not public.
            (
                "paths: {/a: {get: {x-freya-public: \"true\"}}}",
                "manifest: GET /a declares no permission",
            ),
        ] {
            assert_eq!(routes(doc.as_bytes(), &["p:r"]).unwrap_err().0, want, "{doc}");
        }
    }
}
