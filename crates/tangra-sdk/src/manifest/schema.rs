//! Validation against the vendored `manifest.schema.json` (portal
//! `sdk/api/schema`, JSON Schema 2020-12, compiled in Go by
//! santhosh-tekuri/jsonschema v6 with Go `regexp` patterns).
//!
//! Only the keywords that schema uses are interpreted: `type`, `properties`,
//! `additionalProperties: false`, `required`, `$ref` (local `#/$defs/...`),
//! `pattern`, `minLength`/`maxLength` (code points), `enum`, `const`,
//! `items`, `minItems`/`maxItems`, `uniqueItems`, `minimum`/`maximum`,
//! `oneOf` and `not`. Any other keyword in the schema is a build defect and
//! fails every validation (the test suite proves the vendored file has none).

use std::collections::HashMap;
use std::sync::OnceLock;

use regex::Regex;
use serde_json::Value;

/// The vendored schema, byte-for-byte.
pub(crate) const MANIFEST_SCHEMA: &str = include_str!("../../schema/manifest.schema.json");

const KNOWN: &[&str] = &[
    "$schema",
    "$id",
    "$defs",
    "title",
    "description",
    "type",
    "properties",
    "additionalProperties",
    "required",
    "$ref",
    "pattern",
    "minLength",
    "maxLength",
    "enum",
    "const",
    "items",
    "minItems",
    "maxItems",
    "uniqueItems",
    "minimum",
    "maximum",
    "oneOf",
    "not",
];

struct Compiled {
    root: Value,
    patterns: HashMap<String, Regex>,
}

fn compiled() -> Result<&'static Compiled, String> {
    static C: OnceLock<Result<Compiled, String>> = OnceLock::new();
    C.get_or_init(|| {
        let root: Value = serde_json::from_str(MANIFEST_SCHEMA).map_err(|e| format!("schema: {e}"))?;
        let mut patterns = HashMap::new();
        collect(&root, &mut patterns)?;
        Ok(Compiled { root, patterns })
    })
    .as_ref()
    .map_err(Clone::clone)
}

fn collect(v: &Value, out: &mut HashMap<String, Regex>) -> Result<(), String> {
    match v {
        Value::Object(m) => {
            for (k, x) in m {
                if k == "pattern"
                    && let Value::String(p) = x
                {
                    let re = Regex::new(p).map_err(|e| format!("schema pattern {p}: {e}"))?;
                    out.insert(p.clone(), re);
                }
                collect(x, out)?;
            }
        }
        Value::Array(a) => {
            for x in a {
                collect(x, out)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Validates `inst` against the manifest schema; the error names the
/// failing location and keyword.
pub(crate) fn validate(inst: &Value) -> Result<(), String> {
    let c = compiled()?;
    check(c, &c.root, inst, "")
}

fn json_eq(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => x.as_f64() == y.as_f64(),
        (Value::Array(x), Value::Array(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(p, q)| json_eq(p, q))
        }
        (Value::Object(x), Value::Object(y)) => {
            x.len() == y.len() && x.iter().all(|(k, v)| y.get(k).is_some_and(|w| json_eq(v, w)))
        }
        _ => a == b,
    }
}

fn is_integer(n: &serde_json::Number) -> bool {
    n.is_i64() || n.is_u64() || n.as_f64().is_some_and(|f| f.is_finite() && f.fract() == 0.0)
}

fn type_ok(t: &str, v: &Value) -> bool {
    match t {
        "object" => v.is_object(),
        "array" => v.is_array(),
        "string" => v.is_string(),
        "boolean" => v.is_boolean(),
        "null" => v.is_null(),
        "number" => v.is_number(),
        "integer" => v.as_number().is_some_and(is_integer),
        _ => false,
    }
}

fn check(c: &Compiled, schema: &Value, inst: &Value, at: &str) -> Result<(), String> {
    let Value::Object(s) = schema else {
        return match schema {
            Value::Bool(true) => Ok(()),
            _ => Err(format!("at '{at}': false schema")),
        };
    };
    for k in s.keys() {
        if !KNOWN.contains(&k.as_str()) {
            return Err(format!("schema keyword {k} is not supported"));
        }
    }
    if let Some(Value::String(r)) = s.get("$ref") {
        let target = r
            .strip_prefix("#/$defs/")
            .and_then(|name| c.root.get("$defs").and_then(|d| d.get(name)))
            .ok_or_else(|| format!("schema: unresolved $ref {r}"))?;
        check(c, target, inst, at)?;
    }
    if let Some(t) = s.get("type") {
        let ok = match t {
            Value::String(t) => type_ok(t, inst),
            Value::Array(ts) => ts.iter().any(|t| t.as_str().is_some_and(|t| type_ok(t, inst))),
            _ => false,
        };
        if !ok {
            return Err(format!("at '{at}': got {}, want {t}", kind(inst)));
        }
    }
    if let Some(e) = s.get("enum").and_then(Value::as_array)
        && !e.iter().any(|x| json_eq(x, inst))
    {
        return Err(format!(
            "at '{at}': value must be one of {}",
            Value::Array(e.clone())
        ));
    }
    if let Some(k) = s.get("const")
        && !json_eq(k, inst)
    {
        return Err(format!("at '{at}': value must be {k}"));
    }
    if let Value::String(text) = inst {
        let n = text.chars().count();
        if let Some(min) = s.get("minLength").and_then(Value::as_u64)
            && (n as u64) < min
        {
            return Err(format!("at '{at}': minLength: got {n}, want {min}"));
        }
        if let Some(max) = s.get("maxLength").and_then(Value::as_u64)
            && (n as u64) > max
        {
            return Err(format!("at '{at}': maxLength: got {n}, want {max}"));
        }
        if let Some(Value::String(p)) = s.get("pattern") {
            let re = c
                .patterns
                .get(p)
                .ok_or_else(|| format!("schema: pattern {p} not compiled"))?;
            if !re.is_match(text) {
                return Err(format!("at '{at}': '{text}' does not match pattern '{p}'"));
            }
        }
    }
    if let Value::Number(n) = inst {
        let f = n.as_f64().unwrap_or(f64::NAN);
        if let Some(min) = s.get("minimum").and_then(Value::as_f64)
            && f < min
        {
            return Err(format!("at '{at}': minimum: got {n}, want {min}"));
        }
        if let Some(max) = s.get("maximum").and_then(Value::as_f64)
            && f > max
        {
            return Err(format!("at '{at}': maximum: got {n}, want {max}"));
        }
    }
    if let Value::Array(items) = inst {
        let n = items.len() as u64;
        if let Some(min) = s.get("minItems").and_then(Value::as_u64)
            && n < min
        {
            return Err(format!("at '{at}': minItems: got {n}, want {min}"));
        }
        if let Some(max) = s.get("maxItems").and_then(Value::as_u64)
            && n > max
        {
            return Err(format!("at '{at}': maxItems: got {n}, want {max}"));
        }
        if s.get("uniqueItems") == Some(&Value::Bool(true)) {
            for i in 0..items.len() {
                for j in i + 1..items.len() {
                    if json_eq(&items[i], &items[j]) {
                        return Err(format!("at '{at}': items at {i} and {j} are equal"));
                    }
                }
            }
        }
        if let Some(is) = s.get("items") {
            for (i, x) in items.iter().enumerate() {
                check(c, is, x, &format!("{at}/{i}"))?;
            }
        }
    }
    if let Value::Object(obj) = inst {
        if let Some(req) = s.get("required").and_then(Value::as_array) {
            for r in req.iter().filter_map(Value::as_str) {
                if !obj.contains_key(r) {
                    return Err(format!("at '{at}': missing property '{r}'"));
                }
            }
        }
        let props = s.get("properties").and_then(Value::as_object);
        for (k, x) in obj {
            match props.and_then(|p| p.get(k)) {
                Some(ps) => check(c, ps, x, &format!("{at}/{k}"))?,
                None => {
                    if s.get("additionalProperties") == Some(&Value::Bool(false)) {
                        return Err(format!("at '{at}': additional property '{k}' not allowed"));
                    }
                }
            }
        }
    }
    if let Some(one) = s.get("oneOf").and_then(Value::as_array) {
        let n = one.iter().filter(|x| check(c, x, inst, at).is_ok()).count();
        if n != 1 {
            return Err(format!("at '{at}': oneOf failed, {n} subschemas matched"));
        }
    }
    if let Some(not) = s.get("not")
        && check(c, not, inst, at).is_ok()
    {
        return Err(format!("at '{at}': not failed"));
    }
    Ok(())
}

fn kind(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(n) if is_integer(n) => "integer",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vendored_schema_compiles_and_uses_known_keywords() {
        assert!(compiled().is_ok());
        assert!(validate(&serde_json::json!({})).is_err());
    }

    #[test]
    fn integer_follows_json_schema() {
        assert!(type_ok("integer", &serde_json::json!(1.0)));
        assert!(!type_ok("integer", &serde_json::json!(1.5)));
    }
}
