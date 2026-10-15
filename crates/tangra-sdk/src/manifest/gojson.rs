//! Byte-exact Go `encoding/json` `Marshal` output for the gateway's manifest
//! structs: struct fields in declaration order, map keys sorted, HTML
//! escaping on, float64 numbers formatted like Go.

use serde_json::Value;

/// An ordered JSON value (objects keep insertion order like Go structs).
#[derive(Debug, Clone)]
pub(crate) enum J {
    Null,
    Bool(bool),
    Int(i64),
    Str(String),
    Arr(Vec<J>),
    Obj(Vec<(&'static str, J)>),
    /// A Go `map[string]any` (keys sorted on output).
    Map(serde_json::Map<String, Value>),
}

impl J {
    pub(crate) fn str(s: &str) -> Self {
        Self::Str(s.to_owned())
    }

    pub(crate) fn strs(v: &[String]) -> Self {
        Self::Arr(v.iter().map(|s| Self::Str(s.clone())).collect())
    }

    /// A nil-able Go slice: `None` marshals as `null`.
    pub(crate) fn opt_strs(v: Option<&Vec<String>>) -> Self {
        v.map_or(Self::Null, |v| Self::strs(v))
    }
}

/// Builds a struct, skipping `omitempty` fields that are empty.
#[derive(Default)]
pub(crate) struct Obj(Vec<(&'static str, J)>);

impl Obj {
    pub(crate) fn field(mut self, k: &'static str, v: J) -> Self {
        self.0.push((k, v));
        self
    }

    pub(crate) fn omit_str(self, k: &'static str, v: &str) -> Self {
        if v.is_empty() {
            self
        } else {
            self.field(k, J::str(v))
        }
    }

    pub(crate) fn omit_bool(self, k: &'static str, v: bool) -> Self {
        if v { self.field(k, J::Bool(true)) } else { self }
    }

    pub(crate) fn omit_int(self, k: &'static str, v: i64) -> Self {
        if v == 0 { self } else { self.field(k, J::Int(v)) }
    }

    pub(crate) fn omit_strs(self, k: &'static str, v: &[String]) -> Self {
        if v.is_empty() {
            self
        } else {
            self.field(k, J::strs(v))
        }
    }

    pub(crate) fn build(self) -> J {
        J::Obj(self.0)
    }
}

pub(crate) fn marshal(v: &J) -> String {
    let mut out = String::new();
    write(&mut out, v);
    out
}

fn write(out: &mut String, v: &J) {
    match v {
        J::Null => out.push_str("null"),
        J::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        J::Int(i) => out.push_str(&i.to_string()),
        J::Str(s) => write_str(out, s),
        J::Arr(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write(out, x);
            }
            out.push(']');
        }
        J::Obj(fields) => {
            out.push('{');
            for (i, (k, x)) in fields.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_str(out, k);
                out.push(':');
                write(out, x);
            }
            out.push('}');
        }
        J::Map(m) => write_value(out, &Value::Object(m.clone())),
    }
}

/// A decoded `any` (numbers are float64, maps sorted).
fn write_value(out: &mut String, v: &Value) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&crate::gofmt::json_float(n.as_f64().unwrap_or(0.0))),
        Value::String(s) => write_str(out, s),
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(out, x);
            }
            out.push(']');
        }
        Value::Object(m) => {
            // serde_json's Map is a BTreeMap: byte order, as Go sorts keys.
            out.push('{');
            for (i, (k, x)) in m.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_str(out, k);
                out.push(':');
                write_value(out, x);
            }
            out.push('}');
        }
    }
}

fn write_str(out: &mut String, s: &str) {
    // serde_json's escaping equals Go's (\b \f \n \r \t, \u00xx lowercase)
    // once Go's HTML escaping is applied on top.
    let enc = serde_json::to_string(s).unwrap_or_else(|_| "\"\"".to_owned());
    out.push_str(&crate::gofmt::escape_html_json(&enc));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_go_marshal() {
        // Go: json.Marshal(map[string]any{"a":"\b\f\x01<>& é","n":[]any{1e21,1e20,0.000001,1e-7,123456789012345678.0}})
        let v: Value = serde_json::json!({"n": [1e21, 1e20, 0.000001, 1e-7, 123456789012345678.0], "a": "\u{8}\u{c}\u{1}<>&\u{2028}é"});
        let Value::Object(m) = v else { panic!() };
        assert_eq!(
            marshal(&J::Map(m)),
            "{\"a\":\"\\b\\f\\u0001\\u003c\\u003e\\u0026\\u2028é\",\"n\":[1e+21,100000000000000000000,0.000001,1e-7,123456789012345680]}"
        );
    }
}
