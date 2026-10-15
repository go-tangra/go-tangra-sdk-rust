//! Go text formats the wire depends on: `time.Duration` parsing/printing,
//! `fmt`'s `%g` for floats (Prometheus text) and `encoding/json` number and
//! string escaping (slog JSON lines, error bodies).

use std::fmt;
use std::time::Duration;

/// A signed Go `time.Duration` (nanoseconds). Config durations are written in
/// Go syntax ("30s", "1h30m", "250ms") and may be negative, exactly as
/// `time.ParseDuration` accepts them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GoDuration(pub i64);

impl GoDuration {
    /// One nanosecond.
    pub const NANOSECOND: i64 = 1;
    /// One microsecond.
    pub const MICROSECOND: i64 = 1_000;
    /// One millisecond.
    pub const MILLISECOND: i64 = 1_000_000;
    /// One second.
    pub const SECOND: i64 = 1_000_000_000;
    /// One minute.
    pub const MINUTE: i64 = 60 * Self::SECOND;
    /// One hour.
    pub const HOUR: i64 = 60 * Self::MINUTE;

    /// Builds a duration from whole seconds.
    pub const fn from_secs(s: i64) -> Self {
        Self(s * Self::SECOND)
    }

    /// Builds a duration from whole minutes.
    pub const fn from_mins(m: i64) -> Self {
        Self(m * Self::MINUTE)
    }

    /// Builds a duration from whole hours.
    pub const fn from_hours(h: i64) -> Self {
        Self(h * Self::HOUR)
    }

    /// Nanoseconds.
    pub const fn as_nanos(self) -> i64 {
        self.0
    }

    /// The duration as a `std::time::Duration` (negative values clamp to zero).
    pub fn to_std(self) -> Duration {
        Duration::from_nanos(u64::try_from(self.0).unwrap_or(0))
    }

    /// Parses Go `time.ParseDuration` syntax.
    pub fn parse(s: &str) -> Result<Self, String> {
        parse_duration(s).map(Self)
    }
}

impl From<Duration> for GoDuration {
    fn from(d: Duration) -> Self {
        Self(i64::try_from(d.as_nanos()).unwrap_or(i64::MAX))
    }
}

impl fmt::Display for GoDuration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&format_duration(self.0))
    }
}

impl<'de> serde::Deserialize<'de> for GoDuration {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        // yaml.v3 decodes a time.Duration only from a string scalar.
        let s = String::deserialize(d)?;
        GoDuration::parse(&s).map_err(serde::de::Error::custom)
    }
}

impl serde::Serialize for GoDuration {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

fn unit_nanos(u: &str) -> Option<u64> {
    Some(match u {
        "ns" => 1,
        "us" | "\u{b5}s" | "\u{3bc}s" => 1_000,
        "ms" => 1_000_000,
        "s" => 1_000_000_000,
        "m" => 60 * 1_000_000_000,
        "h" => 3600 * 1_000_000_000,
        _ => return None,
    })
}

/// Port of Go's `time.ParseDuration`.
fn parse_duration(orig: &str) -> Result<i64, String> {
    let err = || format!("time: invalid duration {orig:?}");
    let mut s = orig;
    let mut neg = false;
    if let Some(c) = s.chars().next()
        && (c == '-' || c == '+')
    {
        neg = c == '-';
        s = &s[1..];
    }
    if s == "0" {
        return Ok(0);
    }
    if s.is_empty() {
        return Err(err());
    }
    let mut total: u64 = 0;
    while !s.is_empty() {
        let b = s.as_bytes();
        if !(b[0] == b'.' || b[0].is_ascii_digit()) {
            return Err(err());
        }
        // Integer part.
        let int_end = b.iter().position(|c| !c.is_ascii_digit()).unwrap_or(b.len());
        let pre = int_end != 0;
        let mut v: u64 = 0;
        for &c in &b[..int_end] {
            v = v
                .checked_mul(10)
                .and_then(|x| x.checked_add(u64::from(c - b'0')))
                .ok_or_else(err)?;
            if v > 1 << 63 {
                return Err(err());
            }
        }
        s = &s[int_end..];
        // Fraction.
        let mut f: u64 = 0;
        let mut scale: f64 = 1.0;
        let mut post = false;
        if s.starts_with('.') {
            s = &s[1..];
            let b = s.as_bytes();
            let end = b.iter().position(|c| !c.is_ascii_digit()).unwrap_or(b.len());
            post = end != 0;
            let mut overflow = false;
            for &c in &b[..end] {
                if overflow {
                    continue;
                }
                if f > (1u64 << 63) / 10 {
                    overflow = true;
                    continue;
                }
                let y = f * 10 + u64::from(c - b'0');
                if y > 1 << 63 {
                    overflow = true;
                    continue;
                }
                f = y;
                scale *= 10.0;
            }
            s = &s[end..];
        }
        if !pre && !post {
            return Err(err());
        }
        let ub = s.as_bytes();
        let uend = ub
            .iter()
            .position(|&c| c == b'.' || c.is_ascii_digit())
            .unwrap_or(ub.len());
        if uend == 0 {
            return Err(format!("time: missing unit in duration {orig:?}"));
        }
        let u = &s[..uend];
        s = &s[uend..];
        let unit = unit_nanos(u).ok_or_else(|| format!("time: unknown unit {u:?} in duration {orig:?}"))?;
        if v > (1u64 << 63) / unit {
            return Err(err());
        }
        v *= unit;
        if f > 0 {
            #[allow(
                clippy::cast_possible_truncation,
                clippy::cast_sign_loss,
                clippy::cast_precision_loss
            )]
            let frac = (f as f64 * (unit as f64 / scale)) as u64;
            v = v.checked_add(frac).ok_or_else(err)?;
            if v > 1 << 63 {
                return Err(err());
            }
        }
        total = total.checked_add(v).ok_or_else(err)?;
        if total > 1 << 63 {
            return Err(err());
        }
    }
    if neg {
        return Ok(0i64.wrapping_sub_unsigned(total));
    }
    if total > (1u64 << 63) - 1 {
        return Err(err());
    }
    i64::try_from(total).map_err(|_| err())
}

/// Port of Go's `time.Duration.String`.
fn format_duration(d: i64) -> String {
    let neg = d < 0;
    let mut u = d.unsigned_abs();
    let mut out = String::new();
    if u < 1_000_000_000 {
        // Sub-second: use the smallest unit with a leading digit.
        let (prec, unit) = if u == 0 {
            return "0s".to_owned();
        } else if u < 1_000 {
            (0, "ns")
        } else if u < 1_000_000 {
            (3, "\u{b5}s")
        } else {
            (6, "ms")
        };
        let s = fmt_frac_int(u, prec);
        if neg {
            out.push('-');
        }
        out.push_str(&s);
        out.push_str(unit);
        return out;
    }
    let mut parts = String::new();
    // Seconds with fraction.
    let secs_frac = fmt_frac_int(u % (60 * 1_000_000_000), 9);
    u /= 60 * 1_000_000_000;
    parts.insert_str(0, &format!("{secs_frac}s"));
    if u > 0 {
        let mins = u % 60;
        u /= 60;
        parts.insert_str(0, &format!("{mins}m"));
        if u > 0 {
            parts.insert_str(0, &format!("{u}h"));
        }
    }
    if neg {
        out.push('-');
    }
    out.push_str(&parts);
    out
}

/// Formats v / 10^prec with trailing fractional zeros (and a bare '.') removed.
fn fmt_frac_int(v: u64, prec: u32) -> String {
    let p = 10u64.pow(prec);
    let int = v / p;
    let frac = v % p;
    if prec == 0 || frac == 0 {
        return int.to_string();
    }
    let mut fs = format!("{frac:0width$}", width = prec as usize);
    while fs.ends_with('0') {
        fs.pop();
    }
    format!("{int}.{fs}")
}

/// Splits a finite float into its shortest decimal digits and decimal-point
/// position (value = 0.d1d2... * 10^dp), like strconv's `decimal`.
fn shortest_digits(v: f64) -> (String, i32) {
    // `{:e}` prints the shortest round-tripping mantissa.
    let s = format!("{:e}", v.abs());
    let (mant, exp) = s.split_once('e').unwrap_or((s.as_str(), "0"));
    let exp: i32 = exp.parse().unwrap_or(0);
    let digits: String = mant.chars().filter(char::is_ascii_digit).collect();
    let digits = digits.trim_end_matches('0');
    let digits = if digits.is_empty() { "0" } else { digits };
    (digits.to_owned(), exp + 1)
}

/// Go `strconv.FormatFloat(v, 'g', -1, 64)` (also `fmt` `%g`/`%v` for float64).
pub fn format_g(v: f64) -> String {
    if v.is_nan() {
        return "NaN".to_owned();
    }
    if v.is_infinite() {
        return if v > 0.0 {
            "+Inf".to_owned()
        } else {
            "-Inf".to_owned()
        };
    }
    if v == 0.0 {
        return if v.is_sign_negative() {
            "-0".to_owned()
        } else {
            "0".to_owned()
        };
    }
    let (digits, dp) = shortest_digits(v);
    let sign = if v < 0.0 { "-" } else { "" };
    let exp = dp - 1;
    // Shortest formatting decides with precision 6 (strconv ftoa.go).
    if !(-4..6).contains(&exp) {
        // %e with the shortest digits.
        let mut m = digits[..1].to_owned();
        if digits.len() > 1 {
            m.push('.');
            m.push_str(&digits[1..]);
        }
        let es = if exp < 0 { '-' } else { '+' };
        let ea = exp.unsigned_abs();
        return format!("{sign}{m}e{es}{ea:02}");
    }
    format!("{sign}{}", plain_decimal(&digits, dp))
}

/// Writes digits with the decimal point at dp, without exponent.
fn plain_decimal(digits: &str, dp: i32) -> String {
    let n = i32::try_from(digits.len()).unwrap_or(i32::MAX);
    if dp <= 0 {
        let zeros = "0".repeat(dp.unsigned_abs() as usize);
        format!("0.{zeros}{digits}")
    } else if dp >= n {
        let zeros = "0".repeat((dp - n) as usize);
        format!("{digits}{zeros}")
    } else {
        let (a, b) = digits.split_at(dp as usize);
        format!("{a}.{b}")
    }
}

/// Go `encoding/json` float64 encoding (used by slog's JSON handler).
pub fn json_float(v: f64) -> String {
    if !v.is_finite() {
        // encoding/json refuses these; slog then prints the error text.
        return format!("\"!ERROR:json: unsupported value: {}\"", format_g(v));
    }
    let abs = v.abs();
    if abs != 0.0 && !(1e-6..1e21).contains(&abs) {
        let (digits, dp) = shortest_digits(v);
        let exp = dp - 1;
        let mut m = digits[..1].to_owned();
        if digits.len() > 1 {
            m.push('.');
            m.push_str(&digits[1..]);
        }
        let sign = if v < 0.0 { "-" } else { "" };
        let es = if exp < 0 { '-' } else { '+' };
        // encoding/json cleans "e-07" to "e-7".
        return format!("{sign}{m}e{es}{}", exp.unsigned_abs());
    }
    if v == 0.0 {
        return "0".to_owned();
    }
    let (digits, dp) = shortest_digits(v);
    let sign = if v < 0.0 { "-" } else { "" };
    format!("{sign}{}", plain_decimal(&digits, dp))
}

/// Serialises `v` the way Go's `json.Encoder` does with its default
/// `SetEscapeHTML(true)`: `<`, `>`, `&`, U+2028 and U+2029 are escaped.
pub fn json_html_escaped<T: serde::Serialize + ?Sized>(v: &T) -> String {
    let s = serde_json::to_string(v).unwrap_or_else(|_| "null".to_owned());
    escape_html_json(&s)
}

/// Applies Go's HTML escaping to already-encoded JSON (these characters only
/// ever occur inside string literals).
pub fn escape_html_json(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '<' => out.push_str("\\u003c"),
            '>' => out.push_str("\\u003e"),
            '&' => out.push_str("\\u0026"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_go_durations() {
        let ok = [
            ("0", 0),
            ("5s", 5 * GoDuration::SECOND),
            ("30s", 30 * GoDuration::SECOND),
            ("1.5s", 1_500_000_000),
            ("-1.5h", -(90 * GoDuration::MINUTE)),
            ("1h15m30.918273645s", 4_530_918_273_645),
            ("100ms", 100 * GoDuration::MILLISECOND),
            ("10us", 10_000),
            ("10\u{b5}s", 10_000),
            ("3ns", 3),
            (".5m", 30 * GoDuration::SECOND),
            ("+5m", 5 * GoDuration::MINUTE),
            ("9223372036854775807ns", i64::MAX),
            ("-9223372036854775808ns", i64::MIN),
        ];
        for (s, want) in ok {
            assert_eq!(GoDuration::parse(s), Ok(GoDuration(want)), "{s}");
        }
        for bad in [
            "",
            "3",
            "-",
            "s",
            ".s",
            "1d",
            "3000000h",
            "9223372036854775808ns",
            "1.s.5",
        ] {
            let r = GoDuration::parse(bad);
            assert!(r.is_err(), "{bad}: {r:?}");
        }
    }

    #[test]
    fn format_go_durations() {
        let cases = [
            (0, "0s"),
            (1, "1ns"),
            (1100, "1.1\u{b5}s"),
            (2_200_000, "2.2ms"),
            (3_300_000_000, "3.3s"),
            (4 * GoDuration::MINUTE + 5 * GoDuration::SECOND, "4m5s"),
            (4 * GoDuration::MINUTE + 5_001_000_000, "4m5.001s"),
            (
                5 * GoDuration::HOUR + 6 * GoDuration::MINUTE + 7_001_000_000,
                "5h6m7.001s",
            ),
            (8 * GoDuration::MINUTE + 1, "8m0.000000001s"),
            (5 * GoDuration::MINUTE, "5m0s"),
            (GoDuration::HOUR, "1h0m0s"),
            (30 * GoDuration::SECOND, "30s"),
            (-GoDuration::SECOND, "-1s"),
            (i64::MAX, "2562047h47m16.854775807s"),
            (i64::MIN, "-2562047h47m16.854775808s"),
        ];
        for (d, want) in cases {
            assert_eq!(GoDuration(d).to_string(), want);
        }
    }

    #[test]
    fn format_g_matches_go() {
        let cases = [
            (0.001, "0.001"),
            (0.0025, "0.0025"),
            (1.0, "1"),
            (2.5, "2.5"),
            (10.0, "10"),
            (123_456.0, "123456"),
            (1_000_000.0, "1e+06"),
            (1_234_567.0, "1.234567e+06"),
            (0.0001, "0.0001"),
            (0.00001, "1e-05"),
            (1.5e-7, "1.5e-07"),
            (-2.0, "-2"),
            (f64::INFINITY, "+Inf"),
        ];
        for (v, want) in cases {
            assert_eq!(format_g(v), want, "{v}");
        }
    }

    #[test]
    fn json_float_matches_encoding_json() {
        let cases = [
            (1.5, "1.5"),
            (0.123456, "0.123456"),
            (100.0, "100"),
            (1.5e-7, "1.5e-7"),
            (1e21, "1e+21"),
            (0.0, "0"),
        ];
        for (v, want) in cases {
            assert_eq!(json_float(v), want, "{v}");
        }
    }

    #[test]
    fn html_escaping() {
        assert_eq!(json_html_escaped("<a&b>"), "\"\\u003ca\\u0026b\\u003e\"");
    }
}
