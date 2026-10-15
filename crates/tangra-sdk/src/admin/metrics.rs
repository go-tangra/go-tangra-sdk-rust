//! The framework instruments rendered in Prometheus text format exactly as
//! go-tangra `observe/metrics.go` renders its OpenTelemetry instruments:
//! `freya_up`, then (in creation order, only once they have data)
//! `freya_calls_total`, `freya_authn_refusals_total`,
//! `freya_authz_refusals_total`, `freya_identity_renewals_total`,
//! `freya_audit_dropped_total` and the `freya_call_duration_seconds`
//! histogram. A module may add its own counters next to them.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::{Arc, Mutex};

use crate::gofmt::format_g;

/// Histogram bucket bounds of `freya.call.duration` (seconds).
pub const DURATION_BOUNDS: [f64; 13] = [
    0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

const CALLS: usize = 0;
const AUTHN: usize = 1;
const AUTHZ: usize = 2;
const RENEWALS: usize = 3;
const DROPPED: usize = 4;
const DURATION: usize = 5;

type Labels = Vec<(String, String)>;

#[derive(Debug)]
enum Data {
    Sum(BTreeMap<Labels, i64>),
    Hist(BTreeMap<Labels, Hist>),
}

#[derive(Debug, Default, Clone)]
struct Hist {
    buckets: Vec<u64>,
    sum: f64,
    count: u64,
}

#[derive(Debug)]
struct Family {
    name: String,
    help: String,
    data: Data,
}

/// The instrument registry served on the admin `/metrics` endpoint.
#[derive(Debug)]
pub struct Metrics {
    families: Mutex<Vec<Family>>,
}

/// A monotonic counter registered by a module (rendered as `<name>_total`).
#[derive(Debug, Clone)]
pub struct Counter {
    m: Arc<Metrics>,
    idx: usize,
}

impl Counter {
    /// Adds `n` to the series identified by `labels`.
    pub fn add(&self, labels: &[(&str, &str)], n: i64) {
        self.m.add(self.idx, labels, n);
    }
}

fn labels(l: &[(&str, &str)]) -> Labels {
    let mut v: Labels = l
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect();
    v.sort();
    v
}

fn prom_name(n: &str) -> String {
    n.replace(['.', '-', '/'], "_")
}

fn sanitize(v: &str) -> String {
    v.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n")
}

/// `{k="v",...}` with the parts sorted as strings (go-tangra `labelsWith`).
fn render_labels(l: &Labels, extra: Option<(&str, &str)>) -> String {
    let mut parts: Vec<String> = l
        .iter()
        .map(|(k, v)| format!("{k}=\"{}\"", sanitize(v)))
        .collect();
    if let Some((k, v)) = extra {
        parts.push(format!("{k}=\"{v}\""));
    }
    if parts.is_empty() {
        return String::new();
    }
    parts.sort();
    format!("{{{}}}", parts.join(","))
}

impl Metrics {
    /// The registry with the framework instruments.
    pub fn new() -> Arc<Self> {
        let sum = |name: &str, help: &str| Family {
            name: name.to_owned(),
            help: help.to_owned(),
            data: Data::Sum(BTreeMap::new()),
        };
        Arc::new(Self {
            families: Mutex::new(vec![
                sum("freya.calls", "Calls handled, by peer and outcome"),
                sum("freya.authn.refusals", "Authentication refusals by reason"),
                sum(
                    "freya.authz.refusals",
                    "Authorization refusals by peer and operation",
                ),
                sum("freya.identity.renewals", "Identity renewals by outcome"),
                sum(
                    "freya.audit.dropped",
                    "Audit events dropped because the queue was full",
                ),
                Family {
                    name: "freya.call.duration".to_owned(),
                    help: String::new(),
                    data: Data::Hist(BTreeMap::new()),
                },
            ]),
        })
    }

    /// Registers a module counter (name in OpenTelemetry dotted form).
    pub fn counter(self: &Arc<Self>, name: &str, help: &str) -> Counter {
        let idx = self
            .families
            .lock()
            .map(|mut f| {
                f.push(Family {
                    name: name.to_owned(),
                    help: help.to_owned(),
                    data: Data::Sum(BTreeMap::new()),
                });
                f.len() - 1
            })
            .unwrap_or(usize::MAX);
        Counter {
            m: Arc::clone(self),
            idx,
        }
    }

    fn add(&self, idx: usize, l: &[(&str, &str)], n: i64) {
        if let Ok(mut f) = self.families.lock()
            && let Some(Family {
                data: Data::Sum(m), ..
            }) = f.get_mut(idx)
        {
            *m.entry(labels(l)).or_insert(0) += n;
        }
    }

    fn observe(&self, idx: usize, l: &[(&str, &str)], v: f64) {
        if let Ok(mut f) = self.families.lock()
            && let Some(Family {
                data: Data::Hist(m), ..
            }) = f.get_mut(idx)
        {
            let h = m.entry(labels(l)).or_insert_with(|| Hist {
                buckets: vec![0; DURATION_BOUNDS.len() + 1],
                ..Hist::default()
            });
            let i = DURATION_BOUNDS
                .iter()
                .position(|b| v <= *b)
                .unwrap_or(DURATION_BOUNDS.len());
            h.buckets[i] += 1;
            h.sum += v;
            h.count += 1;
        }
    }

    /// Records one call (go-tangra `observe.Instrument`).
    pub(crate) fn record_call(&self, peer: &str, outcome: &str, seconds: f64, reason: &str, operation: &str) {
        let pl = [("peer", peer), ("outcome", outcome)];
        self.add(CALLS, &pl, 1);
        self.observe(DURATION, &pl, seconds);
        match outcome {
            "authn_refused" => self.add(AUTHN, &[("reason", reason)], 1),
            "authz_refused" => self.add(AUTHZ, &[("peer", peer), ("operation", operation)], 1),
            _ => {}
        }
    }

    /// Records a renewal outcome (`ok` or `failed`).
    pub fn identity_renewal(&self, outcome: &str) {
        self.add(RENEWALS, &[("outcome", outcome)], 1);
    }

    /// Adds to the dropped-audit counter.
    pub fn audit_dropped(&self, n: i64) {
        self.add(DROPPED, &[], n);
    }

    /// Prometheus text (`text/plain; version=0.0.4`).
    pub fn render(&self) -> String {
        let mut sb = String::from(
            "# HELP freya_up Always 1 while the admin listener serves.\n# TYPE freya_up gauge\nfreya_up 1\n",
        );
        let Ok(fams) = self.families.lock() else {
            return sb;
        };
        for f in fams.iter() {
            let name = prom_name(&f.name);
            match &f.data {
                Data::Sum(m) if !m.is_empty() => {
                    let name = format!("{name}_total");
                    let _ = write!(sb, "# HELP {name} {}\n# TYPE {name} counter\n", f.help);
                    let mut pts: Vec<(String, i64)> =
                        m.iter().map(|(l, v)| (render_labels(l, None), *v)).collect();
                    pts.sort();
                    for (l, v) in pts {
                        let _ = writeln!(sb, "{name}{l} {v}");
                    }
                }
                Data::Hist(m) if !m.is_empty() => {
                    let name = format!("{name}_seconds");
                    let _ = write!(sb, "# HELP {name} {}\n# TYPE {name} histogram\n", f.help);
                    for (l, h) in m {
                        let mut cum = 0u64;
                        for (i, b) in DURATION_BOUNDS.iter().enumerate() {
                            cum += h.buckets[i];
                            let _ = writeln!(
                                sb,
                                "{name}_bucket{} {cum}",
                                render_labels(l, Some(("le", &format_g(*b))))
                            );
                        }
                        cum += h.buckets[DURATION_BOUNDS.len()];
                        let _ = writeln!(
                            sb,
                            "{name}_bucket{} {cum}",
                            render_labels(l, Some(("le", "+Inf")))
                        );
                        let ls = render_labels(l, None);
                        let _ = write!(
                            sb,
                            "{name}_sum{ls} {}\n{name}_count{ls} {}\n",
                            format_g(h.sum),
                            h.count
                        );
                    }
                }
                _ => {}
            }
        }
        sb
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_like_go() {
        let m = Metrics::new();
        assert_eq!(
            m.render(),
            "# HELP freya_up Always 1 while the admin listener serves.\n# TYPE freya_up gauge\nfreya_up 1\n"
        );
        m.record_call("gateway", "ok", 0.002, "", "/x");
        m.record_call("gateway", "ok", 0.5, "", "/x");
        m.record_call("unknown", "authn_refused", 0.0001, "no_identity", "/x");
        m.record_call("web", "authz_refused", 0.0001, "", "GET /a\"b");
        m.identity_renewal("ok");
        let c = m.counter("orders.created", "Orders created");
        c.add(&[("tenant", "t1")], 2);
        let out = m.render();
        let want_prefix = "# HELP freya_up Always 1 while the admin listener serves.\n# TYPE freya_up gauge\nfreya_up 1\n\
# HELP freya_calls_total Calls handled, by peer and outcome\n# TYPE freya_calls_total counter\n\
freya_calls_total{outcome=\"authn_refused\",peer=\"unknown\"} 1\n\
freya_calls_total{outcome=\"authz_refused\",peer=\"web\"} 1\n\
freya_calls_total{outcome=\"ok\",peer=\"gateway\"} 2\n\
# HELP freya_authn_refusals_total Authentication refusals by reason\n# TYPE freya_authn_refusals_total counter\n\
freya_authn_refusals_total{reason=\"no_identity\"} 1\n\
# HELP freya_authz_refusals_total Authorization refusals by peer and operation\n# TYPE freya_authz_refusals_total counter\n\
freya_authz_refusals_total{operation=\"GET /a\\\"b\",peer=\"web\"} 1\n\
# HELP freya_identity_renewals_total Identity renewals by outcome\n# TYPE freya_identity_renewals_total counter\n\
freya_identity_renewals_total{outcome=\"ok\"} 1\n\
# HELP freya_call_duration_seconds \n# TYPE freya_call_duration_seconds histogram\n";
        assert!(out.starts_with(want_prefix), "{out}");
        assert!(out.contains(
            "freya_call_duration_seconds_bucket{le=\"0.0025\",outcome=\"ok\",peer=\"gateway\"} 1\n"
        ));
        assert!(
            out.contains(
                "freya_call_duration_seconds_bucket{le=\"+Inf\",outcome=\"ok\",peer=\"gateway\"} 2\n"
            )
        );
        assert!(out.contains("freya_call_duration_seconds_sum{outcome=\"ok\",peer=\"gateway\"} 0.502\n"));
        assert!(out.contains("freya_call_duration_seconds_count{outcome=\"ok\",peer=\"gateway\"} 2\n"));
        assert!(out.ends_with(
            "# HELP orders_created_total Orders created\n# TYPE orders_created_total counter\norders_created_total{tenant=\"t1\"} 2\n"
        ));
    }
}
