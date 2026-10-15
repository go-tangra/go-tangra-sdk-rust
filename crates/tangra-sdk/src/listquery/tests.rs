//! Mirrors go-tangra `listquery/*_test.go`.

use super::*;
use std::time::Duration;

fn host_spec() -> Spec {
    let mut fields = BTreeMap::new();
    fields.insert(
        "hostname",
        Field {
            expr: "h.hostname",
            text: true,
            ..Field::default()
        },
    );
    fields.insert(
        "last_seen",
        Field {
            expr: "h.last_seen",
            default_dir: Some(Dir::Desc),
            ..Field::default()
        },
    );
    fields.insert(
        "size",
        Field {
            expr: "h.size",
            default_dir: Some(Dir::Asc),
            ..Field::default()
        },
    );
    fields.insert(
        "created",
        Field {
            expr: "h.created_at",
            default_dir: Some(Dir::Desc),
            not_null: true,
            ..Field::default()
        },
    );
    fields.insert(
        "name",
        Field {
            expr: "h.name",
            text: true,
            not_null: true,
            ..Field::default()
        },
    );
    Spec {
        fields,
        default: "hostname",
        tie_break: "h.id",
        ..Spec::default()
    }
}

fn q(kv: &[(&'static str, &'static str)]) -> Query {
    Query::from_pairs(kv.iter().copied())
}

fn req(page: i64, size: i64, sort: &str, order: Dir) -> Request {
    Request {
        page,
        page_size: size,
        sort: sort.to_owned(),
        order,
    }
}

#[test]
fn parse_defaults() {
    let r = parse(&Query::default(), &host_spec()).expect("defaults");
    assert_eq!(r, req(1, DEFAULT_PAGE_SIZE, "hostname", Dir::Asc));
}

#[test]
fn parse_valid() {
    let cases = [
        (
            q(&[
                ("page", "3"),
                ("page_size", "50"),
                ("sort", "last_seen"),
                ("order", "asc"),
            ]),
            req(3, 50, "last_seen", Dir::Asc),
        ),
        (q(&[("sort", "last_seen")]), req(1, 25, "last_seen", Dir::Desc)),
        (q(&[("sort", "size")]), req(1, 25, "size", Dir::Asc)),
        (
            q(&[("sort", "hostname"), ("order", "desc")]),
            req(1, 25, "hostname", Dir::Desc),
        ),
        (q(&[("page_size", "200")]), req(1, 200, "hostname", Dir::Asc)),
        (
            q(&[("page_size", "1"), ("page", "2147483647")]),
            req(2_147_483_647, 1, "hostname", Dir::Asc),
        ),
        (q(&[("order", "desc")]), req(1, 25, "hostname", Dir::Desc)),
    ];
    for (query, want) in cases {
        assert_eq!(parse(&query, &host_spec()), Ok(want), "{query:?}");
    }
}

#[test]
fn parse_invalid() {
    let mut small = host_spec();
    small.max_size = 50;
    let hs = host_spec();
    let cases: Vec<(Query, &Spec, &str)> = vec![
        (q(&[("page", "0")]), &hs, "page"),
        (q(&[("page", "-1")]), &hs, "page"),
        (q(&[("page", "abc")]), &hs, "page"),
        (q(&[("page", "")]), &hs, "page"),
        (q(&[("page", "2147483648")]), &hs, "page"),
        (q(&[("page_size", "0")]), &hs, "page_size"),
        (q(&[("page_size", "201")]), &hs, "page_size"),
        (q(&[("page_size", "abc")]), &hs, "page_size"),
        (q(&[("page_size", "51")]), &small, "page_size"),
        (q(&[("sort", "bogus")]), &hs, "sort"),
        (q(&[("sort", "")]), &hs, "sort"),
        (q(&[("sort", "hostname;drop table x")]), &hs, "sort"),
        (q(&[("order", "up")]), &hs, "order"),
        (q(&[("order", "DESC")]), &hs, "order"),
        (q(&[("cursor", "x"), ("page", "2")]), &hs, "cursor"),
        (q(&[("limit", "10"), ("sort", "hostname")]), &hs, "cursor"),
    ];
    for (query, spec, param) in cases {
        let e = parse(&query, spec).expect_err("must fail");
        assert_eq!(e.param, param, "{query:?}");
        assert_eq!(e.to_string(), format!("listquery: invalid {param}"));
    }
}

#[test]
fn parse_raw_query_strings() {
    let r = parse(
        &Query::parse("page=2&page_size=10&sort=last%5Fseen&x=1"),
        &host_spec(),
    )
    .expect("ok");
    assert_eq!(r, req(2, 10, "last_seen", Dir::Desc));
    // url.Values.Get returns the first value.
    let r = parse(&Query::parse("page=3&page=9"), &host_spec()).expect("ok");
    assert_eq!(r.page, 3);
    assert_eq!(
        parse(&Query::parse("page"), &host_spec()).map_err(|e| e.param),
        Err("page")
    );
}

#[test]
fn legacy_detection() {
    let cases = [
        (Query::default(), false),
        (q(&[("cursor", "abc")]), true),
        (q(&[("limit", "10")]), true),
        (
            q(&[("cursor", "abc"), ("limit", "10"), ("status", "active")]),
            true,
        ),
        (q(&[("cursor", "abc"), ("page", "1")]), false),
        (q(&[("limit", "10"), ("order", "asc")]), false),
        (q(&[("page", "1")]), false),
    ];
    for (query, want) in cases {
        assert_eq!(legacy(&query), want, "{query:?}");
    }
}

#[test]
fn new_requests() {
    let hs = host_spec();
    assert_eq!(new(0, 0, "", None, &hs), Ok(req(1, 25, "hostname", Dir::Asc)));
    assert_eq!(
        new(4, 10, "last_seen", None, &hs),
        Ok(req(4, 10, "last_seen", Dir::Desc))
    );
    for (page, size, sort, param) in [
        (-1, 0, "", "page"),
        (0, -1, "", "page_size"),
        (0, 201, "", "page_size"),
        (0, 0, "nope", "sort"),
    ] {
        assert_eq!(new(page, size, sort, None, &hs).map_err(|e| e.param), Err(param));
    }
}

#[test]
fn spec_validate() {
    assert_eq!(host_spec().validate(), Ok(()));
    let one = |expr: &'static str| {
        let mut f = BTreeMap::new();
        f.insert(
            "a",
            Field {
                expr,
                ..Field::default()
            },
        );
        f
    };
    let bad = [
        Spec {
            default: "a",
            tie_break: "id",
            ..Spec::default()
        },
        Spec {
            fields: one("a"),
            default: "b",
            tie_break: "id",
            ..Spec::default()
        },
        Spec {
            fields: one("a"),
            default: "a",
            ..Spec::default()
        },
        Spec {
            fields: one(""),
            default: "a",
            tie_break: "id",
            ..Spec::default()
        },
        Spec {
            fields: one("a"),
            default: "a",
            tie_break: "id",
            max_size: 201,
            ..Spec::default()
        },
        Spec {
            fields: one("a"),
            default: "a",
            tie_break: "id",
            max_size: -1,
            ..Spec::default()
        },
        Spec {
            fields: one("a"),
            default: "a",
            tie_break: "id",
            max_size: 10,
            default_size: 20,
        },
        Spec {
            fields: one("a"),
            default: "a",
            tie_break: "id",
            default_size: -1,
            ..Spec::default()
        },
    ];
    for s in bad {
        assert!(s.validate().is_err(), "{s:?}");
    }
    let ok = Spec {
        fields: one("a"),
        default: "a",
        tie_break: "id",
        max_size: 50,
        default_size: 50,
    };
    assert_eq!(ok.validate(), Ok(()));
    assert_eq!((ok.default_page_size(), ok.max()), (50, 50));
    let capped = Spec {
        fields: one("a"),
        default: "a",
        tie_break: "id",
        max_size: 10,
        ..Spec::default()
    };
    assert_eq!(capped.default_page_size(), 10);
}

#[test]
fn new_page_shape() {
    let r = req(2, 10, "hostname", Dir::Desc);
    let p: Page<String> = Page::new(Vec::new(), 12, &r);
    assert_eq!(
        serde_json::to_string(&p).expect("json"),
        r#"{"items":[],"total":12,"page":2,"page_size":10,"sort":"hostname","order":"desc"}"#
    );
    assert_eq!(Page::new(vec![1, 2], 2, &r).items.len(), 2);
}

#[test]
fn order_by() {
    let hs = host_spec();
    let cases = [
        (
            req(1, 25, "hostname", Dir::Asc),
            "lower(h.hostname) ASC NULLS LAST, h.id ASC",
        ),
        (
            req(1, 25, "hostname", Dir::Desc),
            "lower(h.hostname) DESC NULLS LAST, h.id DESC",
        ),
        (
            req(1, 25, "last_seen", Dir::Desc),
            "h.last_seen DESC NULLS LAST, h.id DESC",
        ),
        (req(1, 25, "size", Dir::Asc), "h.size ASC NULLS LAST, h.id ASC"),
        (req(1, 25, "created", Dir::Desc), "h.created_at DESC, h.id DESC"),
        (req(1, 25, "created", Dir::Asc), "h.created_at ASC, h.id ASC"),
        (req(1, 25, "name", Dir::Desc), "lower(h.name) DESC, h.id DESC"),
        (req(1, 25, "name", Dir::Asc), "lower(h.name) ASC, h.id ASC"),
        (
            req(1, 25, "x; drop", Dir::Asc),
            "lower(h.hostname) ASC NULLS LAST, h.id ASC",
        ),
    ];
    for (r, want) in cases {
        assert_eq!(r.order_by(&hs), want, "{r:?}");
    }
}

#[test]
fn limit_offset() {
    let r = req(3, 50, "", Dir::Asc);
    assert_eq!((r.limit(), r.offset()), (50, 100));
    assert_eq!(req(0, 10, "", Dir::Asc).offset(), 0);
}

#[test]
fn clamp() {
    for (page, size, total, want) in [
        (1, 50, 1234, 1),
        (25, 50, 1234, 25),
        (26, 50, 1234, 25),
        (999, 50, 1234, 25),
        (3, 50, 100, 2),
        (2, 50, 100, 2),
        (5, 25, 0, 1),
        (4, 0, 10, 4),
    ] {
        assert_eq!(
            req(page, size, "", Dir::Asc).clamp(total).page,
            want,
            "{page} {size} {total}"
        );
    }
}

#[derive(Debug, Clone)]
struct Row {
    id: &'static str,
    name: SortKey,
    n: SortKey,
    when: SortKey,
    ratio: SortKey,
    other: SortKey,
}

impl Row {
    fn new(id: &'static str) -> Self {
        Self {
            id,
            name: SortKey::Null,
            n: SortKey::Null,
            when: SortKey::Null,
            ratio: SortKey::Null,
            other: SortKey::Null,
        }
    }
}

fn row_key(r: &Row, f: &str) -> SortKey {
    match f {
        "name" => r.name.clone(),
        "n" => r.n.clone(),
        "when" => r.when.clone(),
        "ratio" => r.ratio.clone(),
        _ => r.other.clone(),
    }
}

fn ids(rs: &[Row]) -> String {
    rs.iter().map(|r| r.id).collect()
}

fn sort(rs: &mut [Row], field: &str, order: Dir) {
    sort_slice(rs, &req(1, 1, field, order), row_key, |r| r.id.to_owned());
}

#[test]
fn sort_slice_strings() {
    let mk = |id, name: Option<&str>| Row {
        name: name.map_or(SortKey::Null, |s| SortKey::Str(s.to_owned())),
        ..Row::new(id)
    };
    let mut rs = vec![
        mk("a", Some("beta")),
        mk("b", Some("Alpha")),
        mk("c", None),
        mk("d", Some("alpha")),
    ];
    sort(&mut rs, "name", Dir::Asc);
    assert_eq!(ids(&rs), "bdac");
    sort(&mut rs, "name", Dir::Desc);
    assert_eq!(ids(&rs), "adbc");
}

#[test]
fn sort_slice_numbers_and_times() {
    let t0 = SystemTime::UNIX_EPOCH + Duration::from_secs(1_767_225_600);
    let h = Duration::from_secs(3600);
    let mut rs = vec![
        Row {
            n: SortKey::Int(3),
            when: SortKey::Time(t0 + h),
            ratio: SortKey::Float(0.5),
            ..Row::new("a")
        },
        Row {
            n: SortKey::Int(1),
            when: SortKey::Time(t0),
            ratio: SortKey::Float(1.5),
            ..Row::new("b")
        },
        Row::new("c"),
        Row {
            n: SortKey::Int(1),
            when: SortKey::Time(t0 + 2 * h),
            ratio: SortKey::Float(0.25),
            ..Row::new("d")
        },
    ];
    sort(&mut rs, "n", Dir::Asc);
    assert_eq!(ids(&rs), "bdac");
    sort(&mut rs, "when", Dir::Desc);
    assert_eq!(ids(&rs), "dabc");
    sort(&mut rs, "ratio", Dir::Asc);
    assert_eq!(ids(&rs), "dabc");
}

#[test]
fn sort_slice_ints_and_mixed() {
    let mut rs = vec![
        Row {
            other: SortKey::Int(2),
            ..Row::new("a")
        },
        Row {
            other: SortKey::Int(1),
            ..Row::new("b")
        },
        Row {
            other: SortKey::Int(2),
            ..Row::new("c")
        },
    ];
    sort(&mut rs, "other", Dir::Desc);
    assert_eq!(ids(&rs), "cab");
    let mut mixed = vec![
        Row {
            other: SortKey::Bool(true),
            ..Row::new("a")
        },
        Row {
            other: SortKey::Str("abc".into()),
            ..Row::new("b")
        },
        Row {
            other: SortKey::Int(7),
            ..Row::new("c")
        },
    ];
    sort(&mut mixed, "other", Dir::Asc);
    assert_eq!(ids(&mixed), "cba");
}

#[test]
fn sort_slice_not_null_matches_order_by() {
    let t0 = SystemTime::UNIX_EPOCH + Duration::from_secs(1_767_225_600);
    let h = Duration::from_secs(3600);
    let rows = || {
        vec![
            Row {
                when: SortKey::Time(t0),
                ..Row::new("b")
            },
            Row {
                when: SortKey::Time(t0),
                ..Row::new("a")
            },
            Row {
                when: SortKey::Time(t0 + h),
                ..Row::new("c")
            },
            Row {
                when: SortKey::Time(t0 - h),
                ..Row::new("d")
            },
        ]
    };
    let mut desc = rows();
    sort(&mut desc, "when", Dir::Desc);
    assert_eq!(ids(&desc), "cbad");
    let mut asc = rows();
    sort(&mut asc, "when", Dir::Asc);
    assert_eq!(ids(&asc), "dabc");
}

#[test]
fn window_pages() {
    let rs: Vec<i64> = (1..=1234).collect();
    let (page, total, applied) = window(&rs, &req(999, 50, "", Dir::Asc));
    assert_eq!((total, applied.page, page.len(), page[0]), (1234, 25, 34, 1201));
    for size in [1, 7, 25, 200] {
        let mut seen = vec![0u32; rs.len() + 1];
        let mut p = 1;
        loop {
            let (pg, _, a) = window(&rs, &req(p, size, "", Dir::Asc));
            if a.page != p {
                break;
            }
            for v in pg {
                seen[usize::try_from(*v).unwrap_or(0)] += 1;
            }
            p += 1;
        }
        assert!(seen[1..].iter().all(|c| *c == 1), "size {size}");
    }
    let empty: Vec<i64> = Vec::new();
    let (pg, total, applied) = window(&empty, &req(3, 10, "", Dir::Asc));
    assert_eq!((pg.len(), total, applied.page), (0, 0, 1));
    let letters = ["a", "b", "c", "d", "e"];
    let (pg, total, applied) = window(&letters, &req(2, 2, "", Dir::Asc));
    assert_eq!((pg, total, applied.page), (&["c", "d"][..], 5, 2));
}

/// No input can make `order_by` emit anything but the spec's constants, and
/// errors only ever name a known parameter (the Go fuzz property, sampled).
#[test]
fn parse_never_leaks_request_text() {
    let hs = host_spec();
    let mut allowed = std::collections::HashSet::new();
    for name in hs.fields.keys() {
        for d in [Dir::Asc, Dir::Desc] {
            allowed.insert(req(1, 1, name, d).order_by(&hs));
        }
    }
    let samples = [
        "1",
        "25",
        "hostname",
        "asc",
        "0",
        "201",
        "bogus",
        "up",
        "",
        "hostname;drop table h",
        "desc, (select 1)",
        "99999999999",
        "-5",
        "last_seen",
        "DESC",
        "+3",
        "1e3",
    ];
    for page in samples {
        for size in samples {
            for sort in samples {
                for order in ["", "asc", "desc", "x"] {
                    let mut pairs = vec![];
                    for (k, v) in [
                        ("page", page),
                        ("page_size", size),
                        ("sort", sort),
                        ("order", order),
                    ] {
                        if !v.is_empty() {
                            pairs.push((k, v));
                        }
                    }
                    match parse(&Query::from_pairs(pairs), &hs) {
                        Ok(r) => {
                            assert!(allowed.contains(&r.order_by(&hs)));
                            assert!(
                                r.page >= 1 && (1..=MAX_PAGE_SIZE).contains(&r.page_size) && r.offset() >= 0
                            );
                        }
                        Err(e) => {
                            assert!(["page", "page_size", "sort", "order", "cursor"].contains(&e.param))
                        }
                    }
                }
            }
        }
    }
}
