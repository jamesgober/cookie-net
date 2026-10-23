//! The client side: what the server side writes, the client side reads the
//! same way; the jar's headers read back through the server parser; user
//! agent behaviour as data; bounded memory under a stream of cookies.

#![cfg(feature = "jar")]

use cookie_net::{
    self as cookie, IgnoreReason, Jar, JarLimits, Limits, RequestContext, RequestUrl, SameSite,
    SameSiteAttr, SetCookie, StoreOutcome, ValueMode, parse_set_cookie,
};
use proptest::prelude::*;

const NOW: u64 = 1_800_000_000;

fn text(c: &SetCookie<'_>) -> String {
    let mut buf = vec![0u8; c.encoded_len()];
    String::from(c.encode_into(&mut buf).unwrap())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1024))]

    /// Every cookie the builder accepts reads back with the same attributes.
    #[test]
    fn prop_set_cookie_round_trips_through_the_client_parser(
        name in "[A-Za-z0-9_.-]{1,10}",
        value in "[!#-+\\--:<-\\[\\]-~]{0,30}",
        path in proptest::option::of("/[a-z/]{0,8}"),
        domain in proptest::option::of("[a-z]{1,8}\\.(com|org)"),
        max_age in proptest::option::of(1u64..=34_560_000),
        expires in proptest::option::of(0u64..30_000_000),
        flags in any::<u8>(),
    ) {
        let mut b = SetCookie::builder(&name, &value);
        if let Some(p) = &path { b = b.path(p); }
        if let Some(d) = &domain { b = b.domain(d); }
        if let Some(m) = max_age { b = b.max_age(m); }
        if let Some(e) = expires { b = b.expires(NOW + e, NOW); }
        if flags & 1 != 0 { b = b.insecure(); }
        if flags & 2 != 0 { b = b.script_readable(); }
        if flags & 4 != 0 { b = b.partitioned(); }
        b = b.same_site(match flags >> 6 { 0 => SameSite::Lax, 1 => SameSite::Strict, _ => SameSite::None });
        if flags & 8 != 0 { b = b.delete(); }
        let Ok(c) = b.build() else { return Ok(()) };
        let line = text(&c);
        let v = parse_set_cookie(&line).unwrap();
        prop_assert_eq!(v.name, c.name().as_bytes());
        prop_assert_eq!(v.value, c.value().as_bytes());
        prop_assert_eq!(v.path, Some(c.path().as_bytes()));
        prop_assert_eq!(v.domain, c.domain().map(str::as_bytes));
        prop_assert_eq!(v.max_age, c.max_age().map(|m| i64::try_from(m).unwrap()));
        prop_assert_eq!(v.expires, c.expires().map(|e| i64::try_from(e).unwrap()));
        prop_assert_eq!((v.secure, v.http_only, v.partitioned), (c.is_secure(), c.is_http_only(), c.is_partitioned()));
        let same_site = match c.same_site() { SameSite::Strict => SameSiteAttr::Strict, SameSite::Lax => SameSiteAttr::Lax, _ => SameSiteAttr::None };
        prop_assert_eq!(v.same_site, same_site);
    }

    /// Whatever the jar stores, the Cookie header it writes reads back, pair
    /// for pair, through the server parser.
    #[test]
    fn prop_jar_header_reads_back(
        cookies in proptest::collection::vec(("[A-Za-z0-9_]{1,8}", "[A-Za-z0-9_=-]{0,12}", "(/|/a|/a/b)"), 0..20),
    ) {
        let mut jar = Jar::new();
        let url = RequestUrl::https("example.com", "/a/b/c");
        for (n, v, p) in &cookies {
            jar.store(&url, &format!("{n}={v}; Path={p}"), NOW);
        }
        let header = jar.cookie_header(&url, NOW).unwrap_or_default();
        let read: Vec<(String, String)> = cookie::parse(&header).iter().map(|p| (p.name().to_string(), p.value().to_string())).collect();
        let stored: Vec<(String, String)> = jar.cookies().map(|c| (String::from_utf8(c.name.clone()).unwrap(), String::from_utf8(c.value.clone()).unwrap())).collect();
        prop_assert_eq!(read.len(), stored.len());
        for pair in &read {
            prop_assert!(stored.contains(pair));
        }
    }

    /// Any line, any order: the jar keeps its bounds and never panics.
    #[test]
    fn prop_jar_bounded(lines in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..80), 0..60)) {
        let mut jar = Jar::new().with_limits(JarLimits::DEFAULT.per_domain(4).total(10));
        for (i, l) in lines.iter().enumerate() {
            let host = ["a.example", "b.example", "c.example"][i % 3];
            jar.store(&RequestUrl::new(i % 2 == 0, host, "/"), l, NOW + i as u64);
            prop_assert!(jar.len() <= 10);
            let _ = jar.cookie_header(&RequestUrl::https(host, "/"), NOW + i as u64);
        }
    }
}

/// User-agent behaviour as data, in the style of the web-platform-tests
/// `cookies/` suite: the line set from `url`, then the `Cookie` header the
/// same origin gets back.
#[test]
fn test_user_agent_behaviour_cases() {
    struct Case {
        line: &'static str,
        secure_origin: bool,
        expect: Option<&'static str>,
    }
    let cases = [
        Case {
            line: "a=b",
            secure_origin: true,
            expect: Some("a=b"),
        },
        Case {
            line: "a=b; Path=/",
            secure_origin: false,
            expect: Some("a=b"),
        },
        Case {
            line: "  a  =  b  ",
            secure_origin: true,
            expect: Some("a=b"),
        },
        Case {
            line: "a=\"b\"",
            secure_origin: true,
            expect: Some("a=\"b\""),
        },
        Case {
            line: "a=b=c",
            secure_origin: true,
            expect: Some("a=b=c"),
        },
        Case {
            line: "nameless",
            secure_origin: true,
            expect: Some("nameless"),
        },
        Case {
            line: "=nameless",
            secure_origin: true,
            expect: Some("nameless"),
        },
        Case {
            line: "=",
            secure_origin: true,
            expect: None,
        },
        Case {
            line: "a=b\x07",
            secure_origin: true,
            expect: None,
        },
        Case {
            line: "a=b\tc",
            secure_origin: true,
            expect: Some("a=b\tc"),
        },
        Case {
            line: "a=b; Secure",
            secure_origin: false,
            expect: None,
        },
        Case {
            line: "a=b; Secure",
            secure_origin: true,
            expect: Some("a=b"),
        },
        Case {
            line: "__Secure-a=b",
            secure_origin: true,
            expect: None,
        },
        Case {
            line: "__Secure-a=b; Secure",
            secure_origin: true,
            expect: Some("__Secure-a=b"),
        },
        Case {
            line: "__SECURE-a=b",
            secure_origin: true,
            expect: None,
        },
        Case {
            line: "__Host-a=b; Secure",
            secure_origin: true,
            expect: None,
        },
        Case {
            line: "__Host-a=b; Secure; Path=/",
            secure_origin: true,
            expect: Some("__Host-a=b"),
        },
        Case {
            line: "__host-a=b; Secure; Path=/a",
            secure_origin: true,
            expect: None,
        },
        Case {
            line: "=__Host-a=b; Secure; Path=/",
            secure_origin: true,
            expect: None,
        },
        Case {
            line: "a=b; SameSite=None",
            secure_origin: true,
            expect: None,
        },
        Case {
            line: "a=b; SameSite=None; Secure",
            secure_origin: true,
            expect: Some("a=b"),
        },
        Case {
            line: "a=b; Partitioned",
            secure_origin: true,
            expect: None,
        },
        Case {
            line: "a=b; Max-Age=0",
            secure_origin: true,
            expect: None,
        },
        Case {
            line: "a=b; Max-Age=-5",
            secure_origin: true,
            expect: None,
        },
        Case {
            line: "a=b; Max-Age=abc",
            secure_origin: true,
            expect: Some("a=b"),
        },
        Case {
            line: "a=b; Expires=Thu, 01 Jan 1970 00:00:01 GMT",
            secure_origin: true,
            expect: None,
        },
        Case {
            line: "a=b; Domain=example.com",
            secure_origin: true,
            expect: Some("a=b"),
        },
        Case {
            line: "a=b; Domain=.example.com",
            secure_origin: true,
            expect: Some("a=b"),
        },
        Case {
            line: "a=b; Domain=EXAMPLE.COM",
            secure_origin: true,
            expect: Some("a=b"),
        },
        Case {
            line: "a=b; Domain=com",
            secure_origin: true,
            expect: None,
        },
        Case {
            line: "a=b; Domain=other.example",
            secure_origin: true,
            expect: None,
        },
        Case {
            line: "a=b; Path=/other",
            secure_origin: true,
            expect: None,
        },
        Case {
            line: "a=b; Path=relative",
            secure_origin: true,
            expect: Some("a=b"),
        },
    ];
    for (i, c) in cases.iter().enumerate() {
        let mut jar = Jar::new();
        let url = RequestUrl::new(c.secure_origin, "example.com", "/");
        jar.store(&url, c.line, NOW);
        assert_eq!(
            jar.cookie_header(&url, NOW).as_deref(),
            c.expect,
            "case {i}: {:?}",
            c.line
        );
    }
}

#[test]
fn test_insecure_origin_cannot_toss_over_a_secure_cookie() {
    let mut jar = Jar::new();
    jar.store(
        &RequestUrl::https("example.com", "/"),
        "sid=real; Secure; HttpOnly",
        NOW,
    );
    let http = RequestUrl::http("example.com", "/");
    assert_eq!(
        jar.store(&http, "sid=attacker", NOW),
        StoreOutcome::Ignored(IgnoreReason::WouldShadowSecure)
    );
    assert_eq!(
        jar.cookie_header(&RequestUrl::https("example.com", "/"), NOW)
            .as_deref(),
        Some("sid=real")
    );
}

#[test]
fn test_supercookie_refused_without_a_list() {
    let mut jar = Jar::new();
    let url = RequestUrl::https("user.github.io", "/");
    assert_eq!(
        jar.store(&url, "a=1; Domain=github.io", NOW),
        StoreOutcome::Ignored(IgnoreReason::DomainNotAllowed)
    );
    assert_eq!(
        jar.store(&url, "a=1; Domain=io", NOW),
        StoreOutcome::Ignored(IgnoreReason::DomainNotAllowed)
    );
}

#[test]
fn test_cross_site_rules_for_a_client_acting_in_a_browser_context() {
    let mut jar = Jar::new();
    let url = RequestUrl::https("example.com", "/");
    jar.store(&url, "strict=1; SameSite=Strict", NOW);
    jar.store(&url, "lax=1; SameSite=Lax", NOW);
    jar.store(&url, "none=1; SameSite=None; Secure", NOW);
    let header = |cx: RequestContext<'_>, jar: &mut Jar| jar.cookie_header_for(&url, &cx, NOW);
    assert_eq!(
        header(RequestContext::cross_site(), &mut jar).as_deref(),
        Some("none=1")
    );
    assert_eq!(
        header(RequestContext::cross_site().navigation(true), &mut jar).as_deref(),
        Some("lax=1; none=1")
    );
    assert_eq!(
        header(RequestContext::same_site(), &mut jar).as_deref(),
        Some("strict=1; lax=1; none=1")
    );
}

#[test]
fn test_one_hour_of_cookies_in_a_bounded_jar() {
    // a short stand-in for the one-hour soak of 0.7: a stream of cookies for
    // many hosts, with expiry, replacement, and retrieval, never grows past
    // the bounds
    let limits = JarLimits::DEFAULT.per_domain(50).total(3000);
    let mut jar = Jar::new().with_limits(limits);
    let mut seed = 0x9e37_79b9_7f4a_7c15u64;
    let mut next = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    for t in 0..20_000u64 {
        let r = next();
        let host = format!("h{}.example", r % 120);
        let url = RequestUrl::https(&host, "/");
        let line = format!(
            "c{}={}; Max-Age={}",
            (r >> 8) % 80,
            r >> 20,
            1 + (r >> 40) % 3600
        );
        jar.store(&url, &line, NOW + t);
        if t % 7 == 0 {
            let _ = jar.cookie_header(&url, NOW + t);
        }
        assert!(jar.len() <= 3000);
    }
    assert!(jar.cookies().all(|c| c.value.len() < 32));
    let per_domain_max = (0..120)
        .map(|i| {
            let d = format!("h{i}.example");
            jar.cookies().filter(|c| c.domain == d).count()
        })
        .max()
        .unwrap_or(0);
    assert!(per_domain_max <= 50);
}

#[test]
fn test_lenient_reading_of_what_a_jar_sends() {
    let mut jar = Jar::new();
    let url = RequestUrl::https("example.com", "/");
    jar.store(&url, "json={\"a\":1}", NOW);
    let header = jar.cookie_header(&url, NOW).unwrap();
    let lenient =
        cookie::Cookies::with_limits(&header, &Limits::DEFAULT.value_mode(ValueMode::Lenient))
            .unwrap();
    assert_eq!(lenient.get("json"), Some("{\"a\":1}"));
}

#[test]
fn test_clear_site_data_value() {
    assert_eq!(cookie::CLEAR_SITE_DATA_COOKIES, "\"cookies\"");
}
