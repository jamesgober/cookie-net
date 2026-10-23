//! Property tests for the invariants in dev/DIRECTIVES.md section 4 and
//! dev/PLAN.md section 11.

use cookie_net::{
    self as cookie, Ambiguous, Cookies, Limits, Lookup, Pair, Prefix, SameSite, SetCookie,
    ValueMode,
};
use proptest::prelude::*;

/// A `cookie-octet` string.
fn value() -> impl Strategy<Value = String> {
    proptest::string::string_regex("[!#-+\\--:<-\\[\\]-~]{0,40}").unwrap()
}

/// A `token` string.
fn name() -> impl Strategy<Value = String> {
    prop_oneof![
        proptest::string::string_regex("[A-Za-z0-9!#$%&'*+.^_`|~-]{1,20}").unwrap(),
        proptest::string::string_regex("(__Host-|__Secure-|__host-|__SECURE-)[a-z]{0,6}").unwrap(),
    ]
}

fn text(c: &SetCookie<'_>) -> String {
    let mut buf = vec![0u8; c.encoded_len()];
    String::from(c.encode_into(&mut buf).unwrap())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2048))]

    /// Reading never panics, and every accepted pair meets the grammar.
    #[test]
    fn prop_parse_never_panics(header in proptest::collection::vec(any::<u8>(), 0..600)) {
        for limits in [Limits::DEFAULT, Limits::DEFAULT.value_mode(ValueMode::Lenient), Limits::DEFAULT.max_pairs(3)] {
            let c = Cookies::with_limits(&header, &limits).unwrap();
            let pairs: Vec<Pair<'_>> = c.iter().collect();
            let stats = c.stats();
            prop_assert_eq!(pairs.len(), usize::from(stats.pairs));
            for p in &pairs {
                prop_assert!(!p.name().is_empty());
                prop_assert!(p.name().bytes().all(parse_net::class::is_tchar));
                prop_assert!(!p.value().contains(';'));
                if limits.mode() == ValueMode::Strict {
                    prop_assert!(p.value().is_ascii() && !p.value().contains(' '));
                }
            }
        }
    }

    /// Text of mostly valid pairs with noise: lookups agree with each other.
    #[test]
    fn prop_lookups_agree(
        pairs in proptest::collection::vec((name(), value()), 0..12),
        target in name(),
        noise in proptest::collection::vec(" |;|,|\t|=| ;|\"", 0..4),
    ) {
        let mut h = String::new();
        for (i, (n, v)) in pairs.iter().enumerate() {
            if i > 0 { h.push_str("; "); }
            if let Some(x) = noise.get(i) { h.push_str(x); }
            h.push_str(n); h.push('='); h.push_str(v);
        }
        let all: Vec<&str> = cookie::get_all(&h, &target).collect();
        let found = cookie::locate(&h, &target, &Limits::DEFAULT);
        match (cookie::get_unique(&h, &target), found.lookup) {
            (Ok(None), Lookup::Missing) => prop_assert!(all.is_empty()),
            (Ok(Some(v)), Lookup::One(w)) => { prop_assert_eq!(v, w); prop_assert_eq!(all, vec![v]); }
            (Err(Ambiguous::Duplicate { count }), Lookup::Many { first, count: c }) => {
                prop_assert_eq!(count, c);
                prop_assert_eq!(usize::from(count), all.len());
                prop_assert_eq!(Some(first), cookie::get(&h, &target));
            }
            (u, l) => prop_assert!(false, "get_unique {:?} and locate {:?} disagree", u, l),
        }
    }

    /// Splitting a header into crumbs at any `"; "` gives the same pairs.
    #[test]
    fn prop_crumbs_match_joined(pairs in proptest::collection::vec((name(), value()), 1..10), cuts in proptest::collection::vec(any::<bool>(), 10)) {
        let joined = pairs.iter().map(|(n, v)| format!("{n}={v}")).collect::<Vec<_>>().join("; ");
        let mut lines: Vec<String> = vec![String::new()];
        for (i, (n, v)) in pairs.iter().enumerate() {
            let last = lines.last_mut().unwrap();
            if !last.is_empty() { last.push_str("; "); }
            last.push_str(&format!("{n}={v}"));
            if cuts[i] { lines.push(String::new()); }
        }
        let lines: Vec<&[u8]> = lines.iter().map(String::as_bytes).collect();
        let split: Vec<Pair<'_>> = Cookies::from_lines(&lines, &Limits::DEFAULT).unwrap().iter().collect();
        let whole: Vec<Pair<'_>> = cookie::parse(&joined).iter().collect();
        prop_assert_eq!(split, whole);
    }

    /// No builder input produces a cookie that breaks a prefix, `SameSite=None`,
    /// or `Partitioned` rule, or that holds a control byte; what is written
    /// reads back as written.
    #[test]
    fn prop_builder_rules_hold(
        name in prop_oneof![name(), any::<String>()],
        value in prop_oneof![value(), any::<String>()],
        path in prop_oneof![Just(None), proptest::option::of("/[a-z/]{0,8}"), proptest::option::of(any::<String>())],
        domain in prop_oneof![Just(None), proptest::option::of("[a-z]{1,8}\\.(com|org)"), proptest::option::of(any::<String>())],
        flags in any::<u8>(),
        max_age in proptest::option::of(0u64..40_000_000),
    ) {
        let mut b = SetCookie::builder(&name, &value);
        if let Some(p) = &path { b = b.path(p); }
        if let Some(d) = &domain { b = b.domain(d); }
        if flags & 1 != 0 { b = b.insecure(); }
        if flags & 2 != 0 { b = b.partitioned(); }
        if flags & 4 != 0 { b = b.script_readable(); }
        if flags & 8 != 0 { b = b.delete(); }
        b = b.same_site(match flags >> 6 { 0 => SameSite::Lax, 1 => SameSite::Strict, _ => SameSite::None });
        if let Some(m) = max_age { b = b.max_age(m); }
        if let Ok(c) = b.build() {
            let line = text(&c);
            prop_assert!(line.bytes().all(|b| (0x20..0x7f).contains(&b)));
            match Prefix::of(c.name()) {
                Prefix::Host => prop_assert!(c.is_secure() && c.path() == "/" && c.domain().is_none()),
                Prefix::Secure => prop_assert!(c.is_secure()),
                _ => {}
            }
            if c.same_site() == SameSite::None || c.is_partitioned() { prop_assert!(c.is_secure()); }
            let pair = format!("{}={}", c.name(), c.value());
            let limits = Limits::DEFAULT.max_name_len(4096);
            prop_assert_eq!(Cookies::with_limits(&pair, &limits).unwrap().get_unique(c.name()), Ok(Some(c.value())));
        }
    }

    /// Values never reach `Debug`.
    #[test]
    fn prop_debug_never_contains_value(secret in "[A-Za-z0-9]{24,40}") {
        let h = format!("__Host-sid={secret}; x={secret}");
        let c = cookie::parse(&h);
        let shown = format!("{:?} {:?} {:?}", c, c.locate("__Host-sid"), c.iter().collect::<Vec<_>>());
        prop_assert!(!shown.contains(&secret));
        let s = cookie::session_cookie("__Host-sid", &secret, 60).unwrap();
        let shown = format!("{s:?}");
        prop_assert!(!shown.contains(&secret));
    }
}
