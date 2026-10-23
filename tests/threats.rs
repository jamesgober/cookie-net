//! One attack test per threat in dev/PLAN.md section 9 that 0.3 covers.
//! Each must fail to get through.

use cookie_net::{
    self as cookie, Ambiguous, CookieError, Cookies, Limits, Lookup, SameSite, SetCookie,
};

const TOKEN: &str = "Zk3J9qL0wX7aP2mT8sV1cR5dY4hN6bE0uK9gF3jQ2oA";

/// T1: CR, LF, NUL, or any control in any field never reaches the output.
#[test]
fn test_t1_set_cookie_refuses_every_ctl_in_every_field() {
    for b in (0u8..0x20).chain([0x7f]) {
        let bad = String::from_utf8(vec![b'x', b, b'y']).unwrap();
        let path = format!("/{bad}");
        let domain = format!("{bad}.example.com");
        let attempts = [
            SetCookie::builder(&bad, "v").build(),
            SetCookie::builder("n", &bad).build(),
            SetCookie::builder("n", "v").path(&path).build(),
            SetCookie::builder("n", "v").domain(&domain).build(),
            SetCookie::builder("n", "v").extension(&bad).build(),
        ];
        for (i, r) in attempts.into_iter().enumerate() {
            assert!(r.is_err(), "byte {b:#x} in field {i} was accepted");
        }
    }
}

/// T1: header splitting through a value is impossible.
#[test]
fn test_t1_header_splitting_refused() {
    let attack = "x\r\nSet-Cookie: __Host-sid=attacker";
    assert_eq!(
        SetCookie::new("pref", attack).unwrap_err(),
        CookieError::InvalidValue { at: 1 }
    );
}

/// T2: `;` cannot add attributes.
#[test]
fn test_t2_semicolon_in_value_refused() {
    assert_eq!(
        SetCookie::new("pref", "1; Domain=evil.example; SameSite=None").unwrap_err(),
        CookieError::InvalidValue { at: 1 }
    );
}

#[test]
fn test_t2_semicolon_in_path_refused() {
    assert_eq!(
        SetCookie::builder("pref", "1")
            .path("/; Domain=evil.example")
            .build()
            .unwrap_err(),
        CookieError::InvalidPath { at: 1 }
    );
}

/// T3: a tossed duplicate of a `__Host-` credential is ambiguous, and a
/// parent-domain `sid` beside it is a shadow, never the credential.
#[test]
fn test_t3_tossed_duplicate_host_sid_is_ambiguous() {
    let h = format!("__Host-sid={TOKEN}; theme=dark; __Host-sid=attacker");
    assert_eq!(
        cookie::get_unique(&h, "__Host-sid"),
        Err(Ambiguous::Duplicate { count: 2 })
    );
    let found = cookie::locate(&h, "__Host-sid", &Limits::DEFAULT);
    assert!(matches!(found.lookup, Lookup::Many { count: 2, .. }));
    assert_eq!(found.severity_hint(), 30);
    assert_eq!(found.stats.prefixed_duplicates, 1);
}

#[test]
fn test_t3_parent_domain_sid_is_a_shadow_not_the_credential() {
    let h = format!("sid=attacker; __Host-sid={TOKEN}");
    let found = cookie::locate(&h, "__Host-sid", &Limits::DEFAULT);
    assert_eq!(found.lookup, Lookup::One(TOKEN));
    assert_eq!(found.shadows, 1);
    assert_eq!(cookie::get_unique("sid=attacker", "__Host-sid"), Ok(None));
}

/// T4: oversized cookies are refused when writing and skipped when reading.
#[test]
fn test_t4_name_plus_value_4097_refused() {
    let v = "v".repeat(4096);
    assert_eq!(SetCookie::new("a", &v).unwrap_err(), CookieError::TooLarge);
}

#[test]
fn test_t4_header_8193_too_long() {
    let h = format!("a={}", "v".repeat(8191));
    assert_eq!(h.len(), 8193);
    assert_eq!(
        Cookies::with_limits(&h, &Limits::DEFAULT).unwrap_err(),
        CookieError::HeaderTooLong
    );
    assert_eq!(cookie::get_unique(&h, "a"), Err(Ambiguous::HeaderTooLong));
}

/// T5: a cookie bomb is truncated, never a panic, and never yields the
/// credential as `One`.
#[test]
fn test_t5_cookie_bomb_header_truncated_not_panicking() {
    let bomb: String = (0..300)
        .map(|i| format!("bomb{i}={}; ", "x".repeat(30)))
        .collect();
    let h = format!("{bomb}__Host-sid={TOKEN}");
    let found = cookie::locate(&h, "__Host-sid", &Limits::DEFAULT);
    assert_eq!(found.lookup, Lookup::HeaderTooLong);
    let big = Limits::DEFAULT.max_header_len(65_536);
    let found = cookie::locate(&h, "__Host-sid", &big);
    assert_eq!(found.lookup, Lookup::Truncated);
    assert!(found.stats.truncated);
}

#[test]
fn test_t5_locate_truncated_is_not_one() {
    let h: String = (0..64)
        .map(|i| format!("c{i}=1; "))
        .chain([format!("__Host-sid={TOKEN}")])
        .collect();
    assert_eq!(
        cookie::locate(&h, "__Host-sid", &Limits::DEFAULT).lookup,
        Lookup::Truncated
    );
    assert_eq!(
        cookie::get_unique(&h, "__Host-sid"),
        Err(Ambiguous::Truncated)
    );
}

/// T6: whitespace and Unicode before a name never make it a host cookie.
#[test]
fn test_t6_nbsp_prefixed_name_not_host_cookie() {
    let h = format!("\u{a0}__Host-sid=attacker; __Host-sid={TOKEN}");
    assert_eq!(cookie::get_unique(&h, "__Host-sid"), Ok(Some(TOKEN)));
    assert_eq!(cookie::parse(&h).stats().skipped, 1);
}

#[test]
fn test_t6_unicode_space_prefixed_name_skipped() {
    for space in [
        "\u{2000}", "\u{3000}", "\u{feff}", "\u{85}", "\u{b}", "\u{c}",
    ] {
        let h = format!("{space}__Host-sid=attacker");
        assert_eq!(cookie::get(&h, "__Host-sid"), None, "{space:?}");
    }
}

/// T7: a planted duplicate from a nameless cookie on an old user agent is
/// detected.
#[test]
fn test_t7_planted_host_sid_duplicate_detected() {
    // `Set-Cookie: =__Host-sid=x` on an old browser serializes as `__Host-sid=x`.
    let h = format!("__Host-sid=x; __Host-sid={TOKEN}");
    assert!(matches!(
        cookie::get_unique(&h, "__Host-sid"),
        Err(Ambiguous::Duplicate { .. })
    ));
}

/// T8: case variants of a prefix are never the credential.
#[test]
fn test_t8_case_variant_prefix_not_matched() {
    let h = "__HOST-sid=attacker; __host-sid=attacker";
    assert_eq!(cookie::get_unique(h, "__Host-sid"), Ok(None));
    assert_eq!(cookie::locate(h, "__Host-sid", &Limits::DEFAULT).shadows, 2);
    // writing applies prefix rules whatever the case
    assert_eq!(
        SetCookie::builder("__HOST-sid", "x")
            .domain("example.com")
            .build()
            .unwrap_err(),
        CookieError::HostPrefix
    );
}

/// T9: names are never percent-decoded.
#[test]
fn test_t9_percent_encoded_name_not_decoded() {
    let h = "%5F_Host-sid=attacker; __Host%2Dsid=attacker";
    assert_eq!(cookie::get(h, "__Host-sid"), None);
    assert_eq!(cookie::get(h, "%5F_Host-sid"), Some("attacker"));
}

/// T10: quotes stay part of the value.
#[test]
fn test_t10_quoted_value_kept() {
    let p = cookie::parse("a=\"x\"").iter().next().unwrap();
    assert_eq!((p.value(), p.value_unquoted()), ("\"x\"", "x"));
}

/// T11: a comma is not a separator.
#[test]
fn test_t11_comma_not_separator() {
    let h = "a=1, __Host-sid=attacker";
    assert_eq!(cookie::get(h, "__Host-sid"), None);
    assert_eq!(cookie::get(h, " __Host-sid"), None);
    assert_eq!(cookie::parse(h).stats().skipped, 1);
}

/// T12: RFC 2965 attributes are ordinary names.
#[test]
fn test_t12_dollar_names_are_plain_pairs() {
    let h = "$Version=1; sid=x; $Path=/; $Domain=evil.example";
    let names: Vec<&str> = cookie::parse(h).iter().map(|p| p.name()).collect();
    assert_eq!(names, ["$Version", "sid", "$Path", "$Domain"]);
    assert_eq!(cookie::get_unique(h, "sid"), Ok(Some("x")));
}

/// T13: two cookies of one name on different paths are ambiguous.
#[test]
fn test_t13_get_unique_two_paths_is_ambiguous() {
    assert_eq!(
        cookie::get_unique("sid=from-/app; sid=from-/", "sid"),
        Err(Ambiguous::Duplicate { count: 2 })
    );
}

/// T19: the session cookie's attributes cannot be weakened through the helper.
#[test]
fn test_t19_session_cookie_attributes_fixed() {
    let c = cookie::session_cookie("__Host-sid", TOKEN, cookie::HOUR).unwrap();
    assert!(c.is_secure() && c.is_http_only());
    assert_eq!(
        (c.path(), c.domain(), c.same_site()),
        ("/", None, SameSite::Lax)
    );
    assert_eq!(
        cookie::session_cookie("sid", TOKEN, cookie::HOUR).unwrap_err(),
        CookieError::HostPrefix
    );
}

/// T20: the default is `SameSite=Lax`.
#[test]
fn test_t20_default_same_site_lax() {
    assert_eq!(SetCookie::new("a", "1").unwrap().same_site(), SameSite::Lax);
    assert_eq!(
        cookie::elevated_cookie("__Host-sudo", TOKEN, 600)
            .unwrap()
            .same_site(),
        SameSite::Strict
    );
}

/// T21: cookies browsers would silently drop are refused.
#[test]
fn test_t21_none_without_secure_refused() {
    assert_eq!(
        SetCookie::builder("a", "1")
            .same_site(SameSite::None)
            .insecure()
            .build()
            .unwrap_err(),
        CookieError::SameSiteNoneNeedsSecure
    );
}

#[test]
fn test_t21_partitioned_without_secure_refused() {
    assert_eq!(
        SetCookie::builder("a", "1")
            .partitioned()
            .insecure()
            .build()
            .unwrap_err(),
        CookieError::PartitionedNeedsSecure
    );
}

/// T22: single-label and IP domains are refused.
#[test]
fn test_t22_domain_single_label_refused() {
    for d in ["com", "localhost", "127.0.0.1", "[::1]", "10.0.0.1"] {
        assert_eq!(
            SetCookie::builder("a", "1").domain(d).build().unwrap_err(),
            CookieError::InvalidDomain,
            "{d}"
        );
    }
}

/// T23: secrets never reach `Debug` or `Display`.
#[test]
fn test_t23_debug_never_contains_value() {
    let secret = "S3CR3T-T0K3N-V4LU3-0123456789";
    let h = format!("__Host-sid={secret}; __Host-sid={secret}x");
    let cookies = cookie::parse(&h);
    let shown = [
        format!("{cookies:?}"),
        format!("{:?}", cookies.iter().next().unwrap()),
        format!("{:?}", cookies.locate("__Host-sid")),
        format!("{:?}", cookies.locate("__Host-sid").lookup),
        format!(
            "{:?}",
            cookie::session_cookie("__Host-sid", secret, 60).unwrap()
        ),
        format!("{:?}", SetCookie::builder("__Host-sid", secret)),
        format!("{}", cookie::get_unique(&h, "__Host-sid").unwrap_err()),
        format!(
            "{}",
            SetCookie::new("a", &format!("{secret} x")).unwrap_err()
        ),
    ];
    for s in shown {
        assert!(!s.contains("S3CR3T"), "{s}");
    }
}

/// T28: a session cookie cannot carry an empty or tiny token.
#[test]
fn test_t28_tiny_session_token_refused() {
    for t in ["", "1", "user-42", "aaaaaaaaaaaaaaaaaaaaa"] {
        assert_eq!(
            cookie::session_cookie("__Host-sid", t, 60).unwrap_err(),
            CookieError::TokenTooShort,
            "{t}"
        );
    }
}
