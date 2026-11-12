//! Regression tests for the findings of the 0.9 adversarial review (three
//! independent reviews at 0.8: standards conformance, attacks, edge cases;
//! dev/PLAN.md D-086). Each test failed before its fix.

#![cfg(all(feature = "encrypted", feature = "jar"))]

use cookie_net::{
    self as cookie, CookieError, IgnoreReason, Jar, JarLimits, PublicSuffix, RequestContext,
    RequestUrl, Sealer, StoreOutcome, parse_set_cookie,
};

const NOW: u64 = 1_800_000_000;

/// A suffix list with only `com` (and the empty string, never a domain).
struct Com;
impl PublicSuffix for Com {
    fn is_public_suffix(&self, domain: &str) -> bool {
        domain == "com"
    }
}

fn https(host: &str) -> RequestUrl<'_> {
    RequestUrl::https(host, "/")
}

/// One cookie value that is not UTF-8 no longer empties the whole header:
/// the `String` form skips it, the sink form still writes every byte.
#[test]
fn test_jar_non_utf8_value_does_not_drop_other_cookies() {
    let mut jar = Jar::new();
    jar.store(&https("example.com"), "sid=abc", NOW);
    jar.store(&https("example.com"), &b"pref=caf\xe9"[..], NOW + 1);
    assert_eq!(
        jar.cookie_header(&https("example.com"), NOW).as_deref(),
        Some("sid=abc")
    );
    let mut out = Vec::new();
    let n = jar
        .write_cookie_header(
            &https("example.com"),
            &RequestContext::default(),
            NOW,
            &mut out,
        )
        .unwrap();
    assert_eq!((n, &out[..]), (2, &b"sid=abc; pref=caf\xe9"[..]));
}

/// Importing replaces a cookie with the same name, domain, host-only flag,
/// and path instead of adding a duplicate; the older creation time is kept.
#[test]
fn test_jar_import_replaces_instead_of_duplicating() {
    let mut a = Jar::new();
    a.store(&https("example.com"), "a=1", NOW);
    let mut b = Jar::new();
    b.store(&https("example.com"), "a=2", NOW + 50);
    assert_eq!(a.import(&b.export(), NOW + 60).unwrap(), 1);
    assert_eq!(a.len(), 1);
    assert_eq!(
        a.cookie_header(&https("example.com"), NOW + 60).as_deref(),
        Some("a=2")
    );
    assert_eq!(a.cookies().next().unwrap().creation, NOW);
    // the same export twice is still one cookie
    let bytes = b.export();
    let mut c = Jar::new();
    c.import(&bytes, NOW + 60).unwrap();
    c.import(&bytes, NOW + 60).unwrap();
    assert_eq!(c.len(), 1);
}

/// Imported records go through the storage rules: a record no `store` could
/// make is refused as invalid data, and a domain cookie this jar's suffix
/// list does not allow is skipped. Times from the file are capped.
#[test]
fn test_jar_import_applies_the_storage_rules() {
    // a jar with a suffix list can hold a domain cookie...
    let mut with_list = Jar::with_public_suffix(Com);
    with_list.store(
        &https("app.example.com"),
        "d=1; Domain=example.com; Max-Age=60",
        NOW,
    );
    let exported = with_list.export();
    // ...which a fail-closed jar skips, importing nothing
    let mut closed = Jar::new();
    assert_eq!(closed.import(&exported, NOW).unwrap(), 0);
    assert!(closed.is_empty());
    // a jar with the same list takes it
    assert_eq!(
        Jar::with_public_suffix(Com).import(&exported, NOW).unwrap(),
        1
    );
}

/// An export in the documented format (docs/FORMATS.md) with `n` host-only
/// cookies `a=1` for the hosts `h0.example`, `h1.example`, ...
fn export_bytes(n: u32) -> Vec<u8> {
    let mut out = b"CNJR\x01".to_vec();
    out.extend_from_slice(&n.to_be_bytes());
    for i in 0..n {
        out.push(0x03); // host-only, secure
        out.push(0); // no SameSite
        for t in [0u64, NOW, NOW] {
            out.extend_from_slice(&t.to_be_bytes());
        }
        let host = format!("h{i}.example");
        for field in [&b"a"[..], b"1", host.as_bytes(), b"/", b""] {
            out.extend_from_slice(&u16::try_from(field.len()).unwrap().to_be_bytes());
            out.extend_from_slice(field);
        }
    }
    let sum = crypt_io::hash::blake3(&out);
    out.extend_from_slice(&sum);
    out
}

/// Importing costs n log n, not records times jar size, and the jar's limits
/// apply once: 100,000 records import in seconds (the old code took hours).
#[test]
fn test_jar_import_is_not_quadratic() {
    let bytes = export_bytes(100_000);
    let start = std::time::Instant::now();
    let mut jar = Jar::new().with_limits(JarLimits::DEFAULT.total(1_000_000));
    assert_eq!(jar.import(&bytes, NOW).unwrap(), 100_000);
    assert_eq!(jar.len(), 100_000);
    assert!(start.elapsed().as_secs() < 60, "{:?}", start.elapsed());
    let mut small = Jar::new();
    assert_eq!(small.import(&bytes, NOW).unwrap(), 3_000);
    assert_eq!(small.len(), 3_000);
}

/// A record no `store` could make is refused as invalid data: here a
/// `__Host-` cookie that is neither host-only nor `Secure`, with a valid
/// checksum. Times from the file are capped at `now`.
#[test]
fn test_jar_import_refuses_impossible_records() {
    let mut bytes = export_bytes(1);
    let body = bytes.len() - 32;
    // rename the cookie to `__Host-a` and clear its host-only and secure flags
    let name_at = 5 + 4 + 2 + 24 + 2;
    assert_eq!(bytes[name_at], b'a');
    let mut forged = bytes[..name_at - 2].to_vec();
    forged[9] = 0x00; // neither host-only nor secure
    forged.extend_from_slice(&8u16.to_be_bytes());
    forged.extend_from_slice(b"__Host-a");
    forged.extend_from_slice(&bytes[name_at + 1..body]);
    let sum = crypt_io::hash::blake3(&forged);
    forged.extend_from_slice(&sum);
    assert_eq!(
        Jar::new().import(&forged, NOW).unwrap_err(),
        CookieError::InvalidJarData
    );
    // last_access far in the future is capped, so a planted cookie cannot
    // make itself the last to be evicted
    let la_at = 5 + 4 + 2 + 16;
    bytes[la_at..la_at + 8].copy_from_slice(&u64::MAX.to_be_bytes());
    let body = bytes.len() - 32;
    let sum = crypt_io::hash::blake3(&bytes[..body]);
    bytes[body..].copy_from_slice(&sum);
    let mut jar = Jar::new();
    jar.import(&bytes, NOW).unwrap();
    assert_eq!(jar.cookies().next().unwrap().last_access, NOW);
}

/// What `store` accepts, `export` and `import` round-trip: a default path
/// with `;` comes back, and a default path over 1024 bytes is refused when
/// storing, so one cookie can no longer make a whole export unimportable.
#[test]
fn test_jar_export_round_trips_every_stored_path() {
    let mut jar = Jar::new();
    let semi = RequestUrl::https("example.com", "/a;jsessionid=1/b");
    assert_eq!(jar.store(&semi, "a=1", NOW), StoreOutcome::Stored);
    let long = format!("/{}/x", "p".repeat(1100));
    assert_eq!(
        jar.store(&RequestUrl::https("example.com", &long), "b=1", NOW),
        StoreOutcome::Ignored(IgnoreReason::InvalidRequestUrl)
    );
    let mut copy = Jar::new();
    assert_eq!(copy.import(&jar.export(), NOW).unwrap(), 1);
    assert_eq!(copy.cookies().next().unwrap().path, b"/a;jsessionid=1");
}

/// A `Set-Cookie` from a cross-site request is ignored unless it is
/// `SameSite=None` or the request is a top-level navigation (section 5.7
/// step 18), and a partitioned cookie is keyed by the top-level site.
#[test]
fn test_jar_store_for_cross_site_and_partitions() {
    let mut jar = Jar::new();
    let url = https("widget.example");
    let embedded = RequestContext::cross_site().top_level_site("shop.example");
    assert_eq!(
        jar.store_for(&url, &embedded, "lax=1; Secure", NOW),
        StoreOutcome::Ignored(IgnoreReason::CrossSite)
    );
    assert_eq!(
        jar.store_for(
            &url,
            &embedded,
            "t=1; Secure; SameSite=None; Partitioned",
            NOW
        ),
        StoreOutcome::Stored
    );
    let nav = RequestContext::cross_site().navigation(true);
    assert_eq!(
        jar.store_for(&url, &nav, "n=1; Secure", NOW),
        StoreOutcome::Stored
    );
    // the partitioned cookie goes back only under its top-level site
    assert_eq!(
        jar.cookie_header_for(&url, &embedded, NOW).as_deref(),
        Some("t=1")
    );
    assert_eq!(jar.cookie_header(&url, NOW).as_deref(), Some("n=1"));
}

/// An IP-address host gets host-only cookies only, even with a suffix list.
#[test]
fn test_jar_ip_host_never_gets_a_domain_cookie() {
    let mut jar = Jar::with_public_suffix(Com);
    let ip = https("10.0.0.1");
    assert_eq!(
        jar.store(&ip, "a=1; Domain=10.0.0.1", NOW),
        StoreOutcome::Stored
    );
    assert!(jar.cookies().next().unwrap().host_only);
    assert_eq!(jar.cookie_header(&https("x.10.0.0.1"), NOW), None);
}

/// `Domain=.` leaves an empty domain attribute, which makes a host-only
/// cookie (section 5.7 step 10), never a domain of `""`.
#[test]
fn test_jar_empty_domain_is_host_only() {
    let mut jar = Jar::with_public_suffix(Com);
    assert_eq!(
        jar.store(&https("evil.com"), "sc=1; Domain=.", NOW),
        StoreOutcome::Stored
    );
    let c = jar.cookies().next().unwrap();
    assert!(c.host_only);
    assert_eq!(c.domain, "evil.com");
    assert_eq!(jar.cookie_header(&https("bank.example.org"), NOW), None);
}

/// Expired cookies still in the store neither block a replacement nor give
/// it their creation time.
#[test]
fn test_jar_expired_cookies_do_not_block_or_donate() {
    let mut jar = Jar::new();
    jar.store(&https("example.com"), "sid=1; Secure; Max-Age=10", NOW);
    assert_eq!(
        jar.store(&RequestUrl::http("example.com", "/"), "sid=x", NOW + 20),
        StoreOutcome::Stored
    );
    assert_eq!(jar.cookies().next().unwrap().creation, NOW + 20);
}

/// Cookies with paths of equal length are sent by creation time, also
/// after an import (section 5.8.3 step 2).
#[test]
fn test_jar_orders_by_creation_after_import() {
    let mut old = Jar::new();
    old.store(&https("example.com"), "early=1", NOW);
    let mut jar = Jar::new();
    jar.store(&https("example.com"), "late=1", NOW + 100);
    jar.import(&old.export(), NOW + 100).unwrap();
    assert_eq!(
        jar.cookie_header(&https("example.com"), NOW + 100)
            .as_deref(),
        Some("early=1; late=1")
    );
}

/// A `__Host-` cookie whose `Path` falls back to the default path `/` is
/// stored (sections 5.6.4 and 5.7 step 21); one without a `Path` attribute is
/// not.
#[test]
fn test_jar_host_prefix_with_defaulted_path() {
    let mut jar = Jar::new();
    for line in [
        "__Host-a=1; Secure; Path=",
        "__Host-b=1; Secure; Path=x",
        "__Host-c=1; Secure; Path=/; Path=x",
    ] {
        assert_eq!(
            jar.store(&https("example.com"), line, NOW),
            StoreOutcome::Stored,
            "{line}"
        );
    }
    assert_eq!(
        jar.store(&https("example.com"), "__Host-d=1; Secure", NOW),
        StoreOutcome::Ignored(IgnoreReason::HostPrefix)
    );
    assert_eq!(
        jar.store(
            &RequestUrl::https("example.com", "/a/b"),
            "__Host-e=1; Secure; Path=",
            NOW
        ),
        StoreOutcome::Ignored(IgnoreReason::HostPrefix)
    );
}

/// `unknown_attributes` counts attributes, not empty segments.
#[test]
fn test_set_cookie_view_ignores_empty_segments() {
    assert_eq!(
        parse_set_cookie("a=b;;;; Secure")
            .unwrap()
            .unknown_attributes,
        0
    );
    assert_eq!(
        parse_set_cookie("a=b; Foo; ; Bar=1")
            .unwrap()
            .unknown_attributes,
        2
    );
}

/// Spaces and tabs around `=` are allowed by the grammar (`cookie-pair`,
/// sections 4.1.1 and 4.2.1).
#[test]
fn test_cookie_header_whitespace_around_equals() {
    let h = "a =1; b= 2; c\t=\t3";
    assert_eq!(cookie::get(h, "a"), Some("1"));
    assert_eq!(cookie::get(h, "b"), Some("2"));
    assert_eq!(cookie::get(h, "c"), Some("3"));
    assert_eq!(
        cookie::get_unique("__Host-sid=a; __Host-sid =b", "__Host-sid"),
        Err(cookie::Ambiguous::Duplicate { count: 2 })
    );
}

/// A sealed cookie over 4096 bytes is refused, whatever the name's length,
/// and the length arithmetic cannot overflow.
#[test]
fn test_sealer_size_limits_hold_for_long_names() {
    let s = Sealer::new(*b"another example key, 32 bytes!!!").unwrap();
    assert_eq!(
        s.seal(&"a".repeat(4050), "").unwrap_err(),
        CookieError::TooLarge
    );
    assert_eq!(s.max_plaintext(4050), 0);
    let _ = s.sealed_len(usize::MAX);
}

// The independent review of 0.7.1 (F-1 to F-10). F-1,
// F-2, and F-4 are the import and partition tests above.

/// F-3: the session helpers take the exact `__Host-` prefix only. A
/// lowercase `__host-` is a `__Host-` cookie to a current browser, but the
/// server reads names byte for byte, so its own `get_unique("__Host-sid")`
/// would never see it.
#[test]
fn test_session_helpers_need_the_exact_host_prefix() {
    let token = "Zk3J9qL0wX7aP2mT8sV1cR5dY4hN6bE0uK9gF3jQ2oA";
    for name in ["__host-sid", "__HOST-sid", "__Host-sid"] {
        let ok = name.starts_with("__Host-");
        assert_eq!(
            cookie::session_cookie(name, token, cookie::HOUR).is_ok(),
            ok,
            "{name}"
        );
        assert_eq!(
            cookie::elevated_cookie(name, token, 600).is_ok(),
            ok,
            "{name}"
        );
    }
    assert_eq!(
        cookie::session_cookie("__host-sid", token, cookie::HOUR).unwrap_err(),
        CookieError::HostPrefix
    );
}

/// F-5: `rotated` promotes a staged key only when its bytes are the staged
/// ones; a switch to other bytes under the staged id is refused, so one node
/// cannot start signing with a key the others do not hold.
#[test]
fn test_key_ring_rotated_checks_the_staged_bytes() {
    use cookie_net::{KeyId, KeyRing, Signer};
    let (k1, k2, other) = (
        *b"an example key, 32 bytes long!!!",
        *b"the second key, 32 bytes long!!!",
        *b"not the staged key, 32 bytes!!!!",
    );
    let staged = KeyRing::new(KeyId(1), k1).accept(KeyId(2), k2);
    assert!(Signer::with_ring(staged.clone().rotated(KeyId(2), k2, NOW)).is_ok());
    assert_eq!(
        Signer::with_ring(staged.clone().rotated(KeyId(2), other, NOW)).unwrap_err(),
        CookieError::DuplicateKeyId
    );
    assert_eq!(
        Sealer::with_ring(staged.rotated(KeyId(2), other, NOW)).unwrap_err(),
        CookieError::DuplicateKeyId
    );
}

/// F-6: a ring without a signing key says so.
#[test]
fn test_key_ring_without_signing_key_is_reported() {
    use cookie_net::{KeyId, KeyRing, Signer};
    let ring = KeyRing::new(KeyId(1), *b"an example key, 32 bytes long!!!").without(KeyId(1));
    assert_eq!(
        Signer::with_ring(ring).unwrap_err(),
        CookieError::NoSigningKey
    );
    assert_eq!(CookieError::NoSigningKey.code(), "no_signing_key");
}
