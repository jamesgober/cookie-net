//! Attack tests for threats T14 to T30 (dev/PLAN.md section 9 and
//! docs/SECURITY.md): signed and sealed values, keys, the client side, and
//! the jar. Each must fail to get through.

#![cfg(all(feature = "encrypted", feature = "jar"))]

use cookie_net::{
    self as cookie, CookieError, IgnoreReason, Jar, JarLimits, KeyId, KeyRing, Rejected,
    RequestUrl, Sealer, SetCookie, Signer, StoreOutcome,
};

const K1: [u8; 32] = *b"an example key, 32 bytes long!!!";
const K2: [u8; 32] = *b"the second key, 32 bytes long!!!";
const NOW: u64 = 1_800_000_000;

/// T14: any change to a signed or sealed value is refused.
#[test]
fn test_t14_every_changed_byte_of_signed_and_sealed_values_refused() {
    let s = Signer::new(K1).unwrap();
    let signed = s.sign("prefs", "lang=fr|beta=1").unwrap().into_bytes();
    let o = Sealer::new(K1).unwrap();
    let sealed = o.seal("flash", "Saved.").unwrap().into_bytes();
    for (raw, check) in [
        (
            &signed,
            &(|m: &[u8]| s.verify("prefs", m, NOW).is_err()) as &dyn Fn(&[u8]) -> bool,
        ),
        (&sealed, &|m: &[u8]| o.open("flash", m, NOW).is_err()),
    ] {
        for i in 0..raw.len() {
            for replacement in *b"A_-0z~%" {
                let mut m = raw.clone();
                if m[i] == replacement {
                    continue;
                }
                m[i] = replacement;
                assert!(check(&m), "byte {i} set to {}", replacement as char);
            }
        }
        // truncated and extended
        assert!(check(&raw[..raw.len() - 1]));
        let mut longer = raw.clone();
        longer.push(b'A');
        assert!(check(&longer));
    }
}

/// T15: a value cannot move to another cookie name.
#[test]
fn test_t15_values_never_verify_under_another_name() {
    let s = Signer::new(K1).unwrap();
    let v = s.sign("prefs", "plan=pro").unwrap();
    for other in ["pref", "prefs2", "Prefs", "__Host-prefs", "plan"] {
        assert_eq!(s.verify(other, &v, NOW), Err(Rejected::BadTag), "{other}");
    }
    let o = Sealer::new(K1).unwrap();
    let sealed = o.seal("flash", "Saved.").unwrap();
    assert_eq!(o.open("Flash", &sealed, NOW).unwrap_err(), Rejected::BadTag);
}

/// T16: old signed state cannot be replayed past its expiry or its key.
#[test]
fn test_t16_expired_and_retired_values_refused() {
    let s = Signer::new(K1).unwrap().with_skew(0);
    let v = s.sign_until("notice", "seen", NOW).unwrap();
    assert_eq!(s.verify("notice", &v, NOW), Err(Rejected::Expired));
    let rotated = Signer::with_ring(KeyRing::new(KeyId(1), K2).retired(KeyId(0), K1, NOW)).unwrap();
    let old = Signer::new(K1).unwrap().sign("prefs", "x").unwrap();
    assert!(rotated.verify("prefs", &old, NOW - 1).is_ok());
    assert_eq!(
        rotated.verify("prefs", &old, NOW),
        Err(Rejected::UnknownKey)
    );
}

/// T17: a compromised key is dropped without touching the others.
#[test]
fn test_t17_dropping_a_compromised_key() {
    let ring = KeyRing::new(KeyId(1), K2).accept(KeyId(0), K1);
    let made_with_k1 = Signer::new(K1).unwrap().sign("prefs", "x").unwrap();
    assert!(
        Signer::with_ring(ring.clone())
            .unwrap()
            .verify("prefs", &made_with_k1, NOW)
            .is_ok()
    );
    let without = Signer::with_ring(ring.without(KeyId(0))).unwrap();
    assert_eq!(
        without.verify("prefs", &made_with_k1, NOW),
        Err(Rejected::UnknownKey)
    );
    assert!(
        without
            .verify("prefs", &without.sign("prefs", "y").unwrap(), NOW)
            .is_ok()
    );
}

/// T18: forged tags are refused through the constant-time path, whatever
/// the prefix of the tag that matches (timing is checked in tests/crypto.rs).
#[test]
fn test_t18_forged_tags_with_matching_prefixes_refused() {
    let s = Signer::new(K1).unwrap();
    let good = s.sign("a", "value").unwrap().into_bytes();
    for at in [8, 12, 20, 28] {
        let mut m = good.clone();
        m[at] = if m[at] == b'A' { b'B' } else { b'A' };
        assert_eq!(s.verify("a", &m, NOW), Err(Rejected::BadTag), "{at}");
    }
}

/// T22: supercookies are refused by the builder and the jar.
#[test]
fn test_t22_jar_supercookie_refused_without_list() {
    let mut jar = Jar::new();
    let url = RequestUrl::https("shop.example.co.uk", "/");
    assert_eq!(
        jar.store(&url, "a=1; Domain=co.uk", NOW),
        StoreOutcome::Ignored(IgnoreReason::DomainNotAllowed)
    );
    assert_eq!(
        jar.store(&url, "a=1; Domain=uk", NOW),
        StoreOutcome::Ignored(IgnoreReason::DomainNotAllowed)
    );
    assert_eq!(
        SetCookie::builder("a", "1")
            .domain("uk")
            .build()
            .unwrap_err(),
        CookieError::InvalidDomain
    );
}

/// T23: no key, token, value, or plaintext reaches `Debug` or `Display`.
#[test]
fn test_t23_secrets_never_printed_by_crypto_and_client_types() {
    let secret = "S3CR3T-0123456789-abcdefghij";
    let s = Signer::new(K1).unwrap();
    let signed = s.sign("prefs", secret).unwrap();
    let verified = s.verify_detailed("prefs", &signed, &[], NOW).unwrap();
    let o = Sealer::new(K1).unwrap();
    let plain = o
        .open("flash", &o.seal("flash", secret).unwrap(), NOW)
        .unwrap();
    let mut jar = Jar::new();
    jar.store(
        &RequestUrl::https("example.com", "/"),
        &format!("sid={secret}")[..],
        NOW,
    );
    let line = format!("sid={secret}; Secure");
    let view = cookie::parse_set_cookie(&line).unwrap();
    let shown = [
        format!("{s:?}"),
        format!("{verified:?}"),
        format!("{o:?}"),
        format!("{plain:?}"),
        format!("{jar:?}"),
        format!("{:?}", jar.cookies().next().unwrap()),
        format!("{view:?}"),
        format!("{:?}", cookie::Key::from(K1)),
        format!("{:?}", KeyRing::new(KeyId(0), K1)),
    ];
    for text in shown {
        assert!(
            !text.contains("S3CR3T") && !text.contains("example key"),
            "{text}"
        );
    }
}

/// T24: the jar's memory is bounded whatever it is sent.
#[test]
fn test_t24_jar_bounded_under_a_flood() {
    let mut jar = Jar::new().with_limits(JarLimits::DEFAULT.per_domain(10).total(50));
    for i in 0..10_000u64 {
        let host = format!("h{}.example", i % 37);
        let big = "v".repeat(4000);
        jar.store(
            &RequestUrl::https(&host, "/"),
            &format!("c{i}={big}")[..],
            NOW + i,
        );
        assert!(jar.len() <= 50);
    }
    assert!(jar.cookies().all(|c| c.name.len() + c.value.len() <= 4096));
}

/// T25: a non-secure origin cannot overwrite or shadow a `Secure` cookie.
#[test]
fn test_t25_jar_insecure_cannot_shadow_secure() {
    let mut jar = Jar::new();
    jar.store(
        &RequestUrl::https("example.com", "/"),
        "sid=real; Secure",
        NOW,
    );
    for line in [
        "sid=evil",
        "sid=evil; Path=/deep",
        "sid=evil; Domain=example.com",
    ] {
        assert_eq!(
            jar.store(&RequestUrl::http("example.com", "/deep/x"), line, NOW),
            StoreOutcome::Ignored(IgnoreReason::WouldShadowSecure),
            "{line}"
        );
    }
}

/// T27: a valid signed or sealed value of one session is refused in another.
#[test]
fn test_t27_session_bound_values_refused_in_another_session() {
    let s = Signer::new(K1).unwrap();
    let v = s.sign_bound("cart", "c-1", b"session-a-digest").unwrap();
    assert_eq!(
        s.verify_bound("cart", &v, b"session-b-digest", NOW),
        Err(Rejected::BadTag)
    );
    let o = Sealer::new(K1).unwrap();
    let sealed = o
        .seal_bound("return_to", "/orders", b"session-a-digest")
        .unwrap();
    assert_eq!(
        o.open_bound("return_to", &sealed, b"session-b-digest", NOW)
            .unwrap_err(),
        Rejected::BadTag
    );
}

/// T29: an extension attribute cannot be read as two words by one parser
/// and one attribute by another.
#[test]
fn test_t29_extension_names_must_be_tokens() {
    for ext in ["x Max-Age=0", " Path=/", "a\tb", "=v"] {
        assert!(
            matches!(
                SetCookie::builder("a", "1").extension(ext).build(),
                Err(CookieError::InvalidExtension { .. })
            ),
            "{ext}"
        );
    }
}

/// T30: a tampered jar export imports nothing.
#[test]
fn test_t30_tampered_jar_export_refused() {
    let mut jar = Jar::new();
    jar.store(
        &RequestUrl::https("example.com", "/"),
        "sid=abc; Secure",
        NOW,
    );
    let bytes = jar.export();
    for i in 0..bytes.len() {
        let mut m = bytes.clone();
        m[i] ^= 0x40;
        let mut target = Jar::new();
        assert_eq!(
            target.import(&m, NOW),
            Err(CookieError::InvalidJarData),
            "byte {i}"
        );
        assert!(target.is_empty());
    }
}
