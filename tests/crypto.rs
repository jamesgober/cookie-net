//! Signed and encrypted cookies: properties (dev/DIRECTIVES.md section 4),
//! a two-node rotation simulation, and the flows WASP uses them for.

#![cfg(all(feature = "signed", feature = "encrypted"))]

use cookie_net::{
    self as cookie, Key, KeyId, KeyRing, KeyRole, Rejected, Sealer, SetCookie, Signer,
};
use proptest::prelude::*;

const K1: [u8; 32] = *b"an example key, 32 bytes long!!!";
const K2: [u8; 32] = *b"the second key, 32 bytes long!!!";
const NOW: u64 = 1_800_000_000;

fn octets() -> impl Strategy<Value = String> {
    proptest::string::string_regex("[!#-+\\--:<-\\[\\]-~]{0,60}").unwrap()
}

fn name() -> impl Strategy<Value = String> {
    proptest::string::string_regex("[A-Za-z0-9_.-]{1,12}").unwrap()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// Signing then verifying passes; any other name, binding, or key fails.
    #[test]
    fn prop_signed_round_trip_and_isolation(
        n in name(), other in name(), v in octets(),
        bind in proptest::collection::vec(any::<u8>(), 0..40),
        other_bind in proptest::collection::vec(any::<u8>(), 0..40),
    ) {
        let s = Signer::new(K1).unwrap();
        let raw = s.sign_bound(&n, &v, &bind).unwrap();
        prop_assert_eq!(s.verify_bound(&n, &raw, &bind, NOW), Ok(v.as_str()));
        if other != n {
            prop_assert_eq!(s.verify_bound(&other, &raw, &bind, NOW), Err(Rejected::BadTag));
        }
        if other_bind != bind {
            prop_assert_eq!(s.verify_bound(&n, &raw, &other_bind, NOW), Err(Rejected::BadTag));
        }
        let k2 = Signer::new(K2).unwrap();
        prop_assert_eq!(k2.verify_bound(&n, &raw, &bind, NOW), Err(Rejected::BadTag));
    }

    /// Any change to a signed value is refused.
    #[test]
    fn prop_signed_any_change_refused(v in octets(), at in any::<prop::sample::Index>(), byte in any::<u8>()) {
        let s = Signer::new(K1).unwrap();
        let raw = s.sign("a", &v).unwrap().into_bytes();
        let i = at.index(raw.len());
        let mut m = raw.clone();
        m[i] = byte;
        if m != raw {
            prop_assert!(s.verify("a", &m, NOW).is_err());
        }
    }

    /// Sealing then opening passes; any other name, binding, key, or change fails.
    #[test]
    fn prop_sealed_round_trip_and_isolation(
        n in name(), other in name(),
        p in proptest::collection::vec(any::<u8>(), 0..200),
        bind in proptest::collection::vec(any::<u8>(), 0..40),
        at in any::<prop::sample::Index>(), byte in any::<u8>(),
    ) {
        let s = Sealer::new(K1).unwrap();
        let raw = s.seal_bound(&n, &p, &bind).unwrap();
        let opened = s.open_bound(&n, &raw, &bind, NOW).unwrap();
        prop_assert_eq!(opened.as_bytes(), &p[..]);
        if other != n {
            prop_assert_eq!(s.open_bound(&other, &raw, &bind, NOW).unwrap_err(), Rejected::BadTag);
        }
        prop_assert!(Sealer::new(K2).unwrap().open_bound(&n, &raw, &bind, NOW).is_err());
        let mut m = raw.clone().into_bytes();
        let i = at.index(m.len());
        m[i] = byte;
        if m != raw.as_bytes() {
            prop_assert!(s.open_bound(&n, &m, &bind, NOW).is_err());
        }
    }

    /// Verification never panics on any input.
    #[test]
    fn prop_verify_and_open_never_panic(raw in proptest::collection::vec(any::<u8>(), 0..300)) {
        let s = Signer::new(K1).unwrap();
        let _ = s.verify("a", &raw, NOW);
        let o = Sealer::new(K1).unwrap();
        let _ = o.open("a", &raw, NOW);
    }
}

/// Two nodes, staged rotation: at no step does either node refuse a cookie
/// the other just made.
#[test]
fn test_two_node_staged_rotation_refuses_nothing() {
    let t = NOW + 3600;
    let v1 = || KeyRing::new(KeyId(1), K1);
    let staged = || KeyRing::new(KeyId(1), K1).accept(KeyId(2), K2);
    let switched = || staged().rotated(KeyId(2), K2, t);
    let dropped = || KeyRing::new(KeyId(2), K2);

    // step 0: both nodes on v1
    let a = Signer::with_ring(v1()).unwrap();
    let old_cookie = a.sign("prefs", "v1").unwrap();
    // step 1: node A staged, node B still v1: both sign with key 1
    let (a, b) = (
        Signer::with_ring(staged()).unwrap(),
        Signer::with_ring(v1()).unwrap(),
    );
    for (x, y) in [(&a, &b), (&b, &a)] {
        assert!(
            y.verify("prefs", &x.sign("prefs", "s1").unwrap(), NOW)
                .is_ok()
        );
    }
    // step 2: node A switched, node B staged: A signs with key 2, B accepts it
    let (a, b) = (
        Signer::with_ring(switched()).unwrap(),
        Signer::with_ring(staged()).unwrap(),
    );
    for (x, y) in [(&a, &b), (&b, &a)] {
        assert!(
            y.verify("prefs", &x.sign("prefs", "s2").unwrap(), NOW)
                .is_ok()
        );
    }
    assert_eq!(
        a.verify_detailed("prefs", &old_cookie, &[], NOW)
            .unwrap()
            .role,
        KeyRole::Retired { until: t }
    );
    // step 3: both switched
    let (a, b) = (
        Signer::with_ring(switched()).unwrap(),
        Signer::with_ring(switched()).unwrap(),
    );
    assert!(
        b.verify("prefs", &a.sign("prefs", "s3").unwrap(), NOW)
            .is_ok()
    );
    assert!(a.verify("prefs", &old_cookie, t - 1).is_ok());
    // step 4: after t, key 1 is dropped; its cookies are UnknownKey
    let a = Signer::with_ring(dropped()).unwrap();
    assert_eq!(a.verify("prefs", &old_cookie, t), Err(Rejected::UnknownKey));
    // fingerprints agree across nodes holding the same key
    let (x, y) = (
        Signer::with_ring(staged()).unwrap(),
        Signer::with_ring(switched()).unwrap(),
    );
    assert_eq!(x.fingerprint(KeyId(2)), y.fingerprint(KeyId(2)));
}

/// One master serves signing and sealing for several services, and nothing
/// made for one verifies for another.
#[test]
fn test_one_master_many_services() {
    let master = [0x2au8; 32]
        .map(|b| b ^ 0x5c)
        .iter()
        .enumerate()
        .map(|(i, b)| b ^ i as u8)
        .collect::<Vec<u8>>();
    let web = Key::derive(&master, b"wasp-web").unwrap();
    let api = Key::derive(&master, b"wasp-api").unwrap();
    let (web_signer, api_signer) = (Signer::new(web.clone()).unwrap(), Signer::new(api).unwrap());
    let v = web_signer.sign("prefs", "x").unwrap();
    assert_eq!(api_signer.verify("prefs", &v, NOW), Err(Rejected::BadTag));
    // the same key feeds a sealer with a separate subkey
    let web_sealer = Sealer::new(web).unwrap();
    assert_ne!(
        web_signer.fingerprint(KeyId(0)),
        web_sealer.fingerprint(KeyId(0))
    );
}

/// A flash message: seal, set, read, open, delete.
#[test]
fn test_flash_message_flow() {
    let sealer = Sealer::new(K1).unwrap();
    let v = sealer
        .seal_until("flash", "Payment received, Ana.", NOW + 60)
        .unwrap();
    let set = SetCookie::builder("flash", &v).max_age(60).build().unwrap();
    let header = format!("theme=dark; {}={}", set.name(), set.value());
    let raw = cookie::get(&header, "flash").unwrap();
    assert_eq!(
        sealer.open("flash", raw, NOW + 1).unwrap().as_str(),
        Some("Payment received, Ana.")
    );
    assert!(SetCookie::delete("flash").unwrap().is_deletion());
}

/// A signed preference fits a `Set-Cookie` value as it is.
#[test]
fn test_signed_value_is_a_valid_cookie_value() {
    let signer = Signer::new(K1).unwrap();
    let v = signer
        .sign_until("plan_banner", "dismissed", NOW + cookie::DAY)
        .unwrap();
    let set = SetCookie::builder("plan_banner", &v)
        .max_age(cookie::DAY)
        .build()
        .unwrap();
    let header = format!("{}={}", set.name(), set.value());
    assert_eq!(
        signer
            .verify(
                "plan_banner",
                cookie::get(&header, "plan_banner").unwrap(),
                NOW
            )
            .unwrap(),
        "dismissed"
    );
}

/// Constant-time smoke test (dudect method, short). Two classes of forgery:
/// one wrong in the first tag byte, one wrong only in the last. A comparison
/// that returned at the first differing byte would refuse the first class
/// sooner. The MAC computation dominates the timing, so this catches gross
/// leaks (an early exit before or inside the MAC), not cycle-level ones; the
/// tag compare itself is crypt-io's `Tag::ct_eq`, and the long statistical
/// run happens before 1.0.
#[test]
fn test_tag_comparison_time_does_not_depend_on_matching_prefix() {
    use std::{hint::black_box, time::Instant};
    let s = Signer::new(K1).unwrap();
    let good = s.sign("a", "value").unwrap().into_bytes();
    // header characters 8 and 28 hold the top bits of the first and the last
    // tag byte; replacing either with another alphabet character stays
    // canonical and changes only that byte
    let swap = |raw: &[u8], at: usize| {
        let mut m = raw.to_vec();
        m[at] = if m[at] == b'A' { b'B' } else { b'A' };
        m
    };
    let (first_wrong, last_wrong) = (swap(&good, 8), swap(&good, 28));
    assert_eq!(s.verify("a", &first_wrong, NOW), Err(Rejected::BadTag));
    assert_eq!(s.verify("a", &last_wrong, NOW), Err(Rejected::BadTag));
    let median = |raw: &[u8]| {
        let mut v: Vec<u128> = (0..1500)
            .map(|_| {
                let t = Instant::now();
                for _ in 0..40 {
                    let _ = black_box(s.verify("a", black_box(raw), NOW));
                }
                t.elapsed().as_nanos()
            })
            .collect();
        v.sort_unstable();
        v[v.len() / 2] as f64
    };
    // interleave the classes so drift on a busy machine hits both
    let (mut a, mut b) = (0.0, 0.0);
    for _ in 0..3 {
        a += median(&first_wrong);
        b += median(&last_wrong);
    }
    let ratio = if a > b { a / b } else { b / a };
    assert!(
        ratio < 1.25,
        "median times {a} and {b} differ by {ratio:.2}x"
    );
}
