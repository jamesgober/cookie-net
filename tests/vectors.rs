//! Format v1 test vectors, the same as in docs/FORMATS.md. Any change here
//! is a format change and needs a new version byte.

#![cfg(feature = "encrypted")]

use cookie_net::{Key, KeyId, KeyRing, Sealer, Signer};

const KEY: [u8; 32] = *b"an example key, 32 bytes long!!!";

#[test]
fn test_signed_vectors() {
    let s = Signer::new(KEY).unwrap();
    assert_eq!(
        s.sign("prefs", "lang=fr").unwrap(),
        "AQAAAAAAhfXF4159Jdt-UI1cyLRlBQlang=fr"
    );
    assert_eq!(
        s.sign_until("prefs", "lang=fr", 1_800_000_000).unwrap(),
        "AQANPfEAhdsBFt9CEWgSKtEHwEA57glang=fr"
    );
    assert_eq!(
        s.sign_bound("cart", "c-81731", b"session-digest").unwrap(),
        "AQAAAAAADU2S5JDhYllf0TPv6lTLiAc-81731"
    );
    let r = Signer::with_ring(KeyRing::new(KeyId(7), KEY)).unwrap();
    assert_eq!(
        r.sign("prefs", "").unwrap(),
        "AQcAAAAAhZgoFuZTF4B7mPpB7mWYrQ"
    );
    assert_eq!(
        s.fingerprint(KeyId(0)).unwrap().to_string(),
        "a61431af66c98393"
    );
}

#[test]
fn test_sealed_vectors_open() {
    let o = Sealer::new(KEY).unwrap();
    assert_eq!(
        o.fingerprint(KeyId(0)).unwrap().to_string(),
        "d55b16096c4e8786"
    );
    let v1 = "AgAAAAAAzGjJwQDAVhz2jWtZvKYe-3dsf_AHgYGeiTeQ0Hhrq4PMphuNs2yOW4JW3vGsMA";
    let v2 = "AgANPfEA4tMKDOdxtSjBrgzj-FcQeXwwoTaN4xLq31PS2OBrq2b1HdbSZe2J3u-wl0PQ2g";
    assert_eq!(
        o.open("flash", v1, 1_900_000_000).unwrap().as_bytes(),
        b"Saved."
    );
    assert_eq!(
        o.open("flash", v2, 1_799_999_999).unwrap().as_bytes(),
        b"Saved."
    );
    assert!(o.open("flash", v2, 1_800_000_060).is_err());
}

#[test]
fn test_derived_key_vector() {
    let master: Vec<u8> = (0u8..32).map(|i| 0x42 ^ i).collect();
    let k = Key::derive(&master, b"wasp-web").unwrap();
    assert_eq!(
        Signer::new(k)
            .unwrap()
            .fingerprint(KeyId(0))
            .unwrap()
            .to_string(),
        "aa76cfb6e1d139f8"
    );
}
