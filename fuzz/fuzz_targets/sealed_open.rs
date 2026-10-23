#![no_main]

use cookie_net::{KeyId, KeyRing, Sealer};
use libfuzzer_sys::fuzz_target;

// Input: a name, 0x00, a binding, 0x00, a raw value. Opening never panics
// and never succeeds on bytes not made by a sealer with this key; a value
// sealed here opens to the same plaintext, and any change is refused.
fuzz_target!(|data: &[u8]| {
    let mut parts = data.splitn(3, |&b| b == 0);
    let (Some(name), Some(bind), Some(raw)) = (parts.next(), parts.next(), parts.next()) else { return };
    let Ok(name) = core::str::from_utf8(name) else { return };
    let ring = KeyRing::new(KeyId(0), *b"another example key, 32 bytes!!!");
    let s = Sealer::with_ring(ring).unwrap();
    let mut out = Vec::new();
    assert!(s.open_into(name, raw, bind, 0, &mut out).is_err(), "opened a value nobody sealed");
    assert!(out.is_empty());
    let Ok(sealed) = s.seal_bound(name, raw, bind) else { return };
    assert_eq!(s.open_bound(name, &sealed, bind, 0).unwrap().as_bytes(), raw);
    let mut m = sealed.into_bytes();
    let i = usize::from(data.first().copied().unwrap_or(0)) % m.len();
    m[i] ^= data.last().copied().unwrap_or(1) | 1;
    assert!(s.open_bound(name, &m, bind, 0).is_err());
});
