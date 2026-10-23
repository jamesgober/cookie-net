#![no_main]

use cookie_net::{KeyId, KeyRing, Rejected, Signer};
use libfuzzer_sys::fuzz_target;

// Input: a name, 0x00, a binding, 0x00, a raw value. Verification never
// panics; a value that verifies re-signs to the same bytes; a value made
// here verifies, and any change to it is refused.
fuzz_target!(|data: &[u8]| {
    let mut parts = data.splitn(3, |&b| b == 0);
    let (Some(name), Some(bind), Some(raw)) = (parts.next(), parts.next(), parts.next()) else { return };
    let Ok(name) = core::str::from_utf8(name) else { return };
    let ring = KeyRing::new(KeyId(0), *b"an example key, 32 bytes long!!!")
        .accept(KeyId(1), *b"the second key, 32 bytes long!!!")
        .retired(KeyId(2), *b"a retired key..., 32 bytes long!", 1_700_000_000);
    let s = Signer::with_ring(ring).unwrap();
    let now = 1_650_000_000;
    if let Ok(v) = s.verify_detailed(name, raw, bind, now) {
        assert_eq!(v.key, KeyId(0), "only key 0 signs in this target");
        let again = s.sign_into_vec(name, v.value, v.expires, bind);
        assert_eq!(again.as_deref(), Some(raw));
    }
    // sign the raw bytes as a value when they are cookie-octets
    let Ok(value) = core::str::from_utf8(raw) else { return };
    let Ok(signed) = s.sign_bound(name, value, bind) else { return };
    assert_eq!(s.verify_bound(name, &signed, bind, now), Ok(value));
    let mut m = signed.into_bytes();
    let i = usize::from(data.first().copied().unwrap_or(0)) % m.len();
    m[i] ^= data.last().copied().unwrap_or(1) | 1;
    assert!(matches!(
        s.verify_bound(name, &m, bind, now),
        Err(Rejected::Malformed | Rejected::UnsupportedVersion | Rejected::UnknownKey | Rejected::BadTag)
    ));
});

trait SignIntoVec {
    fn sign_into_vec(&self, name: &str, value: &str, expires: Option<u64>, bind: &[u8]) -> Option<Vec<u8>>;
}

impl SignIntoVec for Signer {
    fn sign_into_vec(&self, name: &str, value: &str, expires: Option<u64>, bind: &[u8]) -> Option<Vec<u8>> {
        let mut out = Vec::new();
        self.sign_into(name, value, expires, bind, &mut out).ok()?;
        Some(out)
    }
}
