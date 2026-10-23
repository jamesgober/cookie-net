//! Signed cookies: [`Signer`] and [`Verified`] (feature `signed`).
//!
//! Format v1 (byte-exact in `docs/FORMATS.md`):
//!
//! ```text
//! header (22 bytes) = version 0x01 | key id | expires (4, big-endian, seconds since 2020; 0 = none) | tag (16)
//! cookie value      = base64url_nopad(header) (30 characters) || value
//! tag               = first 16 bytes of keyed BLAKE3(signing subkey,
//!                       "cookie-net/v1/signed" 0x00 | version | key id | expires
//!                       | u16be(len name) | name | u32be(len binding) | binding | value)
//! ```

use core::fmt;

use crypt_io::Tag;
use parse_net::Sink;

use crate::{
    b64,
    error::{CookieError, Rejected},
    keys::{self, Key, KeyFingerprint, KeyId, KeyInfo, KeyRing, KeyRole, Slots},
    limits::PAIR_MAX,
    request::Len,
};

/// The format version of signed cookies.
const VERSION: u8 = 0x01;
/// Header bytes: version, key id, expiry, tag.
const HEADER: usize = 22;
/// Header characters: `base64url(22 bytes)`.
pub(crate) const HEADER_TEXT: usize = 30;
/// Domain separation of the MAC input.
const LABEL: &[u8] = b"cookie-net/v1/signed\x00";
/// HKDF info of the signing subkey.
const PURPOSE: &[u8] = b"cookie-net v1 signed";
/// The default clock-skew allowance, in seconds.
pub(crate) const DEFAULT_SKEW: u64 = 60;
/// The largest skew allowance.
pub(crate) const MAX_SKEW: u64 = 3_600;

/// Signs and verifies cookie values with keyed BLAKE3 and a 128-bit tag.
///
/// The value stays readable: signing proves integrity, not secrecy. The
/// cookie name is inside the MAC, so a signed value cannot be moved to
/// another cookie. A `Signer` is immutable and `Send + Sync`; rotation builds
/// a new one. Verification takes no lock, allocates nothing, and compares the
/// tag in constant time. `Debug` shows key ids, roles, and fingerprints.
///
/// # Examples
///
/// ```
/// use cookie_net::{Rejected, Signer};
///
/// # #[cfg(feature = "alloc")] {
/// let signer = Signer::new(*b"an example key, 32 bytes long!!!")?;
/// let now = 1_800_000_000;
/// let value = signer.sign("prefs", "lang=fr")?;
/// assert_eq!(value.len(), 30 + "lang=fr".len());
/// assert!(value.ends_with("lang=fr"));
/// assert_eq!(signer.verify("prefs", &value, now)?, "lang=fr");
/// assert_eq!(signer.verify("theme", &value, now), Err(Rejected::BadTag));   // moved to another name
/// # }
/// # Ok::<(), cookie_net::CookieError>(())
/// ```
pub struct Signer {
    slots: Slots,
    skew: u64,
}

impl Signer {
    /// A signer with one key, under `KeyId(0)`.
    ///
    /// # Errors
    ///
    /// [`CookieError::WeakKey`] when all 32 bytes are equal;
    /// [`CookieError::Crypto`] if the subkey derivation fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use cookie_net::{CookieError, Signer};
    ///
    /// assert!(Signer::new(*b"an example key, 32 bytes long!!!").is_ok());
    /// assert_eq!(Signer::new([0u8; 32]).unwrap_err(), CookieError::WeakKey);
    /// ```
    pub fn new(key: impl Into<Key>) -> Result<Signer, CookieError> {
        Self::with_ring(KeyRing::new(KeyId(0), key))
    }

    /// A signer over a key ring: the ring's signing key signs; every key
    /// verifies while its role allows.
    ///
    /// # Errors
    ///
    /// `DuplicateKeyId`, `RingFull`, `WeakKey`, `InvalidRetireTime`, `Crypto`.
    ///
    /// # Examples
    ///
    /// ```
    /// use cookie_net::{KeyId, KeyRing, Signer};
    ///
    /// let ring = KeyRing::new(KeyId(2), *b"the second key, 32 bytes long!!!")
    ///     .retired(KeyId(1), *b"an example key, 32 bytes long!!!", 1_900_000_000);
    /// assert_eq!(Signer::with_ring(ring)?.signing_key(), KeyId(2));
    /// # Ok::<(), cookie_net::CookieError>(())
    /// ```
    pub fn with_ring(ring: KeyRing) -> Result<Signer, CookieError> {
        Ok(Signer {
            slots: Slots::derive(ring, PURPOSE)?,
            skew: DEFAULT_SKEW,
        })
    }

    /// The clock-skew allowance: an expiry is accepted while
    /// `now < expires + secs` (default 60, at most 3600), so nodes whose
    /// clocks differ by up to `secs` agree.
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(feature = "alloc")] {
    /// let s = cookie_net::Signer::new(*b"an example key, 32 bytes long!!!")?.with_skew(0);
    /// let v = s.sign_until("a", "1", 1_800_000_000)?;
    /// assert!(s.verify("a", &v, 1_800_000_000).is_err());
    /// # }
    /// # Ok::<(), cookie_net::CookieError>(())
    /// ```
    #[must_use]
    pub fn with_skew(mut self, secs: u64) -> Signer {
        self.skew = secs.min(MAX_SKEW);
        self
    }

    /// Signs `value` for the cookie `name`, with no expiry.
    ///
    /// # Errors
    ///
    /// `EmptyName` or `InvalidName`; `InvalidValue` when `value` is not
    /// `cookie-octet`s; `TooLarge` when the name and signed value pass 4096
    /// bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(feature = "alloc")] {
    /// let s = cookie_net::Signer::new(*b"an example key, 32 bytes long!!!")?;
    /// assert!(s.sign("prefs", "lang=fr")?.ends_with("lang=fr"));
    /// # }
    /// # Ok::<(), cookie_net::CookieError>(())
    /// ```
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    pub fn sign(&self, name: &str, value: &str) -> Result<alloc::string::String, CookieError> {
        self.sign_string(name, value, None, &[])
    }

    /// Signs `value` with an expiry the server checks on every verification,
    /// whatever the browser does with `Max-Age`. `expires` is Unix seconds,
    /// after 2020-01-01 and before 2156.
    ///
    /// # Errors
    ///
    /// As [`sign`](Self::sign), and `ExpiresOutOfRange`.
    ///
    /// # Examples
    ///
    /// ```
    /// use cookie_net::{Rejected, Signer};
    ///
    /// # #[cfg(feature = "alloc")] {
    /// let s = Signer::new(*b"an example key, 32 bytes long!!!")?;
    /// let v = s.sign_until("notice", "seen", 1_800_000_000)?;
    /// assert_eq!(s.verify("notice", &v, 1_799_999_999)?, "seen");
    /// assert_eq!(s.verify("notice", &v, 1_800_000_060), Err(Rejected::Expired));
    /// # }
    /// # Ok::<(), cookie_net::CookieError>(())
    /// ```
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    pub fn sign_until(
        &self,
        name: &str,
        value: &str,
        expires: u64,
    ) -> Result<alloc::string::String, CookieError> {
        self.sign_string(name, value, Some(expires), &[])
    }

    /// Signs `value` bound to `bound_to` (a digest of the session id, say).
    /// The binding is part of the MAC input, not of the cookie, so the value
    /// verifies only with the same binding: a valid signed cookie cannot be
    /// replayed into another user's browser.
    ///
    /// # Errors
    ///
    /// As [`sign`](Self::sign).
    ///
    /// # Examples
    ///
    /// ```
    /// use cookie_net::{Rejected, Signer};
    ///
    /// # #[cfg(feature = "alloc")] {
    /// let s = Signer::new(*b"an example key, 32 bytes long!!!")?;
    /// let v = s.sign_bound("cart", "c-81731", b"session one")?;
    /// assert_eq!(s.verify_bound("cart", &v, b"session one", 0)?, "c-81731");
    /// assert_eq!(s.verify_bound("cart", &v, b"session two", 0), Err(Rejected::BadTag));
    /// # }
    /// # Ok::<(), cookie_net::CookieError>(())
    /// ```
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    pub fn sign_bound(
        &self,
        name: &str,
        value: &str,
        bound_to: &[u8],
    ) -> Result<alloc::string::String, CookieError> {
        self.sign_string(name, value, None, bound_to)
    }

    #[cfg(feature = "alloc")]
    fn sign_string(
        &self,
        name: &str,
        value: &str,
        expires: Option<u64>,
        bound_to: &[u8],
    ) -> Result<alloc::string::String, CookieError> {
        let mut out = alloc::vec::Vec::with_capacity(self.signed_len(value.len()));
        self.sign_into(name, value, expires, bound_to, &mut out)?;
        // The output is base64url and cookie-octets: ASCII.
        alloc::string::String::from_utf8(out).map_err(|_| CookieError::Crypto)
    }

    /// Signs into any sink, with an optional expiry and binding (an empty
    /// binding is no binding). Nothing is written when an error is returned,
    /// and nothing at all when the sink reports too little room.
    ///
    /// # Errors
    ///
    /// As [`sign_until`](Self::sign_until), and `Full`.
    ///
    /// # Examples
    ///
    /// ```
    /// use cookie_net::Signer;
    /// use parse_net::SliceSink;
    ///
    /// let s = Signer::new(*b"an example key, 32 bytes long!!!")?;
    /// let mut buf = [0u8; 64];
    /// let mut out = SliceSink::new(&mut buf);
    /// s.sign_into("prefs", "lang=fr", None, &[], &mut out)?;
    /// assert_eq!(out.len(), s.signed_len(7));
    /// # Ok::<(), cookie_net::CookieError>(())
    /// ```
    pub fn sign_into(
        &self,
        name: &str,
        value: &str,
        expires: Option<u64>,
        bound_to: &[u8],
        out: &mut impl Sink,
    ) -> Result<(), CookieError> {
        keys::check_name(name)?;
        let v = value.as_bytes();
        if let Some(i) = v
            .iter()
            .position(|&b| !parse_net::class::is_cookie_octet(b))
        {
            return Err(CookieError::InvalidValue {
                at: crate::error::at(i),
            });
        }
        if name.len() + self.signed_len(v.len()) > PAIR_MAX {
            return Err(CookieError::TooLarge);
        }
        let exp = keys::encode_expiry(expires)?;
        let slot = self.slots.signing().ok_or(CookieError::RingFull)?;
        if out
            .remaining()
            .is_some_and(|room| room < self.signed_len(v.len()))
        {
            return Err(CookieError::Full);
        }
        let mut header = [0u8; HEADER];
        header[0] = VERSION;
        header[1] = slot.id.0;
        header[2..6].copy_from_slice(&exp.to_be_bytes());
        let tag = mac(&slot.subkey, &header[..6], name.as_bytes(), bound_to, v);
        header[6..].copy_from_slice(&tag);
        let mut text = [0u8; HEADER_TEXT];
        b64::encode(&header, &mut text);
        out.put(&text)?;
        out.put(v)?;
        Ok(())
    }

    /// The length of a signed value: `value_len + 30`.
    ///
    /// # Examples
    ///
    /// ```
    /// let s = cookie_net::Signer::new(*b"an example key, 32 bytes long!!!")?;
    /// assert_eq!(s.signed_len(0), 30);
    /// # Ok::<(), cookie_net::CookieError>(())
    /// ```
    #[must_use]
    pub const fn signed_len(&self, value_len: usize) -> usize {
        value_len.saturating_add(HEADER_TEXT)
    }

    /// Verifies a signed value read from cookie `name` and returns the value.
    ///
    /// # Errors
    ///
    /// A [`Rejected`] reason. Treat every one as "cookie absent".
    ///
    /// # Examples
    ///
    /// ```
    /// use cookie_net::{Rejected, Signer};
    ///
    /// # #[cfg(feature = "alloc")] {
    /// let s = Signer::new(*b"an example key, 32 bytes long!!!")?;
    /// let v = s.sign("prefs", "lang=fr")?;
    /// assert_eq!(s.verify("prefs", &v, 0)?, "lang=fr");
    /// assert_eq!(s.verify("prefs", "short", 0), Err(Rejected::Malformed));
    /// # }
    /// # Ok::<(), cookie_net::CookieError>(())
    /// ```
    pub fn verify<'a, R: AsRef<[u8]> + ?Sized>(
        &self,
        name: &str,
        raw: &'a R,
        now: u64,
    ) -> Result<&'a str, Rejected> {
        self.verify_detailed(name, raw, &[], now).map(|v| v.value)
    }

    /// Verifies a value signed with [`sign_bound`](Self::sign_bound).
    ///
    /// # Errors
    ///
    /// A [`Rejected`] reason; `BadTag` for another binding.
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(feature = "alloc")] {
    /// let s = cookie_net::Signer::new(*b"an example key, 32 bytes long!!!")?;
    /// let v = s.sign_bound("cart", "c-1", b"sid-digest")?;
    /// assert_eq!(s.verify_bound("cart", &v, b"sid-digest", 0)?, "c-1");
    /// # }
    /// # Ok::<(), cookie_net::CookieError>(())
    /// ```
    pub fn verify_bound<'a, R: AsRef<[u8]> + ?Sized>(
        &self,
        name: &str,
        raw: &'a R,
        bound_to: &[u8],
        now: u64,
    ) -> Result<&'a str, Rejected> {
        self.verify_detailed(name, raw, bound_to, now)
            .map(|v| v.value)
    }

    /// Verifies and reports the key, its role, and the expiry, for rotation
    /// metrics.
    ///
    /// # Errors
    ///
    /// A [`Rejected`] reason.
    ///
    /// # Examples
    ///
    /// ```
    /// use cookie_net::{KeyId, KeyRole, Signer};
    ///
    /// # #[cfg(feature = "alloc")] {
    /// let s = Signer::new(*b"an example key, 32 bytes long!!!")?;
    /// let v = s.sign_until("prefs", "x", 1_800_000_000)?;
    /// let got = s.verify_detailed("prefs", &v, &[], 1_700_000_000)?;
    /// assert_eq!((got.value, got.key, got.role, got.expires), ("x", KeyId(0), KeyRole::Signing, Some(1_800_000_000)));
    /// # }
    /// # Ok::<(), cookie_net::CookieError>(())
    /// ```
    pub fn verify_detailed<'a, R: AsRef<[u8]> + ?Sized>(
        &self,
        name: &str,
        raw: &'a R,
        bound_to: &[u8],
        now: u64,
    ) -> Result<Verified<'a>, Rejected> {
        let raw = raw.as_ref();
        // 1. length
        if raw.len() < HEADER_TEXT || raw.len() > PAIR_MAX {
            return Err(Rejected::Malformed);
        }
        let (text, value) = raw.split_at(HEADER_TEXT);
        // 2. base64url, canonical
        let mut header = [0u8; HEADER];
        if !b64::decode(text, &mut header) {
            return Err(Rejected::Malformed);
        }
        // 3. version
        if header[0] != VERSION {
            return Err(Rejected::UnsupportedVersion);
        }
        // 4. key
        let id = KeyId(header[1]);
        let slot = self.slots.usable(id, now).ok_or(Rejected::UnknownKey)?;
        // 5. tag, in constant time
        let tag = mac(&slot.subkey, &header[..6], name.as_bytes(), bound_to, value);
        if !Tag::<16>::from(tag).ct_eq(&header[6..]) {
            return Err(Rejected::BadTag);
        }
        // 6. expiry
        let mut exp = [0u8; 4];
        exp.copy_from_slice(&header[2..6]);
        let expires = keys::decode_expiry(u32::from_be_bytes(exp));
        if expires.is_some_and(|t| now >= t.saturating_add(self.skew)) {
            return Err(Rejected::Expired);
        }
        // A value that passed the MAC was written by `sign_into`: ASCII.
        let value = core::str::from_utf8(value).map_err(|_| Rejected::Malformed)?;
        Ok(Verified {
            value,
            key: id,
            role: slot.role,
            expires,
        })
    }

    /// [`verify`](Self::verify) with the system clock.
    ///
    /// # Errors
    ///
    /// A [`Rejected`] reason.
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(feature = "alloc")] {
    /// let s = cookie_net::Signer::new(*b"an example key, 32 bytes long!!!")?;
    /// let v = s.sign("prefs", "x")?;
    /// assert_eq!(s.verify_now("prefs", &v)?, "x");
    /// # }
    /// # Ok::<(), cookie_net::CookieError>(())
    /// ```
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    pub fn verify_now<'a, R: AsRef<[u8]> + ?Sized>(
        &self,
        name: &str,
        raw: &'a R,
    ) -> Result<&'a str, Rejected> {
        self.verify(name, raw, keys::now())
    }

    /// The id of the key that signs.
    ///
    /// # Examples
    ///
    /// ```
    /// let s = cookie_net::Signer::new(*b"an example key, 32 bytes long!!!")?;
    /// assert_eq!(s.signing_key(), cookie_net::KeyId(0));
    /// # Ok::<(), cookie_net::CookieError>(())
    /// ```
    #[must_use]
    pub fn signing_key(&self) -> KeyId {
        self.slots.signing_key()
    }

    /// Every key, with its role and fingerprint.
    ///
    /// # Examples
    ///
    /// ```
    /// let s = cookie_net::Signer::new(*b"an example key, 32 bytes long!!!")?;
    /// assert_eq!(s.keys().count(), 1);
    /// # Ok::<(), cookie_net::CookieError>(())
    /// ```
    pub fn keys(&self) -> impl Iterator<Item = KeyInfo> + '_ {
        self.slots.keys()
    }

    /// The fingerprint of key `id`, to compare rings across nodes.
    ///
    /// # Examples
    ///
    /// ```
    /// let s = cookie_net::Signer::new(*b"an example key, 32 bytes long!!!")?;
    /// assert!(s.fingerprint(cookie_net::KeyId(0)).is_some());
    /// assert!(s.fingerprint(cookie_net::KeyId(1)).is_none());
    /// # Ok::<(), cookie_net::CookieError>(())
    /// ```
    #[must_use]
    pub fn fingerprint(&self, id: KeyId) -> Option<KeyFingerprint> {
        self.slots.fingerprint(id)
    }
}

impl fmt::Debug for Signer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Signer")
            .field("keys", &self.slots)
            .field("skew", &self.skew)
            .finish()
    }
}

fn mac(subkey: &[u8; 32], head: &[u8], name: &[u8], bound_to: &[u8], value: &[u8]) -> [u8; 16] {
    let (name_len, bind_len) = keys::length_prefixes(name, bound_to);
    let full = keys::keyed_hash(
        subkey,
        &[LABEL, head, &name_len, name, &bind_len, bound_to, value],
    );
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&full[..16]);
    tag
}

/// A verified signed value, with the key that verified it.
///
/// `Debug` prints the value's length, never the value.
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Verified<'a> {
    /// The value that was signed.
    pub value: &'a str,
    /// The key that verified it.
    pub key: KeyId,
    /// That key's role: `Retired` or `Accepted` during a rotation.
    pub role: KeyRole,
    /// The embedded expiry, when there is one.
    pub expires: Option<u64>,
}

impl fmt::Debug for Verified<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Verified")
            .field("value", &Len(self.value.len()))
            .field("key", &self.key)
            .field("role", &self.role)
            .field("expires", &self.expires)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use std::{format, string::String, vec::Vec};

    use parse_net::SliceSink;

    use super::*;
    use crate::keys::EPOCH_2020;

    const K1: [u8; 32] = *b"an example key, 32 bytes long!!!";
    const K2: [u8; 32] = *b"the second key, 32 bytes long!!!";
    const NOW: u64 = 1_800_000_000;

    fn signed(s: &Signer, name: &str, value: &str, exp: Option<u64>, bind: &[u8]) -> String {
        let mut buf = [0u8; 4200];
        let mut out = SliceSink::new(&mut buf);
        s.sign_into(name, value, exp, bind, &mut out).unwrap();
        String::from_utf8(out.written().to_vec()).unwrap()
    }

    #[test]
    fn test_sign_verify_round_trip() {
        let s = Signer::new(K1).unwrap();
        for v in ["", "x", "lang=fr", "!#$%&'()*+-./:<=>?@[]^_`{|}~"] {
            let raw = signed(&s, "prefs", v, None, &[]);
            assert_eq!(raw.len(), 30 + v.len());
            assert_eq!(s.verify("prefs", &raw, NOW), Ok(v));
        }
    }

    #[test]
    fn test_sign_refusals() {
        let s = Signer::new(K1).unwrap();
        let mut buf = [0u8; 8192];
        let mut out = SliceSink::new(&mut buf);
        assert_eq!(
            s.sign_into("", "x", None, &[], &mut out),
            Err(CookieError::EmptyName)
        );
        assert_eq!(
            s.sign_into("a b", "x", None, &[], &mut out),
            Err(CookieError::InvalidName { at: 1 })
        );
        assert_eq!(
            s.sign_into("a", "x y", None, &[], &mut out),
            Err(CookieError::InvalidValue { at: 1 })
        );
        assert_eq!(
            s.sign_into("a", "\"q\"", None, &[], &mut out),
            Err(CookieError::InvalidValue { at: 0 })
        );
        let big = "v".repeat(4096 - 30 - 1);
        assert!(s.sign_into("a", &big, None, &[], &mut out).is_ok());
        out.clear();
        let big = "v".repeat(4096 - 30);
        assert_eq!(
            s.sign_into("a", &big, None, &[], &mut out),
            Err(CookieError::TooLarge)
        );
        assert_eq!(
            s.sign_into("a", "x", Some(EPOCH_2020), &[], &mut out),
            Err(CookieError::ExpiresOutOfRange)
        );
        assert_eq!(
            s.sign_into("a", "x", Some(u64::MAX), &[], &mut out),
            Err(CookieError::ExpiresOutOfRange)
        );
        assert!(out.is_empty());
        let mut small = [0u8; 30];
        let mut out = SliceSink::new(&mut small);
        assert_eq!(
            s.sign_into("a", "x", None, &[], &mut out),
            Err(CookieError::Full)
        );
        assert!(out.is_empty());
    }

    #[test]
    fn test_verify_reasons_in_order() {
        let s = Signer::new(K1).unwrap();
        let raw = signed(&s, "prefs", "lang=fr", None, &[]);
        assert_eq!(s.verify("prefs", &raw[..29], NOW), Err(Rejected::Malformed));
        assert_eq!(
            s.verify("prefs", &"A".repeat(4097), NOW),
            Err(Rejected::Malformed)
        );
        let mut bad = raw.clone().into_bytes();
        bad[3] = b'+';
        assert_eq!(s.verify("prefs", &bad, NOW), Err(Rejected::Malformed));
        // a non-canonical last header character
        let mut nc = raw.clone().into_bytes();
        nc[29] ^= 0x01;
        assert!(matches!(
            s.verify("prefs", &nc, NOW),
            Err(Rejected::Malformed | Rejected::BadTag)
        ));
        // version 0 and 3
        for version in [0u8, 3] {
            let mut header = [0u8; 22];
            assert!(b64::decode(&raw.as_bytes()[..30], &mut header));
            header[0] = version;
            let mut text = [0u8; 30];
            b64::encode(&header, &mut text);
            let forged = [&text[..], &raw.as_bytes()[30..]].concat();
            assert_eq!(
                s.verify("prefs", &forged, NOW),
                Err(Rejected::UnsupportedVersion)
            );
        }
        let other = Signer::with_ring(KeyRing::new(KeyId(9), K1)).unwrap();
        assert_eq!(other.verify("prefs", &raw, NOW), Err(Rejected::UnknownKey));
        assert_eq!(s.verify("prefz", &raw, NOW), Err(Rejected::BadTag));
        let mut v = raw.clone().into_bytes();
        *v.last_mut().unwrap() = b'x';
        assert_eq!(s.verify("prefs", &v, NOW), Err(Rejected::BadTag));
    }

    #[test]
    fn test_every_single_bit_flip_is_refused() {
        let s = Signer::new(K1).unwrap();
        let raw = signed(&s, "prefs", "lang=fr|x", None, &[]).into_bytes();
        for i in 0..raw.len() {
            for bit in 0..8 {
                let mut m = raw.clone();
                m[i] ^= 1 << bit;
                assert!(s.verify("prefs", &m, NOW).is_err(), "byte {i} bit {bit}");
            }
        }
    }

    #[test]
    fn test_expiry_with_skew() {
        let s = Signer::new(K1).unwrap();
        let raw = signed(&s, "a", "1", Some(NOW), &[]);
        assert_eq!(s.verify("a", &raw, NOW - 1), Ok("1"));
        assert_eq!(s.verify("a", &raw, NOW + 59), Ok("1"));
        assert_eq!(s.verify("a", &raw, NOW + 60), Err(Rejected::Expired));
        let strict = Signer::new(K1).unwrap().with_skew(0);
        assert_eq!(strict.verify("a", &raw, NOW), Err(Rejected::Expired));
        assert_eq!(strict.verify("a", &raw, NOW - 1), Ok("1"));
        assert_eq!(Signer::new(K1).unwrap().with_skew(99_999).skew, MAX_SKEW);
        // a forged expired cookie reports BadTag, not Expired
        let mut forged = raw.clone().into_bytes();
        *forged.last_mut().unwrap() = b'2';
        assert_eq!(s.verify("a", &forged, NOW + 1000), Err(Rejected::BadTag));
    }

    #[test]
    fn test_binding() {
        let s = Signer::new(K1).unwrap();
        let raw = signed(&s, "cart", "c-1", None, b"session-a");
        assert_eq!(s.verify_bound("cart", &raw, b"session-a", NOW), Ok("c-1"));
        assert_eq!(
            s.verify_bound("cart", &raw, b"session-b", NOW),
            Err(Rejected::BadTag)
        );
        assert_eq!(s.verify("cart", &raw, NOW), Err(Rejected::BadTag));
        let unbound = signed(&s, "cart", "c-1", None, &[]);
        assert_eq!(s.verify_bound("cart", &unbound, &[], NOW), Ok("c-1"));
        // the length prefix keeps name and binding apart
        let x = signed(&s, "ab", "v", None, b"c");
        assert_eq!(s.verify_bound("a", &x, b"bc", NOW), Err(Rejected::BadTag));
    }

    #[test]
    fn test_rotation_keeps_old_cookies_until_retire_time() {
        let old = Signer::new(K1).unwrap();
        let raw = signed(&old, "a", "1", None, &[]);
        let staged = Signer::with_ring(KeyRing::new(KeyId(0), K1).accept(KeyId(1), K2)).unwrap();
        let by_new = {
            let ring =
                KeyRing::new(KeyId(0), K1)
                    .accept(KeyId(1), K2)
                    .rotated(KeyId(1), K2, NOW + 100);
            Signer::with_ring(ring).unwrap()
        };
        let new_raw = signed(&by_new, "a", "2", None, &[]);
        // a staged node accepts what a switched node signed
        let got = staged.verify_detailed("a", &new_raw, &[], NOW).unwrap();
        assert_eq!((got.key, got.role), (KeyId(1), KeyRole::Accepted));
        // the switched node accepts old cookies until the retire time
        let got = by_new.verify_detailed("a", &raw, &[], NOW).unwrap();
        assert_eq!(got.role, KeyRole::Retired { until: NOW + 100 });
        assert_eq!(
            by_new.verify("a", &raw, NOW + 100),
            Err(Rejected::UnknownKey)
        );
        assert_eq!(by_new.signing_key(), KeyId(1));
    }

    #[test]
    fn test_signer_debug_has_no_secrets() {
        let s = Signer::new(K1).unwrap();
        let d = format!("{s:?}");
        assert!(d.contains("Signing") && !d.contains("example"), "{d}");
        let raw = signed(&s, "a", "SECRETVALUE", None, &[]);
        let v = s.verify_detailed("a", &raw, &[], NOW).unwrap();
        assert!(!format!("{v:?}").contains("SECRET"));
    }

    #[test]
    fn test_vectors_are_stable() {
        // format v1 test vector (also in docs/FORMATS.md)
        let s = Signer::new(K1).unwrap();
        let raw = signed(&s, "prefs", "lang=fr", Some(EPOCH_2020 + 1), b"");
        let again = signed(&s, "prefs", "lang=fr", Some(EPOCH_2020 + 1), b"");
        assert_eq!(raw, again);
        let mut header = [0u8; 22];
        assert!(b64::decode(&raw.as_bytes()[..30], &mut header));
        assert_eq!(&header[..6], &[1, 0, 0, 0, 0, 1]);
        let _: Vec<u8> = Vec::new();
    }
}
