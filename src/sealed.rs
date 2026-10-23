//! Encrypted cookies: [`Sealer`], [`Plaintext`], [`Opened`] (feature
//! `encrypted`).
//!
//! Format v1 (byte-exact in `docs/FORMATS.md`):
//!
//! ```text
//! bytes        = version 0x02 | key id | expires (4) | nonce (24) | ciphertext (n) | tag (16)
//! cookie value = base64url_nopad(bytes)
//! AEAD         = XChaCha20-Poly1305 under the sealing subkey, random 192-bit nonce
//! AAD          = "cookie-net/v1/sealed" 0x00 | version | key id | expires
//!                | keyed BLAKE3(sealing subkey, u16be(len name) | name | u32be(len binding) | binding)
//! ```

use alloc::{string::String, vec::Vec};
use core::fmt;

use crypt_io::{Crypt, Zeroizing};
use parse_net::Sink;

use crate::{
    b64,
    error::{CookieError, Rejected},
    keys::{self, Key, KeyFingerprint, KeyId, KeyInfo, KeyRing, KeyRole, Slots},
    limits::PAIR_MAX,
    signed::{DEFAULT_SKEW, MAX_SKEW},
};

/// The format version of sealed cookies.
const VERSION: u8 = 0x02;
/// Version, key id, expiry.
const HEADER: usize = 6;
/// Header, nonce, and tag.
const OVERHEAD: usize = HEADER + 24 + 16;
/// Domain separation of the associated data.
const LABEL: &[u8] = b"cookie-net/v1/sealed\x00";
/// HKDF info of the sealing subkey.
const PURPOSE: &[u8] = b"cookie-net v1 sealed";
/// The associated data: label, header, and the name-and-binding digest.
const AAD: usize = LABEL.len() + HEADER + 32;
/// The largest decoded sealed value: 4096 characters of base64url.
const MAX_BYTES: usize = PAIR_MAX / 4 * 3;
/// Bytes encoded per output chunk (a multiple of 3, so chunks join cleanly).
const CHUNK: usize = 768;

/// Encrypts and opens cookie values with XChaCha20-Poly1305.
///
/// The cookie name, the header, and an optional binding are associated
/// data, so a sealed value cannot be moved to another name or session. A
/// random 192-bit nonce per cookie means nonces never collide in practice,
/// however many cookies one key seals. A `Sealer` is immutable and
/// `Send + Sync`; any node with the same ring opens what another sealed.
///
/// # Examples
///
/// ```
/// use cookie_net::{self as cookie, Sealer};
///
/// let sealer = Sealer::new(*b"another example key, 32 bytes!!!")?;
/// let now = 1_800_000_000;
/// let v = sealer.seal_until("flash", "Saved your address, Ana.", now + 5 * cookie::MINUTE)?;
/// let text = sealer.open("flash", &v, now)?;
/// assert_eq!(text.as_str(), Some("Saved your address, Ana."));
/// assert!(sealer.open("flash", &v, now + 10 * cookie::MINUTE).is_err());
/// # Ok::<(), cookie::CookieError>(())
/// ```
pub struct Sealer {
    slots: Slots,
    skew: u64,
    crypt: Crypt,
}

impl Sealer {
    /// A sealer with one key, under `KeyId(0)`. The sealing subkey is derived
    /// separately from any signing subkey, so one key can feed both.
    ///
    /// # Errors
    ///
    /// [`CookieError::WeakKey`], [`CookieError::Crypto`].
    ///
    /// # Examples
    ///
    /// ```
    /// assert!(cookie_net::Sealer::new(*b"another example key, 32 bytes!!!").is_ok());
    /// ```
    pub fn new(key: impl Into<Key>) -> Result<Sealer, CookieError> {
        Self::with_ring(KeyRing::new(KeyId(0), key))
    }

    /// A sealer over a key ring.
    ///
    /// # Errors
    ///
    /// `DuplicateKeyId`, `RingFull`, `WeakKey`, `InvalidRetireTime`, `Crypto`.
    ///
    /// # Examples
    ///
    /// ```
    /// use cookie_net::{KeyId, KeyRing, Sealer};
    ///
    /// let ring = KeyRing::new(KeyId(1), *b"another example key, 32 bytes!!!");
    /// assert_eq!(Sealer::with_ring(ring)?.signing_key(), KeyId(1));
    /// # Ok::<(), cookie_net::CookieError>(())
    /// ```
    pub fn with_ring(ring: KeyRing) -> Result<Sealer, CookieError> {
        Ok(Sealer {
            slots: Slots::derive(ring, PURPOSE)?,
            skew: DEFAULT_SKEW,
            crypt: Crypt::xchacha20_poly1305(),
        })
    }

    /// The clock-skew allowance for expiries (default 60, at most 3600).
    ///
    /// # Examples
    ///
    /// ```
    /// let s = cookie_net::Sealer::new(*b"another example key, 32 bytes!!!")?.with_skew(0);
    /// let v = s.seal_until("a", "x", 1_800_000_000)?;
    /// assert!(s.open("a", &v, 1_800_000_000).is_err());
    /// # Ok::<(), cookie_net::CookieError>(())
    /// ```
    #[must_use]
    pub fn with_skew(mut self, secs: u64) -> Sealer {
        self.skew = secs.min(MAX_SKEW);
        self
    }

    /// Seals `plaintext` for the cookie `name`, with no expiry.
    ///
    /// # Errors
    ///
    /// `EmptyName`, `InvalidName`, `TooLarge` (over
    /// [`max_plaintext`](Self::max_plaintext), checked before any crypto),
    /// `Crypto` when the random source fails (nothing is returned).
    ///
    /// # Examples
    ///
    /// ```
    /// let s = cookie_net::Sealer::new(*b"another example key, 32 bytes!!!")?;
    /// let v = s.seal("flash", "Saved.")?;
    /// assert_eq!(v.len(), s.sealed_len(6));
    /// # Ok::<(), cookie_net::CookieError>(())
    /// ```
    pub fn seal<P: AsRef<[u8]> + ?Sized>(
        &self,
        name: &str,
        plaintext: &P,
    ) -> Result<String, CookieError> {
        self.seal_string(name, plaintext.as_ref(), None, &[])
    }

    /// Seals `plaintext` with an expiry the server checks on every opening.
    ///
    /// # Errors
    ///
    /// As [`seal`](Self::seal), and `ExpiresOutOfRange`.
    ///
    /// # Examples
    ///
    /// ```
    /// let s = cookie_net::Sealer::new(*b"another example key, 32 bytes!!!")?;
    /// let v = s.seal_until("flash", "Saved.", 1_800_000_000)?;
    /// assert!(s.open("flash", &v, 1_800_000_000).is_ok());
    /// # Ok::<(), cookie_net::CookieError>(())
    /// ```
    pub fn seal_until<P: AsRef<[u8]> + ?Sized>(
        &self,
        name: &str,
        plaintext: &P,
        expires: u64,
    ) -> Result<String, CookieError> {
        self.seal_string(name, plaintext.as_ref(), Some(expires), &[])
    }

    /// Seals `plaintext` bound to `bound_to` (a digest of the session id, say);
    /// it opens only with the same binding.
    ///
    /// # Errors
    ///
    /// As [`seal`](Self::seal).
    ///
    /// # Examples
    ///
    /// ```
    /// use cookie_net::{Rejected, Sealer};
    ///
    /// let s = Sealer::new(*b"another example key, 32 bytes!!!")?;
    /// let v = s.seal_bound("return_to", "/orders/81", b"session one")?;
    /// assert!(s.open_bound("return_to", &v, b"session one", 0).is_ok());
    /// assert_eq!(s.open_bound("return_to", &v, b"session two", 0).unwrap_err(), Rejected::BadTag);
    /// # Ok::<(), cookie_net::CookieError>(())
    /// ```
    pub fn seal_bound<P: AsRef<[u8]> + ?Sized>(
        &self,
        name: &str,
        plaintext: &P,
        bound_to: &[u8],
    ) -> Result<String, CookieError> {
        self.seal_string(name, plaintext.as_ref(), None, bound_to)
    }

    fn seal_string(
        &self,
        name: &str,
        plaintext: &[u8],
        expires: Option<u64>,
        bound_to: &[u8],
    ) -> Result<String, CookieError> {
        let mut scratch = Vec::new();
        let mut out = Vec::with_capacity(self.sealed_len(plaintext.len()));
        self.seal_into(name, plaintext, expires, bound_to, &mut scratch, &mut out)?;
        // base64url text: ASCII.
        String::from_utf8(out).map_err(|_| CookieError::Crypto)
    }

    /// Seals into any sink, reusing `scratch` for the ciphertext (its
    /// capacity is kept, so steady-state sealing allocates nothing). Nothing
    /// is written when an error is returned, and nothing at all when the sink
    /// reports too little room.
    ///
    /// # Errors
    ///
    /// As [`seal_until`](Self::seal_until), and `Full`.
    ///
    /// # Examples
    ///
    /// ```
    /// let s = cookie_net::Sealer::new(*b"another example key, 32 bytes!!!")?;
    /// let (mut scratch, mut out) = (Vec::new(), Vec::new());
    /// s.seal_into("flash", b"Saved.", None, &[], &mut scratch, &mut out)?;
    /// assert_eq!(out.len(), s.sealed_len(6));
    /// # Ok::<(), cookie_net::CookieError>(())
    /// ```
    pub fn seal_into(
        &self,
        name: &str,
        plaintext: &[u8],
        expires: Option<u64>,
        bound_to: &[u8],
        scratch: &mut Vec<u8>,
        out: &mut impl Sink,
    ) -> Result<(), CookieError> {
        keys::check_name(name)?;
        if plaintext.len() > self.max_plaintext(name.len()) {
            return Err(CookieError::TooLarge);
        }
        let exp = keys::encode_expiry(expires)?;
        let slot = self.slots.signing().ok_or(CookieError::RingFull)?;
        let text_len = self.sealed_len(plaintext.len());
        if out.remaining().is_some_and(|room| room < text_len) {
            return Err(CookieError::Full);
        }
        let mut header = [0u8; HEADER];
        header[0] = VERSION;
        header[1] = slot.id.0;
        header[2..].copy_from_slice(&exp.to_be_bytes());
        let aad = aad(&slot.subkey, &header, name.as_bytes(), bound_to);
        self.crypt
            .encrypt_with_aad_into(&slot.subkey[..], plaintext, &aad, scratch)
            .map_err(|_| CookieError::Crypto)?;
        // The header is two whole base64 groups, so it encodes on its own.
        let mut text = [0u8; CHUNK / 3 * 4];
        b64::encode(&header, &mut text[..8]);
        out.put(&text[..8])?;
        for chunk in scratch.chunks(CHUNK) {
            let n = b64::encoded_len(chunk.len());
            let dst = text.get_mut(..n).ok_or(CookieError::Full)?;
            b64::encode(chunk, dst);
            out.put(dst)?;
        }
        Ok(())
    }

    /// The length of a sealed value of `plaintext_len` bytes:
    /// `ceil((46 + n) * 4 / 3)`.
    ///
    /// # Examples
    ///
    /// ```
    /// let s = cookie_net::Sealer::new(*b"another example key, 32 bytes!!!")?;
    /// assert_eq!(s.sealed_len(0), 62);
    /// # Ok::<(), cookie_net::CookieError>(())
    /// ```
    #[must_use]
    pub const fn sealed_len(&self, plaintext_len: usize) -> usize {
        b64::encoded_len(plaintext_len.saturating_add(OVERHEAD))
    }

    /// The largest plaintext a cookie named with `name_len` bytes can carry
    /// within 4096 bytes of name and value: `floor((4096 - L) * 3 / 4) - 46`.
    ///
    /// # Examples
    ///
    /// ```
    /// let s = cookie_net::Sealer::new(*b"another example key, 32 bytes!!!")?;
    /// assert_eq!(s.max_plaintext(5), 3022);
    /// # Ok::<(), cookie_net::CookieError>(())
    /// ```
    #[must_use]
    pub const fn max_plaintext(&self, name_len: usize) -> usize {
        (PAIR_MAX.saturating_sub(name_len) * 3 / 4).saturating_sub(OVERHEAD)
    }

    /// Opens a sealed value read from cookie `name`. The plaintext is wiped
    /// when the returned [`Plaintext`] is dropped.
    ///
    /// # Errors
    ///
    /// A [`Rejected`] reason. Treat every one as "cookie absent".
    ///
    /// # Examples
    ///
    /// ```
    /// use cookie_net::{Rejected, Sealer};
    ///
    /// let s = Sealer::new(*b"another example key, 32 bytes!!!")?;
    /// let v = s.seal("flash", "Saved.")?;
    /// assert_eq!(s.open("flash", &v, 0)?.as_bytes(), b"Saved.");
    /// assert_eq!(s.open("other", &v, 0).unwrap_err(), Rejected::BadTag);
    /// # Ok::<(), cookie_net::CookieError>(())
    /// ```
    pub fn open<R: AsRef<[u8]> + ?Sized>(
        &self,
        name: &str,
        raw: &R,
        now: u64,
    ) -> Result<Plaintext, Rejected> {
        self.open_bound(name, raw, &[], now)
    }

    /// Opens a value sealed with [`seal_bound`](Self::seal_bound).
    ///
    /// # Errors
    ///
    /// A [`Rejected`] reason; `BadTag` for another binding.
    ///
    /// # Examples
    ///
    /// ```
    /// let s = cookie_net::Sealer::new(*b"another example key, 32 bytes!!!")?;
    /// let v = s.seal_bound("a", "x", b"sid")?;
    /// assert_eq!(s.open_bound("a", &v, b"sid", 0)?.as_str(), Some("x"));
    /// # Ok::<(), cookie_net::CookieError>(())
    /// ```
    pub fn open_bound<R: AsRef<[u8]> + ?Sized>(
        &self,
        name: &str,
        raw: &R,
        bound_to: &[u8],
        now: u64,
    ) -> Result<Plaintext, Rejected> {
        let mut out = Vec::new();
        self.open_into(name, raw, bound_to, now, &mut out)?;
        Ok(Plaintext(Zeroizing::new(out)))
    }

    /// Opens into the caller's buffer, which is cleared first and wiped on
    /// every failure; once it has capacity, opening allocates nothing.
    ///
    /// # Errors
    ///
    /// A [`Rejected`] reason.
    ///
    /// # Examples
    ///
    /// ```
    /// use cookie_net::{KeyId, Sealer};
    ///
    /// let s = Sealer::new(*b"another example key, 32 bytes!!!")?;
    /// let v = s.seal("flash", "Saved.")?;
    /// let mut plain = Vec::with_capacity(512);
    /// let opened = s.open_into("flash", &v, &[], 0, &mut plain)?;
    /// assert_eq!((plain.as_slice(), opened.key), (&b"Saved."[..], KeyId(0)));
    /// # Ok::<(), cookie_net::CookieError>(())
    /// ```
    pub fn open_into<R: AsRef<[u8]> + ?Sized>(
        &self,
        name: &str,
        raw: &R,
        bound_to: &[u8],
        now: u64,
        out: &mut Vec<u8>,
    ) -> Result<Opened, Rejected> {
        out.clear();
        let raw = raw.as_ref();
        // 1. length
        if raw.len() < b64::encoded_len(OVERHEAD) || raw.len() > PAIR_MAX {
            return Err(Rejected::Malformed);
        }
        let n = b64::decoded_len(raw.len()).ok_or(Rejected::Malformed)?;
        // 2. base64url, canonical, into a stack buffer
        let mut buf = [0u8; MAX_BYTES];
        let bytes = buf.get_mut(..n).ok_or(Rejected::Malformed)?;
        if !b64::decode(raw, bytes) {
            return Err(Rejected::Malformed);
        }
        let (header, sealed) = bytes.split_at(HEADER);
        // 3. version
        if header[0] != VERSION {
            return Err(Rejected::UnsupportedVersion);
        }
        // 4. key
        let id = KeyId(header[1]);
        let slot = self.slots.usable(id, now).ok_or(Rejected::UnknownKey)?;
        // 5. authenticate and decrypt
        let aad = aad(&slot.subkey, header, name.as_bytes(), bound_to);
        self.crypt
            .decrypt_with_aad_into(&slot.subkey[..], sealed, &aad, out)
            .map_err(|_| Rejected::BadTag)?;
        // 6. expiry
        let mut exp = [0u8; 4];
        exp.copy_from_slice(&header[2..]);
        let expires = keys::decode_expiry(u32::from_be_bytes(exp));
        if expires.is_some_and(|t| now >= t.saturating_add(self.skew)) {
            // The plaintext is already in `out`: wipe it before refusing.
            drop(Zeroizing::new(core::mem::take(out)));
            return Err(Rejected::Expired);
        }
        Ok(Opened {
            key: id,
            role: slot.role,
            expires,
        })
    }

    /// [`open`](Self::open) with the system clock.
    ///
    /// A clock that reads before 2020-01-01 (the epoch of the expiry
    /// encoding) is treated as the far future: values with an expiry and
    /// retired keys are refused, not accepted. Values without an expiry are
    /// unaffected.
    ///
    /// # Errors
    ///
    /// A [`Rejected`] reason.
    ///
    /// # Examples
    ///
    /// ```
    /// let s = cookie_net::Sealer::new(*b"another example key, 32 bytes!!!")?;
    /// let v = s.seal("a", "x")?;
    /// assert_eq!(s.open_now("a", &v)?.as_str(), Some("x"));
    /// # Ok::<(), cookie_net::CookieError>(())
    /// ```
    pub fn open_now<R: AsRef<[u8]> + ?Sized>(
        &self,
        name: &str,
        raw: &R,
    ) -> Result<Plaintext, Rejected> {
        self.open(name, raw, keys::now())
    }

    /// The id of the key that seals.
    ///
    /// # Examples
    ///
    /// ```
    /// let s = cookie_net::Sealer::new(*b"another example key, 32 bytes!!!")?;
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
    /// let s = cookie_net::Sealer::new(*b"another example key, 32 bytes!!!")?;
    /// assert_eq!(s.keys().count(), 1);
    /// # Ok::<(), cookie_net::CookieError>(())
    /// ```
    pub fn keys(&self) -> impl Iterator<Item = KeyInfo> + '_ {
        self.slots.keys()
    }

    /// The fingerprint of key `id`.
    ///
    /// # Examples
    ///
    /// ```
    /// let s = cookie_net::Sealer::new(*b"another example key, 32 bytes!!!")?;
    /// assert!(s.fingerprint(cookie_net::KeyId(0)).is_some());
    /// # Ok::<(), cookie_net::CookieError>(())
    /// ```
    #[must_use]
    pub fn fingerprint(&self, id: KeyId) -> Option<KeyFingerprint> {
        self.slots.fingerprint(id)
    }
}

impl fmt::Debug for Sealer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sealer")
            .field("keys", &self.slots)
            .field("skew", &self.skew)
            .finish()
    }
}

fn aad(subkey: &[u8; 32], header: &[u8], name: &[u8], bound_to: &[u8]) -> [u8; AAD] {
    let (name_len, bind_len) = keys::length_prefixes(name, bound_to);
    let digest = keys::keyed_hash(subkey, &[&name_len, name, &bind_len, bound_to]);
    let mut aad = [0u8; AAD];
    let (label, rest) = aad.split_at_mut(LABEL.len());
    label.copy_from_slice(LABEL);
    let (head, tail) = rest.split_at_mut(HEADER);
    head.copy_from_slice(header.get(..HEADER).unwrap_or(&[0; HEADER]));
    tail.copy_from_slice(&digest);
    aad
}

/// An opened plaintext, wiped from memory when dropped. `Debug` prints its
/// length only.
///
/// # Examples
///
/// ```
/// let s = cookie_net::Sealer::new(*b"another example key, 32 bytes!!!")?;
/// let p = s.open("a", &s.seal("a", "secret")?, 0)?;
/// assert_eq!((p.len(), &p[..]), (6, &b"secret"[..]));
/// assert_eq!(format!("{p:?}"), "Plaintext(6 bytes)");
/// # Ok::<(), cookie_net::CookieError>(())
/// ```
pub struct Plaintext(Zeroizing<Vec<u8>>);

impl Plaintext {
    /// The bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// let s = cookie_net::Sealer::new(*b"another example key, 32 bytes!!!")?;
    /// assert_eq!(s.open("a", &s.seal("a", b"\x01\x02")?, 0)?.as_bytes(), &[1, 2]);
    /// # Ok::<(), cookie_net::CookieError>(())
    /// ```
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The bytes as text, when they are UTF-8.
    ///
    /// # Examples
    ///
    /// ```
    /// let s = cookie_net::Sealer::new(*b"another example key, 32 bytes!!!")?;
    /// assert_eq!(s.open("a", &s.seal("a", b"\xff")?, 0)?.as_str(), None);
    /// # Ok::<(), cookie_net::CookieError>(())
    /// ```
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        core::str::from_utf8(&self.0).ok()
    }

    /// The length in bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// let s = cookie_net::Sealer::new(*b"another example key, 32 bytes!!!")?;
    /// assert_eq!(s.open("a", &s.seal("a", "abc")?, 0)?.len(), 3);
    /// # Ok::<(), cookie_net::CookieError>(())
    /// ```
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether there are no bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// let s = cookie_net::Sealer::new(*b"another example key, 32 bytes!!!")?;
    /// assert!(s.open("a", &s.seal("a", "")?, 0)?.is_empty());
    /// # Ok::<(), cookie_net::CookieError>(())
    /// ```
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl core::ops::Deref for Plaintext {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Plaintext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Plaintext({} bytes)", self.0.len())
    }
}

/// What [`Sealer::open_into`] reports besides the plaintext.
///
/// # Examples
///
/// ```
/// use cookie_net::{KeyRole, Sealer};
///
/// let s = Sealer::new(*b"another example key, 32 bytes!!!")?;
/// let v = s.seal_until("a", "x", 1_800_000_000)?;
/// let o = s.open_into("a", &v, &[], 0, &mut Vec::new())?;
/// assert_eq!((o.role, o.expires), (KeyRole::Signing, Some(1_800_000_000)));
/// # Ok::<(), cookie_net::CookieError>(())
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Opened {
    /// The key that opened it.
    pub key: KeyId,
    /// That key's role.
    pub role: KeyRole,
    /// The embedded expiry, when there is one.
    pub expires: Option<u64>,
}

#[cfg(test)]
mod tests {
    extern crate std;
    use std::{format, vec};

    use super::*;

    const K1: [u8; 32] = *b"another example key, 32 bytes!!!";
    const K2: [u8; 32] = *b"one more example key, 32 bytes!!";
    const NOW: u64 = 1_800_000_000;

    #[test]
    fn test_seal_open_round_trip_and_lengths() {
        let s = Sealer::new(K1).unwrap();
        for n in [0usize, 1, 2, 3, 64, 767, 768, 769, 1536, 3022] {
            let p: Vec<u8> = (0..n).map(|i| i as u8).collect();
            let v = s.seal("f", &p).unwrap();
            assert_eq!(v.len(), s.sealed_len(n), "{n}");
            assert_eq!(s.open("f", &v, NOW).unwrap().as_bytes(), &p[..], "{n}");
        }
        assert_eq!(s.max_plaintext(1), 3025);
        let too_big = vec![0u8; s.max_plaintext(1) + 1];
        assert_eq!(s.seal("f", &too_big).unwrap_err(), CookieError::TooLarge);
        assert!(s.seal("f", &vec![0u8; s.max_plaintext(1)]).is_ok());
    }

    #[test]
    fn test_nonces_differ() {
        let s = Sealer::new(K1).unwrap();
        assert_ne!(s.seal("f", "same").unwrap(), s.seal("f", "same").unwrap());
    }

    #[test]
    fn test_open_reasons() {
        let s = Sealer::new(K1).unwrap();
        let v = s.seal("flash", "Saved.").unwrap();
        assert_eq!(
            s.open("flash", &v[..61], NOW).unwrap_err(),
            Rejected::Malformed
        );
        assert!(matches!(
            s.open("flash", &v[..v.len() - 1], NOW).unwrap_err(),
            Rejected::Malformed | Rejected::BadTag
        ));
        let mut bad = v.clone().into_bytes();
        bad[10] = b'/';
        assert_eq!(s.open("flash", &bad, NOW).unwrap_err(), Rejected::Malformed);
        let other = Sealer::with_ring(KeyRing::new(KeyId(4), K1)).unwrap();
        assert_eq!(
            other.open("flash", &v, NOW).unwrap_err(),
            Rejected::UnknownKey
        );
        assert_eq!(s.open("flasH", &v, NOW).unwrap_err(), Rejected::BadTag);
        // a signer's subkey is not a sealer's
        let signer_made = crate::Signer::new(K1).unwrap().sign("flash", "x").unwrap();
        assert!(s.open("flash", &signer_made, NOW).is_err());
    }

    #[test]
    fn test_every_single_bit_flip_is_refused() {
        let s = Sealer::new(K1).unwrap();
        let v = s.seal("f", "flash text").unwrap().into_bytes();
        for i in 0..v.len() {
            for bit in 0..8 {
                let mut m = v.clone();
                m[i] ^= 1 << bit;
                assert!(s.open("f", &m, NOW).is_err(), "byte {i} bit {bit}");
            }
        }
    }

    #[test]
    fn test_expiry_wipes_and_refuses() {
        let s = Sealer::new(K1).unwrap();
        let v = s.seal_until("f", "x", NOW).unwrap();
        let mut out = Vec::with_capacity(64);
        assert!(s.open_into("f", &v, &[], NOW + 59, &mut out).is_ok());
        assert_eq!(out, b"x");
        assert_eq!(
            s.open_into("f", &v, &[], NOW + 60, &mut out).unwrap_err(),
            Rejected::Expired
        );
        assert!(out.is_empty());
        assert_eq!(
            s.seal_until("f", "x", u64::MAX).unwrap_err(),
            CookieError::ExpiresOutOfRange
        );
    }

    #[test]
    fn test_binding_and_rotation() {
        let s = Sealer::new(K1).unwrap();
        let v = s.seal_bound("f", "x", b"sid-a").unwrap();
        assert!(s.open_bound("f", &v, b"sid-a", NOW).is_ok());
        assert_eq!(
            s.open_bound("f", &v, b"sid-b", NOW).unwrap_err(),
            Rejected::BadTag
        );
        assert_eq!(s.open("f", &v, NOW).unwrap_err(), Rejected::BadTag);
        let rotated =
            Sealer::with_ring(KeyRing::new(KeyId(0), K1).rotated(KeyId(1), K2, NOW + 10)).unwrap();
        let old = s.seal("f", "old").unwrap();
        let o = rotated
            .open_into("f", &old, &[], NOW, &mut Vec::new())
            .unwrap();
        assert_eq!(o.role, KeyRole::Retired { until: NOW + 10 });
        assert_eq!(
            rotated.open("f", &old, NOW + 10).unwrap_err(),
            Rejected::UnknownKey
        );
    }

    #[test]
    fn test_full_sink_writes_nothing() {
        let s = Sealer::new(K1).unwrap();
        let mut buf = [0u8; 40];
        let mut out = parse_net::SliceSink::new(&mut buf);
        assert_eq!(
            s.seal_into("f", b"x", None, &[], &mut Vec::new(), &mut out),
            Err(CookieError::Full)
        );
        assert!(out.is_empty());
    }

    #[test]
    fn test_debug_has_no_secrets() {
        let s = Sealer::new(K1).unwrap();
        assert!(!format!("{s:?}").contains("example"));
        let p = s.open("f", &s.seal("f", "SECRET").unwrap(), NOW).unwrap();
        assert_eq!(format!("{p:?}"), "Plaintext(6 bytes)");
    }
}
