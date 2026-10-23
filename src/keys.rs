//! Keys for signed and encrypted cookies: [`Key`], [`KeyId`], [`KeyRole`],
//! [`KeyInfo`], [`KeyFingerprint`], [`KeyRing`].
//!
//! The names and meanings match csrf-sec's key ring, so one runbook serves
//! both crates (decision D-020). cookie-net never generates keys: a key made
//! at boot differs between the nodes of a cluster and changes at every
//! restart (decision D-032). Keys come from persisted configuration.

use core::fmt;

use crypt_io::{
    Zeroizing,
    kdf::hkdf_sha256_into,
    mac::{Blake3Mac, blake3_keyed},
};

use crate::error::CookieError;

/// Key length in bytes.
const KEY_LEN: usize = 32;
/// The most keys a ring holds.
pub(crate) const RING_SLOTS: usize = 8;
/// 2020-01-01T00:00:00Z, the zero of the embedded expiry.
pub(crate) const EPOCH_2020: u64 = 1_577_836_800;
/// The latest embedded time: 2020 plus `u32::MAX` seconds (early 2156).
pub(crate) const MAX_TIME: u64 = EPOCH_2020 + u32::MAX as u64;
/// The longest context `Key::derive` takes.
const MAX_CONTEXT: usize = 200;
/// HKDF info prefix for `Key::derive`.
const DERIVE_LABEL: &[u8] = b"cookie-net v1 key\x00";
/// Label of key fingerprints; distinct from every MAC input.
const FINGERPRINT_LABEL: &[u8] = b"cookie-net/v1 key fingerprint";

/// A 32-byte key, wiped from memory when dropped. `Debug` prints `Key(..)`.
///
/// Every function that takes a key takes `impl Into<Key>`, so a `[u8; 32]`
/// works directly.
///
/// # Examples
///
/// ```
/// use cookie_net::Key;
///
/// let key = Key::from_bytes(*b"an example key, 32 bytes long!!!");
/// assert_eq!(format!("{key:?}"), "Key(..)");
/// let same: Key = (*b"an example key, 32 bytes long!!!").into();
/// # let _ = same;
/// ```
#[derive(Clone)]
pub struct Key(Zeroizing<[u8; KEY_LEN]>);

impl Key {
    /// A key from its 32 bytes. The array is moved in and wiped when the key
    /// is dropped; wipe any other copy you hold.
    ///
    /// # Examples
    ///
    /// ```
    /// let key = cookie_net::Key::from_bytes(*b"an example key, 32 bytes long!!!");
    /// # let _ = key;
    /// ```
    #[must_use]
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Key {
        Key(Zeroizing::new(bytes))
    }

    /// A key derived from `master` for one `context` (a service name, say),
    /// with HKDF-SHA-256: `info = "cookie-net v1 key" 0x00 || context`. One
    /// master in key-vault can then serve several services, each with its own
    /// keys.
    ///
    /// # Errors
    ///
    /// [`CookieError::KeyTooShort`] when `master` is shorter than 32 bytes,
    /// [`CookieError::ContextTooLong`] when `context` is over 200 bytes,
    /// [`CookieError::Crypto`] if HKDF fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use cookie_net::{CookieError, Key, Signer};
    ///
    /// let master = [0x5au8; 64];
    /// let web = Key::derive(&master, b"wasp-web")?;
    /// let api = Key::derive(&master, b"wasp-api")?;
    /// let (web, api) = (Signer::new(web)?, Signer::new(api)?);
    /// assert_ne!(web.fingerprint(web.signing_key()), api.fingerprint(api.signing_key()));
    /// assert_eq!(Key::derive(&[1u8; 31], b"x").unwrap_err(), CookieError::KeyTooShort);
    /// # Ok::<(), CookieError>(())
    /// ```
    pub fn derive(master: &[u8], context: &[u8]) -> Result<Key, CookieError> {
        if master.len() < KEY_LEN {
            return Err(CookieError::KeyTooShort);
        }
        if context.len() > MAX_CONTEXT {
            return Err(CookieError::ContextTooLong);
        }
        let mut info = [0u8; DERIVE_LABEL.len() + MAX_CONTEXT];
        let n = DERIVE_LABEL.len() + context.len();
        let (label, rest) = info.split_at_mut(DERIVE_LABEL.len());
        label.copy_from_slice(DERIVE_LABEL);
        rest.get_mut(..context.len())
            .ok_or(CookieError::ContextTooLong)?
            .copy_from_slice(context);
        let mut out = Zeroizing::new([0u8; KEY_LEN]);
        let info = info.get(..n).ok_or(CookieError::ContextTooLong)?;
        hkdf_sha256_into(master, None, info, &mut out[..]).map_err(|_| CookieError::Crypto)?;
        Ok(Key(out))
    }

    pub(crate) fn bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl From<[u8; KEY_LEN]> for Key {
    fn from(bytes: [u8; KEY_LEN]) -> Key {
        Key::from_bytes(bytes)
    }
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Key(..)")
    }
}

/// A key's id, written into every signed and sealed cookie. Never reuse an
/// id while cookies made under the old key may still be presented.
///
/// # Examples
///
/// ```
/// let id = cookie_net::KeyId(3);
/// assert_eq!((id.0, id.to_string()), (3, "3".to_string()));
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct KeyId(pub u8);

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

/// What a key in a ring may do.
///
/// # Examples
///
/// ```
/// # fn key(b: u8) -> [u8; 32] { core::array::from_fn(|i| b ^ i as u8) }
/// use cookie_net::{KeyId, KeyRing, KeyRole, Signer};
///
/// let ring = KeyRing::new(KeyId(1), key(1)).accept(KeyId(2), key(2));
/// let roles: Vec<KeyRole> = Signer::with_ring(ring)?.keys().map(|k| k.role()).collect();
/// assert_eq!(roles, [KeyRole::Signing, KeyRole::Accepted]);
/// # Ok::<(), cookie_net::CookieError>(())
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KeyRole {
    /// Signs (or seals) new cookies, and verifies.
    Signing,
    /// Verifies only, with no end: a key staged on every node before any node
    /// signs with it.
    Accepted,
    /// Verifies only, while `now < until` (Unix seconds).
    Retired {
        /// Unix time at which the key stops verifying.
        until: u64,
    },
}

/// A public fingerprint of a key: eight bytes of keyed BLAKE3 over a fixed
/// label under the key's subkey. It reveals nothing that helps forge a
/// cookie, but two nodes holding the same key under the same id show the
/// same fingerprint, so a misdeployed ring shows up before it causes a wave
/// of `BadTag` refusals. `Display` is 16 lowercase hex digits.
///
/// # Examples
///
/// ```
/// # fn key(b: u8) -> [u8; 32] { core::array::from_fn(|i| b ^ i as u8) }
/// use cookie_net::Signer;
///
/// let a = Signer::new(key(9))?;
/// let b = Signer::new(key(9))?;
/// let fp = |s: &Signer| s.fingerprint(s.signing_key()).unwrap();
/// assert_eq!(fp(&a), fp(&b));
/// assert_eq!(fp(&a).to_string().len(), 16);
/// # Ok::<(), cookie_net::CookieError>(())
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeyFingerprint([u8; 8]);

impl KeyFingerprint {
    /// The fingerprint bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// # fn key(b: u8) -> [u8; 32] { core::array::from_fn(|i| b ^ i as u8) }
    /// let s = cookie_net::Signer::new(key(3))?;
    /// assert_eq!(s.fingerprint(s.signing_key()).unwrap().as_bytes().len(), 8);
    /// # Ok::<(), cookie_net::CookieError>(())
    /// ```
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 8] {
        &self.0
    }
}

impl fmt::Display for KeyFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for KeyFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KeyFingerprint({self})")
    }
}

/// One key of a signer or sealer, as `keys()` reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct KeyInfo {
    id: KeyId,
    role: KeyRole,
    fingerprint: KeyFingerprint,
}

impl KeyInfo {
    /// The key id.
    ///
    /// # Examples
    ///
    /// ```
    /// # fn key(b: u8) -> [u8; 32] { core::array::from_fn(|i| b ^ i as u8) }
    /// let s = cookie_net::Signer::new(key(1))?;
    /// assert_eq!(s.keys().next().unwrap().id(), cookie_net::KeyId(0));
    /// # Ok::<(), cookie_net::CookieError>(())
    /// ```
    #[must_use]
    pub const fn id(&self) -> KeyId {
        self.id
    }

    /// What the key may do.
    ///
    /// # Examples
    ///
    /// ```
    /// # fn key(b: u8) -> [u8; 32] { core::array::from_fn(|i| b ^ i as u8) }
    /// let s = cookie_net::Signer::new(key(1))?;
    /// assert_eq!(s.keys().next().unwrap().role(), cookie_net::KeyRole::Signing);
    /// # Ok::<(), cookie_net::CookieError>(())
    /// ```
    #[must_use]
    pub const fn role(&self) -> KeyRole {
        self.role
    }

    /// The key's public fingerprint.
    ///
    /// # Examples
    ///
    /// ```
    /// # fn key(b: u8) -> [u8; 32] { core::array::from_fn(|i| b ^ i as u8) }
    /// let s = cookie_net::Signer::new(key(1))?;
    /// let k = s.keys().next().unwrap();
    /// assert_eq!(Some(k.fingerprint()), s.fingerprint(k.id()));
    /// # Ok::<(), cookie_net::CookieError>(())
    /// ```
    #[must_use]
    pub const fn fingerprint(&self) -> KeyFingerprint {
        self.fingerprint
    }
}

#[derive(Clone)]
struct Entry {
    id: KeyId,
    role: KeyRole,
    key: Key,
}

/// One signing key and up to seven others, in a fixed array.
///
/// The methods never fail, so a ring reads as one chain;
/// [`Signer::with_ring`](crate::Signer::with_ring) and
/// [`Sealer::with_ring`](crate::Sealer::with_ring) check it. `Debug` prints
/// ids and roles, never key bytes.
///
/// # Examples
///
/// ```
/// # fn key(b: u8) -> [u8; 32] { core::array::from_fn(|i| b ^ i as u8) }
/// use cookie_net::{KeyId, KeyRing, Signer};
///
/// let retire_at = 1_800_000_000;
/// let ring = KeyRing::new(KeyId(2), key(2)).retired(KeyId(1), key(1), retire_at);
/// assert_eq!(Signer::with_ring(ring)?.signing_key(), KeyId(2));
/// # Ok::<(), cookie_net::CookieError>(())
/// ```
#[derive(Clone)]
pub struct KeyRing {
    entries: [Option<Entry>; RING_SLOTS],
    overflow: bool,
}

impl KeyRing {
    /// A ring whose signing key is `key` under `id`.
    ///
    /// # Examples
    ///
    /// ```
    /// # fn key(b: u8) -> [u8; 32] { core::array::from_fn(|i| b ^ i as u8) }
    /// let ring = cookie_net::KeyRing::new(cookie_net::KeyId(1), key(1));
    /// assert_eq!(ring.signing_key(), cookie_net::KeyId(1));
    /// ```
    #[must_use]
    pub fn new(id: KeyId, key: impl Into<Key>) -> KeyRing {
        KeyRing {
            entries: Default::default(),
            overflow: false,
        }
        .push(id, KeyRole::Signing, key.into())
    }

    fn push(mut self, id: KeyId, role: KeyRole, key: Key) -> KeyRing {
        match self.entries.iter_mut().find(|e| e.is_none()) {
            Some(slot) => *slot = Some(Entry { id, role, key }),
            None => self.overflow = true,
        }
        self
    }

    /// Adds a key that verifies but does not sign, with no end. Stage a new
    /// key on every node with `accept` before any node signs with it.
    ///
    /// # Examples
    ///
    /// ```
    /// # fn key(b: u8) -> [u8; 32] { core::array::from_fn(|i| b ^ i as u8) }
    /// use cookie_net::{KeyId, KeyRing};
    ///
    /// let ring = KeyRing::new(KeyId(1), key(1)).accept(KeyId(2), key(2));
    /// assert_eq!(ring.signing_key(), KeyId(1));
    /// ```
    #[must_use]
    pub fn accept(self, id: KeyId, key: impl Into<Key>) -> KeyRing {
        self.push(id, KeyRole::Accepted, key.into())
    }

    /// Adds a key that verifies while `now < until` (Unix seconds), then is
    /// refused as `UnknownKey`. Set `until` at least one cookie lifetime plus
    /// the skew allowance after the key stopped signing.
    ///
    /// # Examples
    ///
    /// ```
    /// # fn key(b: u8) -> [u8; 32] { core::array::from_fn(|i| b ^ i as u8) }
    /// use cookie_net::{KeyId, KeyRing};
    ///
    /// let ring = KeyRing::new(KeyId(2), key(2)).retired(KeyId(1), key(1), 1_800_000_000);
    /// # let _ = ring;
    /// ```
    #[must_use]
    pub fn retired(self, id: KeyId, key: impl Into<Key>, until: u64) -> KeyRing {
        self.push(id, KeyRole::Retired { until }, key.into())
    }

    /// Makes `key` under `id` the signing key; the previous signing key
    /// becomes `Retired { until: retire_old_at }`, and an `Accepted` entry
    /// with the same id is replaced (promoted).
    ///
    /// # Examples
    ///
    /// ```
    /// # fn key(b: u8) -> [u8; 32] { core::array::from_fn(|i| b ^ i as u8) }
    /// use cookie_net::{KeyId, KeyRing, KeyRole, Signer};
    ///
    /// let staged = KeyRing::new(KeyId(1), key(1)).accept(KeyId(2), key(2));
    /// let switched = staged.rotated(KeyId(2), key(2), 1_800_000_000);
    /// let s = Signer::with_ring(switched)?;
    /// assert_eq!(s.signing_key(), KeyId(2));
    /// assert!(s.keys().any(|k| k.id() == KeyId(1) && k.role() == KeyRole::Retired { until: 1_800_000_000 }));
    /// # Ok::<(), cookie_net::CookieError>(())
    /// ```
    #[must_use]
    pub fn rotated(mut self, id: KeyId, key: impl Into<Key>, retire_old_at: u64) -> KeyRing {
        for slot in &mut self.entries {
            match slot {
                Some(e) if e.role == KeyRole::Signing => {
                    e.role = KeyRole::Retired {
                        until: retire_old_at,
                    };
                }
                Some(e) if e.id == id && e.role == KeyRole::Accepted => *slot = None,
                _ => {}
            }
        }
        self.push(id, KeyRole::Signing, key.into())
    }

    /// Removes every key under `id` (a retired key past its time, say).
    ///
    /// # Examples
    ///
    /// ```
    /// # fn key(b: u8) -> [u8; 32] { core::array::from_fn(|i| b ^ i as u8) }
    /// use cookie_net::{KeyId, KeyRing, Signer};
    ///
    /// let ring = KeyRing::new(KeyId(2), key(2)).retired(KeyId(1), key(1), 0).without(KeyId(1));
    /// assert_eq!(Signer::with_ring(ring)?.keys().count(), 1);
    /// # Ok::<(), cookie_net::CookieError>(())
    /// ```
    #[must_use]
    pub fn without(mut self, id: KeyId) -> KeyRing {
        for slot in &mut self.entries {
            if slot.as_ref().is_some_and(|e| e.id == id) {
                *slot = None;
            }
        }
        self
    }

    /// The id of the signing key.
    ///
    /// # Examples
    ///
    /// ```
    /// # fn key(b: u8) -> [u8; 32] { core::array::from_fn(|i| b ^ i as u8) }
    /// let ring = cookie_net::KeyRing::new(cookie_net::KeyId(4), key(4));
    /// assert_eq!(ring.signing_key(), cookie_net::KeyId(4));
    /// ```
    #[must_use]
    pub fn signing_key(&self) -> KeyId {
        self.entries
            .iter()
            .flatten()
            .find(|e| e.role == KeyRole::Signing)
            .map_or(KeyId(0), |e| e.id)
    }
}

impl fmt::Debug for KeyRing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list()
            .entries(self.entries.iter().flatten().map(|e| (e.id, e.role)))
            .finish()
    }
}

/// One usable key: its id, role, purpose subkey, and fingerprint.
pub(crate) struct Slot {
    pub(crate) id: KeyId,
    pub(crate) role: KeyRole,
    pub(crate) subkey: Zeroizing<[u8; KEY_LEN]>,
    fingerprint: KeyFingerprint,
}

/// A checked ring with per-purpose subkeys, shared by `Signer` and `Sealer`.
pub(crate) struct Slots {
    slots: [Option<Slot>; RING_SLOTS],
    signing: usize,
}

impl Slots {
    /// Checks `ring` and derives a subkey for `purpose` from every key.
    pub(crate) fn derive(ring: KeyRing, purpose: &[u8]) -> Result<Slots, CookieError> {
        if ring.overflow {
            return Err(CookieError::RingFull);
        }
        let mut slots: [Option<Slot>; RING_SLOTS] = Default::default();
        let mut signing = None;
        for (i, entry) in ring.entries.iter().enumerate() {
            let Some(e) = entry else { continue };
            if ring
                .entries
                .iter()
                .take(i)
                .flatten()
                .any(|other| other.id == e.id)
            {
                return Err(CookieError::DuplicateKeyId);
            }
            let k = e.key.bytes();
            if k.iter().all(|&b| b == k[0]) {
                return Err(CookieError::WeakKey);
            }
            if let KeyRole::Retired { until } = e.role {
                if until > MAX_TIME {
                    return Err(CookieError::InvalidRetireTime);
                }
            }
            let mut subkey = Zeroizing::new([0u8; KEY_LEN]);
            hkdf_sha256_into(&k[..], None, purpose, &mut subkey[..])
                .map_err(|_| CookieError::Crypto)?;
            let mac = blake3_keyed(&subkey, FINGERPRINT_LABEL);
            let mut fp = [0u8; 8];
            fp.copy_from_slice(mac.get(..8).unwrap_or(&[0; 8]));
            if e.role == KeyRole::Signing {
                signing = Some(i);
            }
            if let Some(slot) = slots.get_mut(i) {
                *slot = Some(Slot {
                    id: e.id,
                    role: e.role,
                    subkey,
                    fingerprint: KeyFingerprint(fp),
                });
            }
        }
        let signing = signing.ok_or(CookieError::RingFull)?;
        Ok(Slots { slots, signing })
    }

    /// The signing slot.
    pub(crate) fn signing(&self) -> Option<&Slot> {
        self.slots.get(self.signing).and_then(Option::as_ref)
    }

    /// The slot for `id`, if it may verify at `now`.
    pub(crate) fn usable(&self, id: KeyId, now: u64) -> Option<&Slot> {
        self.slots.iter().flatten().find(|s| {
            s.id == id
                && match s.role {
                    KeyRole::Signing | KeyRole::Accepted => true,
                    KeyRole::Retired { until } => now < until,
                }
        })
    }

    pub(crate) fn keys(&self) -> impl Iterator<Item = KeyInfo> + '_ {
        self.slots.iter().flatten().map(|s| KeyInfo {
            id: s.id,
            role: s.role,
            fingerprint: s.fingerprint,
        })
    }

    pub(crate) fn fingerprint(&self, id: KeyId) -> Option<KeyFingerprint> {
        self.slots
            .iter()
            .flatten()
            .find(|s| s.id == id)
            .map(|s| s.fingerprint)
    }

    pub(crate) fn signing_key(&self) -> KeyId {
        self.signing().map_or(KeyId(0), |s| s.id)
    }
}

impl fmt::Debug for Slots {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.keys()).finish()
    }
}

/// The embedded expiry: 0 for none, else seconds since 2020.
pub(crate) fn encode_expiry(expires: Option<u64>) -> Result<u32, CookieError> {
    match expires {
        None => Ok(0),
        Some(t) if t > EPOCH_2020 && t <= MAX_TIME => {
            u32::try_from(t - EPOCH_2020).map_err(|_| CookieError::ExpiresOutOfRange)
        }
        Some(_) => Err(CookieError::ExpiresOutOfRange),
    }
}

pub(crate) fn decode_expiry(e: u32) -> Option<u64> {
    (e != 0).then(|| EPOCH_2020 + u64::from(e))
}

/// Inputs up to this many bytes are hashed in one call from a stack buffer.
const ONE_SHOT: usize = 512;

/// Keyed BLAKE3 of the concatenation of `parts`. Short inputs (all real
/// cookies) are copied into a stack buffer and hashed in one call, which
/// costs about a third of feeding the same bytes through several `update`
/// calls; longer ones stream. Both give the same output.
pub(crate) fn keyed_hash(subkey: &[u8; KEY_LEN], parts: &[&[u8]]) -> [u8; 32] {
    let total = parts.iter().fold(0usize, |n, p| n.saturating_add(p.len()));
    if total <= ONE_SHOT {
        let mut buf = [0u8; ONE_SHOT];
        let mut at = 0;
        for p in parts {
            if let Some(dst) = buf.get_mut(at..at + p.len()) {
                dst.copy_from_slice(p);
            }
            at += p.len();
        }
        return blake3_keyed(subkey, buf.get(..at).unwrap_or(&[]));
    }
    let mut m = Blake3Mac::new(subkey);
    for p in parts {
        m.update(p);
    }
    m.finalize()
}

/// The length prefixes of a name and a binding, as they enter a MAC.
pub(crate) fn length_prefixes(name: &[u8], bound_to: &[u8]) -> ([u8; 2], [u8; 4]) {
    let name_len = u16::try_from(name.len()).unwrap_or(u16::MAX);
    let bind_len = u32::try_from(bound_to.len()).unwrap_or(u32::MAX);
    (name_len.to_be_bytes(), bind_len.to_be_bytes())
}

/// Checks a cookie name for signing or sealing.
pub(crate) fn check_name(name: &str) -> Result<(), CookieError> {
    let n = name.as_bytes();
    if n.is_empty() {
        return Err(CookieError::EmptyName);
    }
    if let Some(i) = crate::name::first_non_tchar(n) {
        return Err(CookieError::InvalidName {
            at: crate::error::at(i),
        });
    }
    if n.len() > crate::limits::PAIR_MAX {
        return Err(CookieError::TooLarge);
    }
    Ok(())
}

/// The current Unix time, for the `*_now` functions.
#[cfg(feature = "std")]
pub(crate) fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(test)]
mod tests {
    extern crate std;
    use std::{format, string::ToString};

    use super::*;

    #[test]
    fn test_key_debug_is_redacted() {
        assert_eq!(format!("{:?}", Key::from_bytes([1; 32])), "Key(..)");
    }

    #[test]
    fn test_derive_refusals_and_separation() {
        assert_eq!(
            Key::derive(&[0; 31], b"").unwrap_err(),
            CookieError::KeyTooShort
        );
        assert_eq!(
            Key::derive(&[0; 32], &[b'x'; 201]).unwrap_err(),
            CookieError::ContextTooLong
        );
        assert!(Key::derive(&[0; 32], &[b'x'; 200]).is_ok());
        let a = Key::derive(&[7; 32], b"a").unwrap();
        let b = Key::derive(&[7; 32], b"b").unwrap();
        assert_ne!(a.bytes(), b.bytes());
        assert_eq!(a.bytes(), Key::derive(&[7; 32], b"a").unwrap().bytes());
    }

    #[test]
    fn test_ring_checks() {
        let k = |b: u8| {
            let mut a = [b; 32];
            a[0] ^= 0x55;
            a
        };
        let dup = KeyRing::new(KeyId(1), k(1)).accept(KeyId(1), k(2));
        assert_eq!(
            Slots::derive(dup, b"x").unwrap_err(),
            CookieError::DuplicateKeyId
        );
        let weak = KeyRing::new(KeyId(1), [0u8; 32]);
        assert_eq!(Slots::derive(weak, b"x").unwrap_err(), CookieError::WeakKey);
        let late = KeyRing::new(KeyId(1), k(1)).retired(KeyId(2), k(2), MAX_TIME + 1);
        assert_eq!(
            Slots::derive(late, b"x").unwrap_err(),
            CookieError::InvalidRetireTime
        );
        let mut full = KeyRing::new(KeyId(0), k(0));
        for i in 1..8 {
            full = full.accept(KeyId(i), k(i));
        }
        assert!(Slots::derive(full.clone(), b"x").is_ok());
        assert_eq!(
            Slots::derive(full.accept(KeyId(9), k(9)), b"x").unwrap_err(),
            CookieError::RingFull
        );
        let none = KeyRing::new(KeyId(1), k(1)).without(KeyId(1));
        assert_eq!(
            Slots::derive(none, b"x").unwrap_err(),
            CookieError::RingFull
        );
    }

    #[test]
    fn test_usable_by_role_and_time() {
        let k = |b: u8| {
            let mut a = [b; 32];
            a[1] = !b;
            a
        };
        let ring = KeyRing::new(KeyId(1), k(1))
            .accept(KeyId(2), k(2))
            .retired(KeyId(3), k(3), 100);
        let s = Slots::derive(ring, b"x").unwrap();
        assert!(s.usable(KeyId(1), u64::MAX).is_some());
        assert!(s.usable(KeyId(2), u64::MAX).is_some());
        assert!(s.usable(KeyId(3), 99).is_some());
        assert!(s.usable(KeyId(3), 100).is_none());
        assert!(s.usable(KeyId(4), 0).is_none());
        assert_eq!(s.signing_key(), KeyId(1));
        assert!(!format!("{s:?}").is_empty());
    }

    #[test]
    fn test_purposes_give_different_subkeys() {
        let ring = || KeyRing::new(KeyId(1), *b"an example key, 32 bytes long!!!");
        let a = Slots::derive(ring(), b"cookie-net v1 signed").unwrap();
        let b = Slots::derive(ring(), b"cookie-net v1 sealed").unwrap();
        assert_ne!(
            a.signing().unwrap().subkey[..],
            b.signing().unwrap().subkey[..]
        );
        assert_ne!(a.fingerprint(KeyId(1)), b.fingerprint(KeyId(1)));
    }

    #[test]
    fn test_expiry_encoding_bounds() {
        assert_eq!(encode_expiry(None), Ok(0));
        assert_eq!(
            encode_expiry(Some(EPOCH_2020)),
            Err(CookieError::ExpiresOutOfRange)
        );
        assert_eq!(encode_expiry(Some(EPOCH_2020 + 1)), Ok(1));
        assert_eq!(encode_expiry(Some(MAX_TIME)), Ok(u32::MAX));
        assert_eq!(
            encode_expiry(Some(MAX_TIME + 1)),
            Err(CookieError::ExpiresOutOfRange)
        );
        assert_eq!(decode_expiry(0), None);
        assert_eq!(decode_expiry(5), Some(EPOCH_2020 + 5));
    }

    #[test]
    fn test_keyed_hash_one_shot_equals_streaming() {
        let key = [9u8; 32];
        for total in [0usize, 1, 100, 511, 512, 513, 2000] {
            let data: std::vec::Vec<u8> = (0..total).map(|i| i as u8).collect();
            let (a, b) = data.split_at(total / 3);
            let mut m = Blake3Mac::new(&key);
            m.update(a);
            m.update(b);
            assert_eq!(keyed_hash(&key, &[a, b]), m.finalize(), "{total}");
            assert_eq!(keyed_hash(&key, &[&data]), blake3_keyed(&key, &data));
        }
    }

    #[test]
    fn test_fingerprint_display_and_debug() {
        let fp = KeyFingerprint([0xab, 0, 1, 2, 3, 4, 5, 0xff]);
        assert_eq!(fp.to_string(), "ab000102030405ff");
        assert_eq!(format!("{fp:?}"), "KeyFingerprint(ab000102030405ff)");
    }

    #[test]
    fn test_ring_debug_has_no_key_bytes() {
        let ring = KeyRing::new(KeyId(1), [0x41u8; 32]);
        let d = format!("{ring:?}");
        assert!(!d.contains("65") && !d.contains("AAAA"), "{d}");
    }
}
