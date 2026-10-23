//! # cookie_net
//!
//! HTTP cookies for Rust, following RFC 6265 and its revision
//! draft-ietf-httpbis-rfc6265bis: strict, zero-copy parsing of the `Cookie`
//! header, and `Set-Cookie` writing that refuses every cookie a browser would
//! drop or an attacker could use, with secure defaults.
//!
//! ## Reading
//!
//! ```
//! use cookie_net as cookie;
//!
//! let header = "__Host-sid=t0k3n; theme=dark";
//! let sid = cookie::get_unique(header, "__Host-sid")?;      // Err if planted twice
//! assert_eq!(sid, Some("t0k3n"));
//! assert_eq!(cookie::get(header, "theme"), Some("dark"));
//! for pair in cookie::parse(header) {
//!     println!("{} ({} bytes)", pair.name(), pair.value().len());   // never log the value
//! }
//! # Ok::<(), cookie::CookieError>(())
//! ```
//!
//! ## Writing
//!
//! ```
//! use cookie_net::{self as cookie, SetCookie};
//!
//! # #[cfg(feature = "alloc")] {
//! let set = SetCookie::new("theme", "dark")?;               // Secure; HttpOnly; SameSite=Lax; Path=/
//! assert_eq!(set.encode(), "theme=dark; Path=/; Secure; HttpOnly; SameSite=Lax");
//! let token = "Zk3J9qL0wX7aP2mT8sV1cR5dY4hN6bE0uK9gF3jQ2oA";
//! let login = cookie::session_cookie("__Host-sid", token, 12 * cookie::HOUR)?;
//! let logout = SetCookie::delete("__Host-sid")?;
//! # let _ = (login, logout);
//! # }
//! # Ok::<(), cookie::CookieError>(())
//! ```
//!
//! ## Rules
//!
//! - **Names are bytes.** Compared byte for byte: no trimming beyond SP and
//!   HTAB around a pair, no case folding, no percent-decoding, no Unicode
//!   normalization, because every known prefix bypass relies on a server that
//!   does one of those.
//! - **Bad pairs are skipped and counted**, never repaired and never fatal;
//!   credentials use [`get_unique`] or [`locate`], which fail closed.
//! - **Invalid cookies cannot be built.** A [`SetCookie`] that exists passed
//!   every rule (see [`SetCookieBuilder::build`]).
//! - **Secrets never print.** `Debug` shows names and lengths, never values,
//!   and no type implements `Display` for a value.
//!
//! The full API, with the version that ships each item, is in `docs/API.md`
//! in the [repository](https://github.com/jamesgober/cookie-net).
//!
//! ## Features
//!
//! `std` (default) adds the `*_now` functions that read the system clock and
//! implies `alloc`, which adds [`SetCookie::encode`] and the `String`-returning
//! signing functions. `signed` adds keys and `Signer` (keyed BLAKE3, through
//! crypt-io; it works without `std` but needs an allocator, because crypt-io
//! links `alloc`). `encrypted` adds `Sealer` (XChaCha20-Poly1305; needs `std`
//! for the OS random source). Without default features the core is `no_std`
//! and needs no allocator.

#![doc(html_root_url = "https://docs.rs/cookie-net")]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "signed")]
mod b64;
mod error;
#[cfg(feature = "signed")]
mod keys;
mod limits;
mod name;
mod request;
mod response;
#[cfg(feature = "encrypted")]
mod sealed;
mod session;
#[cfg(feature = "signed")]
mod signed;

pub use error::{Ambiguous, CookieError, Rejected};
#[cfg(feature = "signed")]
#[cfg_attr(docsrs, doc(cfg(feature = "signed")))]
pub use keys::{Key, KeyFingerprint, KeyId, KeyInfo, KeyRing, KeyRole};
pub use limits::{Limits, ValueMode};
pub use name::Prefix;
pub use request::{Cookies, GetAll, Iter, Located, Lookup, Pair, Stats};
pub use response::{SameSite, SetCookie, SetCookieBuilder};
#[cfg(feature = "encrypted")]
#[cfg_attr(docsrs, doc(cfg(feature = "encrypted")))]
pub use sealed::{Opened, Plaintext, Sealer};
pub use session::{elevated_cookie, session_cookie};
#[cfg(feature = "signed")]
#[cfg_attr(docsrs, doc(cfg(feature = "signed")))]
pub use signed::{Signer, Verified};

/// Crate version string, populated by Cargo at build time.
///
/// # Examples
///
/// ```
/// assert_eq!(cookie_net::VERSION.split('.').count(), 3);
/// ```
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// One minute in seconds.
///
/// # Examples
///
/// ```
/// assert_eq!(5 * cookie_net::MINUTE, 300);
/// ```
pub const MINUTE: u64 = 60;

/// One hour in seconds.
///
/// # Examples
///
/// ```
/// assert_eq!(12 * cookie_net::HOUR, 43_200);
/// ```
pub const HOUR: u64 = 3_600;

/// One day in seconds.
///
/// # Examples
///
/// ```
/// use cookie_net as cookie;
///
/// let c = cookie::SetCookie::builder("theme", "dark").max_age(30 * cookie::DAY).build()?;
/// assert_eq!(c.max_age(), Some(2_592_000));
/// # Ok::<(), cookie::CookieError>(())
/// ```
pub const DAY: u64 = 86_400;

/// The longest cookie lifetime user agents keep: 400 days (rfc6265bis
/// section 5.5). `Max-Age` and `Expires` beyond it are refused.
///
/// # Examples
///
/// ```
/// assert_eq!(cookie_net::MAX_LIFETIME, 400 * cookie_net::DAY);
/// ```
pub const MAX_LIFETIME: u64 = 34_560_000;

/// Every pair in a `Cookie` header, with [`Limits::DEFAULT`]. Never fails: a
/// header over the length limit yields no pairs (and `stats().too_long`), and
/// pairs that break the grammar are skipped and counted.
///
/// # Examples
///
/// ```
/// use cookie_net as cookie;
///
/// let names: Vec<&str> = cookie::parse("a=1; bad name=2; b=").iter().map(|p| p.name()).collect();
/// assert_eq!(names, ["a", "b"]);
/// assert_eq!(cookie::parse("a=1; bad name=2; b=").stats().skipped, 1);
/// ```
#[must_use]
pub fn parse<H: AsRef<[u8]> + ?Sized>(header: &H) -> Cookies<'_> {
    Cookies::new(header)
}

/// The value of the first pair named exactly `name`, byte for byte. For
/// preferences; use [`get_unique`] for credentials.
///
/// # Examples
///
/// ```
/// use cookie_net as cookie;
///
/// assert_eq!(cookie::get("theme=dark; lang=fr", "lang"), Some("fr"));
/// assert_eq!(cookie::get("Theme=dark", "theme"), None);       // names are case-sensitive
/// assert_eq!(cookie::get("a=\"1\"", "a"), Some("\"1\""));    // quotes are part of the value
/// ```
#[must_use]
pub fn get<'a, H: AsRef<[u8]> + ?Sized>(header: &'a H, name: &str) -> Option<&'a str> {
    Cookies::new(header).get(name)
}

/// The value of the only pair named `name`. Scans the whole header, because a
/// duplicate can be anywhere. Use it for every credential.
///
/// # Errors
///
/// [`Ambiguous::Duplicate`] when the name appears twice or more (on a
/// `__Host-` name, an attack); [`Ambiguous::Truncated`] when the pair limit
/// cut the scan short; [`Ambiguous::HeaderTooLong`] when nothing was read.
///
/// # Examples
///
/// ```
/// use cookie_net::{self as cookie, Ambiguous};
///
/// assert_eq!(cookie::get_unique("__Host-sid=t0k3n; theme=dark", "__Host-sid"), Ok(Some("t0k3n")));
/// assert_eq!(cookie::get_unique("sid=evil; __Host-sid=t0k3n", "__Host-sid"), Ok(Some("t0k3n")));
/// assert_eq!(cookie::get_unique("__Host-sid=a; __Host-sid=b", "__Host-sid"), Err(Ambiguous::Duplicate { count: 2 }));
/// ```
pub fn get_unique<'a, H: AsRef<[u8]> + ?Sized>(
    header: &'a H,
    name: &str,
) -> Result<Option<&'a str>, Ambiguous> {
    Cookies::new(header).get_unique(name)
}

/// Every value of `name`, in header order, for cookies that legitimately
/// repeat (one name on several paths).
///
/// # Examples
///
/// ```
/// let v: Vec<&str> = cookie_net::get_all("cart=2; theme=dark; cart=1", "cart").collect();
/// assert_eq!(v, ["2", "1"]);
/// ```
#[must_use]
pub fn get_all<'a, 'n, H: AsRef<[u8]> + ?Sized>(header: &'a H, name: &'n str) -> GetAll<'a, 'n> {
    Cookies::new(header).get_all(name)
}

/// Everything the gateway needs about one credential cookie, in one pass with
/// no allocation: the lookup, the shadow names, and the scan's statistics.
///
/// # Examples
///
/// ```
/// use cookie_net::{self as cookie, Limits, Lookup};
///
/// let found = cookie::locate("sid=evil; __Host-sid=t0k3n", "__Host-sid", &Limits::DEFAULT);
/// assert_eq!(found.lookup, Lookup::One("t0k3n"));
/// assert_eq!((found.shadows, found.severity_hint()), (1, 5));
/// ```
#[must_use]
pub fn locate<'a, H: AsRef<[u8]> + ?Sized>(
    header: &'a H,
    name: &str,
    limits: &Limits,
) -> Located<'a> {
    match Cookies::with_limits(header, limits) {
        Ok(c) => c.locate(name),
        Err(_) => Cookies::too_long(limits).locate(name),
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use std::{string::String, vec::Vec};

    use super::*;

    #[test]
    fn test_version_matches_manifest() {
        assert_eq!(VERSION, env!("CARGO_PKG_VERSION"));
        assert_eq!(VERSION.split('.').count(), 3, "expected MAJOR.MINOR.PATCH");
    }

    #[test]
    fn test_lifetime_constants() {
        assert_eq!((MINUTE, HOUR, DAY), (60, 3600, 86_400));
        assert_eq!(MAX_LIFETIME, 400 * DAY);
    }

    #[test]
    fn test_locate_over_long_header_is_header_too_long() {
        let l = Limits::DEFAULT.max_header_len(4);
        let found = locate("a=12345", "a", &l);
        assert_eq!(found.lookup, Lookup::HeaderTooLong);
        assert!(found.stats.too_long);
        assert_eq!(found.severity_hint(), 10);
    }

    #[test]
    fn test_inputs_of_every_byte_like_type() {
        let s = String::from("a=1");
        let v: Vec<u8> = b"a=1".to_vec();
        assert_eq!(get(&s, "a"), Some("1"));
        assert_eq!(get(&v, "a"), Some("1"));
        assert_eq!(get(b"a=1", "a"), Some("1"));
        assert_eq!(get("a=1", "a"), Some("1"));
        assert_eq!(get(&b"a=1"[..], "a"), Some("1"));
    }

    #[test]
    fn test_send_sync() {
        fn check<T: Send + Sync>() {}
        check::<Limits>();
        check::<Cookies<'_>>();
        check::<Pair<'_>>();
        check::<Stats>();
        check::<Lookup<'_>>();
        check::<Located<'_>>();
        check::<SetCookie<'_>>();
        check::<SetCookieBuilder<'_>>();
        check::<Iter<'_>>();
        check::<GetAll<'_, '_>>();
        check::<CookieError>();
    }
}
