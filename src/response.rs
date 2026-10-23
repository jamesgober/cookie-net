//! Writing `Set-Cookie` (rfc6265bis section 4.1): [`SetCookie`],
//! [`SetCookieBuilder`], [`SameSite`].
//!
//! A `SetCookie` is valid by construction (decision D-002): the builder checks
//! every rule before it hands one out, so writing can only run out of room.

use core::fmt;

use parse_net::{CountSink, Full, HttpDate, Sink, SliceSink};

use crate::{
    MAX_LIFETIME,
    error::{CookieError, at},
    limits::PAIR_MAX,
    name::{self, Prefix},
    request::Len,
};

/// The most extension attributes on one cookie.
const MAX_EXTENSIONS: usize = 8;
/// The longest attribute value user agents keep (rfc6265bis section 5.6).
const MAX_ATTRIBUTE: usize = 1024;
/// The attribute names an extension may not redefine.
const DEFINED: [&str; 8] = [
    "Expires",
    "Max-Age",
    "Domain",
    "Path",
    "Secure",
    "HttpOnly",
    "SameSite",
    "Partitioned",
];

/// The `SameSite` attribute (rfc6265bis section 4.1.2.7).
///
/// cookie-net always writes the attribute, so the "Lax-allowing-unsafe"
/// relaxation for cookies without one (section 5.6.7.2) never applies.
///
/// # Examples
///
/// ```
/// use cookie_net::{SameSite, SetCookie};
///
/// assert_eq!(SameSite::default(), SameSite::Lax);
/// let c = SetCookie::builder("a", "1").same_site(SameSite::Strict).build()?;
/// assert_eq!(c.same_site(), SameSite::Strict);
/// # Ok::<(), cookie_net::CookieError>(())
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub enum SameSite {
    /// Never sent with a request started by another site.
    Strict,
    /// Sent with top-level `GET` navigations from other sites, never with
    /// their `POST`, `fetch`, or frames. The default.
    #[default]
    Lax,
    /// Sent everywhere; requires `Secure`.
    None,
}

impl SameSite {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Strict => "Strict",
            Self::Lax => "Lax",
            Self::None => "None",
        }
    }
}

/// One `Set-Cookie` field value, valid by construction.
///
/// The only ways to get one are [`new`](Self::new), [`delete`](Self::delete),
/// [`SetCookieBuilder::build`], and the session helpers; each checks every
/// rule. There is no `Display`: [`encode`](Self::encode) and its siblings are
/// the explicit ways to turn a cookie (and the token in it) into bytes.
/// `Debug` shows the attributes and the value's length, never the value.
///
/// # Examples
///
/// ```
/// use cookie_net::SetCookie;
///
/// # #[cfg(feature = "alloc")] {
/// let c = SetCookie::new("theme", "dark")?;
/// assert_eq!(c.encode(), "theme=dark; Path=/; Secure; HttpOnly; SameSite=Lax");
/// # }
/// # Ok::<(), cookie_net::CookieError>(())
/// ```
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SetCookie<'a> {
    name: &'a str,
    value: &'a str,
    path: &'a str,
    domain: Option<&'a str>,
    max_age: Option<u64>,
    expires: Option<u64>,
    same_site: SameSite,
    secure: bool,
    http_only: bool,
    partitioned: bool,
    deletion: bool,
    extensions: [&'a str; MAX_EXTENSIONS],
    extension_count: u8,
}

impl<'a> SetCookie<'a> {
    /// A cookie with the defaults: `Secure; HttpOnly; SameSite=Lax; Path=/`,
    /// host-only, and no `Max-Age` (the browser drops it when it closes).
    ///
    /// # Errors
    ///
    /// `EmptyName`, `InvalidName`, `InvalidValue`, `TooLarge`, and the prefix
    /// rules: see [rules](SetCookieBuilder::build).
    ///
    /// # Examples
    ///
    /// ```
    /// use cookie_net::{CookieError, SetCookie};
    ///
    /// assert!(SetCookie::new("theme", "dark").is_ok());
    /// assert_eq!(SetCookie::new("a b", "1").unwrap_err(), CookieError::InvalidName { at: 1 });
    /// ```
    pub fn new(name: &'a str, value: &'a str) -> Result<SetCookie<'a>, CookieError> {
        Self::builder(name, value).build()
    }

    /// A builder starting from the defaults of [`new`](Self::new).
    ///
    /// # Examples
    ///
    /// ```
    /// let c = cookie_net::SetCookie::builder("a", "1").max_age(60).build()?;
    /// assert_eq!(c.max_age(), Some(60));
    /// # Ok::<(), cookie_net::CookieError>(())
    /// ```
    #[must_use]
    pub const fn builder(name: &'a str, value: &'a str) -> SetCookieBuilder<'a> {
        SetCookieBuilder {
            draft: SetCookie {
                name,
                value,
                path: "/",
                domain: None,
                max_age: None,
                expires: None,
                same_site: SameSite::Lax,
                secure: true,
                http_only: true,
                partitioned: false,
                deletion: false,
                extensions: [""; MAX_EXTENSIONS],
                extension_count: 0,
            },
            expires_now: None,
            too_many_extensions: false,
        }
    }

    /// A cookie that removes `name` from a browser: an empty value and
    /// `Expires=Thu, 01 Jan 1970 00:00:00 GMT` with the default attributes,
    /// which match any cookie set with the defaults, every `__Host-` cookie
    /// included (removal works only when name, path, and domain match,
    /// rfc6265bis section 3.1). For a cookie set with another `Path` or
    /// `Domain`, use the builder's [`delete`](SetCookieBuilder::delete).
    ///
    /// # Errors
    ///
    /// `EmptyName`, `InvalidName`, `TooLarge`.
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(feature = "alloc")] {
    /// let gone = cookie_net::SetCookie::delete("__Host-sid")?;
    /// assert_eq!(
    ///     gone.encode(),
    ///     "__Host-sid=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Secure; HttpOnly; SameSite=Lax"
    /// );
    /// # }
    /// # Ok::<(), cookie_net::CookieError>(())
    /// ```
    pub fn delete(name: &'a str) -> Result<SetCookie<'a>, CookieError> {
        Self::builder(name, "").delete().build()
    }

    /// Writes the field value into `out`. When the sink knows its room and
    /// the cookie does not fit, nothing is written.
    ///
    /// # Errors
    ///
    /// [`CookieError::Full`] when the sink has no room.
    ///
    /// # Examples
    ///
    /// ```
    /// use cookie_net::SetCookie;
    /// use parse_net::SliceSink;
    ///
    /// let c = SetCookie::new("theme", "dark")?;
    /// let mut buf = [0u8; 128];
    /// let mut out = SliceSink::new(&mut buf);
    /// c.write_to(&mut out)?;
    /// assert_eq!(out.len(), c.encoded_len());
    /// # Ok::<(), cookie_net::CookieError>(())
    /// ```
    pub fn write_to(&self, out: &mut impl Sink) -> Result<(), CookieError> {
        if out
            .remaining()
            .is_some_and(|room| room < self.encoded_len())
        {
            return Err(CookieError::Full);
        }
        self.emit(out).map_err(CookieError::from)
    }

    /// The exact number of bytes [`write_to`](Self::write_to) writes.
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(feature = "alloc")] {
    /// let c = cookie_net::SetCookie::new("a", "1")?;
    /// assert_eq!(c.encoded_len(), c.encode().len());
    /// # }
    /// # Ok::<(), cookie_net::CookieError>(())
    /// ```
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        let mut count = CountSink::new();
        // A CountSink never refuses bytes.
        let _ = self.emit(&mut count);
        count.count()
    }

    /// Writes the field value into the start of `buf` and returns it.
    ///
    /// # Errors
    ///
    /// [`CookieError::Full`] when `buf` is shorter than
    /// [`encoded_len`](Self::encoded_len).
    ///
    /// # Examples
    ///
    /// ```
    /// let c = cookie_net::SetCookie::new("a", "1")?;
    /// let mut buf = [0u8; 64];
    /// assert_eq!(c.encode_into(&mut buf)?, "a=1; Path=/; Secure; HttpOnly; SameSite=Lax");
    /// # Ok::<(), cookie_net::CookieError>(())
    /// ```
    pub fn encode_into<'b>(&self, buf: &'b mut [u8]) -> Result<&'b str, CookieError> {
        let len = self.encoded_len();
        let dst = buf.get_mut(..len).ok_or(CookieError::Full)?;
        self.emit(&mut SliceSink::new(&mut *dst))?;
        let dst: &'b [u8] = dst;
        // Every byte written is ASCII: names are tokens, values cookie-octets,
        // attributes av-octets.
        core::str::from_utf8(dst).map_err(|_| CookieError::Full)
    }

    /// The field value as a `String`.
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(feature = "alloc")] {
    /// let c = cookie_net::SetCookie::new("a", "1")?;
    /// assert!(c.encode().starts_with("a=1; "));
    /// # }
    /// # Ok::<(), cookie_net::CookieError>(())
    /// ```
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    #[must_use]
    pub fn encode(&self) -> alloc::string::String {
        let mut out = alloc::vec::Vec::with_capacity(self.encoded_len());
        // A Vec never refuses bytes.
        let _ = self.emit(&mut out);
        // Every byte written is ASCII (see `encode_into`).
        alloc::string::String::from_utf8(out).unwrap_or_default()
    }

    fn emit<S: Sink + ?Sized>(&self, out: &mut S) -> Result<(), Full> {
        out.put(self.name.as_bytes())?;
        out.put(b"=")?;
        out.put(self.value.as_bytes())?;
        out.put(b"; Path=")?;
        out.put(self.path.as_bytes())?;
        if let Some(domain) = self.domain {
            out.put(b"; Domain=")?;
            put_lowercase(domain.as_bytes(), out)?;
        }
        if let Some(secs) = self.max_age {
            out.put(b"; Max-Age=")?;
            put_decimal(secs, out)?;
        }
        if let Some(secs) = self.expires {
            // `build` proved the date is representable.
            if let Some(date) = i64::try_from(secs)
                .ok()
                .and_then(|s| HttpDate::from_unix(s).ok())
            {
                out.put(b"; Expires=")?;
                out.put(&date.format())?;
            }
        }
        if self.secure {
            out.put(b"; Secure")?;
        }
        if self.http_only {
            out.put(b"; HttpOnly")?;
        }
        out.put(b"; SameSite=")?;
        out.put(self.same_site.as_str().as_bytes())?;
        if self.partitioned {
            out.put(b"; Partitioned")?;
        }
        for ext in self.extensions() {
            out.put(b"; ")?;
            out.put(ext.as_bytes())?;
        }
        Ok(())
    }

    fn extensions(&self) -> &[&'a str] {
        self.extensions
            .get(..usize::from(self.extension_count))
            .unwrap_or_default()
    }

    /// The name.
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(cookie_net::SetCookie::new("a", "1")?.name(), "a");
    /// # Ok::<(), cookie_net::CookieError>(())
    /// ```
    #[must_use]
    pub const fn name(&self) -> &'a str {
        self.name
    }

    /// The value (empty for a deletion).
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(cookie_net::SetCookie::new("a", "1")?.value(), "1");
    /// # Ok::<(), cookie_net::CookieError>(())
    /// ```
    #[must_use]
    pub const fn value(&self) -> &'a str {
        self.value
    }

    /// `Max-Age` in seconds, when set.
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(cookie_net::SetCookie::new("a", "1")?.max_age(), None);
    /// # Ok::<(), cookie_net::CookieError>(())
    /// ```
    #[must_use]
    pub const fn max_age(&self) -> Option<u64> {
        self.max_age
    }

    /// `Expires` as Unix seconds, when set (0 for a deletion).
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(cookie_net::SetCookie::delete("a")?.expires(), Some(0));
    /// # Ok::<(), cookie_net::CookieError>(())
    /// ```
    #[must_use]
    pub const fn expires(&self) -> Option<u64> {
        self.expires
    }

    /// `Path` (default `/`).
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(cookie_net::SetCookie::new("a", "1")?.path(), "/");
    /// # Ok::<(), cookie_net::CookieError>(())
    /// ```
    #[must_use]
    pub const fn path(&self) -> &'a str {
        self.path
    }

    /// `Domain` as given, when set (it is written lowercase).
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(cookie_net::SetCookie::new("a", "1")?.domain(), None);
    /// # Ok::<(), cookie_net::CookieError>(())
    /// ```
    #[must_use]
    pub const fn domain(&self) -> Option<&'a str> {
        self.domain
    }

    /// `SameSite`.
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(cookie_net::SetCookie::new("a", "1")?.same_site(), cookie_net::SameSite::Lax);
    /// # Ok::<(), cookie_net::CookieError>(())
    /// ```
    #[must_use]
    pub const fn same_site(&self) -> SameSite {
        self.same_site
    }

    /// Whether `Secure` is written.
    ///
    /// # Examples
    ///
    /// ```
    /// assert!(cookie_net::SetCookie::new("a", "1")?.is_secure());
    /// # Ok::<(), cookie_net::CookieError>(())
    /// ```
    #[must_use]
    pub const fn is_secure(&self) -> bool {
        self.secure
    }

    /// Whether `HttpOnly` is written.
    ///
    /// # Examples
    ///
    /// ```
    /// assert!(cookie_net::SetCookie::new("a", "1")?.is_http_only());
    /// # Ok::<(), cookie_net::CookieError>(())
    /// ```
    #[must_use]
    pub const fn is_http_only(&self) -> bool {
        self.http_only
    }

    /// Whether `Partitioned` is written.
    ///
    /// # Examples
    ///
    /// ```
    /// assert!(!cookie_net::SetCookie::new("a", "1")?.is_partitioned());
    /// # Ok::<(), cookie_net::CookieError>(())
    /// ```
    #[must_use]
    pub const fn is_partitioned(&self) -> bool {
        self.partitioned
    }

    /// Whether this cookie removes one from the browser.
    ///
    /// # Examples
    ///
    /// ```
    /// assert!(cookie_net::SetCookie::delete("a")?.is_deletion());
    /// # Ok::<(), cookie_net::CookieError>(())
    /// ```
    #[must_use]
    pub const fn is_deletion(&self) -> bool {
        self.deletion
    }
}

impl fmt::Debug for SetCookie<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SetCookie")
            .field("name", &self.name)
            .field("value", &Len(self.value.len()))
            .field("path", &self.path)
            .field("domain", &self.domain)
            .field("max_age", &self.max_age)
            .field("expires", &self.expires)
            .field("secure", &self.secure)
            .field("http_only", &self.http_only)
            .field("same_site", &self.same_site)
            .field("partitioned", &self.partitioned)
            .field("deletion", &self.deletion)
            .field("extensions", &self.extensions())
            .finish()
    }
}

fn put_lowercase<S: Sink + ?Sized>(s: &[u8], out: &mut S) -> Result<(), Full> {
    let mut buf = [0u8; 64];
    for chunk in s.chunks(buf.len()) {
        let dst = buf.get_mut(..chunk.len()).ok_or(Full)?;
        for (d, &b) in dst.iter_mut().zip(chunk) {
            *d = b.to_ascii_lowercase();
        }
        out.put(dst)?;
    }
    Ok(())
}

fn put_decimal<S: Sink + ?Sized>(mut n: u64, out: &mut S) -> Result<(), Full> {
    let mut buf = [0u8; 20];
    let mut i = buf.len();
    loop {
        i -= 1;
        if let Some(d) = buf.get_mut(i) {
            *d = b'0' + (n % 10) as u8;
        }
        n /= 10;
        if n == 0 || i == 0 {
            break;
        }
    }
    out.put(buf.get(i..).unwrap_or_default())
}

/// Builds a [`SetCookie`]. Setters never fail and may come in any order; a
/// later call to the same setter replaces the earlier one. `build` checks
/// every rule.
///
/// # Examples
///
/// ```
/// use cookie_net::{self as cookie, SameSite, SetCookie};
///
/// # #[cfg(feature = "alloc")] {
/// let c = SetCookie::builder("__Secure-pref", "compact")
///     .domain("Example.COM")
///     .max_age(30 * cookie::DAY)
///     .same_site(SameSite::Strict)
///     .build()?;
/// assert_eq!(
///     c.encode(),
///     "__Secure-pref=compact; Path=/; Domain=example.com; Max-Age=2592000; Secure; HttpOnly; SameSite=Strict"
/// );
/// # }
/// # Ok::<(), cookie::CookieError>(())
/// ```
#[derive(Clone, Copy)]
pub struct SetCookieBuilder<'a> {
    draft: SetCookie<'a>,
    expires_now: Option<u64>,
    too_many_extensions: bool,
}

impl<'a> SetCookieBuilder<'a> {
    /// `Max-Age`: 1 to [`MAX_LIFETIME`](crate::MAX_LIFETIME) seconds.
    ///
    /// # Examples
    ///
    /// ```
    /// use cookie_net::{CookieError, SetCookie};
    ///
    /// assert_eq!(SetCookie::builder("a", "1").max_age(0).build().unwrap_err(), CookieError::MaxAgeOutOfRange);
    /// ```
    #[must_use]
    pub const fn max_age(mut self, secs: u64) -> Self {
        self.draft.max_age = Some(secs);
        self
    }

    /// `Expires` at Unix second `at`, which must be at most 400 days after
    /// `now` (rfc6265bis section 5.5). Written as an IMF-fixdate.
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(feature = "alloc")] {
    /// let c = cookie_net::SetCookie::builder("a", "1").expires(1_792_607_880, 1_792_600_000).build()?;
    /// assert!(c.encode().contains("; Expires=Wed, 21 Oct 2026 18:38:00 GMT"));
    /// # }
    /// # Ok::<(), cookie_net::CookieError>(())
    /// ```
    #[must_use]
    pub const fn expires(mut self, at: u64, now: u64) -> Self {
        self.draft.expires = Some(at);
        self.expires_now = Some(now);
        self
    }

    /// `Domain`: the bare domain (`example.com`), written lowercase. Without
    /// it the cookie is host-only, which is safer.
    ///
    /// # Examples
    ///
    /// ```
    /// use cookie_net::{CookieError, SetCookie};
    ///
    /// assert_eq!(SetCookie::builder("a", "1").domain("localhost").build().unwrap_err(), CookieError::InvalidDomain);
    /// ```
    #[must_use]
    pub const fn domain(mut self, domain: &'a str) -> Self {
        self.draft.domain = Some(domain);
        self
    }

    /// `Path`: starts with `/` (default `/`).
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(feature = "alloc")] {
    /// let c = cookie_net::SetCookie::builder("a", "1").path("/app").build()?;
    /// assert!(c.encode().contains("; Path=/app;"));
    /// # }
    /// # Ok::<(), cookie_net::CookieError>(())
    /// ```
    #[must_use]
    pub const fn path(mut self, path: &'a str) -> Self {
        self.draft.path = path;
        self
    }

    /// `SameSite` (default `Lax`).
    ///
    /// # Examples
    ///
    /// ```
    /// use cookie_net::{SameSite, SetCookie};
    ///
    /// # #[cfg(feature = "alloc")] {
    /// let c = SetCookie::builder("a", "1").same_site(SameSite::None).build()?;
    /// assert!(c.encode().ends_with("SameSite=None"));
    /// # }
    /// # Ok::<(), cookie_net::CookieError>(())
    /// ```
    #[must_use]
    pub const fn same_site(mut self, same_site: SameSite) -> Self {
        self.draft.same_site = same_site;
        self
    }

    /// `Partitioned` (CHIPS): the cookie is kept per top-level site.
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(feature = "alloc")] {
    /// let c = cookie_net::SetCookie::builder("w", "1").partitioned().build()?;
    /// assert!(c.encode().ends_with("; Partitioned"));
    /// # }
    /// # Ok::<(), cookie_net::CookieError>(())
    /// ```
    #[must_use]
    pub const fn partitioned(mut self) -> Self {
        self.draft.partitioned = true;
        self
    }

    /// Drops `Secure`, for local development over `http://localhost` only.
    /// Refused with a prefix, `SameSite=None`, or `Partitioned`.
    ///
    /// # Examples
    ///
    /// ```
    /// let dev = cookie_net::SetCookie::builder("theme", "dark").insecure().build()?;
    /// assert!(!dev.is_secure());
    /// # Ok::<(), cookie_net::CookieError>(())
    /// ```
    #[must_use]
    pub const fn insecure(mut self) -> Self {
        self.draft.secure = false;
        self
    }

    /// Drops `HttpOnly`, so page scripts can read the cookie.
    ///
    /// # Examples
    ///
    /// ```
    /// let c = cookie_net::SetCookie::builder("theme", "dark").script_readable().build()?;
    /// assert!(!c.is_http_only());
    /// # Ok::<(), cookie_net::CookieError>(())
    /// ```
    #[must_use]
    pub const fn script_readable(mut self) -> Self {
        self.draft.http_only = false;
        self
    }

    /// Adds an extension attribute such as `Priority=High` (at most 8; not a
    /// defined attribute name).
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(feature = "alloc")] {
    /// let c = cookie_net::SetCookie::builder("a", "1").extension("Priority=High").build()?;
    /// assert!(c.encode().ends_with("; Priority=High"));
    /// # }
    /// # Ok::<(), cookie_net::CookieError>(())
    /// ```
    #[must_use]
    pub fn extension(mut self, attribute: &'a str) -> Self {
        match self
            .draft
            .extensions
            .get_mut(usize::from(self.draft.extension_count))
        {
            Some(slot) => {
                *slot = attribute;
                self.draft.extension_count += 1;
            }
            None => self.too_many_extensions = true,
        }
        self
    }

    /// Makes this a deletion: an empty value, `Expires` in 1970, no
    /// `Max-Age`, every other attribute kept (removal needs the same `Path`
    /// and `Domain` as the cookie it removes).
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(feature = "alloc")] {
    /// let c = cookie_net::SetCookie::builder("pref", "").path("/app").delete().build()?;
    /// assert_eq!(
    ///     c.encode(),
    ///     "pref=; Path=/app; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Secure; HttpOnly; SameSite=Lax"
    /// );
    /// # }
    /// # Ok::<(), cookie_net::CookieError>(())
    /// ```
    #[must_use]
    pub const fn delete(mut self) -> Self {
        self.draft.deletion = true;
        self
    }

    /// Checks every rule, in this order, and returns the first one broken:
    ///
    /// 1. the name is a non-empty `token` (rfc6265bis 4.1.1)
    /// 2. the value is `*cookie-octet` or a quoted one (4.1.1)
    /// 3. name plus value at most 4096 bytes (5.6, 5.7)
    /// 4. `Path`, `Domain`, and each extension at most 1024 bytes (5.6)
    /// 5. `Path` starts with `/` and holds only `av-octet`s (4.1.1)
    /// 6. `Domain` is letter-digit-hyphen labels with a dot (4.1.2.3, 5.6.3)
    /// 7. extensions: at most 8, `av-octet`s, a `token` name that is not a
    ///    defined attribute (4.1.1)
    /// 8. `Max-Age` 1 to 34,560,000 (5.5)
    /// 9. `Expires` at most 400 days after `now` (5.5)
    /// 10. `__Host-`: `Secure`, `Path=/`, no `Domain` (4.1.3.2, 5.4)
    /// 11. `__Secure-`: `Secure` (4.1.3.1)
    /// 12. `SameSite=None` needs `Secure` (5.7)
    /// 13. `Partitioned` needs `Secure` (CHIPS 2.3, 3.1)
    ///
    /// A deletion skips rules 2, 8, and 9: its value and expiry are fixed.
    ///
    /// # Errors
    ///
    /// The [`CookieError`] of the first rule broken.
    ///
    /// # Examples
    ///
    /// ```
    /// use cookie_net::{CookieError, SameSite, SetCookie};
    ///
    /// assert_eq!(SetCookie::builder("__Host-sid", "x").domain("example.com").build().unwrap_err(), CookieError::HostPrefix);
    /// assert_eq!(
    ///     SetCookie::builder("embed", "1").same_site(SameSite::None).insecure().build().unwrap_err(),
    ///     CookieError::SameSiteNoneNeedsSecure
    /// );
    /// ```
    pub fn build(self) -> Result<SetCookie<'a>, CookieError> {
        let mut c = self.draft;
        if c.deletion {
            c.value = "";
            c.max_age = None;
            c.expires = Some(0);
        }
        let name = c.name.as_bytes();
        // 1
        if name.is_empty() {
            return Err(CookieError::EmptyName);
        }
        if let Some(i) = name::first_non_tchar(name) {
            return Err(CookieError::InvalidName { at: at(i) });
        }
        // 2
        if !c.deletion {
            name::check_value(c.value.as_bytes())
                .map_err(|i| CookieError::InvalidValue { at: at(i) })?;
        }
        // 3
        if name.len() + c.value.len() > PAIR_MAX {
            return Err(CookieError::TooLarge);
        }
        // 4
        if c.path.len() > MAX_ATTRIBUTE
            || c.domain.is_some_and(|d| d.len() > MAX_ATTRIBUTE)
            || c.extensions().iter().any(|e| e.len() > MAX_ATTRIBUTE)
        {
            return Err(CookieError::AttributeTooLong);
        }
        // 5
        let path = c.path.as_bytes();
        if path.first() != Some(&b'/') {
            return Err(CookieError::InvalidPath { at: 0 });
        }
        if let Some(i) = name::first_non_av_octet(path) {
            return Err(CookieError::InvalidPath { at: at(i) });
        }
        // 6
        if let Some(domain) = c.domain {
            if !is_domain(domain.as_bytes()) {
                return Err(CookieError::InvalidDomain);
            }
        }
        // 7
        if self.too_many_extensions {
            return Err(CookieError::TooManyExtensions);
        }
        for ext in c.extensions() {
            check_extension(ext)?;
        }
        if !c.deletion {
            // 8
            if c.max_age.is_some_and(|s| s == 0 || s > MAX_LIFETIME) {
                return Err(CookieError::MaxAgeOutOfRange);
            }
            // 9
            if let Some(secs) = c.expires {
                let now = self.expires_now.unwrap_or(0);
                let representable = i64::try_from(secs)
                    .ok()
                    .is_some_and(|s| HttpDate::from_unix(s).is_ok());
                if !representable || secs > now.saturating_add(MAX_LIFETIME) {
                    return Err(CookieError::ExpiresOutOfRange);
                }
            }
        }
        // 10, 11
        match name::of_bytes(name) {
            Prefix::Host if !c.secure || c.path != "/" || c.domain.is_some() => {
                return Err(CookieError::HostPrefix);
            }
            Prefix::Secure if !c.secure => return Err(CookieError::SecurePrefix),
            _ => {}
        }
        // 12
        if c.same_site == SameSite::None && !c.secure {
            return Err(CookieError::SameSiteNoneNeedsSecure);
        }
        // 13
        if c.partitioned && !c.secure {
            return Err(CookieError::PartitionedNeedsSecure);
        }
        Ok(c)
    }
}

impl fmt::Debug for SetCookieBuilder<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SetCookieBuilder")
            .field("draft", &self.draft)
            .field("too_many_extensions", &self.too_many_extensions)
            .finish()
    }
}

/// Rule 6: letter-digit-hyphen labels of 1 to 63 bytes, at least two, no
/// label starting or ending with `-`, at most 253 bytes, and a last label
/// that is not all digits (which refuses IPv4 addresses).
fn is_domain(d: &[u8]) -> bool {
    if d.len() > 253 {
        return false;
    }
    let mut labels = 0usize;
    let mut last_all_digits = false;
    for label in d.split(|&b| b == b'.') {
        let ok = matches!(label.len(), 1..=63)
            && label
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || *b == b'-')
            && label.first() != Some(&b'-')
            && label.last() != Some(&b'-');
        if !ok {
            return false;
        }
        labels += 1;
        last_all_digits = label.iter().all(u8::is_ascii_digit);
    }
    labels >= 2 && !last_all_digits
}

/// Rule 7 for one extension attribute.
fn check_extension(ext: &str) -> Result<(), CookieError> {
    let b = ext.as_bytes();
    if b.is_empty() {
        return Err(CookieError::InvalidExtension { at: 0 });
    }
    if let Some(i) = name::first_non_av_octet(b) {
        return Err(CookieError::InvalidExtension { at: at(i) });
    }
    // The attribute name must be a token, so every parser splits it the same
    // way (`x Max-Age=0` would be one unknown attribute to a user agent and
    // possibly two words to something else).
    let attr = ext.split('=').next().unwrap_or(ext);
    if attr.is_empty() {
        return Err(CookieError::InvalidExtension { at: 0 });
    }
    if let Some(i) = name::first_non_tchar(attr.as_bytes()) {
        return Err(CookieError::InvalidExtension { at: at(i) });
    }
    if DEFINED.iter().any(|d| d.eq_ignore_ascii_case(attr)) {
        return Err(CookieError::ExtensionNotAllowed);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    extern crate std;
    use std::{format, string::String};

    use super::*;
    use crate::DAY;

    fn text(c: &SetCookie<'_>) -> String {
        let mut buf = [0u8; 8192];
        String::from(c.encode_into(&mut buf).unwrap())
    }

    fn enc(c: Result<SetCookie<'_>, CookieError>) -> String {
        text(&c.unwrap())
    }

    fn err(b: SetCookieBuilder<'_>) -> CookieError {
        b.build().unwrap_err()
    }

    #[test]
    fn test_defaults_and_canonical_order() {
        assert_eq!(
            enc(SetCookie::new("theme", "dark")),
            "theme=dark; Path=/; Secure; HttpOnly; SameSite=Lax"
        );
        let c = SetCookie::builder("n", "v")
            .extension("ext1")
            .partitioned()
            .same_site(SameSite::None)
            .expires(1_792_607_880, 1_792_600_000)
            .max_age(3600)
            .domain("Example.com")
            .path("/")
            .extension("ext2=v")
            .build();
        assert_eq!(
            enc(c),
            "n=v; Path=/; Domain=example.com; Max-Age=3600; Expires=Wed, 21 Oct 2026 18:38:00 GMT; Secure; HttpOnly; SameSite=None; Partitioned; ext1; ext2=v"
        );
    }

    #[test]
    fn test_rule_1_name() {
        assert_eq!(err(SetCookie::builder("", "x")), CookieError::EmptyName);
        assert_eq!(
            err(SetCookie::builder("a=b", "x")),
            CookieError::InvalidName { at: 1 }
        );
        assert_eq!(
            err(SetCookie::builder("a;", "x")),
            CookieError::InvalidName { at: 1 }
        );
        assert_eq!(
            err(SetCookie::builder("é", "x")),
            CookieError::InvalidName { at: 0 }
        );
        assert!(SetCookie::new("__Host-", "x").is_ok());
    }

    #[test]
    fn test_rule_2_value() {
        assert_eq!(
            err(SetCookie::builder("a", "a b")),
            CookieError::InvalidValue { at: 1 }
        );
        assert!(SetCookie::new("a", "\"ab\"").is_ok());
        assert_eq!(
            err(SetCookie::builder("a", "\"a")),
            CookieError::InvalidValue { at: 2 }
        );
        assert_eq!(
            err(SetCookie::builder("a", "x;Domain=evil")),
            CookieError::InvalidValue { at: 1 }
        );
        assert!(SetCookie::new("a", "").is_ok());
    }

    #[test]
    fn test_every_control_refused_in_every_field() {
        for b in (0u8..0x20).chain([0x7f]) {
            let s = String::from_utf8(std::vec![b'a', b]).unwrap();
            assert!(
                matches!(
                    err(SetCookie::builder(&s, "x")),
                    CookieError::InvalidName { at: 1 }
                ),
                "{b}"
            );
            assert!(
                matches!(
                    err(SetCookie::builder("a", &s)),
                    CookieError::InvalidValue { at: 1 }
                ),
                "{b}"
            );
            let p = format!("/{s}");
            assert!(
                matches!(
                    err(SetCookie::builder("a", "x").path(&p)),
                    CookieError::InvalidPath { at: 2 }
                ),
                "{b}"
            );
            let d = format!("{s}.com");
            assert_eq!(
                err(SetCookie::builder("a", "x").domain(&d)),
                CookieError::InvalidDomain,
                "{b}"
            );
            assert!(
                matches!(
                    err(SetCookie::builder("a", "x").extension(&s)),
                    CookieError::InvalidExtension { at: 1 }
                ),
                "{b}"
            );
        }
    }

    #[test]
    fn test_rule_3_size() {
        let v = "v".repeat(4095);
        assert!(SetCookie::new("a", &v).is_ok());
        let v = "v".repeat(4096);
        assert_eq!(err(SetCookie::builder("a", &v)), CookieError::TooLarge);
        let n = "n".repeat(4097);
        assert_eq!(
            err(SetCookie::builder(&n, "").delete()),
            CookieError::TooLarge
        );
    }

    #[test]
    fn test_rule_4_attribute_length() {
        let p1024 = format!("/{}", "p".repeat(1023));
        let p1025 = format!("/{}", "p".repeat(1024));
        assert!(SetCookie::builder("a", "1").path(&p1024).build().is_ok());
        assert_eq!(
            err(SetCookie::builder("a", "1").path(&p1025)),
            CookieError::AttributeTooLong
        );
        let d = format!("{}.com", "a".repeat(1021));
        assert_eq!(
            err(SetCookie::builder("a", "1").domain(&d)),
            CookieError::AttributeTooLong
        );
        let e = "e".repeat(1025);
        assert_eq!(
            err(SetCookie::builder("a", "1").extension(&e)),
            CookieError::AttributeTooLong
        );
    }

    #[test]
    fn test_rule_5_path() {
        assert_eq!(
            err(SetCookie::builder("a", "1").path("")),
            CookieError::InvalidPath { at: 0 }
        );
        assert_eq!(
            err(SetCookie::builder("a", "1").path("a")),
            CookieError::InvalidPath { at: 0 }
        );
        assert_eq!(
            err(SetCookie::builder("a", "1").path("/a;b")),
            CookieError::InvalidPath { at: 2 }
        );
        assert_eq!(
            err(SetCookie::builder("a", "1").path("/a\r")),
            CookieError::InvalidPath { at: 2 }
        );
        assert!(
            SetCookie::builder("a", "1")
                .path("/a b,\"c\"")
                .build()
                .is_ok()
        );
    }

    #[test]
    fn test_rule_6_domain() {
        for bad in [
            ".example.com",
            "com",
            "localhost",
            "127.0.0.1",
            "[::1]",
            "exa mple.com",
            "example.com.",
            "a..com",
            "-a.com",
            "a-.com",
            "a_b.com",
            "",
            "1.2.3.4",
        ] {
            assert_eq!(
                err(SetCookie::builder("a", "1").domain(bad)),
                CookieError::InvalidDomain,
                "{bad}"
            );
        }
        let label63 = format!("{}.com", "a".repeat(63));
        let label64 = format!("{}.com", "a".repeat(64));
        assert!(
            SetCookie::builder("a", "1")
                .domain(&label63)
                .build()
                .is_ok()
        );
        assert_eq!(
            err(SetCookie::builder("a", "1").domain(&label64)),
            CookieError::InvalidDomain
        );
        for good in [
            "example.com",
            "EXAMPLE.com",
            "a-b.example.co.uk",
            "123.example.com",
            "xn--bcher-kva.example",
        ] {
            assert!(
                SetCookie::builder("a", "1").domain(good).build().is_ok(),
                "{good}"
            );
        }
        assert!(
            enc(SetCookie::builder("a", "1").domain("EXAMPLE.com").build())
                .contains("Domain=example.com;")
        );
    }

    #[test]
    fn test_rule_7_extensions() {
        assert!(
            SetCookie::builder("a", "1")
                .extension("foo=bar")
                .build()
                .is_ok()
        );
        assert_eq!(
            err(SetCookie::builder("a", "1").extension("foo;bar")),
            CookieError::InvalidExtension { at: 3 }
        );
        assert_eq!(
            err(SetCookie::builder("a", "1").extension("")),
            CookieError::InvalidExtension { at: 0 }
        );
        // the attribute name is a token: no spaces, no empty name
        for (ext, at) in [
            (" Path=/x", 0),
            ("x Max-Age=0", 1),
            ("=v", 0),
            ("Pri(ority", 3),
        ] {
            assert_eq!(
                err(SetCookie::builder("a", "1").extension(ext)),
                CookieError::InvalidExtension { at },
                "{ext}"
            );
        }
        assert!(
            SetCookie::builder("a", "1")
                .extension("Priority=High value, with spaces")
                .build()
                .is_ok()
        );
        for d in [
            "Secure",
            "secure",
            "SameSite=None",
            "domain=evil.com",
            "max-age=1",
            "EXPIRES=x",
            "httponly",
            "Partitioned",
        ] {
            assert_eq!(
                err(SetCookie::builder("a", "1").extension(d)),
                CookieError::ExtensionNotAllowed,
                "{d}"
            );
        }
        let mut b = SetCookie::builder("a", "1");
        for _ in 0..8 {
            b = b.extension("x");
        }
        assert!(b.build().is_ok());
        assert_eq!(err(b.extension("x")), CookieError::TooManyExtensions);
    }

    #[test]
    fn test_rule_8_max_age() {
        assert_eq!(
            err(SetCookie::builder("a", "1").max_age(0)),
            CookieError::MaxAgeOutOfRange
        );
        assert!(SetCookie::builder("a", "1").max_age(1).build().is_ok());
        assert!(
            SetCookie::builder("a", "1")
                .max_age(34_560_000)
                .build()
                .is_ok()
        );
        assert_eq!(
            err(SetCookie::builder("a", "1").max_age(34_560_001)),
            CookieError::MaxAgeOutOfRange
        );
        assert_eq!(
            enc(SetCookie::builder("a", "1").max_age(400 * DAY).build()),
            "a=1; Path=/; Max-Age=34560000; Secure; HttpOnly; SameSite=Lax"
        );
    }

    #[test]
    fn test_rule_9_expires() {
        let now = 1_792_600_000;
        assert!(
            SetCookie::builder("a", "1")
                .expires(now + MAX_LIFETIME, now)
                .build()
                .is_ok()
        );
        assert_eq!(
            err(SetCookie::builder("a", "1").expires(now + MAX_LIFETIME + 1, now)),
            CookieError::ExpiresOutOfRange
        );
        assert!(
            SetCookie::builder("a", "1")
                .expires(now - 10, now)
                .build()
                .is_ok()
        );
        assert_eq!(
            err(SetCookie::builder("a", "1").expires(u64::MAX, u64::MAX)),
            CookieError::ExpiresOutOfRange
        );
    }

    #[test]
    fn test_rule_10_host_prefix() {
        assert!(SetCookie::new("__Host-sid", "x").is_ok());
        assert_eq!(
            err(SetCookie::builder("__Host-sid", "x").domain("example.com")),
            CookieError::HostPrefix
        );
        assert_eq!(
            err(SetCookie::builder("__Host-sid", "x").path("/a")),
            CookieError::HostPrefix
        );
        assert_eq!(
            err(SetCookie::builder("__Host-sid", "x").insecure()),
            CookieError::HostPrefix
        );
        assert_eq!(
            err(SetCookie::builder("__host-sid", "x").insecure()),
            CookieError::HostPrefix
        );
        assert_eq!(
            err(SetCookie::builder("__HOST-sid", "x").path("/a")),
            CookieError::HostPrefix
        );
    }

    #[test]
    fn test_rule_11_secure_prefix() {
        assert!(
            SetCookie::builder("__Secure-a", "x")
                .domain("example.com")
                .path("/a")
                .build()
                .is_ok()
        );
        assert_eq!(
            err(SetCookie::builder("__Secure-a", "x").insecure()),
            CookieError::SecurePrefix
        );
        assert_eq!(
            err(SetCookie::builder("__secure-a", "x").insecure()),
            CookieError::SecurePrefix
        );
    }

    #[test]
    fn test_rules_12_and_13_need_secure() {
        assert_eq!(
            err(SetCookie::builder("a", "1")
                .same_site(SameSite::None)
                .insecure()),
            CookieError::SameSiteNoneNeedsSecure
        );
        assert!(
            SetCookie::builder("a", "1")
                .same_site(SameSite::None)
                .build()
                .is_ok()
        );
        assert_eq!(
            err(SetCookie::builder("a", "1").partitioned().insecure()),
            CookieError::PartitionedNeedsSecure
        );
        assert!(
            SetCookie::builder("a", "1")
                .insecure()
                .same_site(SameSite::Strict)
                .build()
                .is_ok()
        );
    }

    #[test]
    fn test_deletion_keeps_path_and_domain_and_skips_value_rules() {
        let c = SetCookie::builder("pref", "a b")
            .path("/app")
            .domain("example.com")
            .max_age(60)
            .delete()
            .build()
            .unwrap();
        assert_eq!(
            text(&c),
            "pref=; Path=/app; Domain=example.com; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Secure; HttpOnly; SameSite=Lax"
        );
        assert_eq!(
            (c.value(), c.max_age(), c.expires(), c.is_deletion()),
            ("", None, Some(0), true)
        );
        assert_eq!(
            err(SetCookie::builder("__Host-x", "").path("/a").delete()),
            CookieError::HostPrefix
        );
        let gone = SetCookie::delete("__Host-sid").unwrap();
        assert!(!text(&gone).contains("Max-Age"));
    }

    #[test]
    fn test_write_to_full_writes_nothing() {
        let c = SetCookie::new("theme", "dark").unwrap();
        let mut buf = [0u8; 10];
        let mut out = SliceSink::new(&mut buf);
        assert_eq!(c.write_to(&mut out), Err(CookieError::Full));
        assert!(out.is_empty());
        let mut small = [0u8; 10];
        assert_eq!(c.encode_into(&mut small), Err(CookieError::Full));
        let mut exact = std::vec![0u8; c.encoded_len()];
        assert_eq!(c.encode_into(&mut exact).unwrap(), text(&c));
    }

    #[test]
    fn test_getters() {
        let c = SetCookie::builder("a", "1")
            .domain("example.com")
            .path("/p")
            .same_site(SameSite::Strict)
            .script_readable()
            .partitioned()
            .build()
            .unwrap();
        assert_eq!(
            (c.name(), c.value(), c.path(), c.domain()),
            ("a", "1", "/p", Some("example.com"))
        );
        assert_eq!(c.same_site(), SameSite::Strict);
        assert!(c.is_secure() && !c.is_http_only() && c.is_partitioned() && !c.is_deletion());
    }

    #[test]
    fn test_debug_redacts_value() {
        let c = SetCookie::new("__Host-sid", "SECRETTOKEN").unwrap();
        let d = format!("{c:?}");
        assert!(!d.contains("SECRET") && d.contains("11 bytes"), "{d}");
        let b = SetCookie::builder("__Host-sid", "SECRETTOKEN");
        assert!(!format!("{b:?}").contains("SECRET"));
    }

    #[test]
    fn test_put_decimal_edges() {
        let mut buf = [0u8; 32];
        let mut v = SliceSink::new(&mut buf);
        put_decimal(0, &mut v).unwrap();
        put_decimal(u64::MAX, &mut v).unwrap();
        assert_eq!(v.written(), b"018446744073709551615");
    }
}
