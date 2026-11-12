//! A bounded client cookie jar (feature `jar`): the rfc6265bis storage model
//! (section 5.7) and retrieval (section 5.8.3) for a non-browser client.
//!
//! State lives behind [`JarStore`] (decision D-035), with [`MemoryStore`] as
//! the default; [`Jar::export`] and [`Jar::import`] move it to and from
//! durable or shared storage in a versioned, checksummed format.

use alloc::{string::String, vec::Vec};
use core::{fmt, net::Ipv4Addr};

use parse_net::Sink;

use super::set_cookie::{Text, parse_set_cookie};
use crate::{MAX_LIFETIME, SameSite, error::CookieError, request::Len};

/// Decides which domains are public suffixes (`co.uk`, `github.io`), where no
/// site may set a cookie for others.
///
/// The public suffix list is not bundled (it is large and changes often);
/// supply an implementation backed by it to share cookies across sibling
/// subdomains.
///
/// # Examples
///
/// ```
/// use cookie_net::{Jar, PublicSuffix, RequestUrl, StoreOutcome};
///
/// struct Com;
/// impl PublicSuffix for Com {
///     fn is_public_suffix(&self, domain: &str) -> bool { domain == "com" }
/// }
/// let mut jar = Jar::with_public_suffix(Com);
/// let url = RequestUrl::https("app.example.com", "/");
/// assert_eq!(jar.store(&url, "a=1; Domain=example.com", 0), StoreOutcome::Stored);
/// assert!(jar.cookie_header(&RequestUrl::https("www.example.com", "/"), 0).is_some());
/// ```
pub trait PublicSuffix {
    /// Whether `domain` (lowercase, no leading dot) is a public suffix.
    fn is_public_suffix(&self, domain: &str) -> bool;
}

/// The default: no suffix list, so every `Domain` attribute counts as a
/// public suffix and the jar **fails closed**. A `Domain` equal to the
/// request host makes a host-only cookie; any other `Domain` ignores the
/// cookie. No site can set a supercookie, at the cost of no cookie sharing
/// across sibling subdomains.
///
/// # Examples
///
/// ```
/// use cookie_net::{IgnoreReason, Jar, RequestUrl, StoreOutcome};
///
/// let mut jar = Jar::new();
/// let url = RequestUrl::https("app.example.com", "/");
/// assert_eq!(jar.store(&url, "a=1; Domain=app.example.com", 0), StoreOutcome::Stored);
/// assert_eq!(jar.store(&url, "b=1; Domain=example.com", 0), StoreOutcome::Ignored(IgnoreReason::DomainNotAllowed));
/// ```
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct NoSuffixList;

impl PublicSuffix for NoSuffixList {
    fn is_public_suffix(&self, _domain: &str) -> bool {
        true
    }
}

/// The request a cookie came with or goes out on, as parts (from url-lib or
/// any URL parser): `host` is the host without a port; `path` is the path
/// without the query.
///
/// # Examples
///
/// ```
/// let url = cookie_net::RequestUrl::https("api.example.com", "/v1/orders");
/// # let _ = url;
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequestUrl<'a> {
    secure: bool,
    host: &'a str,
    path: &'a str,
}

impl<'a> RequestUrl<'a> {
    /// An `https` URL.
    ///
    /// # Examples
    ///
    /// ```
    /// let _ = cookie_net::RequestUrl::https("example.com", "/");
    /// ```
    #[must_use]
    pub const fn https(host: &'a str, path: &'a str) -> Self {
        Self::new(true, host, path)
    }

    /// An `http` URL.
    ///
    /// # Examples
    ///
    /// ```
    /// let _ = cookie_net::RequestUrl::http("localhost", "/");
    /// ```
    #[must_use]
    pub const fn http(host: &'a str, path: &'a str) -> Self {
        Self::new(false, host, path)
    }

    /// A URL whose scheme is secure (`https`, `wss`) or not.
    ///
    /// # Examples
    ///
    /// ```
    /// let _ = cookie_net::RequestUrl::new(true, "example.com", "/");
    /// ```
    #[must_use]
    pub const fn new(secure: bool, host: &'a str, path: &'a str) -> Self {
        Self { secure, host, path }
    }
}

/// How a request relates to the site that started it, for `SameSite`.
///
/// A non-browser client acts for itself, so the default is same-site.
///
/// # Examples
///
/// ```
/// use cookie_net::RequestContext;
///
/// let nav = RequestContext::cross_site().navigation(true);   // a top-level GET from another site
/// assert_ne!(nav, RequestContext::default());
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequestContext<'a> {
    same_site: bool,
    navigation: bool,
    safe_method: bool,
    top_level_site: Option<&'a str>,
}

impl<'a> RequestContext<'a> {
    /// A same-site request: every cookie that matches is sent.
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(cookie_net::RequestContext::same_site(), cookie_net::RequestContext::default());
    /// ```
    #[must_use]
    pub const fn same_site() -> Self {
        Self {
            same_site: true,
            navigation: false,
            safe_method: false,
            top_level_site: None,
        }
    }

    /// A cross-site request: `Strict` cookies are never sent, `Lax` ones only
    /// on a top-level navigation with a safe method.
    ///
    /// # Examples
    ///
    /// ```
    /// let _ = cookie_net::RequestContext::cross_site();
    /// ```
    #[must_use]
    pub const fn cross_site() -> Self {
        Self {
            same_site: false,
            ..Self::same_site()
        }
    }

    /// Marks a top-level navigation, with a safe method (`GET`, `HEAD`) or not.
    ///
    /// # Examples
    ///
    /// ```
    /// let _ = cookie_net::RequestContext::cross_site().navigation(true);
    /// ```
    #[must_use]
    pub const fn navigation(mut self, safe_method: bool) -> Self {
        self.navigation = true;
        self.safe_method = safe_method;
        self
    }

    /// The top-level site, the key of partitioned cookies (default: the
    /// request host).
    ///
    /// # Examples
    ///
    /// ```
    /// let _ = cookie_net::RequestContext::same_site().top_level_site("shop.example");
    /// ```
    #[must_use]
    pub const fn top_level_site(mut self, site: &'a str) -> Self {
        self.top_level_site = Some(site);
        self
    }
}

impl Default for RequestContext<'_> {
    fn default() -> Self {
        Self::same_site()
    }
}

/// Bounds of a jar.
///
/// # Examples
///
/// ```
/// use cookie_net::{Jar, JarLimits};
///
/// let jar = Jar::new().with_limits(JarLimits::DEFAULT.per_domain(10).total(100));
/// # let _ = jar;
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct JarLimits {
    per_domain: u16,
    total: u32,
}

impl JarLimits {
    /// 50 cookies per domain and 3000 in all, the rfc6265bis section 6.1
    /// minimums.
    pub const DEFAULT: JarLimits = JarLimits {
        per_domain: 50,
        total: 3_000,
    };

    /// Cookies per domain (1 to 1000).
    ///
    /// # Examples
    ///
    /// ```
    /// let _ = cookie_net::JarLimits::DEFAULT.per_domain(20);
    /// ```
    #[must_use]
    pub const fn per_domain(self, n: u16) -> Self {
        let n = if n == 0 {
            1
        } else if n > 1_000 {
            1_000
        } else {
            n
        };
        Self {
            per_domain: n,
            ..self
        }
    }

    /// Cookies in all (1 to 1,000,000).
    ///
    /// # Examples
    ///
    /// ```
    /// let _ = cookie_net::JarLimits::DEFAULT.total(500);
    /// ```
    #[must_use]
    pub const fn total(self, n: u32) -> Self {
        let n = if n == 0 {
            1
        } else if n > 1_000_000 {
            1_000_000
        } else {
            n
        };
        Self { total: n, ..self }
    }
}

impl Default for JarLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// What [`Jar::store`] did.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum StoreOutcome {
    /// A new cookie was stored.
    Stored,
    /// A cookie with the same name, domain, and path was replaced (its
    /// creation time kept).
    Replaced,
    /// The cookie had expired, and the matching stored cookie was removed.
    Removed,
    /// The cookie was ignored.
    Ignored(IgnoreReason),
}

/// Why [`Jar::store`] ignored a cookie (rfc6265bis section 5.7).
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IgnoreReason {
    /// The section 5.6 algorithm ignores the line.
    Malformed,
    /// A nameless cookie whose value starts with `__Host-` or `__Secure-`.
    NamelessPrefixed,
    /// `Secure` from a non-secure origin.
    SecureFromInsecure,
    /// A non-secure origin would overwrite or shadow a `Secure` cookie.
    WouldShadowSecure,
    /// `Domain` does not domain-match the request host.
    DomainMismatch,
    /// `Domain` is a public suffix (with [`NoSuffixList`], any `Domain` other
    /// than the request host).
    DomainNotAllowed,
    /// A `__Host-` name without `Secure`, `Path=/`, or host-only.
    HostPrefix,
    /// A `__Secure-` name without `Secure`.
    SecurePrefix,
    /// `SameSite=None` without `Secure`.
    SameSiteNoneNeedsSecure,
    /// `Partitioned` without `Secure`.
    PartitionedNeedsSecure,
    /// Already expired, and nothing stored to remove.
    Expired,
    /// A cross-site response set a cookie that is not `SameSite=None`, and
    /// the request was not a top-level navigation (section 5.7 step 18).
    CrossSite,
    /// The request URL cannot be kept: a host that is empty or not printable
    /// ASCII, a top-level site likewise, or a cookie path over 1024 bytes or
    /// with a control character.
    InvalidRequestUrl,
}

/// One cookie as a jar stores it. `Debug` prints the value's length only.
#[non_exhaustive]
#[derive(Clone, PartialEq, Eq)]
pub struct StoredCookie {
    /// The name (empty for a nameless cookie).
    pub name: Vec<u8>,
    /// The value.
    pub value: Vec<u8>,
    /// The domain, lowercase: the request host for a host-only cookie.
    pub domain: String,
    /// The path.
    pub path: Vec<u8>,
    /// Unix expiry time; `None` for a session cookie.
    pub expiry: Option<u64>,
    /// Unix creation time (kept when the cookie is replaced).
    pub creation: u64,
    /// Unix time of the last retrieval.
    pub last_access: u64,
    /// Sent only to `domain` itself, not its subdomains.
    pub host_only: bool,
    /// Sent only over secure channels.
    pub secure: bool,
    /// Not exposed to scripts (always sent by this HTTP-only jar).
    pub http_only: bool,
    /// The `SameSite` attribute; `None` when the server sent none (or an
    /// unknown value), which the jar treats as `Lax`.
    pub same_site: Option<SameSite>,
    /// The partition key (top-level site) of a partitioned cookie.
    pub partition: Option<String>,
    /// Creation order, for sorting cookies created in the same second.
    seq: u64,
}

impl fmt::Debug for StoredCookie {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoredCookie")
            .field("name", &Text(&self.name))
            .field("value", &Len(self.value.len()))
            .field("domain", &self.domain)
            .field("path", &Text(&self.path))
            .field("expiry", &self.expiry)
            .field("host_only", &self.host_only)
            .field("secure", &self.secure)
            .field("same_site", &self.same_site)
            .field("partition", &self.partition)
            .finish_non_exhaustive()
    }
}

/// Where a jar keeps its cookies. Implement it to keep them in a durable or
/// shared store (write-through to disk, say); the jar applies every rule and
/// every bound itself, so a store only holds and indexes.
///
/// # Examples
///
/// ```
/// use cookie_net::{Jar, JarStore, MemoryStore, NoSuffixList, RequestUrl, StoredCookie};
///
/// /// A store that counts writes, over the memory store.
/// #[derive(Default)]
/// struct Counting { inner: MemoryStore, writes: usize }
/// impl JarStore for Counting {
///     fn len(&self) -> usize { self.inner.len() }
///     fn get(&self, i: usize) -> Option<&StoredCookie> { self.inner.get(i) }
///     fn get_mut(&mut self, i: usize) -> Option<&mut StoredCookie> { self.inner.get_mut(i) }
///     fn push(&mut self, c: StoredCookie) { self.writes += 1; self.inner.push(c) }
///     fn swap_remove(&mut self, i: usize) -> Option<StoredCookie> { self.writes += 1; self.inner.swap_remove(i) }
///     fn clear(&mut self) { self.inner.clear() }
/// }
/// let mut jar = Jar::with_store(NoSuffixList, Counting::default());
/// jar.store(&RequestUrl::https("example.com", "/"), "a=1", 0);
/// assert_eq!(jar.len(), 1);
/// ```
pub trait JarStore {
    /// The number of cookies.
    fn len(&self) -> usize;
    /// Whether the store is empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// The cookie at `index`.
    fn get(&self, index: usize) -> Option<&StoredCookie>;
    /// The cookie at `index`, to update its last-access time.
    fn get_mut(&mut self, index: usize) -> Option<&mut StoredCookie>;
    /// Adds a cookie.
    fn push(&mut self, cookie: StoredCookie);
    /// Removes the cookie at `index`, moving the last one into its place.
    fn swap_remove(&mut self, index: usize) -> Option<StoredCookie>;
    /// Removes every cookie.
    fn clear(&mut self);
}

/// The default store: a `Vec` in memory.
#[derive(Clone, Debug, Default)]
pub struct MemoryStore(Vec<StoredCookie>);

impl JarStore for MemoryStore {
    fn len(&self) -> usize {
        self.0.len()
    }

    fn get(&self, index: usize) -> Option<&StoredCookie> {
        self.0.get(index)
    }

    fn get_mut(&mut self, index: usize) -> Option<&mut StoredCookie> {
        self.0.get_mut(index)
    }

    fn push(&mut self, cookie: StoredCookie) {
        self.0.push(cookie);
    }

    fn swap_remove(&mut self, index: usize) -> Option<StoredCookie> {
        (index < self.0.len()).then(|| self.0.swap_remove(index))
    }

    fn clear(&mut self) {
        self.0.clear();
    }
}

/// A bounded client cookie jar.
///
/// # Examples
///
/// ```
/// use cookie_net::{IgnoreReason, Jar, RequestUrl, StoreOutcome};
///
/// let now = 1_800_000_000;
/// let mut jar = Jar::new();
/// let login = RequestUrl::https("app.example.com", "/login");
/// assert_eq!(jar.store(&login, "sid=abc; Path=/; Secure; HttpOnly", now), StoreOutcome::Stored);
/// assert_eq!(jar.store(&login, "tracker=1; Domain=com", now), StoreOutcome::Ignored(IgnoreReason::DomainNotAllowed));
///
/// let api = RequestUrl::https("app.example.com", "/api/orders");
/// assert_eq!(jar.cookie_header(&api, now).as_deref(), Some("sid=abc"));
/// assert_eq!(jar.cookie_header(&RequestUrl::http("app.example.com", "/"), now), None);   // Secure over HTTP
/// ```
pub struct Jar<P: PublicSuffix = NoSuffixList, S: JarStore = MemoryStore> {
    store: S,
    suffixes: P,
    limits: JarLimits,
    next_seq: u64,
}

impl Jar<NoSuffixList, MemoryStore> {
    /// An empty jar in memory, with no public suffix list (fail closed).
    ///
    /// # Examples
    ///
    /// ```
    /// assert!(cookie_net::Jar::new().is_empty());
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self::with_store(NoSuffixList, MemoryStore::default())
    }
}

impl Default for Jar<NoSuffixList, MemoryStore> {
    fn default() -> Self {
        Self::new()
    }
}

impl<P: PublicSuffix> Jar<P, MemoryStore> {
    /// An empty jar in memory that uses `suffixes` for public suffixes.
    ///
    /// # Examples
    ///
    /// ```
    /// let jar = cookie_net::Jar::with_public_suffix(cookie_net::NoSuffixList);
    /// # let _ = jar;
    /// ```
    #[must_use]
    pub fn with_public_suffix(suffixes: P) -> Self {
        Self::with_store(suffixes, MemoryStore::default())
    }
}

impl<P: PublicSuffix, S: JarStore> Jar<P, S> {
    /// A jar over `store`, which may already hold cookies.
    ///
    /// # Examples
    ///
    /// ```
    /// use cookie_net::{Jar, MemoryStore, NoSuffixList};
    ///
    /// let jar = Jar::with_store(NoSuffixList, MemoryStore::default());
    /// # let _ = jar;
    /// ```
    #[must_use]
    pub fn with_store(suffixes: P, store: S) -> Self {
        let next_seq = (0..store.len())
            .filter_map(|i| store.get(i).map(|c| c.seq))
            .max()
            .map_or(0, |s| s.saturating_add(1));
        Self {
            store,
            suffixes,
            limits: JarLimits::DEFAULT,
            next_seq,
        }
    }

    /// The jar's bounds (default [`JarLimits::DEFAULT`]).
    ///
    /// # Examples
    ///
    /// ```
    /// let jar = cookie_net::Jar::new().with_limits(cookie_net::JarLimits::DEFAULT.total(10));
    /// # let _ = jar;
    /// ```
    #[must_use]
    pub fn with_limits(mut self, limits: JarLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Stores one `Set-Cookie` line received from `url` at `now`, following
    /// rfc6265bis section 5.7, for a same-site request (what a client that is
    /// its own site makes). [`store_for`](Self::store_for) takes the request
    /// context.
    ///
    /// # Examples
    ///
    /// ```
    /// use cookie_net::{IgnoreReason, Jar, RequestUrl, StoreOutcome};
    ///
    /// let mut jar = Jar::new();
    /// let url = RequestUrl::http("example.com", "/");
    /// assert_eq!(jar.store(&url, "a=1; Secure", 0), StoreOutcome::Ignored(IgnoreReason::SecureFromInsecure));
    /// assert_eq!(jar.store(&url, "a=1", 0), StoreOutcome::Stored);
    /// assert_eq!(jar.store(&url, "a=2", 0), StoreOutcome::Replaced);
    /// assert_eq!(jar.store(&url, "a=; Max-Age=0", 0), StoreOutcome::Removed);
    /// ```
    pub fn store<L: AsRef<[u8]> + ?Sized>(
        &mut self,
        url: &RequestUrl<'_>,
        set_cookie: &L,
        now: u64,
    ) -> StoreOutcome {
        self.store_for(url, &RequestContext::same_site(), set_cookie, now)
    }

    /// As [`store`](Self::store), for the response to a request made in
    /// context `cx`. A cross-site response's cookie is ignored unless it is
    /// `SameSite=None` or the request was a top-level navigation (section 5.7
    /// step 18), and a partitioned cookie is kept under the context's
    /// top-level site (default: the request host).
    ///
    /// # Examples
    ///
    /// ```
    /// use cookie_net::{IgnoreReason, Jar, RequestContext, RequestUrl, StoreOutcome};
    ///
    /// let mut jar = Jar::new();
    /// let url = RequestUrl::https("widget.example", "/");
    /// let embedded = RequestContext::cross_site().top_level_site("shop.example");
    /// assert_eq!(jar.store_for(&url, &embedded, "a=1; Secure", 0), StoreOutcome::Ignored(IgnoreReason::CrossSite));
    /// assert_eq!(jar.store_for(&url, &embedded, "b=1; Secure; SameSite=None; Partitioned", 0), StoreOutcome::Stored);
    /// ```
    pub fn store_for<L: AsRef<[u8]> + ?Sized>(
        &mut self,
        url: &RequestUrl<'_>,
        cx: &RequestContext<'_>,
        set_cookie: &L,
        now: u64,
    ) -> StoreOutcome {
        let Some(v) = parse_set_cookie(set_cookie) else {
            return StoreOutcome::Ignored(IgnoreReason::Malformed);
        };
        if v.name.is_empty()
            && (starts_with_ci(v.value, b"__Secure-") || starts_with_ci(v.value, b"__Host-"))
        {
            return StoreOutcome::Ignored(IgnoreReason::NamelessPrefixed);
        }
        let host = url.host.to_ascii_lowercase();
        let site = cx
            .top_level_site
            .map_or_else(|| host.clone(), str::to_ascii_lowercase);
        if !keepable_host(&host) || !keepable_host(&site) {
            return StoreOutcome::Ignored(IgnoreReason::InvalidRequestUrl);
        }
        // An expired cookie may go at any time (section 5.7); here it would
        // otherwise block a replacement or give it its creation time.
        self.remove_expired(now);
        let cap = now.saturating_add(MAX_LIFETIME);
        let expiry = match (v.max_age, v.expires) {
            (Some(secs), _) => Some(if secs <= 0 {
                0
            } else {
                now.saturating_add(secs.unsigned_abs()).min(cap)
            }),
            (None, Some(t)) => Some(u64::try_from(t).unwrap_or(0).min(cap)),
            (None, None) => None,
        };
        // `Domain=.` leaves an empty domain attribute: a host-only cookie
        // (section 5.7 step 10).
        let (domain, host_only) = match v.domain.filter(|d| !d.is_empty()) {
            Some(d) => {
                let Ok(d) = core::str::from_utf8(d) else {
                    return StoreOutcome::Ignored(IgnoreReason::DomainMismatch);
                };
                let d = d.to_ascii_lowercase();
                if is_ip(&host) {
                    // an IP address only ever gets host-only cookies
                    if d == host {
                        (host.clone(), true)
                    } else {
                        return StoreOutcome::Ignored(IgnoreReason::DomainMismatch);
                    }
                } else if self.suffixes.is_public_suffix(&d) {
                    if d == host {
                        (host.clone(), true)
                    } else {
                        return StoreOutcome::Ignored(IgnoreReason::DomainNotAllowed);
                    }
                } else if domain_match(&host, &d) {
                    (d, false)
                } else {
                    return StoreOutcome::Ignored(IgnoreReason::DomainMismatch);
                }
            }
            None => (host.clone(), true),
        };
        let path: Vec<u8> = match v.path {
            Some(p) => p.to_vec(),
            None => default_path(url.path.as_bytes()).to_vec(),
        };
        if !keepable_path(&path) {
            return StoreOutcome::Ignored(IgnoreReason::InvalidRequestUrl);
        }
        if v.secure && !url.secure {
            return StoreOutcome::Ignored(IgnoreReason::SecureFromInsecure);
        }
        if v.same_site == Some(SameSite::None) && !v.secure {
            return StoreOutcome::Ignored(IgnoreReason::SameSiteNoneNeedsSecure);
        }
        if !cx.same_site && !cx.navigation && v.same_site != Some(SameSite::None) {
            return StoreOutcome::Ignored(IgnoreReason::CrossSite);
        }
        if v.partitioned && !v.secure {
            return StoreOutcome::Ignored(IgnoreReason::PartitionedNeedsSecure);
        }
        if starts_with_ci(v.name, b"__Secure-") && !v.secure {
            return StoreOutcome::Ignored(IgnoreReason::SecurePrefix);
        }
        // A `Path` attribute must be present, and the cookie's path, after a
        // value that does not start with `/` fell back to the default path,
        // must be `/` (sections 5.6.4 and 5.7 step 21).
        if starts_with_ci(v.name, b"__Host-")
            && !(v.secure && host_only && v.has_path && path == b"/")
        {
            return StoreOutcome::Ignored(IgnoreReason::HostPrefix);
        }
        if !v.secure && !url.secure && self.shadows_secure(v.name, &domain, &path) {
            return StoreOutcome::Ignored(IgnoreReason::WouldShadowSecure);
        }
        let partition = v.partitioned.then_some(site);
        let old = (0..self.store.len()).find(|&i| {
            self.store.get(i).is_some_and(|c| {
                c.name == v.name
                    && c.domain == domain
                    && c.host_only == host_only
                    && c.path == path
                    && c.partition == partition
            })
        });
        let old = old.and_then(|i| self.store.swap_remove(i));
        if expiry.is_some_and(|e| e <= now) {
            return if old.is_some() {
                StoreOutcome::Removed
            } else {
                StoreOutcome::Ignored(IgnoreReason::Expired)
            };
        }
        let (creation, seq) = match &old {
            Some(o) => (o.creation, o.seq),
            None => {
                let s = self.next_seq;
                self.next_seq = self.next_seq.saturating_add(1);
                (now, s)
            }
        };
        let replaced = old.is_some();
        let written = domain.clone();
        self.store.push(StoredCookie {
            name: v.name.to_vec(),
            value: v.value.to_vec(),
            domain,
            path,
            expiry,
            creation,
            last_access: now,
            host_only,
            secure: v.secure,
            http_only: v.http_only,
            same_site: v.same_site,
            partition,
            seq,
        });
        self.evict(now, &written);
        if replaced {
            StoreOutcome::Replaced
        } else {
            StoreOutcome::Stored
        }
    }

    /// Stores every line and returns how many were stored or replaced.
    ///
    /// # Examples
    ///
    /// ```
    /// let mut jar = cookie_net::Jar::new();
    /// let url = cookie_net::RequestUrl::https("example.com", "/");
    /// let lines: [&[u8]; 3] = [b"a=1", b"b=2", b"\x01"];
    /// assert_eq!(jar.store_all(&url, lines, 0), 2);
    /// ```
    pub fn store_all<'l, I: IntoIterator<Item = &'l [u8]>>(
        &mut self,
        url: &RequestUrl<'_>,
        lines: I,
        now: u64,
    ) -> usize {
        lines
            .into_iter()
            .filter(|line| {
                matches!(
                    self.store(url, *line, now),
                    StoreOutcome::Stored | StoreOutcome::Replaced
                )
            })
            .count()
    }

    /// The `Cookie` header for a same-site request to `url`, or `None` when
    /// no cookie applies (rfc6265bis section 5.8.3). Updates the last-access
    /// times of the cookies sent.
    ///
    /// # Examples
    ///
    /// ```
    /// use cookie_net::{Jar, RequestUrl};
    ///
    /// let mut jar = Jar::new();
    /// let url = RequestUrl::https("example.com", "/a/b");
    /// jar.store(&url, "short=1; Path=/", 0);
    /// jar.store(&url, "long=2; Path=/a", 0);
    /// assert_eq!(jar.cookie_header(&url, 0).as_deref(), Some("long=2; short=1"));   // longer paths first
    /// ```
    pub fn cookie_header(&mut self, url: &RequestUrl<'_>, now: u64) -> Option<String> {
        self.cookie_header_for(url, &RequestContext::same_site(), now)
    }

    /// As [`cookie_header`](Self::cookie_header), with a request context for
    /// `SameSite` and partitions.
    ///
    /// # Examples
    ///
    /// ```
    /// use cookie_net::{Jar, RequestContext, RequestUrl};
    ///
    /// let mut jar = Jar::new();
    /// let url = RequestUrl::https("example.com", "/");
    /// jar.store(&url, "s=1; SameSite=Strict", 0);
    /// jar.store(&url, "l=1; SameSite=Lax", 0);
    /// let nav = RequestContext::cross_site().navigation(true);
    /// assert_eq!(jar.cookie_header_for(&url, &nav, 0).as_deref(), Some("l=1"));
    /// assert_eq!(jar.cookie_header_for(&url, &RequestContext::cross_site(), 0), None);
    /// ```
    pub fn cookie_header_for(
        &mut self,
        url: &RequestUrl<'_>,
        cx: &RequestContext<'_>,
        now: u64,
    ) -> Option<String> {
        // Names and values come from Set-Cookie lines with no controls; they
        // may hold any other byte, which a `String` cannot, so a cookie that
        // is not UTF-8 is left out here (`write_cookie_header` writes it).
        let mut out = Vec::new();
        let n = self.write_header(url, cx, now, &mut out, true).ok()?;
        if n == 0 {
            return None;
        }
        String::from_utf8(out).ok()
    }

    /// Writes the `Cookie` header value into a sink and returns how many
    /// cookies it holds. Nothing is written when there is no room.
    ///
    /// # Errors
    ///
    /// [`CookieError::Full`].
    ///
    /// # Examples
    ///
    /// ```
    /// use cookie_net::{Jar, RequestContext, RequestUrl};
    ///
    /// let mut jar = Jar::new();
    /// let url = RequestUrl::https("example.com", "/");
    /// jar.store(&url, "a=1", 0);
    /// let mut out = Vec::new();
    /// assert_eq!(jar.write_cookie_header(&url, &RequestContext::default(), 0, &mut out)?, 1);
    /// assert_eq!(out, b"a=1");
    /// # Ok::<(), cookie_net::CookieError>(())
    /// ```
    pub fn write_cookie_header(
        &mut self,
        url: &RequestUrl<'_>,
        cx: &RequestContext<'_>,
        now: u64,
        out: &mut impl Sink,
    ) -> Result<usize, CookieError> {
        self.write_header(url, cx, now, out, false)
    }

    /// The cookies for a request, in order (section 5.8.3), written into
    /// `out`; with `text_only`, cookies whose name or value is not UTF-8 are
    /// left out. Last-access times are updated for the cookies written.
    fn write_header(
        &mut self,
        url: &RequestUrl<'_>,
        cx: &RequestContext<'_>,
        now: u64,
        out: &mut impl Sink,
        text_only: bool,
    ) -> Result<usize, CookieError> {
        let host = url.host.to_ascii_lowercase();
        let path = if url.path.is_empty() { "/" } else { url.path }.as_bytes();
        let site = cx
            .top_level_site
            .map_or_else(|| host.clone(), str::to_ascii_lowercase);
        let mut picked: Vec<usize> = (0..self.store.len())
            .filter(|&i| {
                self.store.get(i).is_some_and(|c| {
                    c.expiry.is_none_or(|e| e > now)
                        && if c.host_only {
                            host == c.domain
                        } else {
                            domain_match(&host, &c.domain)
                        }
                        && path_match(path, &c.path)
                        && (!c.secure || url.secure)
                        && (cx.same_site
                            || match c.same_site {
                                Some(SameSite::None) => true,
                                Some(SameSite::Strict) => false,
                                _ => cx.navigation && cx.safe_method,
                            })
                        && c.partition.as_ref().is_none_or(|p| *p == site)
                        && (!text_only
                            || (core::str::from_utf8(&c.name).is_ok()
                                && core::str::from_utf8(&c.value).is_ok()))
                })
            })
            .collect();
        // longer paths first, then earlier creation (section 5.8.3 step 2)
        picked.sort_by_key(|&i| {
            self.store.get(i).map_or((0, 0, 0), |c| {
                (usize::MAX - c.path.len(), c.creation, c.seq)
            })
        });
        let len: usize = picked
            .iter()
            .filter_map(|&i| self.store.get(i))
            .enumerate()
            .map(|(k, c)| {
                usize::from(k > 0) * 2
                    + c.value.len()
                    + if c.name.is_empty() {
                        0
                    } else {
                        c.name.len() + 1
                    }
            })
            .sum();
        if out.remaining().is_some_and(|room| room < len) {
            return Err(CookieError::Full);
        }
        for (k, &i) in picked.iter().enumerate() {
            let Some(c) = self.store.get(i) else { continue };
            if k > 0 {
                out.put(b"; ")?;
            }
            if !c.name.is_empty() {
                out.put(&c.name)?;
                out.put(b"=")?;
            }
            out.put(&c.value)?;
        }
        for &i in &picked {
            if let Some(c) = self.store.get_mut(i) {
                c.last_access = now;
            }
        }
        Ok(picked.len())
    }

    /// Removes expired cookies and returns how many.
    ///
    /// # Examples
    ///
    /// ```
    /// let mut jar = cookie_net::Jar::new();
    /// jar.store(&cookie_net::RequestUrl::https("example.com", "/"), "a=1; Max-Age=10", 0);
    /// assert_eq!(jar.remove_expired(10), 1);
    /// ```
    pub fn remove_expired(&mut self, now: u64) -> usize {
        self.remove_where(|c| c.expiry.is_some_and(|e| e <= now))
    }

    /// Removes every cookie.
    ///
    /// # Examples
    ///
    /// ```
    /// let mut jar = cookie_net::Jar::new();
    /// jar.store(&cookie_net::RequestUrl::https("example.com", "/"), "a=1", 0);
    /// jar.clear();
    /// assert!(jar.is_empty());
    /// ```
    pub fn clear(&mut self) {
        self.store.clear();
    }

    /// Removes the cookies of `domain` and its subdomains; returns how many.
    ///
    /// # Examples
    ///
    /// ```
    /// let mut jar = cookie_net::Jar::new();
    /// jar.store(&cookie_net::RequestUrl::https("a.example.com", "/"), "a=1", 0);
    /// jar.store(&cookie_net::RequestUrl::https("other.org", "/"), "b=1", 0);
    /// assert_eq!(jar.clear_domain("example.com"), 1);
    /// assert_eq!(jar.len(), 1);
    /// ```
    pub fn clear_domain(&mut self, domain: &str) -> usize {
        let domain = domain.to_ascii_lowercase();
        self.remove_where(|c| domain_match(&c.domain, &domain))
    }

    /// The number of cookies.
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(cookie_net::Jar::new().len(), 0);
    /// ```
    #[must_use]
    pub fn len(&self) -> usize {
        self.store.len()
    }

    /// Whether the jar is empty.
    ///
    /// # Examples
    ///
    /// ```
    /// assert!(cookie_net::Jar::new().is_empty());
    /// ```
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.store.is_empty()
    }

    /// The cookies, for inspection.
    ///
    /// # Examples
    ///
    /// ```
    /// let mut jar = cookie_net::Jar::new();
    /// jar.store(&cookie_net::RequestUrl::https("example.com", "/"), "a=1", 0);
    /// assert_eq!(jar.cookies().next().unwrap().domain, "example.com");
    /// ```
    pub fn cookies(&self) -> impl Iterator<Item = &StoredCookie> + '_ {
        (0..self.store.len()).filter_map(|i| self.store.get(i))
    }

    /// The jar in the export format (`docs/FORMATS.md`): a magic, a version,
    /// the cookies, and a BLAKE3 checksum. Values are included, so treat the
    /// bytes as secrets.
    ///
    /// # Examples
    ///
    /// ```
    /// use cookie_net::{Jar, RequestUrl};
    ///
    /// let mut jar = Jar::new();
    /// jar.store(&RequestUrl::https("example.com", "/"), "a=1", 0);
    /// let bytes = jar.export();
    /// let mut copy = Jar::new();
    /// assert_eq!(copy.import(&bytes, 0)?, 1);
    /// assert_eq!(copy.cookie_header(&RequestUrl::https("example.com", "/"), 0).as_deref(), Some("a=1"));
    /// # Ok::<(), cookie_net::CookieError>(())
    /// ```
    #[must_use]
    pub fn export(&self) -> Vec<u8> {
        // creation order, so an import keeps the order cookies are sent in
        let mut cookies: Vec<&StoredCookie> = self.cookies().collect();
        cookies.sort_by_key(|c| c.seq);
        export::write(cookies.into_iter(), self.len())
    }

    /// Adds the cookies of an exported jar. The bytes are untrusted input:
    /// the format and every field are checked, and a record that no `store`
    /// could have made (a `__Host-` cookie that is not host-only, `Secure`,
    /// and `Path=/`, say) fails the whole import. Records expired at `now`,
    /// and domain cookies this jar's public suffix list does not allow, are
    /// skipped. An imported cookie replaces a stored one with the same name,
    /// domain, host-only flag, path, and partition, keeping its creation
    /// time; times in the file later than `now` are brought back to `now`,
    /// and expiries are capped at 400 days. The jar's limits then apply, in
    /// the eviction order of [`store`](Self::store). Costs `n log n` in the
    /// number of cookies, and rewrites the store. Returns how many imported
    /// cookies were kept.
    ///
    /// # Errors
    ///
    /// [`CookieError::InvalidJarData`] for a wrong magic, version, checksum,
    /// length, field, or an impossible record; nothing is added then.
    ///
    /// # Examples
    ///
    /// ```
    /// use cookie_net::{CookieError, Jar};
    ///
    /// assert_eq!(Jar::new().import(b"not a jar", 0).unwrap_err(), CookieError::InvalidJarData);
    /// ```
    pub fn import(&mut self, bytes: &[u8], now: u64) -> Result<usize, CookieError> {
        let records = export::read(bytes)?;
        if !records.iter().all(could_be_stored) {
            return Err(CookieError::InvalidJarData);
        }
        let cap = now.saturating_add(MAX_LIFETIME);
        let mut all: Vec<Option<StoredCookie>> =
            Vec::with_capacity(self.store.len() + records.len());
        while let Some(c) = self.store.swap_remove(self.store.len().wrapping_sub(1)) {
            if c.expiry.is_none_or(|e| e > now) {
                all.push(Some(c));
            }
        }
        // the jar's cookies in their creation order, then the file's
        all.sort_by_key(|c| c.as_ref().map_or(0, |c| c.seq));
        let existing = all.len();
        for mut c in records {
            if c.expiry.is_some_and(|e| e <= now)
                || (!c.host_only && (is_ip(&c.domain) || self.suffixes.is_public_suffix(&c.domain)))
            {
                continue;
            }
            c.expiry = c.expiry.map(|e| e.min(cap));
            c.creation = c.creation.min(now);
            c.last_access = c.last_access.min(now);
            c.seq = self.next_seq;
            self.next_seq = self.next_seq.saturating_add(1);
            all.push(Some(c));
        }
        // one cookie per identity: the last one wins, with the first one's
        // creation time and order
        let mut order: Vec<usize> = (0..all.len()).collect();
        order.sort_by(|&a, &b| identity(&all[a]).cmp(&identity(&all[b])).then(a.cmp(&b)));
        let mut k = 0;
        while k < order.len() {
            let mut end = k + 1;
            while end < order.len() && identity(&all[order[end]]) == identity(&all[order[k]]) {
                end += 1;
            }
            let first = all[order[k]].as_ref().map(|c| (c.creation, c.seq));
            if let (Some((creation, seq)), Some(last)) = (first, all[order[end - 1]].as_mut()) {
                last.creation = creation;
                last.seq = seq;
            }
            for &dropped in &order[k..end - 1] {
                all[dropped] = None;
            }
            k = end;
        }
        // the limits, once: per domain, then in all, keeping the cookies the
        // eviction order keeps longest
        let keep_key = |c: &StoredCookie| (c.secure, c.last_access, c.seq);
        let mut alive: Vec<usize> = (0..all.len()).filter(|&i| all[i].is_some()).collect();
        alive.sort_by(|&a, &b| {
            let (x, y) = (all[a].as_ref(), all[b].as_ref());
            x.map(|c| &c.domain)
                .cmp(&y.map(|c| &c.domain))
                .then_with(|| y.map(keep_key).cmp(&x.map(keep_key)))
        });
        let per_domain = usize::from(self.limits.per_domain);
        let mut run = 0;
        for w in 0..alive.len() {
            let same = w > 0
                && all[alive[w]].as_ref().map(|c| &c.domain)
                    == all[alive[w - 1]].as_ref().map(|c| &c.domain);
            run = if same { run + 1 } else { 1 };
            if run > per_domain {
                all[alive[w]] = None;
            }
        }
        let total = usize::try_from(self.limits.total).unwrap_or(usize::MAX);
        let mut alive: Vec<usize> = (0..all.len()).filter(|&i| all[i].is_some()).collect();
        if alive.len() > total {
            alive.sort_by(|&a, &b| {
                all[b]
                    .as_ref()
                    .map(keep_key)
                    .cmp(&all[a].as_ref().map(keep_key))
            });
            for &i in &alive[total..] {
                all[i] = None;
            }
        }
        let kept = all[existing..].iter().filter(|c| c.is_some()).count();
        let mut survivors: Vec<StoredCookie> = all.into_iter().flatten().collect();
        survivors.sort_by_key(|c| c.seq);
        for c in survivors {
            self.store.push(c);
        }
        Ok(kept)
    }

    fn shadows_secure(&self, name: &[u8], domain: &str, path: &[u8]) -> bool {
        self.cookies().any(|c| {
            c.name == name
                && c.secure
                && (domain_match(&c.domain, domain) || domain_match(domain, &c.domain))
                && path_match(path, &c.path)
        })
    }

    fn remove_where(&mut self, mut f: impl FnMut(&StoredCookie) -> bool) -> usize {
        let mut removed = 0;
        let mut i = 0;
        while i < self.store.len() {
            if self.store.get(i).is_some_and(&mut f) {
                self.store.swap_remove(i);
                removed += 1;
            } else {
                i += 1;
            }
        }
        removed
    }

    /// Keeps the bounds after a cookie for `domain` was added: that domain,
    /// then the whole jar, in the order of `evict_one`.
    /// Linear in the jar's size.
    fn evict(&mut self, now: u64, domain: &str) {
        let per_domain = usize::from(self.limits.per_domain);
        while self.cookies().filter(|c| c.domain == domain).count() > per_domain {
            if !self.evict_one(now, |c| c.domain == domain) {
                break;
            }
        }
        let total = usize::try_from(self.limits.total).unwrap_or(usize::MAX);
        while self.store.len() > total {
            if !self.evict_one(now, |_| true) {
                break;
            }
        }
    }

    /// Removes one cookie among those `f` selects, in the order of rfc6265bis
    /// section 5.7: an expired one if any, else the least recently used
    /// non-secure one, else the least recently used (then the oldest). Secure
    /// cookies go last, so a non-secure origin cannot flood a domain to evict
    /// a `Secure` cookie and then replace it (threat T25).
    fn evict_one(&mut self, now: u64, f: impl Fn(&StoredCookie) -> bool) -> bool {
        let candidates = (0..self.store.len()).filter(|&i| self.store.get(i).is_some_and(&f));
        let victim = candidates
            .clone()
            .find(|&i| {
                self.store
                    .get(i)
                    .is_some_and(|c| c.expiry.is_some_and(|e| e <= now))
            })
            .or_else(|| {
                candidates.min_by_key(|&i| {
                    self.store
                        .get(i)
                        .map_or((false, 0, 0), |c| (c.secure, c.last_access, c.seq))
                })
            });
        victim.is_some_and(|i| self.store.swap_remove(i).is_some())
    }
}

impl<P: PublicSuffix, S: JarStore> fmt::Debug for Jar<P, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Jar")
            .field("cookies", &self.len())
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

/// A host or top-level site the jar can keep and export: 1 to 255 printable
/// ASCII bytes.
fn keepable_host(host: &str) -> bool {
    (1..=255).contains(&host.len()) && host.bytes().all(|b| b.is_ascii_graphic())
}

/// A cookie path the jar can keep and export: at most 1024 bytes (the
/// attribute limit of section 5.6), no control character.
fn keepable_path(path: &[u8]) -> bool {
    path.len() <= 1024 && !path.iter().any(|&b| b < 0x20 || b == 0x7f)
}

/// Whether some `store` could have made this cookie: the rules that do not
/// depend on the jar (its suffix list) or the time.
fn could_be_stored(c: &StoredCookie) -> bool {
    let nameless_prefixed = c.name.is_empty()
        && (starts_with_ci(&c.value, b"__Secure-") || starts_with_ci(&c.value, b"__Host-"));
    !nameless_prefixed
        && keepable_host(&c.domain)
        && keepable_path(&c.path)
        && c.partition.as_deref().is_none_or(keepable_host)
        && (c.secure || (c.same_site != Some(SameSite::None) && c.partition.is_none()))
        && (c.secure || !starts_with_ci(&c.name, b"__Secure-"))
        && (!starts_with_ci(&c.name, b"__Host-") || (c.secure && c.host_only && c.path == b"/"))
}

/// What makes two cookies the same cookie (section 5.7 step 23), and the
/// partition.
type Identity<'c> = Option<(&'c [u8], &'c str, bool, &'c [u8], Option<&'c str>)>;

fn identity(c: &Option<StoredCookie>) -> Identity<'_> {
    c.as_ref().map(|c| {
        (
            &c.name[..],
            c.domain.as_str(),
            c.host_only,
            &c.path[..],
            c.partition.as_deref(),
        )
    })
}

fn starts_with_ci(s: &[u8], prefix: &[u8]) -> bool {
    s.get(..prefix.len())
        .is_some_and(|h| h.eq_ignore_ascii_case(prefix))
}

fn is_ip(host: &str) -> bool {
    host.contains(':') || host.starts_with('[') || host.parse::<Ipv4Addr>().is_ok()
}

/// Section 5.1.3: `host` is `domain`, or ends with `.domain` and is not an IP
/// address. Both are lowercase.
pub(crate) fn domain_match(host: &str, domain: &str) -> bool {
    if host == domain {
        return true;
    }
    host.len() > domain.len()
        && host.ends_with(domain)
        && host.as_bytes().get(host.len() - domain.len() - 1) == Some(&b'.')
        && !is_ip(host)
}

/// Section 5.1.4: the request path is the cookie path, or starts with it and
/// either the cookie path ends with `/` or the next byte is `/`.
pub(crate) fn path_match(request: &[u8], cookie: &[u8]) -> bool {
    request == cookie
        || (request.starts_with(cookie)
            && (cookie.last() == Some(&b'/') || request.get(cookie.len()) == Some(&b'/')))
}

/// Section 5.1.4: the directory of the request path.
pub(crate) fn default_path(path: &[u8]) -> &[u8] {
    if path.first() != Some(&b'/') {
        return b"/";
    }
    match path.iter().rposition(|&b| b == b'/') {
        Some(0) | None => b"/",
        Some(i) => path.get(..i).unwrap_or(b"/"),
    }
}

mod export {
    //! The jar export format, version 1 (`docs/FORMATS.md`).

    use alloc::{string::String, vec::Vec};

    use crypt_io::hash::blake3;

    use super::StoredCookie;
    use crate::{SameSite, error::CookieError, limits::PAIR_MAX};

    const MAGIC: &[u8; 4] = b"CNJR";
    const VERSION: u8 = 1;
    const MAX_COOKIES: u32 = 1_000_000;

    pub(super) fn write<'a>(cookies: impl Iterator<Item = &'a StoredCookie>, n: usize) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.push(VERSION);
        out.extend_from_slice(&u32::try_from(n).unwrap_or(u32::MAX).to_be_bytes());
        for c in cookies {
            let flags = u8::from(c.host_only)
                | (u8::from(c.secure) << 1)
                | (u8::from(c.http_only) << 2)
                | (u8::from(c.expiry.is_some()) << 3)
                | (u8::from(c.partition.is_some()) << 4);
            out.push(flags);
            out.push(match c.same_site {
                Some(SameSite::Strict) => 1,
                Some(SameSite::Lax) => 2,
                Some(SameSite::None) => 3,
                None => 0,
            });
            for t in [c.expiry.unwrap_or(0), c.creation, c.last_access] {
                out.extend_from_slice(&t.to_be_bytes());
            }
            for field in [
                &c.name[..],
                &c.value[..],
                c.domain.as_bytes(),
                &c.path[..],
                c.partition.as_deref().unwrap_or("").as_bytes(),
            ] {
                out.extend_from_slice(
                    &u16::try_from(field.len()).unwrap_or(u16::MAX).to_be_bytes(),
                );
                out.extend_from_slice(field);
            }
        }
        let sum = blake3(&out);
        out.extend_from_slice(&sum);
        out
    }

    struct Reader<'a>(&'a [u8]);

    impl<'a> Reader<'a> {
        fn take(&mut self, n: usize) -> Result<&'a [u8], CookieError> {
            if n > self.0.len() {
                return Err(CookieError::InvalidJarData);
            }
            let (head, rest) = self.0.split_at(n);
            self.0 = rest;
            Ok(head)
        }

        fn byte(&mut self) -> Result<u8, CookieError> {
            Ok(self.take(1)?.first().copied().unwrap_or(0))
        }

        fn u64(&mut self) -> Result<u64, CookieError> {
            let mut b = [0u8; 8];
            b.copy_from_slice(self.take(8)?);
            Ok(u64::from_be_bytes(b))
        }

        fn field(&mut self) -> Result<&'a [u8], CookieError> {
            let mut b = [0u8; 2];
            b.copy_from_slice(self.take(2)?);
            self.take(usize::from(u16::from_be_bytes(b)))
        }
    }

    fn ascii_lower(b: &[u8]) -> Result<String, CookieError> {
        if b.iter()
            .all(|c| c.is_ascii_graphic() && !c.is_ascii_uppercase())
        {
            Ok(b.iter().map(|&c| char::from(c)).collect())
        } else {
            Err(CookieError::InvalidJarData)
        }
    }

    fn no_controls(b: &[u8]) -> bool {
        !b.iter()
            .any(|&c| (c < 0x20 && c != b'\t') || c == 0x7f || c == b';')
    }

    pub(super) fn read(bytes: &[u8]) -> Result<Vec<StoredCookie>, CookieError> {
        let body_len = bytes
            .len()
            .checked_sub(32)
            .ok_or(CookieError::InvalidJarData)?;
        let (body, sum) = bytes.split_at(body_len);
        if blake3(body)[..] != *sum {
            return Err(CookieError::InvalidJarData);
        }
        let mut r = Reader(body);
        if r.take(4)? != MAGIC || r.byte()? != VERSION {
            return Err(CookieError::InvalidJarData);
        }
        let mut n = [0u8; 4];
        n.copy_from_slice(r.take(4)?);
        let n = u32::from_be_bytes(n);
        if n > MAX_COOKIES {
            return Err(CookieError::InvalidJarData);
        }
        let mut cookies = Vec::new();
        for _ in 0..n {
            let flags = r.byte()?;
            let same_site = match r.byte()? {
                0 => None,
                1 => Some(SameSite::Strict),
                2 => Some(SameSite::Lax),
                3 => Some(SameSite::None),
                _ => return Err(CookieError::InvalidJarData),
            };
            let (expiry, creation, last_access) = (r.u64()?, r.u64()?, r.u64()?);
            let (name, value, domain, path, partition) =
                (r.field()?, r.field()?, r.field()?, r.field()?, r.field()?);
            let ok = flags < 0x20
                && name.len() + value.len() <= PAIR_MAX
                && (!name.is_empty() || !value.is_empty())
                && no_controls(name)
                && no_controls(value)
                && !domain.is_empty()
                && path.first() == Some(&b'/')
                && super::keepable_path(path)
                && (flags & 0x10 != 0) != partition.is_empty();
            if !ok {
                return Err(CookieError::InvalidJarData);
            }
            cookies.push(StoredCookie {
                name: name.to_vec(),
                value: value.to_vec(),
                domain: ascii_lower(domain)?,
                path: path.to_vec(),
                expiry: (flags & 0x08 != 0).then_some(expiry),
                creation,
                last_access,
                host_only: flags & 0x01 != 0,
                secure: flags & 0x02 != 0,
                http_only: flags & 0x04 != 0,
                same_site,
                partition: if partition.is_empty() {
                    None
                } else {
                    Some(ascii_lower(partition)?)
                },
                seq: 0,
            });
        }
        if !r.0.is_empty() {
            return Err(CookieError::InvalidJarData);
        }
        Ok(cookies)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use std::{format, vec};

    use super::*;

    const NOW: u64 = 1_800_000_000;

    fn https(host: &str) -> RequestUrl<'_> {
        RequestUrl::https(host, "/")
    }

    #[test]
    fn test_domain_and_path_matching() {
        assert!(domain_match("example.com", "example.com"));
        assert!(domain_match("a.example.com", "example.com"));
        assert!(!domain_match("aexample.com", "example.com"));
        assert!(!domain_match("example.com", "a.example.com"));
        assert!(!domain_match("1.2.3.4", "2.3.4"));
        assert!(path_match(b"/a/b", b"/a"));
        assert!(path_match(b"/a/b", b"/a/"));
        assert!(path_match(b"/a", b"/a"));
        assert!(!path_match(b"/ab", b"/a"));
        assert!(path_match(b"/", b"/"));
        assert_eq!(default_path(b""), b"/");
        assert_eq!(default_path(b"x"), b"/");
        assert_eq!(default_path(b"/"), b"/");
        assert_eq!(default_path(b"/a"), b"/");
        assert_eq!(default_path(b"/a/b"), b"/a");
        assert_eq!(default_path(b"/a/b/"), b"/a/b");
    }

    #[test]
    fn test_store_rules() {
        let mut jar = Jar::new();
        let s = https("app.example.com");
        let h = RequestUrl::http("app.example.com", "/");
        let ig = StoreOutcome::Ignored;
        assert_eq!(jar.store(&s, "\x01", NOW), ig(IgnoreReason::Malformed));
        assert_eq!(
            jar.store(&s, "=__Host-sid=x", NOW),
            ig(IgnoreReason::NamelessPrefixed)
        );
        assert_eq!(
            jar.store(&s, "__secure-x", NOW),
            ig(IgnoreReason::NamelessPrefixed)
        );
        assert_eq!(
            jar.store(&h, "a=1; Secure", NOW),
            ig(IgnoreReason::SecureFromInsecure)
        );
        assert_eq!(
            jar.store(&s, "a=1; Domain=other.org", NOW),
            ig(IgnoreReason::DomainNotAllowed)
        );
        assert_eq!(
            jar.store(&s, "a=1; SameSite=None", NOW),
            ig(IgnoreReason::SameSiteNoneNeedsSecure)
        );
        assert_eq!(
            jar.store(&s, "a=1; Partitioned", NOW),
            ig(IgnoreReason::PartitionedNeedsSecure)
        );
        assert_eq!(
            jar.store(&s, "__Secure-a=1", NOW),
            ig(IgnoreReason::SecurePrefix)
        );
        assert_eq!(
            jar.store(&s, "__Host-a=1; Secure", NOW),
            ig(IgnoreReason::HostPrefix)
        );
        assert_eq!(
            jar.store(&s, "__Host-a=1; Secure; Path=/a", NOW),
            ig(IgnoreReason::HostPrefix)
        );
        assert_eq!(
            jar.store(
                &s,
                "__Host-a=1; Secure; Path=/; Domain=app.example.com",
                NOW
            ),
            StoreOutcome::Stored
        );
        assert_eq!(
            jar.store(&h, "__Host-b=1; Secure; Path=/", NOW),
            ig(IgnoreReason::SecureFromInsecure)
        );
        assert_eq!(
            jar.store(&s, "a=1; Max-Age=0", NOW),
            ig(IgnoreReason::Expired)
        );
        assert_eq!(
            jar.store(&s, "a=1; Expires=Thu, 01 Jan 1970 00:00:00 GMT", NOW),
            ig(IgnoreReason::Expired)
        );
        assert!(jar.is_empty() || jar.len() == 1);
    }

    #[test]
    fn test_suffix_list_domain_cookies() {
        struct Com;
        impl PublicSuffix for Com {
            fn is_public_suffix(&self, d: &str) -> bool {
                d == "com" || d == "co.uk"
            }
        }
        let mut jar = Jar::with_public_suffix(Com);
        let s = https("app.example.com");
        assert_eq!(
            jar.store(&s, "a=1; Domain=.Example.COM", NOW),
            StoreOutcome::Stored
        );
        assert_eq!(
            jar.store(&s, "b=1; Domain=com", NOW),
            StoreOutcome::Ignored(IgnoreReason::DomainNotAllowed)
        );
        assert_eq!(
            jar.store(&s, "c=1; Domain=other.org", NOW),
            StoreOutcome::Ignored(IgnoreReason::DomainMismatch)
        );
        assert_eq!(
            jar.cookie_header(&https("www.example.com"), NOW).as_deref(),
            Some("a=1")
        );
        assert_eq!(
            jar.cookie_header(&https("example.com"), NOW).as_deref(),
            Some("a=1")
        );
        assert_eq!(jar.cookie_header(&https("example.org"), NOW), None);
        // a Domain on an IP host never makes a domain cookie
        assert_eq!(
            jar.store(&https("10.0.0.1"), "d=1; Domain=0.0.1", NOW),
            StoreOutcome::Ignored(IgnoreReason::DomainMismatch)
        );
    }

    #[test]
    fn test_host_only_not_sent_to_subdomains() {
        let mut jar = Jar::new();
        jar.store(&https("example.com"), "a=1", NOW);
        assert_eq!(
            jar.cookie_header(&https("example.com"), NOW).as_deref(),
            Some("a=1")
        );
        assert_eq!(jar.cookie_header(&https("sub.example.com"), NOW), None);
        assert_eq!(
            jar.cookie_header(&https("EXAMPLE.com"), NOW).as_deref(),
            Some("a=1")
        );
    }

    #[test]
    fn test_insecure_cannot_shadow_secure() {
        let mut jar = Jar::new();
        jar.store(&https("example.com"), "sid=good; Secure", NOW);
        let h = RequestUrl::http("example.com", "/");
        assert_eq!(
            jar.store(&h, "sid=evil", NOW),
            StoreOutcome::Ignored(IgnoreReason::WouldShadowSecure)
        );
        assert_eq!(
            jar.store(
                &RequestUrl::http("example.com", "/deep/x"),
                "sid=evil; Path=/deep",
                NOW
            ),
            StoreOutcome::Ignored(IgnoreReason::WouldShadowSecure)
        );
        assert_eq!(jar.store(&h, "other=1", NOW), StoreOutcome::Stored);
    }

    #[test]
    fn test_replace_keeps_creation_and_order() {
        let mut jar = Jar::new();
        let u = https("example.com");
        jar.store(&u, "a=1", NOW);
        jar.store(&u, "b=1", NOW + 1);
        assert_eq!(jar.store(&u, "a=2", NOW + 2), StoreOutcome::Replaced);
        assert_eq!(jar.cookie_header(&u, NOW + 3).as_deref(), Some("a=2; b=1"));
        let a = jar.cookies().find(|c| c.name == b"a").unwrap();
        assert_eq!(a.creation, NOW);
        assert_eq!(
            jar.store(&u, "a=; Max-Age=0", NOW + 4),
            StoreOutcome::Removed
        );
        assert_eq!(jar.cookie_header(&u, NOW + 5).as_deref(), Some("b=1"));
    }

    #[test]
    fn test_expiry_and_cap() {
        let mut jar = Jar::new();
        let u = https("example.com");
        jar.store(&u, "a=1; Max-Age=10", NOW);
        jar.store(&u, "b=1; Max-Age=99999999999", NOW);
        jar.store(&u, "c=1; Expires=Wed, 01 Jan 2200 00:00:00 GMT", NOW);
        assert_eq!(
            jar.cookie_header(&u, NOW + 9).as_deref(),
            Some("a=1; b=1; c=1")
        );
        assert_eq!(jar.cookie_header(&u, NOW + 10).as_deref(), Some("b=1; c=1"));
        assert_eq!(jar.cookie_header(&u, NOW + MAX_LIFETIME), None);
        assert_eq!(jar.remove_expired(NOW + MAX_LIFETIME), 3);
    }

    #[test]
    fn test_same_site_contexts() {
        let mut jar = Jar::new();
        let u = https("example.com");
        jar.store(&u, "s=1; SameSite=Strict", NOW);
        jar.store(&u, "l=1; SameSite=Lax", NOW);
        jar.store(&u, "d=1", NOW);
        jar.store(&u, "n=1; SameSite=None; Secure", NOW);
        let same = jar.cookie_header(&u, NOW).unwrap();
        assert_eq!(same.matches('=').count(), 4);
        let nav_get = RequestContext::cross_site().navigation(true);
        assert_eq!(
            jar.cookie_header_for(&u, &nav_get, NOW).as_deref(),
            Some("l=1; d=1; n=1")
        );
        let nav_post = RequestContext::cross_site().navigation(false);
        assert_eq!(
            jar.cookie_header_for(&u, &nav_post, NOW).as_deref(),
            Some("n=1")
        );
        assert_eq!(
            jar.cookie_header_for(&u, &RequestContext::cross_site(), NOW)
                .as_deref(),
            Some("n=1")
        );
    }

    #[test]
    fn test_partitioned_cookies_stay_in_their_partition() {
        let mut jar = Jar::new();
        let widget = https("widget.example");
        jar.store(&widget, "w=1; Secure; Partitioned; SameSite=None", NOW);
        assert_eq!(jar.cookie_header(&widget, NOW).as_deref(), Some("w=1"));
        let embedded = RequestContext::cross_site().top_level_site("shop.example");
        assert_eq!(jar.cookie_header_for(&widget, &embedded, NOW), None);
    }

    #[test]
    fn test_nameless_cookie_serializes_as_value() {
        let mut jar = Jar::new();
        let u = https("example.com");
        jar.store(&u, "justvalue", NOW);
        jar.store(&u, "a=1", NOW);
        assert_eq!(
            jar.cookie_header(&u, NOW).as_deref(),
            Some("justvalue; a=1")
        );
    }

    #[test]
    fn test_limits_evict_expired_then_least_recent() {
        let mut jar = Jar::new().with_limits(JarLimits::DEFAULT.per_domain(3).total(5));
        let u = https("example.com");
        jar.store(&u, "a=1; Max-Age=5", NOW);
        jar.store(&u, "b=1", NOW);
        jar.store(&u, "c=1", NOW);
        let _ = jar.cookie_header(&u, NOW + 6); // a expired; b, c accessed
        jar.store(&u, "d=1", NOW + 7); // evicts the expired a
        let names: Vec<_> = jar.cookies().map(|c| c.name.clone()).collect();
        assert!(!names.contains(&b"a".to_vec()) && names.len() == 3);
        jar.store(&u, "e=1", NOW + 8); // evicts b (least recent, oldest)
        assert!(jar.cookies().all(|c| c.name != b"b"));
        for (i, host) in ["a.org", "b.org", "c.org"].iter().enumerate() {
            jar.store(&https(host), &format!("x{i}=1")[..], NOW + 9);
        }
        assert_eq!(jar.len(), 5);
    }

    #[test]
    fn test_write_cookie_header_full_writes_nothing() {
        let mut jar = Jar::new();
        let u = https("example.com");
        jar.store(&u, "a=12345", NOW);
        let mut buf = [0u8; 4];
        let mut out = parse_net::SliceSink::new(&mut buf);
        assert_eq!(
            jar.write_cookie_header(&u, &RequestContext::default(), NOW, &mut out),
            Err(CookieError::Full)
        );
        assert!(out.is_empty());
    }

    #[test]
    fn test_export_import_round_trip_and_tampering() {
        let mut jar = Jar::new();
        let u = https("example.com");
        jar.store(&u, "a=1; Max-Age=100; SameSite=Strict", NOW);
        jar.store(
            &https("w.example"),
            "w=2; Secure; Partitioned; SameSite=None",
            NOW,
        );
        jar.store(&u, "s=3", NOW);
        let bytes = jar.export();
        let mut copy = Jar::new();
        assert_eq!(copy.import(&bytes, NOW), Ok(3));
        let a: Vec<_> = jar
            .cookies()
            .map(|c| {
                (
                    c.name.clone(),
                    c.value.clone(),
                    c.domain.clone(),
                    c.same_site,
                    c.partition.clone(),
                )
            })
            .collect();
        let b: Vec<_> = copy
            .cookies()
            .map(|c| {
                (
                    c.name.clone(),
                    c.value.clone(),
                    c.domain.clone(),
                    c.same_site,
                    c.partition.clone(),
                )
            })
            .collect();
        assert_eq!(a, b);
        // expired cookies are skipped on import
        assert_eq!(Jar::new().import(&bytes, NOW + 100), Ok(2));
        // any change is refused
        for i in 0..bytes.len() {
            let mut m = bytes.clone();
            m[i] ^= 1;
            assert_eq!(
                Jar::new().import(&m, NOW),
                Err(CookieError::InvalidJarData),
                "byte {i}"
            );
        }
        assert_eq!(
            Jar::new().import(&bytes[..bytes.len() - 1], NOW),
            Err(CookieError::InvalidJarData)
        );
        assert_eq!(
            Jar::new().import(&[], NOW),
            Err(CookieError::InvalidJarData)
        );
        // a checksum is not a MAC: a re-checksummed body is still validated
        let mut forged = bytes[..bytes.len() - 32].to_vec();
        forged[5..9].copy_from_slice(&9u32.to_be_bytes());
        let sum = crypt_io::hash::blake3(&forged);
        forged.extend_from_slice(&sum);
        assert_eq!(
            Jar::new().import(&forged, NOW),
            Err(CookieError::InvalidJarData)
        );
    }

    #[test]
    fn test_debug_redacts_values() {
        let mut jar = Jar::new();
        jar.store(&https("example.com"), "sid=SECRET", NOW);
        assert!(!format!("{jar:?}").contains("SECRET"));
        let c = jar.cookies().next().unwrap();
        assert!(!format!("{c:?}").contains("SECRET"));
        let _ = vec![0u8];
    }
}
