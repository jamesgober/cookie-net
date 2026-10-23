//! Reading the `Cookie` request header (rfc6265bis section 4.2).
//!
//! One scanner serves every entry point. It walks the header once, left to
//! right, touching each byte a constant number of times: find the next `;`,
//! trim, split at the first `=`, classify the name and the value. Pairs that
//! break the grammar are skipped and counted (decision D-003); budgets are
//! checked before the work they govern.

use core::{fmt, ops::ControlFlow};

use parse_net::scan::find_byte;

use crate::{
    error::{Ambiguous, CookieError},
    limits::{Limits, PAIR_MAX, ValueMode},
    name::{self, Prefix},
};

/// One accepted cookie pair, borrowed from the header.
///
/// Names and values are `&str`: in strict mode every accepted byte is ASCII,
/// and lenient mode accepts only valid UTF-8. `Debug` prints the name and the
/// value's length, never the value.
///
/// # Examples
///
/// ```
/// use cookie_net::{self as cookie, Prefix};
///
/// let pair = cookie::parse("__Host-sid=\"t0k3n\"").iter().next().unwrap();
/// assert_eq!((pair.name(), pair.value(), pair.value_unquoted()), ("__Host-sid", "\"t0k3n\"", "t0k3n"));
/// assert_eq!(pair.prefix(), Prefix::Host);
/// assert_eq!(format!("{pair:?}"), r#"Pair { name: "__Host-sid", value: 7 bytes }"#);
/// ```
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Pair<'a> {
    name: &'a str,
    value: &'a str,
}

impl<'a> Pair<'a> {
    /// The name, exactly as sent.
    ///
    /// # Examples
    ///
    /// ```
    /// let p = cookie_net::parse("Theme=dark").iter().next().unwrap();
    /// assert_eq!(p.name(), "Theme");
    /// ```
    #[must_use]
    pub const fn name(&self) -> &'a str {
        self.name
    }

    /// The value, with surrounding quotes when present (they are part of the
    /// value, rfc6265bis section 4.1.1).
    ///
    /// # Examples
    ///
    /// ```
    /// let p = cookie_net::parse("a=\"1\"").iter().next().unwrap();
    /// assert_eq!(p.value(), "\"1\"");
    /// ```
    #[must_use]
    pub const fn value(&self) -> &'a str {
        self.value
    }

    /// The value without one surrounding pair of double quotes.
    ///
    /// # Examples
    ///
    /// ```
    /// let p = cookie_net::parse("a=\"1\"").iter().next().unwrap();
    /// assert_eq!(p.value_unquoted(), "1");
    /// ```
    #[must_use]
    pub fn value_unquoted(&self) -> &'a str {
        unquote(self.value)
    }

    /// The name's prefix, compared case-insensitively as user agents do.
    ///
    /// # Examples
    ///
    /// ```
    /// let p = cookie_net::parse("__Secure-a=1").iter().next().unwrap();
    /// assert_eq!(p.prefix(), cookie_net::Prefix::Secure);
    /// ```
    #[must_use]
    pub fn prefix(&self) -> Prefix {
        Prefix::of(self.name)
    }
}

impl fmt::Debug for Pair<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pair")
            .field("name", &self.name)
            .field("value", &Len(self.value.len()))
            .finish()
    }
}

fn unquote(v: &str) -> &str {
    v.strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(v)
}

/// Prints `n bytes`, for redacted `Debug` output.
pub(crate) struct Len(pub(crate) usize);

impl fmt::Debug for Len {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} bytes", self.0)
    }
}

/// Facts about one scan, for customs-sec and sentinel-sec.
///
/// # Examples
///
/// ```
/// let s = cookie_net::parse("a=1;b=2; ; bad name=3; __Host-x=1; __Host-x=2").stats();
/// assert_eq!((s.pairs, s.skipped, s.empty, s.loose_separators, s.prefixed_duplicates), (4, 1, 1, 1, 1));
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct Stats {
    /// Pairs accepted.
    pub pairs: u16,
    /// Pairs that broke the grammar or a length limit (empty pairs are not
    /// counted here).
    pub skipped: u16,
    /// Empty pairs: `;;`, a leading `;`, or a trailing `;`.
    pub empty: u16,
    /// Separators other than `"; "`: a `;` with no SP after it, or with other
    /// or more whitespace.
    pub loose_separators: u16,
    /// Extra occurrences of `__Host-` or `__Secure-` names (byte-exact
    /// repeats). The first 64 distinct prefixed names are tracked.
    pub prefixed_duplicates: u16,
    /// The scan stopped at `max_pairs`.
    pub truncated: bool,
    /// The header is longer than `max_header_len`: nothing was read.
    pub too_long: bool,
}

#[derive(Clone, Copy)]
enum Source<'a> {
    One(&'a [u8]),
    Lines(&'a [&'a [u8]]),
}

/// A `Cookie` header and the limits to read it with.
///
/// A small `Copy` view; nothing is stored or allocated. Each `iter`, `get`,
/// or `stats` scans the header again.
///
/// # Examples
///
/// ```
/// use cookie_net::{Cookies, Limits};
///
/// let lines: [&[u8]; 2] = [b"__Host-sid=t0k3n", b"theme=dark"];
/// let cookies = Cookies::from_lines(&lines, &Limits::DEFAULT)?;
/// assert_eq!(cookies.get_unique("__Host-sid")?, Some("t0k3n"));
/// assert_eq!(cookies.iter().count(), 2);
/// # Ok::<(), cookie_net::CookieError>(())
/// ```
#[derive(Clone, Copy)]
pub struct Cookies<'a> {
    src: Source<'a>,
    limits: Limits,
    too_long: bool,
}

impl<'a> Cookies<'a> {
    /// The header with [`Limits::DEFAULT`]; what [`parse`](crate::parse)
    /// returns. A header over the length limit reads as no pairs, with
    /// `stats().too_long` set.
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(cookie_net::Cookies::new("a=1; b=2").iter().count(), 2);
    /// ```
    #[must_use]
    pub fn new<H: AsRef<[u8]> + ?Sized>(header: &'a H) -> Cookies<'a> {
        let header = header.as_ref();
        Self {
            src: Source::One(header),
            limits: Limits::DEFAULT,
            too_long: header.len() > Limits::DEFAULT.header_len(),
        }
    }

    /// The header with `limits`.
    ///
    /// # Errors
    ///
    /// [`CookieError::HeaderTooLong`] when the header is longer than
    /// `limits.header_len()`, before anything is scanned.
    ///
    /// # Examples
    ///
    /// ```
    /// use cookie_net::{CookieError, Cookies, Limits};
    ///
    /// let l = Limits::DEFAULT.max_header_len(8);
    /// assert!(Cookies::with_limits("a=1", &l).is_ok());
    /// assert_eq!(Cookies::with_limits("a=1234567", &l).unwrap_err(), CookieError::HeaderTooLong);
    /// ```
    pub fn with_limits<H: AsRef<[u8]> + ?Sized>(
        header: &'a H,
        limits: &Limits,
    ) -> Result<Cookies<'a>, CookieError> {
        let header = header.as_ref();
        if header.len() > limits.header_len() {
            return Err(CookieError::HeaderTooLong);
        }
        Ok(Self {
            src: Source::One(header),
            limits: *limits,
            too_long: false,
        })
    }

    /// Several `Cookie` field lines read as one header joined by `"; "`,
    /// without copying: HTTP/2 splits the header into such crumbs (RFC 9113
    /// section 8.2.3). Line lengths are summed for the length limit; an empty
    /// line adds nothing.
    ///
    /// # Errors
    ///
    /// [`CookieError::HeaderTooLong`] when the lines together are longer than
    /// `limits.header_len()`.
    ///
    /// # Examples
    ///
    /// ```
    /// use cookie_net::{Cookies, Limits};
    ///
    /// let lines: [&[u8]; 3] = [b"a=1", b"", b"b=2; c=3"];
    /// let names: Vec<&str> = Cookies::from_lines(&lines, &Limits::DEFAULT)?.iter().map(|p| p.name()).collect();
    /// assert_eq!(names, ["a", "b", "c"]);
    /// # Ok::<(), cookie_net::CookieError>(())
    /// ```
    pub fn from_lines(lines: &'a [&'a [u8]], limits: &Limits) -> Result<Cookies<'a>, CookieError> {
        let total = lines
            .iter()
            .fold(0usize, |sum, line| sum.saturating_add(line.len()));
        if total > limits.header_len() {
            return Err(CookieError::HeaderTooLong);
        }
        Ok(Self {
            src: Source::Lines(lines),
            limits: *limits,
            too_long: false,
        })
    }

    /// A view that reads as a header over the length limit (for `locate`).
    pub(crate) const fn too_long(limits: &Limits) -> Cookies<'a> {
        Self {
            src: Source::One(&[]),
            limits: *limits,
            too_long: true,
        }
    }

    fn scanner(&self) -> Scanner<'a> {
        Scanner::new(self.src, self.limits, self.too_long)
    }

    /// Every accepted pair, in header order.
    ///
    /// # Examples
    ///
    /// ```
    /// let c = cookie_net::Cookies::new("a=1; =2; b=3");
    /// let names: Vec<&str> = c.iter().map(|p| p.name()).collect();
    /// assert_eq!(names, ["a", "b"]);
    /// ```
    #[must_use]
    pub fn iter(&self) -> Iter<'a> {
        Iter {
            scanner: self.scanner(),
        }
    }

    /// The value of the first pair named exactly `name`. Order is the
    /// browser's, but servers should not rely on it (rfc6265bis section
    /// 4.2.2); use [`get_unique`](Self::get_unique) for credentials.
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(cookie_net::Cookies::new("a=1; a=2").get("a"), Some("1"));
    /// ```
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&'a str> {
        self.iter().find(|p| p.name == name).map(|p| p.value)
    }

    /// The value of the only pair named `name`.
    ///
    /// # Errors
    ///
    /// [`Ambiguous::Duplicate`] when the name appears more than once,
    /// [`Ambiguous::Truncated`] when the pair limit cut the scan short before
    /// a duplicate was found, [`Ambiguous::HeaderTooLong`] when nothing could
    /// be read.
    ///
    /// # Examples
    ///
    /// ```
    /// use cookie_net::{Ambiguous, Cookies};
    ///
    /// assert_eq!(Cookies::new("a=1; b=2").get_unique("b"), Ok(Some("2")));
    /// assert_eq!(Cookies::new("a=1; a=2").get_unique("a"), Err(Ambiguous::Duplicate { count: 2 }));
    /// ```
    pub fn get_unique(&self, name: &str) -> Result<Option<&'a str>, Ambiguous> {
        let mut s = self.scanner();
        let mut first = None;
        let mut count: u16 = 0;
        while let Some(p) = s.next_pair() {
            if p.name == name {
                count = count.saturating_add(1);
                first.get_or_insert(p.value);
            }
        }
        if s.stats.too_long {
            Err(Ambiguous::HeaderTooLong)
        } else if count >= 2 {
            Err(Ambiguous::Duplicate { count })
        } else if s.stats.truncated {
            Err(Ambiguous::Truncated)
        } else {
            Ok(first)
        }
    }

    /// Every value of `name`, in header order.
    ///
    /// # Examples
    ///
    /// ```
    /// let v: Vec<&str> = cookie_net::Cookies::new("c=2; t=d; c=1").get_all("c").collect();
    /// assert_eq!(v, ["2", "1"]);
    /// ```
    #[must_use]
    pub fn get_all<'n>(&self, name: &'n str) -> GetAll<'a, 'n> {
        GetAll {
            iter: self.iter(),
            name,
        }
    }

    /// Everything the credential check needs about `name`, in one pass:
    /// the lookup, the shadow names, and the scan's statistics.
    ///
    /// # Examples
    ///
    /// ```
    /// use cookie_net::{Cookies, Lookup};
    ///
    /// let found = Cookies::new("sid=x; __Host-sid=t").locate("__Host-sid");
    /// assert_eq!((found.lookup, found.shadows), (Lookup::One("t"), 1));
    /// ```
    #[must_use]
    pub fn locate(&self, name: &str) -> Located<'a> {
        let target = name.as_bytes();
        let target_core = name::core(target);
        let mut s = self.scanner();
        let mut dups = DupTable::new();
        let mut first = None;
        let mut count: u16 = 0;
        let mut shadows: u16 = 0;
        while let Some(p) = s.next_pair() {
            dups.note(p.name, &mut s.stats);
            let n = p.name.as_bytes();
            if n == target {
                count = count.saturating_add(1);
                first.get_or_insert(p.value);
            } else if name::core(n).eq_ignore_ascii_case(target_core) {
                shadows = shadows.saturating_add(1);
            }
        }
        let lookup = if s.stats.too_long {
            Lookup::HeaderTooLong
        } else if let (Some(first), true) = (first, count >= 2) {
            Lookup::Many { first, count }
        } else if s.stats.truncated {
            Lookup::Truncated
        } else {
            first.map_or(Lookup::Missing, Lookup::One)
        };
        Located {
            lookup,
            shadows,
            stats: s.stats,
            prefixed: name::of_bytes(target) != Prefix::None,
        }
    }

    /// One pass over the pairs, calling `f` for each; `ControlFlow::Break(())`
    /// stops early. The statistics cover the pairs seen up to that point.
    ///
    /// # Examples
    ///
    /// ```
    /// use core::ops::ControlFlow;
    ///
    /// let mut analytics = 0;
    /// let stats = cookie_net::Cookies::new("_ga=1; _gid=2; sid=x").scan(|pair| {
    ///     if pair.name().starts_with('_') { analytics += 1; }
    ///     ControlFlow::Continue(())
    /// });
    /// assert_eq!((analytics, stats.pairs), (2, 3));
    /// ```
    pub fn scan(&self, mut f: impl FnMut(Pair<'a>) -> ControlFlow<()>) -> Stats {
        let mut s = self.scanner();
        let mut dups = DupTable::new();
        while let Some(p) = s.next_pair() {
            dups.note(p.name, &mut s.stats);
            if f(p).is_break() {
                break;
            }
        }
        s.stats
    }

    /// Facts about the whole header.
    ///
    /// # Examples
    ///
    /// ```
    /// let s = cookie_net::Cookies::new("a=1; b c=2").stats();
    /// assert_eq!((s.pairs, s.skipped), (1, 1));
    /// ```
    #[must_use]
    pub fn stats(&self) -> Stats {
        self.scan(|_| ControlFlow::Continue(()))
    }

    /// Whether no pair is accepted.
    ///
    /// # Examples
    ///
    /// ```
    /// assert!(cookie_net::Cookies::new("; =x").is_empty());
    /// ```
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.iter().next().is_none()
    }
}

impl<'a> IntoIterator for Cookies<'a> {
    type Item = Pair<'a>;
    type IntoIter = Iter<'a>;

    fn into_iter(self) -> Iter<'a> {
        self.iter()
    }
}

impl<'a> IntoIterator for &Cookies<'a> {
    type Item = Pair<'a>;
    type IntoIter = Iter<'a>;

    fn into_iter(self) -> Iter<'a> {
        self.iter()
    }
}

impl fmt::Debug for Cookies<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        struct Names<'b>(&'b Cookies<'b>);
        impl fmt::Debug for Names<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_list()
                    .entries(self.0.iter().map(|p| p.name))
                    .finish()
            }
        }
        f.debug_struct("Cookies")
            .field("names", &Names(self))
            .field("too_long", &self.too_long)
            .finish()
    }
}

/// The pairs of a [`Cookies`], in header order.
#[derive(Clone)]
pub struct Iter<'a> {
    scanner: Scanner<'a>,
}

impl<'a> Iterator for Iter<'a> {
    type Item = Pair<'a>;

    fn next(&mut self) -> Option<Pair<'a>> {
        self.scanner.next_pair()
    }
}

impl fmt::Debug for Iter<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Iter").finish_non_exhaustive()
    }
}

/// The values of one name, in header order; from [`get_all`](crate::get_all).
#[derive(Clone)]
pub struct GetAll<'a, 'n> {
    iter: Iter<'a>,
    name: &'n str,
}

impl<'a> Iterator for GetAll<'a, '_> {
    type Item = &'a str;

    fn next(&mut self) -> Option<&'a str> {
        let name = self.name;
        self.iter.find(|p| p.name == name).map(|p| p.value)
    }
}

impl fmt::Debug for GetAll<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GetAll")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

/// The answer of a credential lookup.
///
/// `Debug` prints value lengths, never values.
///
/// # Examples
///
/// ```
/// use cookie_net::{Cookies, Lookup};
///
/// assert_eq!(Cookies::new("a=1").locate("b").lookup, Lookup::Missing);
/// assert_eq!(Cookies::new("a=1; a=2").locate("a").lookup, Lookup::Many { first: "1", count: 2 });
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Lookup<'a> {
    /// No pair carries the name.
    Missing,
    /// Exactly one pair carries it.
    One(&'a str),
    /// Several pairs carry it.
    Many {
        /// The first value.
        first: &'a str,
        /// How many pairs carry the name.
        count: u16,
    },
    /// The pair limit cut the scan short, so a duplicate could hide past it.
    Truncated,
    /// The header is longer than the limit: nothing was read.
    HeaderTooLong,
}

impl fmt::Debug for Lookup<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Missing => f.write_str("Missing"),
            Self::One(v) => f.debug_tuple("One").field(&Len(v.len())).finish(),
            Self::Many { first, count } => f
                .debug_struct("Many")
                .field("first", &Len(first.len()))
                .field("count", &count)
                .finish(),
            Self::Truncated => f.write_str("Truncated"),
            Self::HeaderTooLong => f.write_str("HeaderTooLong"),
        }
    }
}

/// Everything the gateway needs about one credential cookie, from
/// [`locate`](crate::locate).
///
/// `shadows` counts pairs whose name is not the target but equals it, ignoring
/// ASCII case, once a `__Host-` or `__Secure-` prefix is removed from either
/// side: for `__Host-sid`, the names `__host-sid`, `__HOST-SID`, `sid`, and
/// `__Secure-sid`. cookie-net never sets those beside a credential, so their
/// presence is evidence of cookie tossing or a prefix-bypass probe.
///
/// # Examples
///
/// ```
/// use cookie_net::{self as cookie, Limits, Lookup};
///
/// let found = cookie::locate("sid=evil; __Host-sid=t0k3n", "__Host-sid", &Limits::DEFAULT);
/// assert_eq!(found.lookup, Lookup::One("t0k3n"));
/// assert_eq!(found.shadows, 1);
/// assert_eq!(found.severity_hint(), 5);
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Located<'a> {
    /// The answer.
    pub lookup: Lookup<'a>,
    /// Pairs with a shadow of the target name.
    pub shadows: u16,
    /// Facts about the whole scan.
    pub stats: Stats,
    prefixed: bool,
}

impl Located<'_> {
    /// A suggested severity, 0 to 40, higher is worse (the scale WASP's gates
    /// use): `One` and `Missing` 0; `Many` 30 on a prefixed name and 10 on
    /// another; `Truncated` and `HeaderTooLong` 10; plus 5 when there are
    /// shadows; at most 40.
    ///
    /// # Examples
    ///
    /// ```
    /// use cookie_net::Cookies;
    ///
    /// assert_eq!(Cookies::new("__Host-sid=a; __Host-sid=b").locate("__Host-sid").severity_hint(), 30);
    /// assert_eq!(Cookies::new("sid=a; sid=b").locate("sid").severity_hint(), 10);
    /// assert_eq!(Cookies::new("__Host-sid=a").locate("__Host-sid").severity_hint(), 0);
    /// ```
    #[must_use]
    pub const fn severity_hint(&self) -> u8 {
        let base: u8 = match self.lookup {
            Lookup::Missing | Lookup::One(_) => 0,
            Lookup::Many { .. } => {
                if self.prefixed {
                    30
                } else {
                    10
                }
            }
            Lookup::Truncated | Lookup::HeaderTooLong => 10,
        };
        let total = if self.shadows > 0 { base + 5 } else { base };
        if total > 40 { 40 } else { total }
    }
}

impl fmt::Debug for Located<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Located")
            .field("lookup", &self.lookup)
            .field("shadows", &self.shadows)
            .field("stats", &self.stats)
            .finish()
    }
}

/// The scanner behind every entry point.
#[derive(Clone)]
struct Scanner<'a> {
    src: Source<'a>,
    /// Index of the next line to load.
    next_line: usize,
    /// What is left of the current line.
    rest: &'a [u8],
    limits: Limits,
    stats: Stats,
    done: bool,
}

const fn is_ows(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

fn trim_start(s: &[u8]) -> &[u8] {
    let n = s.iter().take_while(|&&b| is_ows(b)).count();
    s.get(n..).unwrap_or_default()
}

fn trim_end(s: &[u8]) -> &[u8] {
    let n = s.iter().rev().take_while(|&&b| is_ows(b)).count();
    s.get(..s.len() - n).unwrap_or_default()
}

impl<'a> Scanner<'a> {
    fn new(src: Source<'a>, limits: Limits, too_long: bool) -> Self {
        let mut s = Self {
            src,
            next_line: 0,
            rest: &[],
            limits,
            stats: Stats::default(),
            done: too_long,
        };
        s.stats.too_long = too_long;
        s
    }

    /// Loads the next line; `false` when there is none.
    fn advance_line(&mut self) -> bool {
        let line = match self.src {
            Source::One(h) => (self.next_line == 0).then_some(h),
            Source::Lines(lines) => lines.get(self.next_line).copied(),
        };
        let Some(line) = line else { return false };
        self.next_line += 1;
        self.rest = trim_start(line);
        true
    }

    /// Looks at the whitespace after a `;` and moves past it.
    fn after_separator(&mut self) {
        let ws = self.rest.iter().take_while(|&&b| is_ows(b)).count();
        let after = self.rest.get(ws..).unwrap_or_default();
        match after.first() {
            // A trailing `;`: an empty pair.
            None => self.stats.empty = self.stats.empty.saturating_add(1),
            // `;;`: the empty pair is counted when it is read.
            Some(b';') => {}
            Some(_) => {
                if !(ws == 1 && self.rest.first() == Some(&b' ')) {
                    self.stats.loose_separators = self.stats.loose_separators.saturating_add(1);
                }
            }
        }
        self.rest = after;
    }

    fn next_pair(&mut self) -> Option<Pair<'a>> {
        loop {
            if self.done {
                return None;
            }
            if self.rest.is_empty() {
                if !self.advance_line() {
                    self.done = true;
                    return None;
                }
                continue;
            }
            let rest = self.rest;
            let seg = match find_byte(b';', rest) {
                Some(i) => {
                    self.rest = rest.get(i + 1..).unwrap_or_default();
                    self.after_separator();
                    rest.get(..i).unwrap_or_default()
                }
                None => {
                    self.rest = &[];
                    rest
                }
            };
            let seg = trim_end(seg);
            if seg.is_empty() {
                self.stats.empty = self.stats.empty.saturating_add(1);
                continue;
            }
            match classify(seg, &self.limits) {
                Some(pair) => {
                    if self.stats.pairs >= self.limits.pairs() {
                        self.stats.truncated = true;
                        self.done = true;
                        return None;
                    }
                    self.stats.pairs += 1;
                    return Some(pair);
                }
                None => self.stats.skipped = self.stats.skipped.saturating_add(1),
            }
        }
    }
}

/// Steps 4 to 6 of the algorithm: split, then check the name and the value.
fn classify<'a>(seg: &'a [u8], limits: &Limits) -> Option<Pair<'a>> {
    let eq = find_byte(b'=', seg)?;
    let name = seg.get(..eq)?;
    let value = seg.get(eq + 1..)?;
    if name.is_empty()
        || name.len() > usize::from(limits.name_len())
        || name::first_non_tchar(name).is_some()
    {
        return None;
    }
    if value.len() > usize::from(limits.value_len()) || name.len() + value.len() > PAIR_MAX {
        return None;
    }
    let ok = match limits.mode() {
        ValueMode::Strict => name::check_value(value).is_ok(),
        ValueMode::Lenient => name::lenient_value_ok(value),
    };
    if !ok {
        return None;
    }
    Some(Pair {
        name: core::str::from_utf8(name).ok()?,
        value: core::str::from_utf8(value).ok()?,
    })
}

/// Linear-time detection of repeated prefixed names (decision D-039): an
/// open-addressed table of the first 64 distinct prefixed names, keyed by an
/// FNV-1a hash, with an exact compare on a match. No allocation.
struct DupTable<'a> {
    slots: [Option<&'a str>; DUP_SLOTS],
    used: usize,
}

const DUP_SLOTS: usize = 64;

impl<'a> DupTable<'a> {
    const fn new() -> Self {
        Self {
            slots: [None; DUP_SLOTS],
            used: 0,
        }
    }

    fn note(&mut self, name: &'a str, stats: &mut Stats) {
        if !name.starts_with("__") || name::of_bytes(name.as_bytes()) == Prefix::None {
            return;
        }
        let mut h: u32 = 0x811c_9dc5;
        for &b in name.as_bytes() {
            h = (h ^ u32::from(b)).wrapping_mul(0x0100_0193);
        }
        let start = h as usize % DUP_SLOTS;
        for i in 0..DUP_SLOTS {
            let slot = (start + i) % DUP_SLOTS;
            match self.slots.get_mut(slot) {
                Some(Some(seen)) if *seen == name => {
                    stats.prefixed_duplicates = stats.prefixed_duplicates.saturating_add(1);
                    return;
                }
                Some(Some(_)) => {}
                Some(empty @ None) => {
                    *empty = Some(name);
                    self.used += 1;
                    return;
                }
                None => return,
            }
        }
        // Full: names past the first 64 distinct ones are not tracked.
        debug_assert_eq!(self.used, DUP_SLOTS);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use std::{format, string::String, vec::Vec};

    use super::*;

    fn names(h: &str) -> Vec<&str> {
        Cookies::new(h).iter().map(|p| p.name()).collect()
    }

    fn values(h: &str) -> Vec<&str> {
        Cookies::new(h).iter().map(|p| p.value()).collect()
    }

    #[test]
    fn test_parse_edge_cases_from_the_specification() {
        assert!(names("").is_empty());
        assert!(names("   \t ").is_empty());
        assert_eq!(names("a=1"), ["a"]);
        assert_eq!(values("a="), [""]);
        assert!(names("=1").is_empty());
        assert!(names("a").is_empty());
        assert_eq!(names("a=1;"), ["a"]);
        assert_eq!(names(";a=1"), ["a"]);
        assert_eq!(names("a=1;;b=2"), ["a", "b"]);
        assert_eq!(names("a=1;b=2"), ["a", "b"]);
        assert_eq!(names("a=1;   b=2"), ["a", "b"]);
        assert_eq!(names("a=1 ; b=2"), ["a", "b"]);
        assert_eq!(values("a=\"1\""), ["\"1\""]);
        assert!(names("a=\"1").is_empty());
        assert_eq!(values("a=\"\""), ["\"\""]);
        assert!(names("a=\"x\"y").is_empty());
        assert_eq!(values("a=b=c"), ["b=c"]);
        assert!(names("a=b c").is_empty());
        assert!(names("a=b\\c").is_empty());
        assert!(names("a=b,c").is_empty());
        assert!(names("a=b\"c").is_empty());
        assert_eq!(names("$Version=1; $Path=/"), ["$Version", "$Path"]);
        for bad in ["[a=1", "a]=1", "a@=1", "a:=1", "a b=1"] {
            assert!(names(bad).is_empty(), "{bad}");
        }
        assert_eq!(names("a=1\t;\tb=2"), ["a", "b"]);
        assert_eq!(
            names("__Host-sid=1; __host-sid=2"),
            ["__Host-sid", "__host-sid"]
        );
    }

    #[test]
    fn test_parse_obs_text_and_controls_skipped_in_strict() {
        let h: &[u8] = b"a=\xc3\xa9; b=1; c=x\ry; d=x\0; e=2";
        let c = Cookies::new(h);
        let n: Vec<&str> = c.iter().map(|p| p.name()).collect();
        assert_eq!(n, ["b", "e"]);
        assert_eq!(c.stats().skipped, 3);
    }

    #[test]
    fn test_parse_lenient_keeps_spaces_and_utf8_but_not_invalid_utf8() {
        let l = Limits::DEFAULT.value_mode(ValueMode::Lenient);
        let h: &[u8] = b"a=x y; b=\xc3\xa9; c=\xff; d=\"q\"r; e=x\x01";
        let c = Cookies::with_limits(h, &l).unwrap();
        let v: Vec<(&str, &str)> = c.iter().map(|p| (p.name(), p.value())).collect();
        assert_eq!(v, [("a", "x y"), ("b", "\u{e9}"), ("d", "\"q\"r")]);
        assert_eq!(c.stats().skipped, 2);
    }

    #[test]
    fn test_parse_comma_is_not_a_separator() {
        let c = Cookies::new("a=1, b=2");
        assert!(c.is_empty());
        assert_eq!(c.stats().skipped, 1);
    }

    #[test]
    fn test_stats_counts_each_kind() {
        let s = Cookies::new("a=1;b=2; ; bad name=3; __Host-x=1; __Host-x=2").stats();
        assert_eq!(s.pairs, 4);
        assert_eq!(s.skipped, 1);
        assert_eq!(s.empty, 1);
        assert_eq!(s.loose_separators, 1);
        assert_eq!(s.prefixed_duplicates, 1);
        assert!(!s.truncated && !s.too_long);
        let s = Cookies::new("a=1;").stats();
        assert_eq!((s.empty, s.loose_separators), (1, 0));
        let s = Cookies::new("a=1;;b=2").stats();
        assert_eq!((s.empty, s.loose_separators), (1, 1));
        let s = Cookies::new("a=1;\tb=2;  c=3").stats();
        assert_eq!(s.loose_separators, 2);
    }

    #[test]
    fn test_name_and_value_length_limits() {
        let n256 = "n".repeat(256);
        let n257 = "n".repeat(257);
        assert_eq!(names(&format!("{n256}=1")).len(), 1);
        assert!(names(&format!("{n257}=1")).is_empty());
        let l = Limits::DEFAULT.max_name_len(4096).max_header_len(65_536);
        let v4096 = "v".repeat(4096);
        let v4095 = "v".repeat(4095);
        let ok = format!("a={v4095}");
        let too_big = format!("a={v4096}");
        assert_eq!(Cookies::with_limits(&ok, &l).unwrap().iter().count(), 1);
        assert_eq!(
            Cookies::with_limits(&too_big, &l).unwrap().iter().count(),
            0
        );
        let ok = format!("{}={}", "n".repeat(2048), "v".repeat(2048));
        assert_eq!(Cookies::with_limits(&ok, &l).unwrap().iter().count(), 1);
    }

    #[test]
    fn test_pair_limit_truncates() {
        let h64: String = (0..64)
            .map(|i| format!("c{i}=1; "))
            .collect::<Vec<_>>()
            .concat();
        let h65: String = (0..65)
            .map(|i| format!("c{i}=1; "))
            .collect::<Vec<_>>()
            .concat();
        let s = Cookies::new(&h64).stats();
        assert_eq!((s.pairs, s.truncated), (64, false));
        let s = Cookies::new(&h65).stats();
        assert_eq!((s.pairs, s.truncated), (64, true));
        assert_eq!(Cookies::new(&h65).iter().count(), 64);
        assert_eq!(
            Cookies::new(&h65).get_unique("c0"),
            Err(Ambiguous::Truncated)
        );
        assert_eq!(Cookies::new(&h65).locate("c0").lookup, Lookup::Truncated);
    }

    #[test]
    fn test_header_length_limit() {
        let h8192 = format!("a={}", "v".repeat(8190));
        let h8193 = format!("a={}", "v".repeat(8191));
        assert!(!Cookies::new(&h8192).stats().too_long);
        let c = Cookies::new(&h8193);
        assert!(c.is_empty());
        assert!(c.stats().too_long);
        assert_eq!(c.get_unique("a"), Err(Ambiguous::HeaderTooLong));
        assert_eq!(c.locate("a").lookup, Lookup::HeaderTooLong);
        assert_eq!(
            Cookies::with_limits(&h8193, &Limits::DEFAULT).unwrap_err(),
            CookieError::HeaderTooLong
        );
    }

    #[test]
    fn test_from_lines_joins_and_sums_lengths() {
        let lines: [&[u8]; 4] = [b"a=1", b"", b"  b=2;", b"c=3"];
        let c = Cookies::from_lines(&lines, &Limits::DEFAULT).unwrap();
        let n: Vec<&str> = c.iter().map(|p| p.name()).collect();
        assert_eq!(n, ["a", "b", "c"]);
        let long = [b"a=12".as_slice(), b"b=34".as_slice()];
        assert_eq!(
            Cookies::from_lines(&long, &Limits::DEFAULT.max_header_len(7)).unwrap_err(),
            CookieError::HeaderTooLong
        );
        assert!(Cookies::from_lines(&long, &Limits::DEFAULT.max_header_len(8)).is_ok());
        let none: [&[u8]; 0] = [];
        assert!(
            Cookies::from_lines(&none, &Limits::DEFAULT)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn test_crumbs_split_at_every_separator_match_joined() {
        let joined = "a=1; __Host-sid=t; b=\"q\"; c=; d=4";
        let parts: Vec<&[u8]> = joined.split("; ").map(str::as_bytes).collect();
        for cut in 0..=parts.len() {
            let (l, r) = parts.split_at(cut);
            let left = l
                .iter()
                .map(|p| core::str::from_utf8(p).unwrap())
                .collect::<Vec<_>>()
                .join("; ");
            let right = r
                .iter()
                .map(|p| core::str::from_utf8(p).unwrap())
                .collect::<Vec<_>>()
                .join("; ");
            let lines = [left.as_bytes(), right.as_bytes()];
            let c = Cookies::from_lines(&lines, &Limits::DEFAULT).unwrap();
            let got: Vec<Pair<'_>> = c.iter().collect();
            let want: Vec<Pair<'_>> = Cookies::new(joined).iter().collect();
            assert_eq!(got, want, "cut {cut}");
        }
        let c = Cookies::from_lines(&parts, &Limits::DEFAULT).unwrap();
        assert_eq!(c.iter().count(), 5);
    }

    #[test]
    fn test_get_first_match_byte_exact() {
        let c = Cookies::new("theme=dark; Theme=light; theme=x");
        assert_eq!(c.get("theme"), Some("dark"));
        assert_eq!(c.get("Theme"), Some("light"));
        assert_eq!(c.get("THEME"), None);
        assert_eq!(c.get(""), None);
    }

    #[test]
    fn test_get_unique_outcomes() {
        assert_eq!(Cookies::new("a=1").get_unique("a"), Ok(Some("1")));
        assert_eq!(Cookies::new("a=1").get_unique("b"), Ok(None));
        assert_eq!(
            Cookies::new("a=1; a=1; a=2").get_unique("a"),
            Err(Ambiguous::Duplicate { count: 3 })
        );
        // a duplicate before the limit wins over truncation
        let h: String = core::iter::once(String::from("x=1; x=2; "))
            .chain((0..70).map(|i| format!("c{i}=1; ")))
            .collect::<Vec<_>>()
            .concat();
        assert_eq!(
            Cookies::new(&h).get_unique("x"),
            Err(Ambiguous::Duplicate { count: 2 })
        );
    }

    #[test]
    fn test_get_all_in_order() {
        let v: Vec<&str> = Cookies::new("c=2; t=d; c=1; c=").get_all("c").collect();
        assert_eq!(v, ["2", "1", ""]);
    }

    #[test]
    fn test_locate_shadows() {
        let h = "__host-sid=a; __HOST-SID=b; sid=c; SID=d; __Secure-sid=e; __Host-sid=t; sidx=f";
        let found = Cookies::new(h).locate("__Host-sid");
        assert_eq!(found.lookup, Lookup::One("t"));
        assert_eq!(found.shadows, 5);
        assert_eq!(found.severity_hint(), 5);
        assert_eq!(found.stats.pairs, 7);
        let none = Cookies::new("theme=dark; lang=fr").locate("__Host-sid");
        assert_eq!(
            (none.lookup, none.shadows, none.severity_hint()),
            (Lookup::Missing, 0, 0)
        );
    }

    #[test]
    fn test_locate_severity_cap_and_truncation() {
        let h: String = (0..70)
            .map(|i| format!("c{i}=1; "))
            .collect::<Vec<_>>()
            .concat();
        let found = Cookies::new(&h).locate("__Host-sid");
        assert_eq!(
            (found.lookup, found.severity_hint()),
            (Lookup::Truncated, 10)
        );
        let found = Cookies::new("__Host-sid=a; __Host-sid=b; sid=x").locate("__Host-sid");
        assert_eq!(
            found.lookup,
            Lookup::Many {
                first: "a",
                count: 2
            }
        );
        assert_eq!(found.severity_hint(), 35);
        assert_eq!(found.stats.prefixed_duplicates, 1);
    }

    #[test]
    fn test_names_never_trimmed_decoded_or_folded() {
        let h = "\u{a0}__Host-sid=x; %5F_Host-sid=y; __HOST-sid=z";
        let c = Cookies::new(h);
        assert_eq!(c.get("__Host-sid"), None);
        assert_eq!(c.get("%5F_Host-sid"), Some("y"));
        assert_eq!(c.stats().skipped, 1);
    }

    #[test]
    fn test_debug_never_prints_values() {
        let c = Cookies::new("__Host-sid=SECRETTOKEN; a=1");
        assert!(!format!("{c:?}").contains("SECRET"));
        let p = c.iter().next().unwrap();
        assert_eq!(
            format!("{p:?}"),
            "Pair { name: \"__Host-sid\", value: 11 bytes }"
        );
        let l = c.locate("__Host-sid");
        let d = format!("{l:?}");
        assert!(!d.contains("SECRET") && d.contains("11 bytes"), "{d}");
        let many = Cookies::new("a=SECRET; a=SECRET2").locate("a");
        assert!(!format!("{many:?}").contains("SECRET"));
        assert!(!format!("{:?}", c.iter()).contains("SECRET"));
        assert!(!format!("{:?}", c.get_all("a")).contains("SECRET"));
    }

    #[test]
    fn test_scan_stops_on_break() {
        let mut seen = 0;
        let s = Cookies::new("a=1; b=2; c=3").scan(|_| {
            seen += 1;
            if seen == 2 {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
        });
        assert_eq!((seen, s.pairs), (2, 2));
    }

    #[test]
    fn test_prefixed_duplicates_are_linear_and_bounded() {
        let h: String = (0..100)
            .map(|i| format!("__Host-n{i}=1; __Host-n{i}=2; "))
            .collect::<Vec<_>>()
            .concat();
        let l = Limits::DEFAULT.max_pairs(1024);
        let s = Cookies::with_limits(&h, &l).unwrap().stats();
        assert_eq!(s.pairs, 200);
        // the first 64 distinct names are tracked
        assert_eq!(s.prefixed_duplicates, 64);
    }

    #[test]
    fn test_into_iterator_both_forms() {
        let c = Cookies::new("a=1; b=2");
        let mut n = 0;
        for _ in &c {
            n += 1;
        }
        for _ in c {
            n += 1;
        }
        assert_eq!(n, 4);
    }

    #[test]
    fn test_value_unquoted() {
        let p = |h: &'static str| Cookies::new(h).iter().next().unwrap();
        assert_eq!(p("a=\"x\"").value_unquoted(), "x");
        assert_eq!(p("a=\"\"").value_unquoted(), "");
        assert_eq!(p("a=x").value_unquoted(), "x");
        assert_eq!(p("a=").value_unquoted(), "");
    }
}
