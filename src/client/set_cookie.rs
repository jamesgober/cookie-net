//! Parsing `Set-Cookie` as a user agent does (rfc6265bis section 5.6):
//! [`parse_set_cookie`], [`SetCookieView`], [`SameSiteAttr`].
//!
//! A client must behave like a browser, so this follows the user-agent
//! algorithm, which is more lenient than the server grammar on purpose. Names
//! and values are bytes, because a client keeps what a server sent.

use core::fmt;

use super::date::cookie_date;
use crate::{MAX_LIFETIME, limits::PAIR_MAX, request::Len};

/// The longest attribute value user agents keep (rfc6265bis section 5.6).
const MAX_ATTRIBUTE: usize = 1024;

/// The `SameSite` attribute as a user agent reads it.
///
/// # Examples
///
/// ```
/// use cookie_net::{SameSiteAttr, parse_set_cookie};
///
/// assert_eq!(parse_set_cookie("a=1; SameSite=lax").unwrap().same_site, SameSiteAttr::Lax);
/// assert_eq!(parse_set_cookie("a=1; SameSite=Bogus").unwrap().same_site, SameSiteAttr::Default);
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub enum SameSiteAttr {
    /// `Strict`.
    Strict,
    /// `Lax`.
    Lax,
    /// `None`.
    None,
    /// Absent or an unknown value; a jar treats it as `Lax` (section 5.6.7).
    #[default]
    Default,
}

/// One `Set-Cookie` line as a user agent reads it.
///
/// `Debug` prints the value's length, never the value.
///
/// # Examples
///
/// ```
/// let v = cookie_net::parse_set_cookie("id=a3fWa; Max-Age=60; Secure").unwrap();
/// assert_eq!((v.name, v.max_age, v.secure), (&b"id"[..], Some(60), true));
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SetCookieView<'a> {
    /// The name, trimmed of SP and HTAB; empty for a nameless cookie.
    pub name: &'a [u8],
    /// The value, trimmed of SP and HTAB.
    pub value: &'a [u8],
    /// `Expires` as Unix seconds (the cookie-date algorithm).
    pub expires: Option<i64>,
    /// `Max-Age` in seconds: 0 or less means "expire now"; capped at 400 days.
    pub max_age: Option<i64>,
    /// `Domain` with one leading `.` removed (lowercased when stored).
    pub domain: Option<&'a [u8]>,
    /// `Path`; `None` also when the value does not start with `/` (the jar
    /// then uses the default path).
    pub path: Option<&'a [u8]>,
    /// `Secure`.
    pub secure: bool,
    /// `HttpOnly`.
    pub http_only: bool,
    /// `SameSite`.
    pub same_site: SameSiteAttr,
    /// `Partitioned` (CHIPS).
    pub partitioned: bool,
    /// Attributes not recognised, saturating at 255.
    pub unknown_attributes: u8,
}

impl fmt::Debug for SetCookieView<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SetCookieView")
            .field("name", &Text(self.name))
            .field("value", &Len(self.value.len()))
            .field("expires", &self.expires)
            .field("max_age", &self.max_age)
            .field("domain", &self.domain.map(Text))
            .field("path", &self.path.map(Text))
            .field("secure", &self.secure)
            .field("http_only", &self.http_only)
            .field("same_site", &self.same_site)
            .field("partitioned", &self.partitioned)
            .field("unknown_attributes", &self.unknown_attributes)
            .finish()
    }
}

/// Bytes printed as an escaped ASCII string, for `Debug`.
pub(crate) struct Text<'a>(pub(crate) &'a [u8]);

impl fmt::Debug for Text<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "\"{}\"", self.0.escape_ascii())
    }
}

/// Parses one `Set-Cookie` field value with the rfc6265bis section 5.6
/// algorithm. `None` means a user agent ignores the whole line: a control
/// byte other than HTAB, an empty name with an empty value, or a name plus
/// value over 4096 bytes. A later attribute replaces an earlier one; an
/// attribute value over 1024 bytes is ignored.
///
/// # Examples
///
/// ```
/// use cookie_net::{SameSiteAttr, parse_set_cookie};
///
/// let v = parse_set_cookie("id=a3fWa; Max-Age=2592000; Domain=.Example.com; secure; SameSite=lax").unwrap();
/// assert_eq!((v.name, v.value), (&b"id"[..], &b"a3fWa"[..]));
/// assert_eq!(v.max_age, Some(2_592_000));
/// assert_eq!(v.domain, Some(&b"Example.com"[..]));
/// assert!(v.secure);
/// assert_eq!(v.same_site, SameSiteAttr::Lax);
/// assert!(parse_set_cookie("a=b\x01c").is_none());
/// ```
#[must_use]
pub fn parse_set_cookie<L: AsRef<[u8]> + ?Sized>(line: &L) -> Option<SetCookieView<'_>> {
    let line = line.as_ref();
    // step 1: a control byte other than HTAB ignores the line
    if line.iter().any(|&b| (b < 0x20 && b != b'\t') || b == 0x7f) {
        return None;
    }
    // step 2: the name-value pair is everything before the first ';'
    let (pair, mut attrs) = match line.iter().position(|&b| b == b';') {
        Some(i) => (line.get(..i)?, line.get(i..)?),
        None => (line, &[][..]),
    };
    // step 3: without '=', the name is empty and the value is the pair
    let (name, value) = match pair.iter().position(|&b| b == b'=') {
        Some(i) => (pair.get(..i)?, pair.get(i + 1..)?),
        None => (&[][..], pair),
    };
    let (name, value) = (trim(name), trim(value));
    if name.is_empty() && value.is_empty() {
        return None;
    }
    if name.len() + value.len() > PAIR_MAX {
        return None;
    }
    let mut view = SetCookieView {
        name,
        value,
        expires: None,
        max_age: None,
        domain: None,
        path: None,
        secure: false,
        http_only: false,
        same_site: SameSiteAttr::Default,
        partitioned: false,
        unknown_attributes: 0,
    };
    // the attributes: each one up to the next ';'
    while let Some(rest) = attrs.strip_prefix(b";") {
        let end = rest.iter().position(|&b| b == b';').unwrap_or(rest.len());
        let av = rest.get(..end)?;
        attrs = rest.get(end..)?;
        let (attr, v) = match av.iter().position(|&b| b == b'=') {
            Some(i) => (av.get(..i)?, av.get(i + 1..)?),
            None => (av, &[][..]),
        };
        let (attr, v) = (trim(attr), trim(v));
        if v.len() > MAX_ATTRIBUTE {
            continue;
        }
        apply(&mut view, attr, v);
    }
    Some(view)
}

fn apply<'a>(view: &mut SetCookieView<'a>, attr: &[u8], v: &'a [u8]) {
    let is = |name: &str| attr.eq_ignore_ascii_case(name.as_bytes());
    if is("Expires") {
        if let Some(t) = cookie_date(v) {
            view.expires = Some(t);
        }
    } else if is("Max-Age") {
        if let Some(secs) = max_age(v) {
            view.max_age = Some(secs);
        }
    } else if is("Domain") {
        // an empty Domain is ignored (section 5.6.3)
        if !v.is_empty() {
            view.domain = Some(v.strip_prefix(b".").unwrap_or(v));
        }
    } else if is("Path") {
        view.path = (v.first() == Some(&b'/')).then_some(v);
    } else if is("Secure") {
        view.secure = true;
    } else if is("HttpOnly") {
        view.http_only = true;
    } else if is("SameSite") {
        view.same_site = if v.eq_ignore_ascii_case(b"Strict") {
            SameSiteAttr::Strict
        } else if v.eq_ignore_ascii_case(b"Lax") {
            SameSiteAttr::Lax
        } else if v.eq_ignore_ascii_case(b"None") {
            SameSiteAttr::None
        } else {
            SameSiteAttr::Default
        };
    } else if is("Partitioned") {
        view.partitioned = true;
    } else {
        view.unknown_attributes = view.unknown_attributes.saturating_add(1);
    }
}

/// Section 5.6.2: the first byte is a digit or `-`, the rest digits; the
/// value saturates and is capped at 400 days. `None` ignores the attribute.
fn max_age(v: &[u8]) -> Option<i64> {
    let (negative, digits) = match v {
        [b'-', rest @ ..] => (true, rest),
        _ => (false, v),
    };
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    if negative {
        return Some(0);
    }
    let cap = i64::try_from(MAX_LIFETIME).unwrap_or(i64::MAX);
    let n = digits.iter().try_fold(0i64, |acc, &b| {
        acc.checked_mul(10)
            .and_then(|x| x.checked_add(i64::from(b - b'0')))
    });
    Some(n.map_or(cap, |n| n.min(cap)))
}

/// Removes leading and trailing SP and HTAB.
fn trim(s: &[u8]) -> &[u8] {
    let start = s.iter().take_while(|&&b| b == b' ' || b == b'\t').count();
    let s = s.get(start..).unwrap_or_default();
    let end = s.len()
        - s.iter()
            .rev()
            .take_while(|&&b| b == b' ' || b == b'\t')
            .count();
    s.get(..end).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    extern crate std;
    use std::{format, string::String};

    use super::*;

    fn p(s: &str) -> SetCookieView<'_> {
        parse_set_cookie(s).unwrap()
    }

    #[test]
    fn test_name_value_forms() {
        assert_eq!((p("a=b").name, p("a=b").value), (&b"a"[..], &b"b"[..]));
        assert_eq!(
            (p("novalue").name, p("novalue").value),
            (&b""[..], &b"novalue"[..])
        );
        assert_eq!(
            (p("=value").name, p("=value").value),
            (&b""[..], &b"value"[..])
        );
        assert_eq!(p("name=").value, b"");
        assert_eq!(
            (p("  a  =  b c  ").name, p("  a  =  b c  ").value),
            (&b"a"[..], &b"b c"[..])
        );
        assert_eq!(p("a=b=c").value, b"b=c");
        assert!(parse_set_cookie("").is_none());
        assert!(parse_set_cookie("=").is_none());
        assert!(parse_set_cookie(" ; Secure").is_none());
        assert!(parse_set_cookie("a=b\tc").is_some());
        for ctl in [0u8, 1, 0x0a, 0x0d, 0x1f, 0x7f] {
            let line = [b'a', b'=', ctl];
            assert!(parse_set_cookie(&line[..]).is_none(), "{ctl}");
        }
        let n = "n".repeat(2048);
        let v = "v".repeat(2048);
        assert!(parse_set_cookie(&format!("{n}={v}")).is_some());
        assert!(parse_set_cookie(&format!("{n}={v}x")).is_none());
    }

    #[test]
    fn test_attributes_case_insensitive_and_later_wins() {
        let v = p("a=b; sEcUrE; HTTPONLY; max-age=10; MAX-AGE=20; partitioned; Foo=bar; baz");
        assert!(v.secure && v.http_only && v.partitioned);
        assert_eq!(v.max_age, Some(20));
        assert_eq!(v.unknown_attributes, 2);
        let v = p("a=b; SameSite=None; SameSite=Strict");
        assert_eq!(v.same_site, SameSiteAttr::Strict);
    }

    #[test]
    fn test_max_age_rules() {
        assert_eq!(p("a=b; Max-Age=-1").max_age, Some(0));
        assert_eq!(p("a=b; Max-Age=0").max_age, Some(0));
        assert_eq!(p("a=b; Max-Age=abc").max_age, None);
        assert_eq!(p("a=b; Max-Age=1a").max_age, None);
        assert_eq!(p("a=b; Max-Age=").max_age, None);
        assert_eq!(p("a=b; Max-Age=-").max_age, None);
        assert_eq!(p("a=b; Max-Age=+5").max_age, None);
        assert_eq!(
            p("a=b; Max-Age=99999999999999999999").max_age,
            Some(34_560_000)
        );
        assert_eq!(p("a=b; Max-Age=34560001").max_age, Some(34_560_000));
        assert_eq!(p("a=b; Max-Age=5; Max-Age=bad").max_age, Some(5));
    }

    #[test]
    fn test_expires_uses_cookie_date() {
        assert_eq!(
            p("a=b; Expires=Wed, 09 Jun 2021 10:18:14 GMT").expires,
            Some(1_623_233_894)
        );
        assert_eq!(
            p("a=b; expires=09-Jun-21 10:18:14").expires,
            Some(1_623_233_894)
        );
        assert_eq!(p("a=b; Expires=garbage").expires, None);
    }

    #[test]
    fn test_domain_and_path() {
        assert_eq!(
            p("a=b; Domain=.example.com").domain,
            Some(&b"example.com"[..])
        );
        assert_eq!(
            p("a=b; Domain=example.com.").domain,
            Some(&b"example.com."[..])
        );
        assert_eq!(p("a=b; Domain=COM").domain, Some(&b"COM"[..]));
        assert_eq!(p("a=b; Domain=").domain, None);
        assert_eq!(p("a=b; Domain=a.com; Domain=").domain, Some(&b"a.com"[..]));
        assert_eq!(p("a=b; Path=").path, None);
        assert_eq!(p("a=b; Path=a").path, None);
        assert_eq!(p("a=b; Path=/a/").path, Some(&b"/a/"[..]));
        assert_eq!(p("a=b; Path=/x; Path=y").path, None);
    }

    #[test]
    fn test_long_attribute_values_ignored() {
        let long = format!("a=b; Path=/{}", "p".repeat(1024));
        assert_eq!(p(&long).path, None);
        let ok = format!("a=b; Path=/{}", "p".repeat(1023));
        assert!(p(&ok).path.is_some());
    }

    #[test]
    fn test_debug_redacts_value() {
        let d = format!("{:?}", p("sid=SECRETTOKEN; Path=/"));
        assert!(!d.contains("SECRET") && d.contains("11 bytes"), "{d}");
        let _: String = String::new();
    }
}
