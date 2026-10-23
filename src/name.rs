//! Name and value classification shared by the request and response sides,
//! and [`Prefix`].

use parse_net::class::{is_av_octet, is_cookie_octet, is_tchar};

/// A cookie-name prefix with rules attached (rfc6265bis section 4.1.3).
///
/// # Examples
///
/// ```
/// use cookie_net::Prefix;
///
/// assert_eq!(Prefix::of("__Host-sid"), Prefix::Host);
/// assert_eq!(Prefix::of("__secure-x"), Prefix::Secure);   // user agents compare prefixes case-insensitively
/// assert_eq!(Prefix::of("_Host-sid"), Prefix::None);
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Prefix {
    /// No prefix.
    None,
    /// `__Secure-`: the cookie must be `Secure` (rfc6265bis section 4.1.3.1).
    Secure,
    /// `__Host-`: `Secure`, `Path=/`, and no `Domain` (rfc6265bis section
    /// 4.1.3.2).
    Host,
}

const HOST: &[u8] = b"__Host-";
const SECURE: &[u8] = b"__Secure-";

impl Prefix {
    /// The prefix of `name`, compared ASCII case-insensitively as user agents
    /// do (rfc6265bis section 5.4).
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(cookie_net::Prefix::of("__HOST-x"), cookie_net::Prefix::Host);
    /// ```
    #[must_use]
    pub fn of(name: &str) -> Prefix {
        of_bytes(name.as_bytes())
    }

    /// The prefix's length in bytes (0 for `None`).
    pub(crate) const fn len(self) -> usize {
        match self {
            Self::None => 0,
            Self::Secure => SECURE.len(),
            Self::Host => HOST.len(),
        }
    }
}

pub(crate) fn of_bytes(name: &[u8]) -> Prefix {
    if starts_with_ci(name, HOST) {
        Prefix::Host
    } else if starts_with_ci(name, SECURE) {
        Prefix::Secure
    } else {
        Prefix::None
    }
}

fn starts_with_ci(s: &[u8], prefix: &[u8]) -> bool {
    s.get(..prefix.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
}

/// `name` without its prefix, for shadow-name comparison.
pub(crate) fn core(name: &[u8]) -> &[u8] {
    name.get(of_bytes(name).len()..).unwrap_or(name)
}

/// Offset of the first byte of `name` that is not a `tchar`; `None` when
/// every byte is one. An empty name is the caller's concern.
pub(crate) fn first_non_tchar(name: &[u8]) -> Option<usize> {
    name.iter().position(|&b| !is_tchar(b))
}

/// Checks a server-side `cookie-value`: `*cookie-octet` or
/// `DQUOTE *cookie-octet DQUOTE` (rfc6265bis section 4.1.1). Returns the
/// offset of the first refused byte.
pub(crate) fn check_value(value: &[u8]) -> Result<(), usize> {
    let inner = match value {
        [b'"', inner @ .., b'"'] => {
            return match inner.iter().position(|&b| !is_cookie_octet(b)) {
                Some(i) => Err(i + 1),
                None => Ok(()),
            };
        }
        // An opening quote that is never closed, or a single quote.
        [b'"', ..] => return Err(value.len()),
        inner => inner,
    };
    match inner.iter().position(|&b| !is_cookie_octet(b)) {
        Some(i) => Err(i),
        None => Ok(()),
    }
}

/// Lenient values: any byte except a control (HTAB allowed) and `;`.
pub(crate) fn lenient_value_ok(value: &[u8]) -> bool {
    value
        .iter()
        .all(|&b| b == b'\t' || (b >= 0x20 && b != 0x7f && b != b';'))
}

/// Offset of the first byte that is not an `av-octet` (any byte from 0x20
/// to 0x7E except `;`, rfc6265bis section 4.1.1).
pub(crate) fn first_non_av_octet(value: &[u8]) -> Option<usize> {
    value.iter().position(|&b| !is_av_octet(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prefix_of_case_insensitive() {
        assert_eq!(Prefix::of("__Host-sid"), Prefix::Host);
        assert_eq!(Prefix::of("__host-sid"), Prefix::Host);
        assert_eq!(Prefix::of("__HOST-"), Prefix::Host);
        assert_eq!(Prefix::of("__Secure-a"), Prefix::Secure);
        assert_eq!(Prefix::of("__SECURE-a"), Prefix::Secure);
        assert_eq!(Prefix::of("__Host"), Prefix::None);
        assert_eq!(Prefix::of(""), Prefix::None);
        assert_eq!(Prefix::of("sid"), Prefix::None);
        assert_eq!(Prefix::of("\u{a0}__Host-sid"), Prefix::None);
    }

    #[test]
    fn test_core_strips_one_prefix() {
        assert_eq!(core(b"__Host-sid"), b"sid");
        assert_eq!(core(b"__secure-sid"), b"sid");
        assert_eq!(core(b"sid"), b"sid");
        assert_eq!(core(b"__Host-"), b"");
    }

    #[test]
    fn test_first_non_tchar() {
        assert_eq!(first_non_tchar(b"abc!#$%&'*+-.^_`|~09AZ"), None);
        assert_eq!(first_non_tchar(b"a b"), Some(1));
        assert_eq!(first_non_tchar(b"a=b"), Some(1));
        assert_eq!(first_non_tchar(b"a;"), Some(1));
        assert_eq!(first_non_tchar("é".as_bytes()), Some(0));
    }

    #[test]
    fn test_check_value_quotes_and_octets() {
        assert_eq!(check_value(b""), Ok(()));
        assert_eq!(check_value(b"abc"), Ok(()));
        assert_eq!(check_value(b"\"\""), Ok(()));
        assert_eq!(check_value(b"\"ab\""), Ok(()));
        assert_eq!(check_value(b"\"a"), Err(2));
        assert_eq!(check_value(b"\""), Err(1));
        assert_eq!(check_value(b"\"a b\""), Err(2));
        assert_eq!(check_value(b"a\"b"), Err(1));
        assert_eq!(check_value(b"\"x\"y"), Err(4));
        assert_eq!(check_value(b"a b"), Err(1));
        assert_eq!(check_value(b"a,b"), Err(1));
        assert_eq!(check_value(b"a\\b"), Err(1));
        assert_eq!(check_value(b"a;b"), Err(1));
        assert_eq!(check_value(&[b'a', 0x80]), Err(1));
    }

    #[test]
    fn test_lenient_value_ok() {
        assert!(lenient_value_ok(b"a b, \"c\"\t{}"));
        assert!(lenient_value_ok(&[0x80, 0xff]));
        assert!(!lenient_value_ok(b"a;b"));
        assert!(!lenient_value_ok(b"a\rb"));
        assert!(!lenient_value_ok(&[0x7f]));
        assert!(!lenient_value_ok(&[0]));
    }

    #[test]
    fn test_first_non_av_octet() {
        assert_eq!(first_non_av_octet(b"/a b,\"c\""), None);
        assert_eq!(first_non_av_octet(b"/a;b"), Some(2));
        assert_eq!(first_non_av_octet(b"/a\r"), Some(2));
        assert_eq!(first_non_av_octet(b"\t"), Some(0));
    }
}
