//! Errors: [`CookieError`] for every fallible call, and [`Ambiguous`] for a
//! unique lookup that could not give one answer.
//!
//! Neither type ever holds or prints input bytes. Positions (`at`) are byte
//! offsets into the input that was refused, saturated at `u16::MAX`.

use core::fmt;

/// Why a cookie could not be built, read, or written.
///
/// One error type for every fallible call, so `?` works in a handler that
/// returns `Result<_, CookieError>`. Each variant names the rule it enforces;
/// the table in `docs/API.md` says what to do about each.
///
/// # Examples
///
/// ```
/// use cookie_net::{CookieError, SetCookie};
///
/// let err = SetCookie::new("sid", "a;Domain=evil.example").unwrap_err();
/// assert_eq!(err, CookieError::InvalidValue { at: 1 });
/// assert_eq!(err.code(), "invalid_value");
/// assert!(!err.to_string().contains("evil"));
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CookieError {
    /// The cookie name is empty. Servers must not produce nameless cookies
    /// (rfc6265bis section 4.1.1).
    EmptyName,
    /// A name byte is not a `tchar` (rfc6265bis section 4.1.1:
    /// `cookie-name = token`).
    InvalidName {
        /// Offset of the first refused byte.
        at: u16,
    },
    /// A value byte is not a `cookie-octet`, or a value opens a quote it does
    /// not close (rfc6265bis section 4.1.1). Encode the value first.
    InvalidValue {
        /// Offset of the first refused byte.
        at: u16,
    },
    /// Name plus value is over 4096 bytes; user agents ignore such a cookie
    /// (rfc6265bis sections 5.6 and 5.7).
    TooLarge,
    /// A session or elevated token is shorter than 22 bytes (128 bits in
    /// base64url): pass the session token, not a user id or an empty string.
    TokenTooShort,
    /// A `Path`, `Domain`, or extension value is over 1024 bytes; user agents
    /// ignore it (rfc6265bis section 5.6).
    AttributeTooLong,
    /// `Path` does not start with `/`, or holds a control byte or `;`
    /// (rfc6265bis section 4.1.1 `path-value`).
    InvalidPath {
        /// Offset of the first refused byte.
        at: u16,
    },
    /// `Domain` is not a host name of letter-digit-hyphen labels with at
    /// least one dot: a leading dot, a single label, an IP address, an empty
    /// label, or a label over 63 bytes (rfc6265bis sections 4.1.2.3, 5.6.3).
    InvalidDomain,
    /// An extension attribute holds a control byte or `;`, or is empty
    /// (rfc6265bis section 4.1.1 `extension-av`).
    InvalidExtension {
        /// Offset of the first refused byte.
        at: u16,
    },
    /// An extension attribute is named like a defined attribute; use the
    /// typed setter instead.
    ExtensionNotAllowed,
    /// More than 8 extension attributes.
    TooManyExtensions,
    /// `Max-Age` is 0 or over 400 days (rfc6265bis section 5.5); for an
    /// elevated cookie, outside 60 to 3600 seconds.
    MaxAgeOutOfRange,
    /// `Expires` is more than 400 days after `now` (rfc6265bis section 5.5),
    /// or outside the dates an HTTP-date can carry.
    ExpiresOutOfRange,
    /// A `__Host-` name (any case) without `Secure`, with a `Path` other than
    /// `/`, or with `Domain` (rfc6265bis sections 4.1.3.2 and 5.4); or a
    /// session helper given a name without the `__Host-` prefix.
    HostPrefix,
    /// A `__Secure-` name (any case) without `Secure` (rfc6265bis section
    /// 4.1.3.1).
    SecurePrefix,
    /// `SameSite=None` without `Secure`; user agents ignore such a cookie
    /// (rfc6265bis section 5.7).
    SameSiteNoneNeedsSecure,
    /// `Partitioned` without `Secure`
    /// (draft-cutler-httpbis-partitioned-cookies sections 2.3 and 3.1).
    PartitionedNeedsSecure,
    /// A `Cookie` header longer than `Limits::max_header_len`.
    HeaderTooLong,
    /// The sink has no room; `encoded_len` says how much is needed.
    Full,
    /// A unique lookup could not give one answer (through `?` only).
    Ambiguous(Ambiguous),
}

impl CookieError {
    /// A stable snake_case identifier for metrics and events. Codes never
    /// change within a major version.
    ///
    /// # Examples
    ///
    /// ```
    /// use cookie_net::{Ambiguous, CookieError};
    ///
    /// assert_eq!(CookieError::HostPrefix.code(), "host_prefix");
    /// assert_eq!(CookieError::Ambiguous(Ambiguous::Truncated).code(), "ambiguous.truncated");
    /// ```
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::EmptyName => "empty_name",
            Self::InvalidName { .. } => "invalid_name",
            Self::InvalidValue { .. } => "invalid_value",
            Self::TooLarge => "too_large",
            Self::TokenTooShort => "token_too_short",
            Self::AttributeTooLong => "attribute_too_long",
            Self::InvalidPath { .. } => "invalid_path",
            Self::InvalidDomain => "invalid_domain",
            Self::InvalidExtension { .. } => "invalid_extension",
            Self::ExtensionNotAllowed => "extension_not_allowed",
            Self::TooManyExtensions => "too_many_extensions",
            Self::MaxAgeOutOfRange => "max_age_out_of_range",
            Self::ExpiresOutOfRange => "expires_out_of_range",
            Self::HostPrefix => "host_prefix",
            Self::SecurePrefix => "secure_prefix",
            Self::SameSiteNoneNeedsSecure => "same_site_none_needs_secure",
            Self::PartitionedNeedsSecure => "partitioned_needs_secure",
            Self::HeaderTooLong => "header_too_long",
            Self::Full => "full",
            Self::Ambiguous(Ambiguous::Duplicate { .. }) => "ambiguous.duplicate",
            Self::Ambiguous(Ambiguous::Truncated) => "ambiguous.truncated",
            Self::Ambiguous(Ambiguous::HeaderTooLong) => "ambiguous.header_too_long",
        }
    }
}

impl fmt::Display for CookieError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::EmptyName => f.write_str("cookie name is empty (rfc6265bis 4.1.1)"),
            Self::InvalidName { at } => {
                write!(
                    f,
                    "cookie name: byte {at} is not a token character (rfc6265bis 4.1.1)"
                )
            }
            Self::InvalidValue { at } => {
                write!(
                    f,
                    "cookie value: byte {at} is not allowed (rfc6265bis 4.1.1)"
                )
            }
            Self::TooLarge => {
                f.write_str("cookie name plus value is over 4096 bytes (rfc6265bis 5.6)")
            }
            Self::TokenTooShort => f.write_str("session token is shorter than 22 bytes"),
            Self::AttributeTooLong => {
                f.write_str("cookie attribute value is over 1024 bytes (rfc6265bis 5.6)")
            }
            Self::InvalidPath { at } => {
                write!(
                    f,
                    "cookie Path: byte {at} is not allowed (rfc6265bis 4.1.1)"
                )
            }
            Self::InvalidDomain => {
                f.write_str("cookie Domain is not a host name with a dot (rfc6265bis 5.6.3)")
            }
            Self::InvalidExtension { at } => {
                write!(
                    f,
                    "cookie extension attribute: byte {at} is not allowed (rfc6265bis 4.1.1)"
                )
            }
            Self::ExtensionNotAllowed => {
                f.write_str("cookie extension attribute redefines a defined attribute")
            }
            Self::TooManyExtensions => f.write_str("more than 8 cookie extension attributes"),
            Self::MaxAgeOutOfRange => {
                f.write_str("cookie Max-Age is out of range (rfc6265bis 5.5)")
            }
            Self::ExpiresOutOfRange => {
                f.write_str("cookie Expires is out of range (rfc6265bis 5.5)")
            }
            Self::HostPrefix => f.write_str(
                "__Host- cookie needs Secure, Path=/, and no Domain (rfc6265bis 4.1.3.2)",
            ),
            Self::SecurePrefix => f.write_str("__Secure- cookie needs Secure (rfc6265bis 4.1.3.1)"),
            Self::SameSiteNoneNeedsSecure => {
                f.write_str("SameSite=None cookie needs Secure (rfc6265bis 5.7)")
            }
            Self::PartitionedNeedsSecure => f.write_str("Partitioned cookie needs Secure"),
            Self::HeaderTooLong => f.write_str("Cookie header is longer than the limit"),
            Self::Full => f.write_str("output buffer is full"),
            Self::Ambiguous(a) => fmt::Display::fmt(&a, f),
        }
    }
}

impl core::error::Error for CookieError {}

impl From<Ambiguous> for CookieError {
    fn from(a: Ambiguous) -> Self {
        Self::Ambiguous(a)
    }
}

impl From<parse_net::Full> for CookieError {
    fn from(_: parse_net::Full) -> Self {
        Self::Full
    }
}

/// Why a unique lookup could not give one answer.
///
/// For a credential every variant means "treat the request as signed out". A
/// `__Host-` name can exist only once per host, so `Duplicate` on one is a
/// planted cookie, not a glitch.
///
/// # Examples
///
/// ```
/// use cookie_net::{self as cookie, Ambiguous};
///
/// let h = "__Host-sid=real; theme=dark; __Host-sid=planted";
/// assert_eq!(cookie::get_unique(h, "__Host-sid"), Err(Ambiguous::Duplicate { count: 2 }));
/// assert_eq!(cookie::get_unique(h, "theme"), Ok(Some("dark")));
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Ambiguous {
    /// The name appears `count` times (2 or more).
    Duplicate {
        /// How many pairs carry the name.
        count: u16,
    },
    /// More than `max_pairs` pairs: a duplicate could hide past the limit.
    Truncated,
    /// The header is longer than `max_header_len`: nothing was read.
    HeaderTooLong,
}

impl Ambiguous {
    /// A stable snake_case identifier for metrics and events.
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(cookie_net::Ambiguous::Truncated.code(), "truncated");
    /// ```
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Duplicate { .. } => "duplicate",
            Self::Truncated => "truncated",
            Self::HeaderTooLong => "header_too_long",
        }
    }
}

impl fmt::Display for Ambiguous {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Duplicate { count } => write!(f, "cookie name appears {count} times"),
            Self::Truncated => f.write_str("Cookie header has more pairs than the limit"),
            Self::HeaderTooLong => f.write_str("Cookie header is longer than the limit"),
        }
    }
}

impl core::error::Error for Ambiguous {}

/// A byte offset as the `u16` the error variants carry.
pub(crate) fn at(offset: usize) -> u16 {
    u16::try_from(offset).unwrap_or(u16::MAX)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use std::{collections::BTreeSet, string::ToString};

    use super::*;

    const ALL: [CookieError; 22] = [
        CookieError::EmptyName,
        CookieError::InvalidName { at: 1 },
        CookieError::InvalidValue { at: 2 },
        CookieError::TooLarge,
        CookieError::TokenTooShort,
        CookieError::AttributeTooLong,
        CookieError::InvalidPath { at: 3 },
        CookieError::InvalidDomain,
        CookieError::InvalidExtension { at: 4 },
        CookieError::ExtensionNotAllowed,
        CookieError::TooManyExtensions,
        CookieError::MaxAgeOutOfRange,
        CookieError::ExpiresOutOfRange,
        CookieError::HostPrefix,
        CookieError::SecurePrefix,
        CookieError::SameSiteNoneNeedsSecure,
        CookieError::PartitionedNeedsSecure,
        CookieError::HeaderTooLong,
        CookieError::Full,
        CookieError::Ambiguous(Ambiguous::Duplicate { count: 2 }),
        CookieError::Ambiguous(Ambiguous::Truncated),
        CookieError::Ambiguous(Ambiguous::HeaderTooLong),
    ];

    #[test]
    fn test_codes_are_unique_and_snake_case() {
        let codes: BTreeSet<&str> = ALL.iter().map(|e| e.code()).collect();
        assert_eq!(codes.len(), ALL.len());
        for c in codes {
            assert!(
                c.bytes()
                    .all(|b| b.is_ascii_lowercase() || b == b'_' || b == b'.'),
                "{c}"
            );
        }
    }

    #[test]
    fn test_display_is_fixed_text_with_offsets() {
        for e in ALL {
            let s = e.to_string();
            assert!(!s.is_empty());
            assert!(s.is_ascii());
        }
        assert!(
            CookieError::InvalidValue { at: 7 }
                .to_string()
                .contains("byte 7")
        );
        assert_eq!(
            CookieError::Ambiguous(Ambiguous::Duplicate { count: 3 }).to_string(),
            "cookie name appears 3 times"
        );
    }

    #[test]
    fn test_from_conversions_wrap() {
        assert_eq!(
            CookieError::from(Ambiguous::Truncated),
            CookieError::Ambiguous(Ambiguous::Truncated)
        );
        assert_eq!(CookieError::from(parse_net::Full), CookieError::Full);
    }

    #[test]
    fn test_ambiguous_codes() {
        assert_eq!(Ambiguous::Duplicate { count: 2 }.code(), "duplicate");
        assert_eq!(Ambiguous::Truncated.code(), "truncated");
        assert_eq!(Ambiguous::HeaderTooLong.code(), "header_too_long");
    }

    #[test]
    fn test_at_saturates() {
        assert_eq!(at(5), 5);
        assert_eq!(at(70_000), u16::MAX);
    }
}
