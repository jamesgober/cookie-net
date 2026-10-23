//! Errors: [`CookieError`] for every fallible call, [`Ambiguous`] for a
//! unique lookup that could not give one answer, and [`Rejected`] for a
//! signed or sealed cookie that did not verify.
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
    /// An extension attribute holds a control byte or `;` (rfc6265bis
    /// section 4.1.1 `extension-av`), is empty, or its name (the part before
    /// `=`) is not a `token`.
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
    /// All 32 key bytes are equal: an unset or zeroed key. Load the real one.
    WeakKey,
    /// `Key::derive` got a master shorter than 32 bytes.
    KeyTooShort,
    /// `Key::derive` got a context over 200 bytes.
    ContextTooLong,
    /// Two keys in a ring share an id.
    DuplicateKeyId,
    /// A ring holds more than 8 keys, or no signing key.
    RingFull,
    /// A retired key's time is after 2156 (a time in milliseconds, say).
    InvalidRetireTime,
    /// crypt-io reported a failure, such as the OS random source failing while
    /// sealing. Nothing was written (fail closed).
    Crypto,
    /// A unique lookup could not give one answer (through `?` only).
    Ambiguous(Ambiguous),
    /// A signed or sealed cookie did not verify (through `?` only).
    Rejected(Rejected),
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
            Self::WeakKey => "weak_key",
            Self::KeyTooShort => "key_too_short",
            Self::ContextTooLong => "context_too_long",
            Self::DuplicateKeyId => "duplicate_key_id",
            Self::RingFull => "ring_full",
            Self::InvalidRetireTime => "invalid_retire_time",
            Self::Crypto => "crypto",
            Self::Rejected(Rejected::Malformed) => "rejected.malformed",
            Self::Rejected(Rejected::UnsupportedVersion) => "rejected.unsupported_version",
            Self::Rejected(Rejected::UnknownKey) => "rejected.unknown_key",
            Self::Rejected(Rejected::BadTag) => "rejected.bad_tag",
            Self::Rejected(Rejected::Expired) => "rejected.expired",
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
            Self::WeakKey => f.write_str("key bytes are all equal: not a real key"),
            Self::KeyTooShort => f.write_str("master secret is shorter than 32 bytes"),
            Self::ContextTooLong => f.write_str("key derivation context is over 200 bytes"),
            Self::DuplicateKeyId => f.write_str("two keys in the ring share an id"),
            Self::RingFull => f.write_str("key ring holds more than 8 keys or no signing key"),
            Self::InvalidRetireTime => f.write_str("retire time is after 2156"),
            Self::Crypto => f.write_str("cryptographic operation failed"),
            Self::Ambiguous(a) => fmt::Display::fmt(&a, f),
            Self::Rejected(r) => fmt::Display::fmt(&r, f),
        }
    }
}

impl core::error::Error for CookieError {}

impl From<Ambiguous> for CookieError {
    fn from(a: Ambiguous) -> Self {
        Self::Ambiguous(a)
    }
}

impl From<Rejected> for CookieError {
    fn from(r: Rejected) -> Self {
        Self::Rejected(r)
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

/// Why a signed or sealed cookie was refused.
///
/// Clients never learn the reason: treat every `Rejected` as "cookie absent"
/// and report the reason as an event.
///
/// | Variant | Most likely | `severity_hint` |
/// |---|---|---|
/// | `Malformed` | tampering or truncation | 10 |
/// | `UnsupportedVersion` | tampering, or a cookie from a newer deployment | 5 |
/// | `UnknownKey` | an old cookie after its key left the ring | 1 |
/// | `BadTag` | forgery, or a value moved between names or sessions | 40 |
/// | `Expired` | an old tab, or client clock games | 1 |
///
/// # Examples
///
/// ```
/// use cookie_net::Rejected;
///
/// assert_eq!(Rejected::BadTag.severity_hint(), 40);
/// assert_eq!(Rejected::Expired.code(), "expired");
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Rejected {
    /// Wrong length, bad base64url, or a non-canonical encoding.
    Malformed,
    /// A format version this build does not know.
    UnsupportedVersion,
    /// The key id is not in the ring, or its retire time has passed.
    UnknownKey,
    /// Forged, altered, moved from another cookie name, or bound to another
    /// session.
    BadTag,
    /// The embedded expiry has passed (plus the skew allowance).
    Expired,
}

impl Rejected {
    /// A stable snake_case identifier for metrics and events.
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(cookie_net::Rejected::UnknownKey.code(), "unknown_key");
    /// ```
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Malformed => "malformed",
            Self::UnsupportedVersion => "unsupported_version",
            Self::UnknownKey => "unknown_key",
            Self::BadTag => "bad_tag",
            Self::Expired => "expired",
        }
    }

    /// A suggested severity, 0 to 40, higher is worse (the scale WASP's gates
    /// use).
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(cookie_net::Rejected::Malformed.severity_hint(), 10);
    /// ```
    #[must_use]
    pub const fn severity_hint(self) -> u8 {
        match self {
            Self::Malformed => 10,
            Self::UnsupportedVersion => 5,
            Self::UnknownKey | Self::Expired => 1,
            Self::BadTag => 40,
        }
    }
}

impl fmt::Display for Rejected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Malformed => "signed cookie refused: malformed",
            Self::UnsupportedVersion => "signed cookie refused: unsupported version",
            Self::UnknownKey => "signed cookie refused: unknown key",
            Self::BadTag => "signed cookie refused: bad tag",
            Self::Expired => "signed cookie refused: expired",
        })
    }
}

impl core::error::Error for Rejected {}

/// A byte offset as the `u16` the error variants carry.
pub(crate) fn at(offset: usize) -> u16 {
    u16::try_from(offset).unwrap_or(u16::MAX)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use std::{collections::BTreeSet, string::ToString};

    use super::*;

    const ALL: [CookieError; 34] = [
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
        CookieError::WeakKey,
        CookieError::KeyTooShort,
        CookieError::ContextTooLong,
        CookieError::DuplicateKeyId,
        CookieError::RingFull,
        CookieError::InvalidRetireTime,
        CookieError::Crypto,
        CookieError::Rejected(Rejected::Malformed),
        CookieError::Rejected(Rejected::UnsupportedVersion),
        CookieError::Rejected(Rejected::UnknownKey),
        CookieError::Rejected(Rejected::BadTag),
        CookieError::Rejected(Rejected::Expired),
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
    fn test_rejected_codes_and_severity() {
        let all = [
            Rejected::Malformed,
            Rejected::UnsupportedVersion,
            Rejected::UnknownKey,
            Rejected::BadTag,
            Rejected::Expired,
        ];
        let sev: std::vec::Vec<u8> = all.iter().map(|r| r.severity_hint()).collect();
        assert_eq!(sev, [10, 5, 1, 40, 1]);
        for r in all {
            assert_eq!(
                CookieError::from(r).code(),
                std::format!("rejected.{}", r.code())
            );
            assert!(r.to_string().starts_with("signed cookie refused"));
        }
    }

    #[test]
    fn test_at_saturates() {
        assert_eq!(at(5), 5);
        assert_eq!(at(70_000), u16::MAX);
    }
}
