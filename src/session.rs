//! Session cookies: [`session_cookie`] for `__Host-sid` and
//! [`elevated_cookie`] for `__Host-sudo`.
//!
//! Session tokens are opaque random values the server looks up, so these
//! cookies are neither signed nor encrypted: nothing in them needs
//! protecting, and the server record is the truth. The `__Host-` prefix makes
//! them host-only, `Secure`, and `Path=/`, so a sibling subdomain cannot set
//! or overwrite them. To end a session, revoke it on the server, then send
//! [`SetCookie::delete`].

use crate::{
    error::CookieError,
    name::{self, Prefix},
    response::{SameSite, SetCookie},
};

/// The value of a `Clear-Site-Data` response header that tells the browser
/// to drop every cookie for the site (W3C Clear Site Data). It is the
/// recovery for cookie bombing: when the credential lookup reports
/// `Truncated` or `HeaderTooLong`, answer with this header and the user can
/// sign in again; the server-side session is not affected. The caller
/// decides when to send it.
///
/// # Examples
///
/// ```
/// use cookie_net::{self as cookie, Ambiguous};
///
/// let bombed = "x=".to_string() + &"y".repeat(9000);
/// if let Err(Ambiguous::Truncated | Ambiguous::HeaderTooLong) = cookie::get_unique(&bombed, "__Host-sid") {
///     assert_eq!(cookie::CLEAR_SITE_DATA_COOKIES, "\"cookies\"");
/// }
/// ```
pub const CLEAR_SITE_DATA_COOKIES: &str = "\"cookies\"";

/// The shortest session token accepted: 22 base64url characters are 128 bits.
const MIN_TOKEN: usize = 22;
/// The elevated cookie's lifetime bounds, in seconds.
const ELEVATED_MIN: u64 = 60;
const ELEVATED_MAX: u64 = 3_600;

/// The `Set-Cookie` for a session token: `Secure; HttpOnly; SameSite=Lax;
/// Path=/`, host-only, `Max-Age=max_age`.
///
/// Issue a new token at every login (session fixation defence) and at every
/// roll. For a browser-session cookie with no `Max-Age`,
/// `SetCookie::new("__Host-sid", token)` has the same attributes.
///
/// # Errors
///
/// `EmptyName` or `InvalidName` for a bad name; `HostPrefix` when the name
/// does not start with `__Host-`; `TokenTooShort` for a token under 22
/// bytes; `InvalidValue` when the token is not `cookie-octet`s; `TooLarge`;
/// `MaxAgeOutOfRange` outside 1 to [`MAX_LIFETIME`](crate::MAX_LIFETIME).
///
/// # Examples
///
/// ```
/// use cookie_net as cookie;
///
/// # #[cfg(feature = "alloc")] {
/// let token = "Zk3J9qL0wX7aP2mT8sV1cR5dY4hN6bE0uK9gF3jQ2oA";
/// let set = cookie::session_cookie("__Host-sid", token, 12 * cookie::HOUR)?;
/// assert_eq!(set.encode(), format!("__Host-sid={token}; Path=/; Max-Age=43200; Secure; HttpOnly; SameSite=Lax"));
/// assert_eq!(cookie::session_cookie("sid", token, cookie::HOUR).unwrap_err(), cookie::CookieError::HostPrefix);
/// assert_eq!(cookie::session_cookie("__Host-sid", "42", cookie::HOUR).unwrap_err(), cookie::CookieError::TokenTooShort);
/// # }
/// # Ok::<(), cookie::CookieError>(())
/// ```
pub fn session_cookie<'a>(
    name: &'a str,
    token: &'a str,
    max_age: u64,
) -> Result<SetCookie<'a>, CookieError> {
    checked(name, token)?;
    SetCookie::builder(name, token).max_age(max_age).build()
}

/// The `Set-Cookie` for an elevated (sudo-mode) token: as
/// [`session_cookie`] with `SameSite=Strict`, so an elevated action never
/// starts from another site, and a lifetime of 60 to 3600 seconds.
///
/// `Path=/` is forced by the `__Host-` prefix. Paths do not isolate cookies
/// anyway (RFC 6265 section 8.5), and the prefix blocks subdomain tossing,
/// which a path cannot.
///
/// # Errors
///
/// As [`session_cookie`], with `MaxAgeOutOfRange` outside 60 to 3600.
///
/// # Examples
///
/// ```
/// use cookie_net as cookie;
///
/// # #[cfg(feature = "alloc")] {
/// let sudo = cookie::elevated_cookie("__Host-sudo", "pX4vB8nM2kL6qW0eR9tY3uI7oP5aS1dF", 10 * cookie::MINUTE)?;
/// assert!(sudo.encode().ends_with("Max-Age=600; Secure; HttpOnly; SameSite=Strict"));
/// assert!(cookie::elevated_cookie("__Host-sudo", "pX4vB8nM2kL6qW0eR9tY3uI7oP5aS1dF", 2 * cookie::HOUR).is_err());
/// # }
/// # Ok::<(), cookie::CookieError>(())
/// ```
pub fn elevated_cookie<'a>(
    name: &'a str,
    token: &'a str,
    max_age: u64,
) -> Result<SetCookie<'a>, CookieError> {
    checked(name, token)?;
    if !(ELEVATED_MIN..=ELEVATED_MAX).contains(&max_age) {
        return Err(CookieError::MaxAgeOutOfRange);
    }
    SetCookie::builder(name, token)
        .max_age(max_age)
        .same_site(SameSite::Strict)
        .build()
}

fn checked(name: &str, token: &str) -> Result<(), CookieError> {
    let n = name.as_bytes();
    if n.is_empty() {
        return Err(CookieError::EmptyName);
    }
    if let Some(i) = name::first_non_tchar(n) {
        return Err(CookieError::InvalidName {
            at: crate::error::at(i),
        });
    }
    if name::of_bytes(n) != Prefix::Host {
        return Err(CookieError::HostPrefix);
    }
    if token.len() < MIN_TOKEN {
        return Err(CookieError::TokenTooShort);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{HOUR, MAX_LIFETIME, MINUTE};

    const TOKEN: &str = "Zk3J9qL0wX7aP2mT8sV1cR5dY4hN6bE0uK9gF3jQ2oA";

    #[test]
    fn test_session_cookie_attributes_fixed() {
        let c = session_cookie("__Host-sid", TOKEN, 12 * HOUR).unwrap();
        assert!(c.is_secure() && c.is_http_only());
        assert_eq!(
            (c.same_site(), c.path(), c.domain(), c.max_age()),
            (SameSite::Lax, "/", None, Some(43_200))
        );
    }

    #[test]
    fn test_session_cookie_refusals() {
        assert_eq!(
            session_cookie("", TOKEN, HOUR).unwrap_err(),
            CookieError::EmptyName
        );
        assert_eq!(
            session_cookie("a b", TOKEN, HOUR).unwrap_err(),
            CookieError::InvalidName { at: 1 }
        );
        assert_eq!(
            session_cookie("sid", TOKEN, HOUR).unwrap_err(),
            CookieError::HostPrefix
        );
        assert_eq!(
            session_cookie("__Secure-sid", TOKEN, HOUR).unwrap_err(),
            CookieError::HostPrefix
        );
        assert_eq!(
            session_cookie("__Host-sid", "", HOUR).unwrap_err(),
            CookieError::TokenTooShort
        );
        assert_eq!(
            session_cookie("__Host-sid", &TOKEN[..21], HOUR).unwrap_err(),
            CookieError::TokenTooShort
        );
        assert!(session_cookie("__Host-sid", &TOKEN[..22], HOUR).is_ok());
        assert_eq!(
            session_cookie("__Host-sid", "aaaaaaaaaaaaaaaaaaaaa b", HOUR).unwrap_err(),
            CookieError::InvalidValue { at: 21 }
        );
        assert_eq!(
            session_cookie("__Host-sid", TOKEN, 0).unwrap_err(),
            CookieError::MaxAgeOutOfRange
        );
        assert_eq!(
            session_cookie("__Host-sid", TOKEN, MAX_LIFETIME + 1).unwrap_err(),
            CookieError::MaxAgeOutOfRange
        );
        assert!(session_cookie("__host-sid", TOKEN, HOUR).is_ok());
    }

    #[test]
    fn test_elevated_cookie_strict_and_bounded() {
        let c = elevated_cookie("__Host-sudo", TOKEN, 10 * MINUTE).unwrap();
        assert_eq!(
            (c.same_site(), c.path(), c.max_age()),
            (SameSite::Strict, "/", Some(600))
        );
        assert!(elevated_cookie("__Host-sudo", TOKEN, 60).is_ok());
        assert!(elevated_cookie("__Host-sudo", TOKEN, 3600).is_ok());
        assert_eq!(
            elevated_cookie("__Host-sudo", TOKEN, 59).unwrap_err(),
            CookieError::MaxAgeOutOfRange
        );
        assert_eq!(
            elevated_cookie("__Host-sudo", TOKEN, 3601).unwrap_err(),
            CookieError::MaxAgeOutOfRange
        );
        assert_eq!(
            elevated_cookie("sudo", TOKEN, 600).unwrap_err(),
            CookieError::HostPrefix
        );
        assert_eq!(
            elevated_cookie("__Host-sudo", "short", 600).unwrap_err(),
            CookieError::TokenTooShort
        );
    }

    #[test]
    fn test_session_deletion_satisfies_host_prefix() {
        let c = SetCookie::delete("__Host-sid").unwrap();
        assert!(c.is_secure() && c.path() == "/" && c.domain().is_none());
    }
}
