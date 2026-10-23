//! # cookie_net
//!
//! HTTP cookies for Rust (RFC 6265bis): strict parsing of `Cookie` headers,
//! `Set-Cookie` writing that refuses invalid cookies, secure defaults, the
//! `__Host-` and `__Secure-` prefixes, `SameSite`, `Partitioned`, signed and
//! encrypted cookies with key rotation, session-cookie helpers, and a client
//! cookie jar.
//!
//! ## Status
//!
//! Design lock (`0.2.0`). The public API from `0.3.0` to `1.0.0` is written
//! down in `docs/API.md`, the reasons in `dev/PLAN.md`, and the schedule in
//! `dev/ROADMAP.md` (all in the
//! [repository](https://github.com/jamesgober/cookie-net)). This release
//! declares the feature flags; the code arrives with `0.3.0`.

#![doc(html_root_url = "https://docs.rs/cookie-net")]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

/// Crate version string, populated by Cargo at build time.
///
/// # Examples
///
/// ```
/// assert_eq!(cookie_net::VERSION.split('.').count(), 3);
/// ```
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::VERSION;

    #[test]
    fn test_version_matches_manifest() {
        assert_eq!(VERSION, env!("CARGO_PKG_VERSION"));
        assert_eq!(VERSION.split('.').count(), 3, "expected MAJOR.MINOR.PATCH");
    }
}
