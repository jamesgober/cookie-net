//! The client side: parsing `Set-Cookie` as a user agent does, the
//! cookie-date algorithm (feature `client`), and the cookie jar (feature
//! `jar`).

pub(crate) mod date;
#[cfg(feature = "jar")]
pub(crate) mod jar;
pub(crate) mod set_cookie;
