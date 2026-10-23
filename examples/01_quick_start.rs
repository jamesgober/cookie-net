//! Reading the `Cookie` header and writing `Set-Cookie`: the README quick
//! start. Run with `cargo run --example 01_quick_start`.

use cookie_net::{self as cookie, CookieError, Limits, Lookup, SameSite, SetCookie};

fn main() -> Result<(), CookieError> {
    // Reading: the credential, a preference
    let header = "__Host-sid=Zk3J9qL0wX7aP2mT8sV1cR5dY4hN6bE0uK9gF3jQ2oA; theme=dark";
    let sid = cookie::get_unique(header, "__Host-sid")?;
    let theme = cookie::get(header, "theme").unwrap_or("light");
    println!("signed in: {}, theme: {theme}", sid.is_some());

    // Writing
    let set = SetCookie::new("theme", "dark")?;
    assert_eq!(
        set.encode(),
        "theme=dark; Path=/; Secure; HttpOnly; SameSite=Lax"
    );
    println!("Set-Cookie: {}", set.encode());

    // The credential locator
    let found = cookie::locate(
        "sid=planted; __Host-sid=t0k3n",
        "__Host-sid",
        &Limits::DEFAULT,
    );
    assert_eq!(found.lookup, Lookup::One("t0k3n"));
    assert_eq!((found.shadows, found.severity_hint()), (1, 5));
    println!("shadow names beside the credential: {}", found.shadows);

    // Rules that cannot be broken
    assert_eq!(
        SetCookie::new("pref", "1; Domain=evil.example").unwrap_err(),
        CookieError::InvalidValue { at: 1 }
    );
    assert_eq!(
        SetCookie::builder("__Host-sid", "x")
            .domain("example.com")
            .build()
            .unwrap_err(),
        CookieError::HostPrefix
    );
    assert_eq!(
        SetCookie::builder("embed", "1")
            .same_site(SameSite::None)
            .insecure()
            .build()
            .unwrap_err(),
        CookieError::SameSiteNoneNeedsSecure
    );
    Ok(())
}
