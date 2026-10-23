//! An outbound client's cookie jar: store what servers set, send what
//! applies, persist across restarts. Run with
//! `cargo run --example 04_client_jar --features jar`.

use cookie_net::{CookieError, IgnoreReason, Jar, RequestUrl, StoreOutcome, parse_set_cookie};

fn main() -> Result<(), CookieError> {
    let now = 1_800_000_000;
    let mut jar = Jar::new();

    // a login response sets a session cookie and a tracker for the whole TLD
    let login = RequestUrl::https("api.example.com", "/oauth/token");
    let responses = [
        "sid=Zk3J9qL0wX7aP2mT8sV1cR5dY4hN6bE0; Path=/; Secure; HttpOnly; SameSite=Lax",
        "tracker=1; Domain=com",
        "prefs=compact; Max-Age=3600",
    ];
    for line in responses {
        let outcome = jar.store(&login, line, now);
        let name = parse_set_cookie(line).map(|v| String::from_utf8_lossy(v.name).into_owned());
        println!("{:<8} {outcome:?}", name.unwrap_or_default());
    }
    assert_eq!(
        jar.store(&login, "tracker=1; Domain=com", now),
        StoreOutcome::Ignored(IgnoreReason::DomainNotAllowed)
    );

    // the next request gets the cookies that apply, longest path first
    let orders = RequestUrl::https("api.example.com", "/v1/orders");
    let header = jar.cookie_header(&orders, now).unwrap_or_default();
    println!(
        "Cookie: {} cookies, {} bytes",
        header.split("; ").count(),
        header.len()
    );

    // plain HTTP never gets the Secure session cookie
    assert!(
        jar.cookie_header(&RequestUrl::http("api.example.com", "/"), now)
            .is_none_or(|h| !h.contains("sid="))
    );

    // persist and restore (the bytes hold the session: store them as a secret)
    let saved = jar.export();
    let mut restored = Jar::new();
    restored.import(&saved, now + 10)?;
    assert_eq!(
        restored.cookie_header(&orders, now + 10),
        jar.cookie_header(&orders, now + 10)
    );
    println!(
        "restored {} cookies from {} bytes",
        restored.len(),
        saved.len()
    );
    Ok(())
}
