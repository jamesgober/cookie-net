//! WASP-style session cookies: login, a request, sudo mode, logout. Run with
//! `cargo run --example 02_sessions`.

use cookie_net::{self as cookie, CookieError, Limits, Lookup, SetCookie};

fn main() -> Result<(), CookieError> {
    // gate-net issues the token: 32 random bytes, base64url
    let token = "Zk3J9qL0wX7aP2mT8sV1cR5dY4hN6bE0uK9gF3jQ2oA";

    let login = cookie::session_cookie("__Host-sid", token, 12 * cookie::HOUR)?;
    // printed here to show the bytes; a server sends them to the client, never to a log
    println!("login   Set-Cookie: {}", login.encode());

    // the next request; the gateway's credential locator
    let request = format!("theme=dark; __Host-sid={token}");
    match cookie::locate(&request, "__Host-sid", &Limits::DEFAULT).lookup {
        Lookup::One(t) => println!("request  session token of {} bytes", t.len()),
        _ => println!("request  guest"),
    }

    let sudo = cookie::elevated_cookie(
        "__Host-sudo",
        "pX4vB8nM2kL6qW0eR9tY3uI7oP5aS1dF",
        10 * cookie::MINUTE,
    )?;
    println!("sudo    Set-Cookie: {}", sudo.encode());

    // logout: revoke on the server first, then clear both cookies
    for name in ["__Host-sid", "__Host-sudo"] {
        println!("logout  Set-Cookie: {}", SetCookie::delete(name)?.encode());
    }
    Ok(())
}
