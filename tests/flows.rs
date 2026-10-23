//! WASP-shaped flows: login sets `__Host-sid`, each request locates it, a
//! roll replaces it, logout deletes it; csrf-sec's expectations of the session
//! cookie; HTTP/2 crumbs.

use cookie_net::{self as cookie, Cookies, Limits, Lookup, SameSite, SetCookie};
use parse_net::SliceSink;

/// The `Set-Cookie` value, without needing the `alloc` feature.
fn text(set: &SetCookie<'_>) -> String {
    let mut buf = [0u8; 1024];
    String::from(set.encode_into(&mut buf).unwrap())
}

/// What a browser sends back for one `Set-Cookie` it accepted: `name=value`.
fn stored(set: &SetCookie<'_>) -> String {
    format!("{}={}", set.name(), set.value())
}

#[test]
fn test_login_request_roll_logout() {
    let token = "Zk3J9qL0wX7aP2mT8sV1cR5dY4hN6bE0uK9gF3jQ2oA";
    let login = cookie::session_cookie("__Host-sid", token, 12 * cookie::HOUR).unwrap();
    assert_eq!(
        text(&login),
        format!("__Host-sid={token}; Path=/; Max-Age=43200; Secure; HttpOnly; SameSite=Lax")
    );

    // the next request carries it with other cookies
    let header = format!("theme=dark; {}; _ga=GA1.2.3", stored(&login));
    let found = cookie::locate(&header, "__Host-sid", &Limits::DEFAULT);
    assert_eq!(found.lookup, Lookup::One(token));
    assert_eq!(found.severity_hint(), 0);

    // a token roll replaces the value under the same name and attributes
    let rolled = "pX4vB8nM2kL6qW0eR9tY3uI7oP5aS1dFgH8jK2lZ4x";
    let roll = cookie::session_cookie("__Host-sid", rolled, 12 * cookie::HOUR).unwrap();
    assert_eq!(
        (roll.path(), roll.domain(), roll.same_site()),
        (login.path(), login.domain(), login.same_site())
    );

    // logout: the deletion matches the cookie it removes
    let logout = SetCookie::delete("__Host-sid").unwrap();
    assert_eq!(
        (logout.name(), logout.path(), logout.domain()),
        ("__Host-sid", "/", None)
    );
    assert!(logout.is_secure());
    assert!(text(&logout).contains("Expires=Thu, 01 Jan 1970 00:00:00 GMT"));

    // a request after logout without the cookie is a guest
    assert_eq!(
        cookie::locate("theme=dark", "__Host-sid", &Limits::DEFAULT).lookup,
        Lookup::Missing
    );
}

#[test]
fn test_elevation_then_expiry_by_deletion() {
    let sudo = cookie::elevated_cookie(
        "__Host-sudo",
        "pX4vB8nM2kL6qW0eR9tY3uI7oP5aS1dF",
        10 * cookie::MINUTE,
    )
    .unwrap();
    assert_eq!(sudo.same_site(), SameSite::Strict);
    let header = format!(
        "__Host-sid=Zk3J9qL0wX7aP2mT8sV1cR5dY4hN6bE0uK9gF3jQ2oA; {}",
        stored(&sudo)
    );
    let cookies = cookie::parse(&header);
    assert!(cookies.get_unique("__Host-sudo").unwrap().is_some());
    assert!(cookies.get_unique("__Host-sid").unwrap().is_some());
    assert!(SetCookie::delete("__Host-sudo").unwrap().is_deletion());
}

/// csrf-sec's third layer relies on the session cookie being `__Host-` and
/// `SameSite=Lax` or stricter, and there is no CSRF cookie to compare tokens
/// with.
#[test]
fn test_csrf_layer_three_expectations() {
    let c = cookie::session_cookie(
        "__Host-sid",
        "Zk3J9qL0wX7aP2mT8sV1cR5dY4hN6bE0uK9gF3jQ2oA",
        cookie::HOUR,
    )
    .unwrap();
    assert_eq!(cookie::Prefix::of(c.name()), cookie::Prefix::Host);
    assert!(matches!(c.same_site(), SameSite::Lax | SameSite::Strict));
    assert!(c.is_http_only());
}

#[test]
fn test_http2_crumbs_read_as_one_header() {
    let lines: Vec<&[u8]> = vec![
        b"__Host-sid=Zk3J9qL0wX7aP2mT8sV1cR5dY4hN6bE0uK9gF3jQ2oA",
        b"theme=dark",
        b"lang=fr",
    ];
    let cookies = Cookies::from_lines(&lines, &Limits::DEFAULT).unwrap();
    assert!(cookies.get_unique("__Host-sid").unwrap().is_some());
    assert_eq!(cookies.get("lang"), Some("fr"));
    // a crumb that duplicates the credential is still caught
    let lines: Vec<&[u8]> = vec![b"__Host-sid=a", b"__Host-sid=b"];
    let cookies = Cookies::from_lines(&lines, &Limits::DEFAULT).unwrap();
    assert!(matches!(
        cookies.locate("__Host-sid").lookup,
        Lookup::Many { count: 2, .. }
    ));
}

#[test]
fn test_writing_many_set_cookie_lines_into_one_buffer() {
    let cookies = [
        SetCookie::new("theme", "dark").unwrap(),
        SetCookie::builder("lang", "fr")
            .max_age(365 * cookie::DAY)
            .build()
            .unwrap(),
        SetCookie::delete("flash").unwrap(),
    ];
    let mut buf = [0u8; 512];
    let mut out = SliceSink::new(&mut buf);
    let mut total = 0;
    for c in &cookies {
        c.write_to(&mut out).unwrap();
        total += c.encoded_len();
        parse_net::Sink::put(&mut out, b"\n").unwrap();
        total += 1;
    }
    assert_eq!(out.len(), total);
    let text = core::str::from_utf8(out.written()).unwrap();
    assert_eq!(text.lines().count(), 3);
}
