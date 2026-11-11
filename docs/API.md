<h1 align="center">
        <img width="99" alt="Rust logo" src="https://raw.githubusercontent.com/jamesgober/rust-collection/72baabd71f00e14aa9184efcb16fa3deddda3a0a/assets/rust-logo.svg">
    <br><b>cookie-net</b><br>
    <sub><sup>API REFERENCE</sup></sub>
</h1>
<div align="center">
    <sup>
        <a href="../README.md" title="Project Home"><b>HOME</b></a>
        <span>&nbsp;│&nbsp;</span>
        <span>API</span>
        <span>&nbsp;│&nbsp;</span>
        <a href="./COOKIES.md" title="Which cookie, when"><b>COOKIES</b></a>
        <span>&nbsp;│&nbsp;</span>
        <a href="./FORMATS.md" title="Formats"><b>FORMATS</b></a>
        <span>&nbsp;│&nbsp;</span>
        <a href="./SECURITY.md" title="Security"><b>SECURITY</b></a>
    </sup>
</div>
<br>

A task-oriented tour of the 0.8 API. The rustdoc on
[docs.rs](https://docs.rs/cookie-net) is the exhaustive reference; every
example here is compiled and run as a doctest with all features enabled.
Examples write `use cookie_net as cookie;` and call `cookie::get(..)`.

- [Setup](#setup)
  - [Features](#features)
  - [Conventions](#conventions)
- [The one-line calls](#the-one-line-calls)
- [Reading the `Cookie` header](#reading-the-cookie-header)
  - [`get`, `get_unique`, `get_all`](#get-get_unique-get_all)
  - [`parse` and `Cookies`](#parse-and-cookies)
  - [`Pair`](#pair)
  - [`Stats`](#stats)
  - [The credential locator: `locate`](#the-credential-locator-locate)
  - [`Prefix`](#prefix)
  - [`Limits` and `ValueMode`](#limits-and-valuemode)
  - [HTTP/2 cookie crumbs](#http2-cookie-crumbs)
  - [How a header is read](#how-a-header-is-read)
- [Writing `Set-Cookie`](#writing-set-cookie)
  - [`SetCookie`](#setcookie)
  - [`SetCookieBuilder`](#setcookiebuilder)
  - [`SameSite`](#samesite)
  - [Rules checked by `build`](#rules-checked-by-build)
  - [Serialization](#serialization)
- [Session cookies](#session-cookies)
  - [`session_cookie` and `elevated_cookie`](#session_cookie-and-elevated_cookie)
  - [Ending a session](#ending-a-session)
  - [Lifetimes and `CLEAR_SITE_DATA_COOKIES`](#lifetimes-and-clear_site_data_cookies)
- [Keys](#keys)
  - [`Key`](#key)
  - [`KeyRing`](#keyring)
  - [Rotating keys across a cluster](#rotating-keys-across-a-cluster)
- [Signed cookies: `Signer`](#signed-cookies-signer)
- [Encrypted cookies: `Sealer`](#encrypted-cookies-sealer)
- [Refused cookies: `Rejected`](#refused-cookies-rejected)
- [Client side](#client-side)
  - [`parse_set_cookie`](#parse_set_cookie)
  - [`cookie_date`](#cookie_date)
- [The cookie jar](#the-cookie-jar)
  - [`Jar`](#jar)
  - [`RequestUrl` and `RequestContext`](#requesturl-and-requestcontext)
  - [Public suffixes](#public-suffixes)
  - [`JarLimits`](#jarlimits)
  - [`StoreOutcome` and `IgnoreReason`](#storeoutcome-and-ignorereason)
  - [Storage, export, and import](#storage-export-and-import)
- [Errors](#errors)
  - [`CookieError`](#cookieerror)
  - [`Ambiguous`](#ambiguous)
- [Thread safety and sizes](#thread-safety-and-sizes)
- [Migrating from 0.7](#migrating-from-07)
- [Examples in the repository](#examples-in-the-repository)

## Setup

```toml
[dependencies]
cookie-net = "0.8"
# signed and encrypted cookies:
# cookie-net = { version = "0.8", features = ["signed", "encrypted"] }
# an outbound client:
# cookie-net = { version = "0.8", features = ["jar"] }
# no_std, no allocator:
# cookie-net = { version = "0.8", default-features = false }
```

### Features

| Feature | Default | Adds | Needs |
|---|---|---|---|
| (none) | | reading `Cookie`, writing `Set-Cookie` into a buffer, the session helpers, errors, limits | parse-net only; `no_std`, no allocator |
| `alloc` | through `std` | `SetCookie::encode` and the `String`-returning `sign*` and `seal*` functions | an allocator |
| `std` | **yes** | `verify_now` and `open_now`, which read the system clock; implies `alloc` | `std` |
| `signed` | no | `Key`, `KeyRing`, `Signer`, and their types | crypt-io; an allocator, because crypt-io links `alloc` (cookie-net's signing code allocates nothing) |
| `encrypted` | no | `Sealer`, `Plaintext`, `Opened`; implies `signed` and `std` | crypt-io and the OS random source |
| `client` | no | `parse_set_cookie`, `SetCookieView`, `cookie_date` | nothing more (`no_std`, no allocator) |
| `jar` | no | `Jar` and its types; implies `client` and `alloc` | crypt-io (hashing only, for the export checksum) |

### Conventions

- **Header input** is one `Cookie` field value without its name, as anything `AsRef<[u8]>`: `&str`, `&[u8]`, `&String`, `&Vec<u8>`. Leading and trailing spaces and tabs are ignored.
- **Names and values come back as `&str`** borrowed from the header. Names are compared byte for byte: no case folding, no percent-decoding, no Unicode trimming, so `__HOST-sid` and `%5F_Host-sid` are never `__Host-sid`.
- **Quotes are part of a value**: `a="1"` has the three-byte value `"1"` (rfc6265bis section 4.1.1). `Pair::value_unquoted` removes one surrounding pair.
- **Time** is whole seconds since the Unix epoch as `u64`, passed in by the caller; the crate never reads a clock except in `verify_now` and `open_now`. Only `cookie_date` returns `i64`, because the cookie-date algorithm accepts years back to 1601.
- **Writing** goes into a [`parse_net::Sink`](https://docs.rs/parse-net/latest/parse_net/trait.Sink.html): a `parse_net::SliceSink` over a stack buffer, a `Vec<u8>`, or a type of yours. A `SetCookie` that exists is valid, so writing it fails only with `CookieError::Full`.
- **Secrets never print.** `Debug` on every type that holds a cookie value or a key shows names, lengths, and attributes, never value or key bytes. No value type implements `Display`. Errors carry byte offsets and fixed text, never input bytes.

## The one-line calls

Most code needs only these. Each is one call with no configuration.

```rust
use cookie_net::{self as cookie, Sealer, SetCookie, Signer};

let header = "__Host-sid=Zk3J9qL0wX7aP2mT8sV1cR5dY4hN6bE0uK9gF3jQ2oA; theme=dark";

// Reading
let sid = cookie::get_unique(header, "__Host-sid")?;      // Option<&str>; Err when planted twice
let theme = cookie::get(header, "theme").unwrap_or("light");
for pair in cookie::parse(header) {
    println!("{} ({} bytes)", pair.name(), pair.value().len());   // never log the value
}

// Writing
let prefs = SetCookie::new("theme", "dark")?;              // Secure; HttpOnly; SameSite=Lax; Path=/
let token = sid.unwrap();
let login = cookie::session_cookie("__Host-sid", token, 12 * cookie::HOUR)?;
let logout = SetCookie::delete("__Host-sid")?;
let line: String = prefs.encode();                         // the Set-Cookie field value

// Signed and encrypted (features `signed` and `encrypted`)
let now = 1_800_000_000;
let signer = Signer::new(*b"an example key, 32 bytes long!!!")?;
let value = signer.sign("prefs", "lang=fr")?;              // readable, tamper-evident
assert_eq!(signer.verify("prefs", &value, now)?, "lang=fr");
let sealer = Sealer::new(*b"another example key, 32 bytes!!!")?;
let flash = sealer.seal_until("flash", "Saved.", now + 5 * cookie::MINUTE)?;
assert_eq!(sealer.open("flash", &flash, now)?.as_str(), Some("Saved."));
# let _ = (theme, login, logout, line);
# Ok::<(), cookie::CookieError>(())
```

Everything below is the next layer: configuration and richer results first, then the allocation-free calls other libraries build on.

## Reading the `Cookie` header

### `get`, `get_unique`, `get_all`

| Function | Returns | Use it for |
|---|---|---|
| `get(header, name)` | `Option<&str>`: the first pair named `name` | preferences, where a duplicate does no harm; stops at the first match |
| `get_unique(header, name)` | `Result<Option<&str>, Ambiguous>`: the only pair named `name` | every credential: scans the whole header, and refuses duplicates, a header cut short by the pair limit, and an over-long header |
| `get_all(header, name)` | `GetAll`, an iterator of `&str` in header order | a name that legitimately repeats (one name set on several paths) |

The header's order is the browser's (longer paths first, then older cookies), but rfc6265bis section 4.2.2 says servers should not rely on it. A `__Host-` name can exist only once per host, so a duplicate of one is a planted cookie, never a glitch.

```rust
use cookie_net::{self as cookie, Ambiguous};

assert_eq!(cookie::get("theme=dark; lang=fr", "lang"), Some("fr"));
assert_eq!(cookie::get("Theme=dark", "theme"), None);             // names are case-sensitive
assert_eq!(cookie::get("a=\"1\"", "a"), Some("\"1\""));          // quotes are part of the value

assert_eq!(cookie::get_unique("__Host-sid=t0k3n; theme=dark", "__Host-sid"), Ok(Some("t0k3n")));
// a sibling subdomain planted `sid`: a different name, so no effect
assert_eq!(cookie::get_unique("sid=evil; __Host-sid=t0k3n", "__Host-sid"), Ok(Some("t0k3n")));
// two values for one `__Host-` name can only be an attack
assert_eq!(
    cookie::get_unique("__Host-sid=a; __Host-sid=b", "__Host-sid"),
    Err(Ambiguous::Duplicate { count: 2 })
);
assert_eq!(cookie::get_unique("theme=dark", "__Host-sid"), Ok(None));

let carts: Vec<&str> = cookie::get_all("cart=2; theme=dark; cart=1", "cart").collect();
assert_eq!(carts, ["2", "1"]);
```

### `parse` and `Cookies`

`parse(header)` returns `Cookies`, a small `Copy` view of the header and the limits to read it with. Nothing is stored or allocated; each call re-scans the header, which costs less than keeping spans for the usual handful of pairs. `parse` never fails: a header over the length limit yields no pairs, and pairs that break the grammar are skipped and counted (one stale cookie must not lock a user out).

| Item | Does |
|---|---|
| `parse(header)` | every pair, with `Limits::DEFAULT` |
| `Cookies::with_limits(header, &limits)` | the same with your limits; `Err(HeaderTooLong)` before scanning anything |
| `Cookies::from_lines(&lines, &limits)` | several `Cookie` field lines read as one header ([HTTP/2 crumbs](#http2-cookie-crumbs)) |
| `.iter()`, `for pair in cookies` | the accepted pairs ([`Pair`](#pair)) in header order |
| `.get(name)`, `.get_unique(name)`, `.get_all(name)` | as the free functions |
| `.locate(name)` | the [credential locator](#the-credential-locator-locate) |
| `.stats()` | [`Stats`](#stats) for the whole header |
| `.scan(f)` | one pass calling `f` for each pair; `ControlFlow::Break(())` stops early; returns `Stats` for the pairs seen |
| `.is_empty()` | no accepted pair |

`Debug` on `Cookies` shows the names and whether the header was too long, never the values.

```rust
use cookie_net as cookie;

let names: Vec<&str> = cookie::parse("a=1; bad name=2; b=").iter().map(|p| p.name()).collect();
assert_eq!(names, ["a", "b"]);
assert_eq!(cookie::parse("a=1; bad name=2; b=").stats().skipped, 1);
assert!(cookie::parse("; =x").is_empty());
```

```rust
use core::ops::ControlFlow;
use cookie_net as cookie;

let mut analytics = 0;
let stats = cookie::parse("_ga=1; _gid=2; sid=x").scan(|pair| {
    if pair.name().starts_with('_') {
        analytics += 1;
    }
    ControlFlow::Continue(())
});
assert_eq!((analytics, stats.pairs), (2, 3));
```

### `Pair`

One accepted pair, borrowed from the header.

| Method | Returns |
|---|---|
| `name()` | the name |
| `value()` | the value, quotes included when present |
| `value_unquoted()` | the value without one surrounding pair of `"` |
| `prefix()` | the name's [`Prefix`](#prefix) |

```rust
use cookie_net::{self as cookie, Prefix};

let pair = cookie::parse("__Host-sid=\"t0k3n\"").iter().next().unwrap();
assert_eq!((pair.name(), pair.value(), pair.value_unquoted()), ("__Host-sid", "\"t0k3n\"", "t0k3n"));
assert_eq!(pair.prefix(), Prefix::Host);
assert_eq!(format!("{pair:?}"), r#"Pair { name: "__Host-sid", value: 7 bytes }"#);
```

### `Stats`

Facts about a header for detection (customs-sec, sentinel-sec). Computing them is part of the scan, in linear time.

| Field | Counts |
|---|---|
| `pairs` | accepted pairs |
| `skipped` | pairs that broke the grammar or a length limit (not empty pairs) |
| `empty` | empty pairs: `;;`, or a leading or trailing `;` |
| `loose_separators` | `;` without one space after it, or with more whitespace |
| `prefixed_duplicates` | extra occurrences of `__Host-` or `__Secure-` names (the first 16 distinct names are tracked) |
| `truncated` | the scan stopped at `max_pairs` |
| `too_long` | the header was over `max_header_len`, so nothing was read |

```rust
use cookie_net as cookie;

let s = cookie::parse("a=1;b=2; ; bad name=3; __Host-x=1; __Host-x=2").stats();
assert_eq!((s.pairs, s.skipped, s.empty, s.loose_separators, s.prefixed_duplicates), (4, 1, 1, 1, 1));
```

### The credential locator: `locate`

`locate(header, name, &limits)` returns everything a gateway needs about one credential in one pass, with no allocation: `Located { lookup, shadows, stats }`. `get_unique` is `lookup` reduced to a `Result`.

| `Lookup` | Meaning |
|---|---|
| `Missing` | no pair has the name |
| `One(value)` | exactly one |
| `Many { first, count }` | two or more |
| `Truncated` | the pair limit cut the scan short, so a duplicate could hide past it |
| `HeaderTooLong` | over the length limit; nothing was read |

`shadows` counts pairs whose name is not `name` but equals it ignoring ASCII case, once a `__Host-` or `__Secure-` prefix is removed from either side. For `__Host-sid` that is `__host-sid`, `sid`, `SID`, `__Secure-sid`. cookie-net never sets those names, so seeing one is evidence of a cookie-tossing attempt or a prefix-bypass probe.

`severity_hint()` scores the result from 0 to 40, higher is worse, on the scale WASP's gates use: `One` or `Missing` 0; `Many` on a prefixed name 30, on another name 10; `Truncated` or `HeaderTooLong` 10; plus 5 when there are shadows, capped at 40.

```rust
use cookie_net::{self as cookie, Limits, Lookup};

let found = cookie::locate("sid=evil; __Host-sid=t0k3n", "__Host-sid", &Limits::DEFAULT);
assert_eq!(found.lookup, Lookup::One("t0k3n"));
assert_eq!(found.shadows, 1);
assert_eq!(found.severity_hint(), 5);

let planted = cookie::locate("__Host-sid=a; __Host-sid=b", "__Host-sid", &Limits::DEFAULT);
assert_eq!(planted.lookup, Lookup::Many { first: "a", count: 2 });
assert_eq!(planted.severity_hint(), 30);
```

A gateway answers every result other than `One` as signed out:

```rust
use cookie_net::{self as cookie, Limits, Lookup};

fn session_token(cookie_header: Option<&[u8]>) -> Option<&str> {
    let found = cookie::locate(cookie_header?, "__Host-sid", &Limits::DEFAULT);
    if found.severity_hint() > 0 {
        // report found.severity_hint() and found.stats as an event
    }
    match found.lookup {
        Lookup::One(token) => Some(token),
        _ => None, // Missing, Many, Truncated, HeaderTooLong: fail closed
    }
}
assert_eq!(session_token(Some(b"__Host-sid=t0k3n")), Some("t0k3n"));
assert_eq!(session_token(Some(b"__Host-sid=a; __Host-sid=b")), None);
assert_eq!(session_token(None), None);
```

### `Prefix`

`Prefix::of(name)` is `Host`, `Secure`, or `None`. Prefixes are matched case-insensitively, as user agents do (rfc6265bis section 5.4).

```rust
use cookie_net::Prefix;

assert_eq!(Prefix::of("__Host-sid"), Prefix::Host);
assert_eq!(Prefix::of("__secure-x"), Prefix::Secure);
assert_eq!(Prefix::of("_Host-sid"), Prefix::None);
```

### `Limits` and `ValueMode`

Budgets for reading a header, each checked before the work it governs. Setters are `const`, so limits can be constants; a value outside a setter's range is brought to the nearest end of it, and the getters show what is in force. Name plus value never passes 4096 bytes, whatever the settings.

| Setter | Range | Default | Getter |
|---|---|---|---|
| `max_header_len(bytes)` | 1 to 65,536 | 8,192 (all lines together) | `header_len()` |
| `max_pairs(n)` | 1 to 1,024 | 64 | `pairs()` |
| `max_name_len(bytes)` | 1 to 4,096 | 256 | `name_len()` |
| `max_value_len(bytes)` | 0 to 4,096 | 4,096 | `value_len()` |
| `value_mode(mode)` | `Strict`, `Lenient` | `Strict` | `mode()` |

`Limits::DEFAULT`, `Limits::new()`, and `Limits::default()` are the same value.

`ValueMode::Strict` accepts the rfc6265bis grammar: `cookie-octet`s, optionally in double quotes. `ValueMode::Lenient` accepts what user agents store when page scripts write JSON or spaces into `document.cookie`: any byte except controls (tab allowed) and `;`, as long as the value is valid UTF-8. Use lenient on hosts that share cookies with third-party scripts. Names must be tokens in both modes.

```rust
use cookie_net::{self as cookie, Cookies, Limits, ValueMode};

const SMALL: Limits = Limits::DEFAULT.max_header_len(4096).max_pairs(16);
assert_eq!(Cookies::with_limits("a=1; b=2", &SMALL)?.iter().count(), 2);
assert_eq!(Limits::DEFAULT.max_pairs(5000).pairs(), 1024);

let h = r#"consent={"ads":false}; sid=abc"#;
assert_eq!(cookie::get(h, "consent"), None);              // strict: skipped and counted
let lenient = Cookies::with_limits(h, &Limits::DEFAULT.value_mode(ValueMode::Lenient))?;
assert_eq!(lenient.get("consent"), Some(r#"{"ads":false}"#));
# Ok::<(), cookie::CookieError>(())
```

### HTTP/2 cookie crumbs

HTTP/2 and HTTP/3 may split the `Cookie` header into several field lines, one pair each (RFC 9113 section 8.2.3). Several lines are therefore normal there, not a sign of an attack. `Cookies::from_lines` reads them as one header joined by `"; "`, without copying; the line lengths are summed for `max_header_len`.

```rust
use cookie_net::{Cookies, Limits};

let lines: [&[u8]; 2] = [b"__Host-sid=t0k3n", b"theme=dark"];
let cookies = Cookies::from_lines(&lines, &Limits::DEFAULT)?;
assert_eq!(cookies.get_unique("__Host-sid")?, Some("t0k3n"));
assert_eq!(cookies.iter().count(), 2);
# Ok::<(), cookie_net::CookieError>(())
```

### How a header is read

The grammar is rfc6265bis section 4.2.1, `cookie-pair *( ";" SP cookie-pair )`. For each line:

```text
 0 total length > max_header_len                ─▶ too long: nothing read
 1 skip spaces and tabs
 2 find the next ';'                            ─▶ the pair is the bytes before it
 3 trim spaces and tabs at the end; an empty pair is counted in `empty`
 4 split at the first '='; no '='               ─▶ skipped (a nameless cookie)
 5 name: 1 to max_name_len bytes, every byte a token character, else skipped
 6 value: strict or lenient as above; longer than max_value_len, or
          name + value > 4096                   ─▶ skipped
 7 accepted; one more than max_pairs            ─▶ stop, truncated
 8 the separator is "; "; ';' with no space or more whitespace is accepted and counted
```

`,` is not a separator, so `a=1, b=2` is one skipped pair in strict mode, never a pair named ` b`. `$Version=1` and `$Path=/` are ordinary pairs, never attributes. Every step is linear.

## Writing `Set-Cookie`

### `SetCookie`

A `Set-Cookie` field value that is valid by construction: the only ways to get one are `new`, `delete`, `SetCookieBuilder::build`, and the session helpers, and each checks every [rule](#rules-checked-by-build). Writing one cannot fail except for room.

| Item | Does |
|---|---|
| `SetCookie::new(name, value)` | `Secure; HttpOnly; SameSite=Lax; Path=/`, host-only, no `Max-Age` (the browser drops it when it closes) |
| `SetCookie::delete(name)` | removes `name` from a browser: an empty value, `Expires` in 1970, the same default attributes |
| `SetCookie::builder(name, value)` | a [`SetCookieBuilder`](#setcookiebuilder) for other attributes |
| `.encode()` | the field value as a `String` (feature `alloc`) |
| `.encode_into(&mut buf)` | into a byte buffer, returning the `&str` written; `Full` when it does not fit |
| `.write_to(&mut sink)` | into a `parse_net::Sink`; `Full` when it does not fit, and a sink that reports its room (`SliceSink`, `Vec`) is left as it was |
| `.encoded_len()` | the exact length of the encoding, to size a buffer once |
| `name()`, `value()`, `path()`, `domain()`, `max_age()`, `expires()`, `same_site()` | the attributes |
| `is_secure()`, `is_http_only()`, `is_partitioned()`, `is_deletion()` | the flags |

`encode`, `encode_into`, and `write_to` produce the same bytes. There is no `Display`, so `format!("{cookie}")` cannot put a token into a log line; `Debug` shows the attributes and the value's length.

`delete` removes any cookie that was set with the default attributes, including every `__Host-` cookie: removal works only when name, path, and domain match (rfc6265bis section 3.1). For a cookie set with another `Path` or `Domain`, use the builder: `SetCookie::builder(name, "").path("/app").delete().build()`.

```rust
use cookie_net::SetCookie;

let c = SetCookie::new("theme", "dark")?;
assert_eq!(c.encode(), "theme=dark; Path=/; Secure; HttpOnly; SameSite=Lax");

let gone = SetCookie::delete("__Host-sid")?;
assert_eq!(
    gone.encode(),
    "__Host-sid=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Secure; HttpOnly; SameSite=Lax"
);
assert!(gone.is_deletion());
# Ok::<(), cookie_net::CookieError>(())
```

Without an allocator:

```rust
use cookie_net::SetCookie;
use parse_net::SliceSink;

let c = SetCookie::new("theme", "dark")?;
let mut buf = [0u8; 128];
assert_eq!(c.encode_into(&mut buf)?, "theme=dark; Path=/; Secure; HttpOnly; SameSite=Lax");

let mut out = SliceSink::new(&mut buf);
c.write_to(&mut out)?;
assert_eq!(out.len(), c.encoded_len());
# Ok::<(), cookie_net::CookieError>(())
```

### `SetCookieBuilder`

Setters never fail and can be called in any order; a later call to the same setter replaces the earlier one. `build` checks every rule and returns the first one broken. The opt-outs have plain names on purpose, so `insecure` and `script_readable` stand out in review.

| Setter | Sets |
|---|---|
| `max_age(secs)` | `Max-Age`, 1 to `MAX_LIFETIME` (400 days) |
| `expires(at, now)` | `Expires` at Unix second `at`, at most 400 days after `now` |
| `domain(domain)` | `Domain`, a bare domain such as `example.com`, written lowercase |
| `path(path)` | `Path`, starting with `/` |
| `same_site(SameSite)` | `SameSite` |
| `partitioned()` | `Partitioned` (CHIPS) |
| `insecure()` | drops `Secure`: for `http://localhost` only |
| `script_readable()` | drops `HttpOnly` |
| `extension(attribute)` | an extra attribute such as `"Priority=High"`, up to 8 |
| `delete()` | turns the cookie into a deletion: empty value, `Expires` in 1970, no `Max-Age` |
| `build()` | `Result<SetCookie, CookieError>` |

```rust
use cookie_net::{self as cookie, CookieError, SameSite, SetCookie};

let c = SetCookie::builder("__Secure-pref", "compact")
    .domain("Example.COM")
    .max_age(30 * cookie::DAY)
    .same_site(SameSite::Strict)
    .build()?;
assert_eq!(
    c.encode(),
    "__Secure-pref=compact; Path=/; Domain=example.com; Max-Age=2592000; Secure; HttpOnly; SameSite=Strict"
);

// a third-party widget cookie, partitioned per top-level site
let widget = SetCookie::builder("widget", "1").same_site(SameSite::None).partitioned().build()?;
assert!(widget.encode().ends_with("SameSite=None; Partitioned"));

// local development over plain HTTP
let dev = SetCookie::builder("theme", "dark").insecure().build()?;
assert!(!dev.is_secure());

// what a browser would drop, or an attacker could use, is refused
assert_eq!(
    SetCookie::builder("__Host-sid", "x").domain("example.com").build().unwrap_err(),
    CookieError::HostPrefix
);
assert_eq!(
    SetCookie::builder("embed", "1").same_site(SameSite::None).insecure().build().unwrap_err(),
    CookieError::SameSiteNoneNeedsSecure
);
# Ok::<(), CookieError>(())
```

### `SameSite`

`Strict`, `Lax` (the default), or `None`. `Lax` lets a top-level `GET` from another site (a link in an email) carry the cookie, while cross-site `POST`, `fetch`, and frames do not. `Strict` never leaves the site. `None` is sent everywhere and requires `Secure`. cookie-net always writes the attribute, so the "Lax-allowing-unsafe" relaxation browsers apply to cookies without one never applies to its cookies. The client side uses the same type, as `Option<SameSite>`.

### Rules checked by `build`

In this order; the first one broken is returned:

| # | Rule | Error | rfc6265bis |
|---|---|---|---|
| 1 | name is a non-empty token | `EmptyName`, `InvalidName { at }` | 4.1.1 |
| 2 | value is `cookie-octet`s, optionally in double quotes | `InvalidValue { at }` | 4.1.1 |
| 3 | name plus value at most 4096 bytes | `TooLarge` | 5.6, 5.7 |
| 4 | `Path`, `Domain`, each extension at most 1024 bytes | `AttributeTooLong` | 5.6 |
| 5 | `Path` starts with `/`, no control, no `;` | `InvalidPath { at }` | 4.1.1, 5.6.4 |
| 6 | `Domain` is letters, digits, and hyphens in dotted labels: no leading dot, no IP address, labels 1 to 63 bytes | `InvalidDomain` | 4.1.2.3, 5.6.3 |
| 7 | an extension has a token name, is not a defined attribute, at most 8 | `InvalidExtension { at }`, `ExtensionNotAllowed`, `TooManyExtensions` | 4.1.1 |
| 8 | `Max-Age` 1 to 34,560,000 | `MaxAgeOutOfRange` | 5.5 |
| 9 | `Expires` at most 400 days after `now` | `ExpiresOutOfRange` | 5.5 |
| 10 | `__Host-` (any case): `Secure`, `Path=/`, no `Domain` | `HostPrefix` | 4.1.3.2, 5.4 |
| 11 | `__Secure-` (any case): `Secure` | `SecurePrefix` | 4.1.3.1 |
| 12 | `SameSite=None` needs `Secure` | `SameSiteNoneNeedsSecure` | 5.7 |
| 13 | `Partitioned` needs `Secure` | `PartitionedNeedsSecure` | CHIPS 2.3, 3.1 |

A deletion skips rules 2, 8, and 9 (its value and expiry are fixed) and keeps every other rule, so deleting a `__Host-` cookie still writes a valid `__Host-` cookie.

### Serialization

One canonical form for each cookie, so tests can compare bytes:

```text
name=value; Path=/; Domain=example.com; Max-Age=3600; Expires=Wed, 21 Oct 2026 18:38:00 GMT; Secure; HttpOnly; SameSite=Lax; Partitioned; ext1; ext2=v
```

Attribute names are written in the case rfc6265bis uses, with `"; "` between attributes. `Path` is always written; `Domain`, `Max-Age`, and `Expires` only when set. `Expires` is an IMF-fixdate (RFC 9110 section 5.6.7). A deletion writes `Expires=Thu, 01 Jan 1970 00:00:00 GMT`, never `Max-Age=0`, because `Max-Age` must start with a non-zero digit.

## Session cookies

| Cookie | Attributes, fixed by the helper | Value |
|---|---|---|
| `__Host-sid` | `Secure; HttpOnly; SameSite=Lax; Path=/`, no `Domain`, `Max-Age` = the session's absolute lifetime | the session token: 32 random bytes in base64url (43 characters) |
| `__Host-sudo` | `Secure; HttpOnly; SameSite=Strict; Path=/`, no `Domain`, `Max-Age` 60 to 3600 | a separate random token for the elevated state |

Session tokens are opaque random values and the server's record is the truth, so they are neither signed nor encrypted. `__Host-` makes a cookie host-only, `Secure`, and `Path=/`, so a sibling subdomain cannot set or overwrite it. For the same reason CSRF tokens (csrf-sec) never go in a cookie: a double-submit cookie can be planted by a sibling subdomain, a session-bound token cannot.

### `session_cookie` and `elevated_cookie`

`session_cookie(name, token, max_age)` and `elevated_cookie(name, token, max_age)` return a `SetCookie` with the attributes above. They refuse:

| Error | When |
|---|---|
| `HostPrefix` | the name does not start with `__Host-` |
| `TokenTooShort` | the token is shorter than 22 bytes (128 bits in base64url): a user id or an empty string by mistake |
| `InvalidValue { at }` | the token is not `cookie-octet`s |
| `MaxAgeOutOfRange` | `max_age` is outside 1 to `MAX_LIFETIME`; for `elevated_cookie`, outside 60 to 3600 |

Issue a new token at every login (against session fixation) and at every roll.

```rust
use cookie_net::{self as cookie, CookieError};

let token = "Zk3J9qL0wX7aP2mT8sV1cR5dY4hN6bE0uK9gF3jQ2oA";
let set = cookie::session_cookie("__Host-sid", token, 12 * cookie::HOUR)?;
assert_eq!(set.encode(), format!("__Host-sid={token}; Path=/; Max-Age=43200; Secure; HttpOnly; SameSite=Lax"));

let sudo = cookie::elevated_cookie("__Host-sudo", "pX4vB8nM2kL6qW0eR9tY3uI7oP5aS1dF", 10 * cookie::MINUTE)?;
assert!(sudo.encode().ends_with("Max-Age=600; Secure; HttpOnly; SameSite=Strict"));

assert_eq!(cookie::session_cookie("sid", token, cookie::HOUR).unwrap_err(), CookieError::HostPrefix);
assert_eq!(cookie::session_cookie("__Host-sid", "42", cookie::HOUR).unwrap_err(), CookieError::TokenTooShort);
# Ok::<(), CookieError>(())
```

For a session cookie without `Max-Age`, which the browser drops when it closes, `SetCookie::new("__Host-sid", token)` already has the same attributes.

### Ending a session

`SetCookie::delete("__Host-sid")` and `SetCookie::delete("__Host-sudo")` remove the cookies; their attributes meet the `__Host-` rules, so browsers accept the removal. Correctness never depends on the browser obeying it: revoke the session on the server first.

```rust
use cookie_net::SetCookie;

let mut set_cookie_lines = Vec::new();
// revoke on the server first, then:
set_cookie_lines.push(SetCookie::delete("__Host-sid")?.encode());
set_cookie_lines.push(SetCookie::delete("__Host-sudo")?.encode());
assert!(set_cookie_lines.iter().all(|l| l.contains("Expires=Thu, 01 Jan 1970")));
# Ok::<(), cookie_net::CookieError>(())
```

### Lifetimes and `CLEAR_SITE_DATA_COOKIES`

`MINUTE`, `HOUR`, and `DAY` are seconds (`u64`), so lifetimes read as what they mean: `12 * HOUR`, `now + 5 * MINUTE`. `MAX_LIFETIME` is 400 days, the cap browsers apply (rfc6265bis section 5.5). `VERSION` is the crate version.

`CLEAR_SITE_DATA_COOKIES` is the value of a `Clear-Site-Data` response header that tells the browser to drop every cookie for the site. It is the recovery from cookie bombing: when a credential lookup reports `Truncated` or `HeaderTooLong`, answer with it and the user can sign in again. The server-side session is not affected, and cookie-net never sends it on its own.

```rust
use cookie_net::{self as cookie, Ambiguous};

let bombed = "x=1; ".repeat(100) + "__Host-sid=t0k3n";
if let Err(Ambiguous::Truncated | Ambiguous::HeaderTooLong) = cookie::get_unique(&bombed, "__Host-sid") {
    let header = ("clear-site-data", cookie::CLEAR_SITE_DATA_COOKIES);
    assert_eq!(header.1, "\"cookies\"");
}
assert_eq!(30 * cookie::DAY, 2_592_000);
```

## Keys

Features `signed` or `encrypted`. Keys are 32 bytes from your configuration (WASP: key-vault), the same on every node of a cluster. cookie-net never generates keys: a key made at boot would invalidate every signed cookie at every restart and differ between nodes.

### `Key`

Every function that takes a key takes `impl Into<Key>`, so a `[u8; 32]` works directly. `Key::from_bytes(bytes)` is the same conversion. A key whose 32 bytes are all equal (an unset or zeroed key) is refused with `WeakKey`. `Key` is wiped on drop and its `Debug` is `Key(..)`.

`Key::derive(master, context)` derives a key with HKDF-SHA-256 for one master secret serving several services: `context` is the service name, at most 200 bytes, and a master shorter than 32 bytes is refused (`KeyTooShort`, `ContextTooLong`).

`Signer` and `Sealer` each derive their own subkey from the key they are given, so one key can feed both and signing and sealing still never share key material.

```rust
use cookie_net::{Key, Sealer, Signer};

let master = b"a master secret from key-vault, at least 32 bytes";
let key = Key::derive(master, b"wasp-web")?;
let signer = Signer::new(key.clone())?;
let sealer = Sealer::new(key)?;                  // a different subkey from the same source
assert_eq!(format!("{signer:?}").contains("Key("), false);
# let _ = sealer;
# Ok::<(), cookie_net::CookieError>(())
```

### `KeyRing`

One signing key and up to seven others, each with a `KeyId` (one byte) and a `KeyRole`:

| `KeyRole` | The key |
|---|---|
| `Signing` | signs (or seals) new cookies and verifies |
| `Accepted` | verifies only, with no end: staged on every node before it signs |
| `Retired { until }` | verifies only while `now < until` |

| Method | Does |
|---|---|
| `KeyRing::new(id, key)` | a ring whose signing key is `key` |
| `.accept(id, key)` | adds an accepted key |
| `.retired(id, key, until)` | adds a retired key |
| `.rotated(id, key, retire_old_at)` | makes `id` the signing key and retires the previous one until `retire_old_at`; an accepted entry with the same id is promoted |
| `.without(id)` | removes a key |
| `.signing_key()` | the signing key's id |

The ring methods never fail, so a ring reads as one chain. `Signer::with_ring` and `Sealer::with_ring` check it and return `DuplicateKeyId`, `RingFull`, `WeakKey`, or `InvalidRetireTime`. `Debug` shows ids and roles, never key bytes. Never reuse a key id while cookies made under the old key may still be presented.

`Signer::keys()` and `Sealer::keys()` list every key as a `KeyInfo` (`id()`, `role()`, `fingerprint()`). A `KeyFingerprint` is eight bytes, printed as 16 hex digits, derived from the key's subkey: it helps nobody forge a cookie, but two nodes holding the same key under the same id show the same fingerprint. Compare fingerprints across a cluster to catch a misdeployed ring before it shows up as a wave of `BadTag` refusals.

```rust
use cookie_net::{KeyId, KeyRing, KeyRole, Signer};

let now = 1_800_000_000;
let ring = KeyRing::new(KeyId(2), *b"the second key, 32 bytes long!!!")
    .retired(KeyId(1), *b"an example key, 32 bytes long!!!", now + 86_400);
let signer = Signer::with_ring(ring)?;
assert_eq!(signer.signing_key(), KeyId(2));

let roles: Vec<KeyRole> = signer.keys().map(|k| k.role()).collect();
assert_eq!(roles, [KeyRole::Signing, KeyRole::Retired { until: now + 86_400 }]);
assert_eq!(signer.fingerprint(KeyId(2)).unwrap().to_string().len(), 16);
# Ok::<(), cookie_net::CookieError>(())
```

### Rotating keys across a cluster

Signed and sealed cookies verify on any node that holds the same ring. A rotation that changed every node at once would, for a moment, refuse cookies signed by nodes that had already switched, so a rotation is three rings, each deployed to every node:

1. **Stage**: `KeyRing::new(KeyId(1), k1).accept(KeyId(2), k2)`. Every node verifies `k2`; none signs with it. Compare fingerprints across nodes.
2. **Switch**: `KeyRing::new(KeyId(1), k1).accept(KeyId(2), k2).rotated(KeyId(2), k2, t)`. New cookies use `k2`; old ones verify until `t`. Set `t` at least one cookie lifetime plus the skew allowance after the switch.
3. **Drop**: after `t`, `KeyRing::new(KeyId(2), k2)`. Old cookies are now `UnknownKey`.

No step signs anyone out. The `role` that `verify_detailed` reports tells an operator when step 3 is safe.

```rust
use cookie_net::{KeyId, KeyRing, Signer};

let (k1, k2) = (*b"an example key, 32 bytes long!!!", *b"the second key, 32 bytes long!!!");
let now = 1_800_000_000;
let old_cookie = Signer::new(k1)?.sign("prefs", "lang=fr")?;

let switched = Signer::with_ring(KeyRing::new(KeyId(0), k1).accept(KeyId(2), k2).rotated(KeyId(2), k2, now + 3600))?;
assert_eq!(switched.verify("prefs", &old_cookie, now)?, "lang=fr");   // still verifies
let new_cookie = switched.sign("prefs", "lang=de")?;

let dropped = Signer::with_ring(KeyRing::new(KeyId(2), k2))?;
assert_eq!(dropped.verify("prefs", &new_cookie, now)?, "lang=de");
assert!(dropped.verify("prefs", &old_cookie, now).is_err());          // UnknownKey
# Ok::<(), cookie_net::CookieError>(())
```

## Signed cookies: `Signer`

Feature `signed`. For small state the client holds and must not forge: preferences, a cart id, a dismissed notice. The value stays readable; signing proves integrity, not secrecy.

| Method | Does |
|---|---|
| `Signer::new(key)` | a signer with one key, id 0 |
| `Signer::with_ring(ring)` | a signer for a [`KeyRing`](#keyring) |
| `.with_skew(secs)` | the clock-skew allowance for expiries; default 60, at most 3600 |
| `.sign(name, value)` | the cookie value as a `String` (feature `alloc`) |
| `.sign_until(name, value, expires)` | with an expiry the server enforces |
| `.sign_bound(name, value, bound_to)` | bound to, say, a digest of the session id |
| `.sign_into(name, value, expires, bound_to, &mut sink)` | any combination, into a `Sink`, without allocating |
| `.signed_len(value_len)` | the length of a signed value: `value_len + 30` |
| `.verify(name, raw, now)` | `Result<&str, Rejected>` |
| `.verify_bound(name, raw, bound_to, now)` | for a value signed with a binding |
| `.verify_detailed(name, raw, bound_to, now)` | `Verified { value, key, role, expires }` |
| `.verify_now(name, raw)` | `verify` with the system clock (feature `std`) |
| `.signing_key()`, `.keys()`, `.fingerprint(id)` | the ring, for operators |

- **The name is inside the MAC**, so a signed value cannot be moved to another cookie.
- **An expiry** is checked on every verification, whatever the browser does with `Max-Age`. It is Unix seconds from 2020-01-01 to 2156 (`ExpiresOutOfRange` otherwise), accepted while `now < expires + skew`.
- **A binding** goes into the MAC without being stored in the cookie. A bound value verifies only with the same binding, so a valid signed cookie cannot be replayed into another user's browser, and it dies with the session. An empty binding is no binding.
- `value` must be `cookie-octet`s with no surrounding quotes (`InvalidValue`), and the name plus the signed value at most 4096 bytes (`TooLarge`), both checked before any MAC work.
- Verification takes no lock, allocates nothing, and compares the 128-bit tag in constant time.
- `verify_now` reads a clock before 2020 as the far future, so a device without a real-time clock refuses expiring values instead of accepting them.

```rust
use cookie_net::{self as cookie, Rejected, SetCookie, Signer};

let now = 1_800_000_000;
let signer = Signer::new(*b"an example key, 32 bytes long!!!")?;

let value = signer.sign("prefs", "lang=fr")?;
assert_eq!(value.len(), signer.signed_len("lang=fr".len()));
assert!(value.ends_with("lang=fr"));                              // readable, not secret
assert_eq!(signer.verify("prefs", &value, now)?, "lang=fr");
assert_eq!(signer.verify("theme", &value, now), Err(Rejected::BadTag));   // moved to another name

let mut forged = value.clone().into_bytes();
*forged.last_mut().unwrap() = b'x';
assert_eq!(signer.verify("prefs", &forged, now), Err(Rejected::BadTag));

// a cart id bound to the session and valid for one day
let session_digest = b"digest of the session id";
let v = signer.sign_bound("cart", "c-81731", session_digest)?;
let set = SetCookie::builder("cart", &v).max_age(cookie::DAY).build()?;
let header = format!("cart={}", set.value());
let cart = cookie::get(&header, "cart").and_then(|raw| signer.verify_bound("cart", raw, session_digest, now).ok());
assert_eq!(cart, Some("c-81731"));
assert_eq!(signer.verify_bound("cart", &v, b"another session", now), Err(Rejected::BadTag));

let notice = signer.sign_until("notice", "seen", now + 60)?;
assert_eq!(signer.verify("notice", &notice, now + 3600), Err(Rejected::Expired));
let detail = signer.verify_detailed("notice", &notice, &[], now)?;
assert_eq!(detail.expires, Some(now + 60));
# Ok::<(), cookie::CookieError>(())
```

The byte layout, the subkey derivation, and test vectors are in [`FORMATS.md`](./FORMATS.md), so another implementation can interoperate.

## Encrypted cookies: `Sealer`

Feature `encrypted`. For small client-held state that must also stay private: a flash message with a name in it, a return URL. XChaCha20-Poly1305 with a random 192-bit nonce per cookie, so nonces never collide however many cookies a cluster issues under one key.

| Method | Does |
|---|---|
| `Sealer::new(key)`, `Sealer::with_ring(ring)`, `.with_skew(secs)` | as for `Signer` |
| `.seal(name, plaintext)` | the cookie value as a `String`; `plaintext` is any bytes |
| `.seal_until(name, plaintext, expires)` | with an expiry the server enforces |
| `.seal_bound(name, plaintext, bound_to)` | bound to, say, a digest of the session id |
| `.seal_into(name, plaintext, expires, bound_to, &mut scratch, &mut sink)` | any combination, into a `Sink`, reusing `scratch` |
| `.sealed_len(plaintext_len)` | the length of a sealed value |
| `.max_plaintext(name_len)` | the largest plaintext that fits in a 4096-byte cookie |
| `.open(name, raw, now)` | `Result<Plaintext, Rejected>` |
| `.open_bound(name, raw, bound_to, now)` | for a value sealed with a binding |
| `.open_into(name, raw, bound_to, now, &mut out)` | into your `Vec`; returns `Opened { key, role, expires }` |
| `.open_now(name, raw)` | `open` with the system clock |
| `.signing_key()`, `.keys()`, `.fingerprint(id)` | the ring, for operators |

- The cookie name, the expiry, and the binding are authenticated, so a sealed value cannot move to another name or session. Expiry, binding, and skew behave as for `Signer`.
- `TooLarge` (the plaintext is over `max_plaintext`) is returned before any cryptography. `Crypto` is returned if the random source fails, and nothing is written.
- `Plaintext` is owned and wiped on drop: `as_bytes()`, `as_str()` (when it is UTF-8), `len()`, `is_empty()`; its `Debug` prints only the length.
- `open_into` writes into your `Vec`. Its whole capacity is wiped first, so no earlier plaintext survives, and again on every failure after decryption; the capacity is kept, so once it has room, opening allocates nothing.

```rust
use cookie_net::{self as cookie, Rejected, Sealer, SetCookie};

let now = 1_800_000_000;
let sealer = Sealer::new(*b"another example key, 32 bytes!!!")?;

let v = sealer.seal_until("flash", "Saved your address, Ana.", now + 5 * cookie::MINUTE)?;
let set = SetCookie::builder("flash", &v).max_age(5 * cookie::MINUTE).build()?;
assert!(!set.value().contains("Ana"));                            // private

let text = sealer.open("flash", &v, now)?;
assert_eq!(text.as_str(), Some("Saved your address, Ana."));
assert_eq!(format!("{text:?}"), "Plaintext(24 bytes)");
assert_eq!(sealer.open("flash", &v, now + 10 * cookie::MINUTE).unwrap_err(), Rejected::Expired);
assert_eq!(sealer.open("other", &v, now).unwrap_err(), Rejected::BadTag);

// steady state without an allocation per request
let mut plain = Vec::with_capacity(512);
let opened = sealer.open_into("flash", &v, &[], now, &mut plain)?;
assert_eq!(plain, b"Saved your address, Ana.");
assert_eq!(opened.expires, Some(now + 5 * cookie::MINUTE));
# Ok::<(), cookie::CookieError>(())
```

## Refused cookies: `Rejected`

Why a signed or sealed cookie was refused. Clients never learn the reason: treat every `Rejected` as "cookie absent", and report the reason as an event.

| Variant | Most likely | `severity_hint()` |
|---|---|---|
| `Malformed` | tampering or truncation: wrong length, bad base64url | 10 |
| `UnsupportedVersion` | tampering, or a cookie from a newer deployment | 5 |
| `UnknownKey` | an old cookie after its key left the ring | 1 |
| `BadTag` | forgery, or a value moved between names or sessions | 40 |
| `Expired` | an old tab, or client clock games | 1 |

Both formats are checked in this order, so the reason is accurate and the work is bounded: length, base64url decoding, version, key id, then the tag in constant time, then the expiry. A forged expired cookie therefore reports `BadTag`, not `Expired`. `code()` gives a stable name such as `"bad_tag"`.

```rust
use cookie_net::{Rejected, Signer};

let signer = Signer::new(*b"an example key, 32 bytes long!!!")?;
assert_eq!(signer.verify("prefs", "short", 0), Err(Rejected::Malformed));
assert_eq!(Rejected::BadTag.severity_hint(), 40);
assert_eq!(Rejected::Expired.code(), "expired");
# Ok::<(), cookie_net::CookieError>(())
```

## Client side

Feature `client`. For outbound HTTP clients, which must treat cookies as a browser does. These functions follow the rfc6265bis user-agent algorithms exactly, which are more lenient than the server grammar on purpose. Names and values here are bytes, because a client keeps what a server sent.

### `parse_set_cookie`

`parse_set_cookie(line)` is the rfc6265bis section 5.6 algorithm. It returns `None` when a browser ignores the whole line: a control character other than tab anywhere, an empty name and value, or name plus value over 4096 bytes. Without `=` the name is empty and the value is the whole pair. Attributes are matched case-insensitively, a later one replaces an earlier one, and an attribute value over 1024 bytes is ignored.

| `SetCookieView` field | Holds |
|---|---|
| `name`, `value` | bytes |
| `expires` | Unix seconds from [`cookie_date`](#cookie_date) |
| `max_age` | seconds; 0 or less means "expire now"; capped at 400 days |
| `domain` | with one leading `.` removed |
| `path` | `None` also when the value does not start with `/` |
| `secure`, `http_only`, `partitioned` | the flags |
| `same_site` | `Option<SameSite>`; `None` when absent or unknown, which a jar treats as `Lax` |
| `unknown_attributes` | how many attributes were not recognised |

```rust
use cookie_net::{SameSite, parse_set_cookie};

let v = parse_set_cookie("id=a3fWa; Max-Age=2592000; Domain=.Example.com; secure; SameSite=lax").unwrap();
assert_eq!((v.name, v.value), (&b"id"[..], &b"a3fWa"[..]));
assert_eq!(v.max_age, Some(2_592_000));
assert_eq!(v.domain, Some(&b"Example.com"[..]));
assert!(v.secure);
assert_eq!(v.same_site, Some(SameSite::Lax));
assert_eq!(parse_set_cookie("a=1; SameSite=Bogus").unwrap().same_site, None);
assert!(parse_set_cookie("a=b\x01c").is_none());
```

### `cookie_date`

`cookie_date(value)` is the lenient cookie-date algorithm of rfc6265bis section 5.1.1, different from HTTP-date on purpose: the first matching time, day, month, and year tokens; two-digit years 70 to 99 mean 1970 to 1999 and 0 to 69 mean 2000 to 2069; years before 1601, invalid days, and invalid times fail.

```rust
use cookie_net::cookie_date;

assert_eq!(cookie_date("Wed, 09 Jun 2021 10:18:14 GMT"), Some(1_623_233_894));
assert_eq!(cookie_date("09-Jun-21 10:18:14"), Some(1_623_233_894));
assert_eq!(cookie_date("Jun 9 2021 10:18"), None);               // no seconds
assert_eq!(cookie_date("Wed, 09 Jun 1600 10:18:14 GMT"), None);
```

## The cookie jar

Feature `jar`. A bounded store that follows the rfc6265bis storage (section 5.7) and retrieval (section 5.8.3) rules for a non-browser client.

### `Jar`

| Method | Does |
|---|---|
| `Jar::new()` | an empty jar with the default limits and no public suffix list |
| `Jar::with_public_suffix(list)` | with your [public suffix list](#public-suffixes) |
| `Jar::with_store(list, store)` | with your list and your [store](#storage-export-and-import) |
| `.with_limits(JarLimits)` | other [limits](#jarlimits) |
| `.store(&url, set_cookie_line, now)` | applies one `Set-Cookie` line; returns a [`StoreOutcome`](#storeoutcome-and-ignorereason) |
| `.store_all(&url, lines, now)` | every line of a response; returns how many were stored |
| `.cookie_header(&url, now)` | the `Cookie` header for a request, or `None` when no cookie applies |
| `.cookie_header_for(&url, &context, now)` | the same for a cross-site or navigation request |
| `.write_cookie_header(&url, &context, now, &mut sink)` | the same bytes into a `Sink`; returns how many cookies it holds |
| `.remove_expired(now)`, `.clear()`, `.clear_domain(domain)` | removal; the first and last return how many went |
| `.len()`, `.is_empty()`, `.cookies()` | what the jar holds |
| `.export()`, `.import(&bytes, now)` | move a jar between processes or nodes |

- `store` applies the storage steps that apply to a client: a `Secure` cookie only from a secure origin; a non-secure origin can neither overwrite nor shadow a `Secure` cookie; `Domain` must domain-match the host and pass the public suffix check; the `__Host-` and `__Secure-` rules; `SameSite=None` and `Partitioned` need `Secure`; a nameless cookie whose value starts with a prefix is ignored; replacing a cookie keeps its creation time; expiry is capped at 400 days.
- `cookie_header` picks host-only or domain-matching cookies, path-matching, `Secure` only over secure channels, `SameSite` against the context; longer paths first, then earlier creation; `"; "` between pairs. It updates last-access times.
- Partitioned cookies are kept under the request host as their partition key and sent only when the context's top-level site matches.
- Memory is bounded by the limits, never by input: over a limit, expired cookies go first, then the least recently used non-secure cookie, then the least recently used secure one (rfc6265bis section 5.7), so a plain-HTTP origin cannot evict a `Secure` cookie by flooding a domain. `Debug` shows counts and limits, never values.

```rust
use cookie_net::{IgnoreReason, Jar, RequestUrl, StoreOutcome};

let now = 1_800_000_000;
let mut jar = Jar::new();
let login = RequestUrl::https("app.example.com", "/login");
assert_eq!(jar.store(&login, "sid=abc; Path=/; Secure; HttpOnly", now), StoreOutcome::Stored);
assert_eq!(
    jar.store(&login, "tracker=1; Domain=com", now),
    StoreOutcome::Ignored(IgnoreReason::DomainNotAllowed)
);

let api = RequestUrl::https("app.example.com", "/api/orders");
assert_eq!(jar.cookie_header(&api, now).as_deref(), Some("sid=abc"));
assert_eq!(jar.cookie_header(&RequestUrl::http("app.example.com", "/"), now), None);   // Secure over HTTP

let response_lines: [&[u8]; 2] = [b"theme=dark; Path=/", b"lang=fr; Max-Age=60"];
assert_eq!(jar.store_all(&api, response_lines, now), 2);
assert_eq!(jar.len(), 3);
assert_eq!(jar.remove_expired(now + 120), 1);
```

### `RequestUrl` and `RequestContext`

The jar takes a URL as its parts, already parsed. `RequestUrl::https(host, path)`, `RequestUrl::http(host, path)`, and `RequestUrl::new(secure, host, path)`: `host` is the host without a port, in ASCII (punycode for international names), with no trailing dot, compared case-insensitively; `path` is the request path without the query (empty means `/`). An IP-address host only ever gets host-only cookies.

`RequestContext::same_site()` (the default, and what `cookie_header` uses) suits a client that is its own site. `RequestContext::cross_site()` is a request from another site; `.navigation(safe_method)` marks a top-level navigation, which carries `Lax` cookies when the method is safe; `.top_level_site(site)` sets the partition key for partitioned cookies.

```rust
use cookie_net::{Jar, RequestContext, RequestUrl};

let now = 1_800_000_000;
let mut jar = Jar::new();
let url = RequestUrl::https("shop.example", "/");
jar.store(&url, "strict=1; SameSite=Strict; Secure", now);
jar.store(&url, "lax=1; SameSite=Lax; Secure", now);

let link = RequestContext::cross_site().navigation(true);
assert_eq!(jar.cookie_header_for(&url, &link, now).as_deref(), Some("lax=1"));
assert_eq!(jar.cookie_header_for(&url, &RequestContext::cross_site(), now), None);
assert_eq!(jar.cookie_header(&url, now).as_deref(), Some("strict=1; lax=1"));
```

### Public suffixes

The public suffix list is about 200 KB and changes often, so it is not bundled. With the default `NoSuffixList` the jar fails closed: a `Domain` equal to the request host makes a host-only cookie, and any other `Domain` is ignored. No site can set a cookie for `co.uk` or `github.io`, at the cost of not sharing cookies across sibling subdomains until you supply a list through the `PublicSuffix` trait.

```rust
use cookie_net::{Jar, PublicSuffix, RequestUrl};

struct Suffixes(&'static [&'static str]);              // loaded from publicsuffix.org in practice
impl PublicSuffix for Suffixes {
    fn is_public_suffix(&self, domain: &str) -> bool {
        self.0.iter().any(|s| s.eq_ignore_ascii_case(domain))
    }
}

let now = 1_800_000_000;
let mut jar = Jar::with_public_suffix(Suffixes(&["com", "co.uk"]));
let url = RequestUrl::https("app.example.com", "/");
jar.store(&url, "shared=1; Domain=example.com; Secure", now);
let sibling = RequestUrl::https("www.example.com", "/");
assert_eq!(jar.cookie_header(&sibling, now).as_deref(), Some("shared=1"));
```

### `JarLimits`

`JarLimits::DEFAULT` is 50 cookies per domain and 3000 in all, the rfc6265bis section 6.1 minimums. `.per_domain(n)` takes 1 to 1,000 and `.total(n)` 1 to 1,000,000. Each cookie is at most 4096 bytes of name and value, so the jar's memory is bounded by its total.

```rust
use cookie_net::{Jar, JarLimits, RequestUrl};

let now = 1_800_000_000;
let mut jar = Jar::new().with_limits(JarLimits::DEFAULT.per_domain(2).total(10));
let url = RequestUrl::https("example.com", "/");
for i in 0..5 {
    jar.store(&url, &format!("c{i}=1; Secure")[..], now + i);
}
assert_eq!(jar.len(), 2);                                // the least recently used went first
```

### `StoreOutcome` and `IgnoreReason`

`store` returns `Stored`, `Replaced`, `Removed` (an expiry in the past removed a stored cookie), or `Ignored(reason)`:

| `IgnoreReason` | The line was ignored because |
|---|---|
| `Malformed` | the section 5.6 algorithm ignores it |
| `NamelessPrefixed` | a nameless cookie's value starts with `__Host-` or `__Secure-` |
| `SecureFromInsecure` | `Secure` from a non-secure origin |
| `WouldShadowSecure` | a non-secure origin would overwrite or shadow a `Secure` cookie |
| `DomainMismatch` | `Domain` does not domain-match the request host |
| `DomainNotAllowed` | a public suffix, or any other domain with `NoSuffixList` |
| `HostPrefix`, `SecurePrefix` | the prefix rules |
| `SameSiteNoneNeedsSecure`, `PartitionedNeedsSecure` | `Secure` is missing |
| `Expired` | already expired, and nothing stored to remove |

```rust
use cookie_net::{IgnoreReason, Jar, RequestUrl, StoreOutcome};

let now = 1_800_000_000;
let mut jar = Jar::new();
jar.store(&RequestUrl::https("example.com", "/"), "sid=real; Secure", now);
assert_eq!(
    jar.store(&RequestUrl::http("example.com", "/"), "sid=evil", now),
    StoreOutcome::Ignored(IgnoreReason::WouldShadowSecure)
);
assert_eq!(
    jar.store(&RequestUrl::https("example.com", "/"), "sid=gone; Max-Age=0; Secure", now),
    StoreOutcome::Removed
);
```

### Storage, export, and import

State lives behind the `JarStore` trait, so a jar can keep its cookies in memory (`MemoryStore`, the default), on disk, or in a shared store. A store only holds and indexes `StoredCookie`s (`len`, `get`, `get_mut`, `push`, `swap_remove`, `clear`); the jar applies every rule and every bound, so a store cannot weaken them. A durable store writes through on `push` and `swap_remove`.

`export` writes the cookies in a versioned format with a BLAKE3 checksum ([`FORMATS.md`](./FORMATS.md#jar-export-format-v1)). `import` treats the bytes as untrusted input: the checksum catches corruption, every field is validated again, cookies already expired at `now` are skipped, and the jar's limits apply. Any problem returns `InvalidJarData` and imports nothing. Exported bytes hold cookie values, so treat them as secrets.

```rust
use cookie_net::{Jar, RequestUrl};

let now = 1_800_000_000;
let mut jar = Jar::new();
jar.store(&RequestUrl::https("example.com", "/"), "sid=abc; Secure; Max-Age=3600", now);
let bytes = jar.export();

let mut other_node = Jar::new();
assert_eq!(other_node.import(&bytes, now)?, 1);
assert_eq!(other_node.cookie_header(&RequestUrl::https("example.com", "/"), now).as_deref(), Some("sid=abc"));

let mut tampered = bytes.clone();
tampered[10] ^= 1;
assert!(Jar::new().import(&tampered, now).is_err());
# Ok::<(), cookie_net::CookieError>(())
```

## Errors

### `CookieError`

One error type for every fallible call, so `?` works in a handler that returns `Result<_, CookieError>`. Every variant exists in every feature combination. `at` is a byte offset into the input that was refused. The enum is `#[non_exhaustive]`.

| Variant | Returned when | What to do |
|---|---|---|
| `EmptyName` | a cookie name is empty | give the cookie a name |
| `InvalidName { at }` | a name byte is not a token character: space, tab, `;`, `=`, `,`, `"`, `(`, `)`, `[`, `]`, `@`, `:`, `/`, `\`, `?`, `{`, `}`, a control, or a byte above 0x7E | use letters, digits, and ``!#$%&'*+-.^_`|~`` |
| `InvalidValue { at }` | a value byte is not a `cookie-octet` (a control, space, `"` inside, `,`, `;`, `\`, a byte above 0x7E), or a quote is not closed | encode the value first (base64url, or percent-encoding) |
| `TooLarge` | name plus value is over 4096 bytes; for signed and sealed values, the encoded result is | keep less in the cookie and more on the server |
| `TokenTooShort` | a session or elevated token is shorter than 22 bytes | pass the session token, not a user id or an empty string |
| `AttributeTooLong` | a `Path`, `Domain`, or extension is over 1024 bytes | shorten it |
| `InvalidPath { at }` | `Path` does not start with `/`, or holds a control or `;` | pass an absolute path such as `/app` |
| `InvalidDomain` | `Domain` is not a dotted host name: a leading dot, one label (`localhost`), an IP address, an empty or over-long label | pass the bare domain (`example.com`), or leave `Domain` unset |
| `InvalidExtension { at }` | an extension holds a control or `;`, is empty, or its name is not a token | use a token name such as `Priority=High` |
| `ExtensionNotAllowed` | an extension is named like a defined attribute (`Expires`, `Max-Age`, `Domain`, `Path`, `Secure`, `HttpOnly`, `SameSite`, `Partitioned`, any case) | use the builder's setter |
| `TooManyExtensions` | more than 8 extensions | use fewer |
| `MaxAgeOutOfRange` | `Max-Age` is 0 or over 400 days; for `elevated_cookie`, outside 60 to 3600 | use `delete` to remove a cookie; cap lifetimes at `MAX_LIFETIME` |
| `ExpiresOutOfRange` | `Expires` is more than 400 days after `now`; a signed or sealed expiry is before 2020 or after 2156 | pass seconds, not milliseconds |
| `HostPrefix` | a `__Host-` name without `Secure`, with another `Path`, or with `Domain`; a session helper given a name without `__Host-` | keep the defaults |
| `SecurePrefix` | a `__Secure-` name without `Secure` | do not call `insecure` |
| `SameSiteNoneNeedsSecure` | `SameSite=None` without `Secure` | do not call `insecure` |
| `PartitionedNeedsSecure` | `Partitioned` without `Secure` | do not call `insecure` |
| `HeaderTooLong` | `Cookies::with_limits` or `from_lines` got more bytes than `max_header_len` | answer `431`, or raise the limit |
| `Full` | the buffer or sink has no room | give a larger buffer; `encoded_len` says how large |
| `WeakKey` | all 32 key bytes are equal | load the real key |
| `KeyTooShort` | `Key::derive` got a master shorter than 32 bytes | use a longer master |
| `ContextTooLong` | `Key::derive` got a context over 200 bytes | use a short service name |
| `DuplicateKeyId` | two keys in a ring share an id | give every key its own id |
| `RingFull` | a ring holds more than 8 keys, or no signing key | drop retired keys with `without`; keep one signing key |
| `InvalidRetireTime` | a retire time is after 2156 | pass seconds |
| `Crypto` | the cryptography failed, such as the random source while sealing; nothing was written | retry; alert if it repeats |
| `InvalidJarData` | `Jar::import` got bytes with a wrong magic, version, checksum, length, or field; nothing was imported | export again; never edit the bytes |
| `Ambiguous(_)`, `Rejected(_)` | through `?` on [`Ambiguous`](#ambiguous) and [`Rejected`](#refused-cookies-rejected) | see those types |

`code()` returns a stable snake_case name for metrics and events (`"host_prefix"`, `"invalid_value"`, `"ambiguous.duplicate"`, `"rejected.bad_tag"`); codes never change within a major version. `Display` prints fixed text with the offset, never input bytes.

```rust
use cookie_net::{CookieError, SetCookie};

assert_eq!(SetCookie::new("sid", "a;Domain=evil.example").unwrap_err(), CookieError::InvalidValue { at: 1 });
assert_eq!(SetCookie::new("", "x").unwrap_err(), CookieError::EmptyName);
assert_eq!(CookieError::HostPrefix.code(), "host_prefix");
assert!(!CookieError::InvalidValue { at: 1 }.to_string().contains("evil"));
```

### `Ambiguous`

Why [`get_unique`](#get-get_unique-get_all) could not give one answer: `Duplicate { count }` (the name appears `count` times), `Truncated` (more than `max_pairs` pairs, so a duplicate could hide past the limit), or `HeaderTooLong` (nothing was read). For a credential every variant means "treat the request as signed out". `code()` gives a stable name such as `"duplicate"`; wrapped in a `CookieError` by `?`, the code gains the prefix (`"ambiguous.duplicate"`).

```rust
use cookie_net::{self as cookie, Ambiguous, CookieError};

let h = "__Host-sid=real; theme=dark; __Host-sid=planted";
assert_eq!(cookie::get_unique(h, "__Host-sid"), Err(Ambiguous::Duplicate { count: 2 }));
assert_eq!(cookie::get_unique(h, "theme"), Ok(Some("dark")));
assert_eq!(Ambiguous::Truncated.code(), "truncated");
assert_eq!(CookieError::from(Ambiguous::Truncated).code(), "ambiguous.truncated");
```

## Thread safety and sizes

| Type | `Send + Sync` | Notes |
|---|---|---|
| `Limits`, `JarLimits`, `Cookies`, `Pair`, `Stats`, `Lookup`, `Located`, `SetCookie`, `SetCookieBuilder`, `SetCookieView` | yes | `Copy` views; no interior mutability |
| `Key`, `KeyRing`, `Signer`, `Sealer` | yes | immutable once built; a rotation builds a new value that the application swaps in, so verification never locks |
| `Plaintext` | yes | owned |
| `Jar` | yes | changes through `&mut self`; no internal locking |

Every row is checked by a test. Sizes on 64-bit targets: `Pair` 32 bytes, `Cookies` 48, `Lookup` 24, `Located` 40, `Stats` 12, `Limits` 16, `SetCookie` 232 (eight extension slots), `SetCookieBuilder` 256.

## Migrating from 0.7

0.8 removes two duplicates and moves to parse-net 0.9. Signed, sealed, and jar export formats are unchanged, so cookies and exports made by 0.7 keep working.

| 0.7 | 0.8 |
|---|---|
| `Cookies::new(header)` | `cookie_net::parse(header)` (the same value; `Cookies::with_limits` and `Cookies::from_lines` are unchanged) |
| `SameSiteAttr` | `Option<SameSite>`: `SameSiteAttr::Strict` is `Some(SameSite::Strict)`, `Lax` and `None` likewise, `SameSiteAttr::Default` is `None` |
| `SetCookieView::same_site: SameSiteAttr`, `StoredCookie::same_site: SameSiteAttr` | `Option<SameSite>` |
| parse-net 0.6 (`Sink`, `SliceSink`, `Full`) | parse-net 0.9: write `parse-net = "0.9"` if you pass a `Sink` to `write_to`, `sign_into`, `seal_into`, or `write_cookie_header` |

## Examples in the repository

| Example | Shows |
|---|---|
| `01_quick_start` | reading, writing, and the rules |
| `02_sessions` | login, roll, sudo, logout, and the credential locator |
| `03_signed_and_sealed` | signed preferences, sealed flash messages, a key rotation |
| `04_client_jar` | an outbound client with a jar |

Run one with `cargo run --example 03_signed_and_sealed --features encrypted` (`04_client_jar` needs `--features jar`).
