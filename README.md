<h1 align="center">
    <img width="99" alt="Rust logo" src="https://raw.githubusercontent.com/jamesgober/rust-collection/72baabd71f00e14aa9184efcb16fa3deddda3a0a/assets/rust-logo.svg">
    <br>
    <b>cookie-net</b>
    <br>
    <sub><sup>HTTP COOKIES</sup></sub>
</h1>

<div align="center">
    <a href="https://crates.io/crates/cookie-net"><img alt="Crates.io" src="https://img.shields.io/crates/v/cookie-net"></a>
    <a href="https://crates.io/crates/cookie-net"><img alt="Downloads" src="https://img.shields.io/crates/d/cookie-net?color=%230099ff"></a>
    <a href="https://docs.rs/cookie-net"><img alt="docs.rs" src="https://img.shields.io/docsrs/cookie-net"></a>
    <a href="https://github.com/jamesgober/cookie-net/actions"><img alt="CI" src="https://github.com/jamesgober/cookie-net/actions/workflows/ci.yml/badge.svg"></a>
    <a href="https://github.com/rust-lang/rfcs/blob/master/text/2495-min-rust-version.md"><img alt="MSRV" src="https://img.shields.io/badge/MSRV-1.85%2B-blue"></a>
    <a href="#license"><img src="https://img.shields.io/badge/license-Apache--2.0%20OR%20MIT-blue.svg" alt="License"></a>
</div>

<p align="center">
    <b>HTTP cookies for Rust, RFC 6265bis, server side first.</b>
    <br>
    <i>Credential lookups that fail closed, and <code>Set-Cookie</code> values that cannot be built wrong.</i>
</p>

<br>

<p>
    <strong>cookie-net</strong> reads the <code>Cookie</code> request header and writes <code>Set-Cookie</code> response headers, following RFC 6265 and its revision <code>draft-ietf-httpbis-rfc6265bis</code>. Reading is zero-copy and allocation-free; writing checks every rule a browser enforces, so a cookie that would be dropped, or that an attacker could use, is refused when it is built. Secure defaults are the defaults: <code>Secure</code>, <code>HttpOnly</code>, <code>SameSite=Lax</code>, <code>Path=/</code>, host-only.
</p>

<p>
    Credentials are read with <code>get_unique</code>, which reports a planted duplicate, a truncated header, or an over-long one instead of guessing, and <code>locate</code>, which also counts look-alike names (<code>sid</code>, <code>__host-sid</code>) as evidence of cookie tossing. Names are compared byte for byte: no trimming, case folding, or decoding, which is what every known <code>__Host-</code> prefix bypass relies on.
</p>

<p>
    Signed cookies (keyed BLAKE3) and encrypted cookies (XChaCha20-Poly1305), both through crypt-io with staged key rotation, arrive in <code>0.4</code>; a client-side <code>Set-Cookie</code> parser and cookie jar in <code>0.5</code>. The whole API, with the version of each item, is in <a href="./docs/API.md"><code>docs/API.md</code></a>.
</p>

---

## Features

### **Reading the `Cookie` header**
- **One call per question** - `get` for preferences, `get_unique` for credentials, `get_all` for repeated names, `parse` for every pair.
- **Fails closed** - duplicates, more pairs than the limit, and over-long headers are reported, never resolved by guessing.
- **Facts for detection** - skipped pairs, empty pairs, loose separators, repeated prefixed names, and shadow names, counted in the same pass.
- **HTTP/2 crumbs** - several `Cookie` field lines read as one header, without copying.
- **Budgets** - header length, pair count, name length, value length, each checked before the work it governs; strict values by default, a lenient mode for hosts that share cookies with third-party scripts.

### **Writing `Set-Cookie`**
- **Valid by construction** - thirteen rules from rfc6265bis and CHIPS, checked by the builder: grammar, sizes, the 400-day cap, `Path` and `Domain` syntax, the `__Host-` and `__Secure-` prefixes, `SameSite=None` and `Partitioned` without `Secure`.
- **No injection** - CR, LF, NUL, `;`, and every other forbidden byte refused in every field.
- **Session helpers** - `session_cookie` and `elevated_cookie` for `__Host-` tokens with their attributes fixed; `SetCookie::delete` for logout.
- **Any output** - write into any `parse_net::Sink` (a stack buffer, a `Vec`), with the exact length known first.

### **Reliability and safety**
- **No unsafe code** - `#![forbid(unsafe_code)]`.
- **No panics** - every fallible call returns `Result`; fuzzed, property-tested, and covered by one attack test per threat.
- **Secrets never print** - `Debug` shows names and lengths, never values; no `Display` for a value.
- **`no_std`** - the core needs neither `std` nor an allocator; one first-party dependency (parse-net).

---

## Installation

```toml
[dependencies]
cookie-net = "0.3"

# no_std, no allocator:
cookie-net = { version = "0.3", default-features = false }
```

| Feature | Default | Adds |
|---|---|---|
| `std` | yes | implies `alloc`; the clock-reading helpers of later versions |
| `alloc` | through `std` | `SetCookie::encode` |
| `signed`, `encrypted`, `client`, `jar` | no | declared; their code arrives in 0.4 and 0.5 |

---

## Quick Start

```rust
use cookie_net::{self as cookie, SetCookie};

// Reading: the credential, a preference
let header = "__Host-sid=Zk3J9qL0wX7aP2mT8sV1cR5dY4hN6bE0uK9gF3jQ2oA; theme=dark";
let sid = cookie::get_unique(header, "__Host-sid")?;          // Option<&str>; Err if planted twice
let theme = cookie::get(header, "theme").unwrap_or("light");

// Writing
let set = SetCookie::new("theme", "dark")?;                   // Secure; HttpOnly; SameSite=Lax; Path=/
assert_eq!(set.encode(), "theme=dark; Path=/; Secure; HttpOnly; SameSite=Lax");
```

### **Sessions**

```rust
use cookie_net::{self as cookie, SetCookie};

let token = "Zk3J9qL0wX7aP2mT8sV1cR5dY4hN6bE0uK9gF3jQ2oA";      // from gate-net: 32 random bytes, base64url
let login = cookie::session_cookie("__Host-sid", token, 12 * cookie::HOUR)?;
// __Host-sid=...; Path=/; Max-Age=43200; Secure; HttpOnly; SameSite=Lax

let sudo = cookie::elevated_cookie("__Host-sudo", token, 10 * cookie::MINUTE)?;   // SameSite=Strict
let logout = SetCookie::delete("__Host-sid")?;                // revoke on the server first
```

### **The credential locator**

```rust
use cookie_net::{self as cookie, Limits, Lookup};

let found = cookie::locate("sid=planted; __Host-sid=t0k3n", "__Host-sid", &Limits::DEFAULT);
assert_eq!(found.lookup, Lookup::One("t0k3n"));
assert_eq!(found.shadows, 1);                // `sid` beside `__Host-sid`: report it
assert_eq!(found.severity_hint(), 5);
```

### **Rules that cannot be broken**

```rust
use cookie_net::{CookieError, SameSite, SetCookie};

assert_eq!(SetCookie::new("pref", "1; Domain=evil.example").unwrap_err(), CookieError::InvalidValue { at: 1 });
assert_eq!(SetCookie::builder("__Host-sid", "x").domain("example.com").build().unwrap_err(), CookieError::HostPrefix);
assert_eq!(SetCookie::builder("embed", "1").same_site(SameSite::None).insecure().build().unwrap_err(),
           CookieError::SameSiteNoneNeedsSecure);
```

More in [`examples/`](./examples) and [`docs/API.md`](./docs/API.md).

---

## Status: plain cookies (`0.3.0`)

**Done:** the request side, the response side, and the session helpers, each rfc6265bis rule tested with its section, property tests, counting-allocator tests, complexity tests, attack tests for the threats this version covers, and four fuzz targets.

**Next:** `0.4` signed and encrypted cookies with key rings and staged rotation; `0.5` the client side and the cookie jar; `0.6` benchmarks against `cookie`, `biscotti`, and `cookie_store`; `0.7` hardening. The schedule is in [`dev/ROADMAP.md`](./dev/ROADMAP.md).

**API stability:** the API was locked at `0.2.0`; names change only with a recorded decision in [`dev/PLAN.md`](./dev/PLAN.md). Performance numbers are targets until `0.6` measures them.

---

## What it is not

- **Sessions** (creation, storage, expiry, rotation, revocation) are gate-net's; cookie-net carries the token.
- **CSRF protection** is csrf-sec's. Its tokens are never double-submit cookies, so there is no CSRF cookie here, on purpose.
- **HTTP framing** is http-net's; the shared field grammar is parse-net's.

---

## Documentation

- **[API Reference](./docs/API.md)** - every public item, its version, errors, and examples
- **[Plan](./dev/PLAN.md)** - design, threats, decisions
- **[Roadmap](./dev/ROADMAP.md)** - versions and exit criteria
- **[docs.rs](https://docs.rs/cookie-net)** - rustdoc
- **[Changelog](./CHANGELOG.md)**

---

## Contributing

See <a href="./dev/DIRECTIVES.md"><code>dev/DIRECTIVES.md</code></a> for engineering standards and the definition of done. Before a PR: `cargo fmt --all`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-features` must be clean.

<br>

<div id="license">
    <h2>License</h2>
    <p>Licensed under either of</p>
    <ul>
        <li><b>Apache License, Version 2.0</b>: see <a href="./LICENSE-APACHE">LICENSE-APACHE</a></li>
        <li><b>MIT License</b>: see <a href="./LICENSE-MIT">LICENSE-MIT</a></li>
    </ul>
    <p>at your option.</p>
</div>

<div align="center">
  <h2></h2>
  <sup>COPYRIGHT <small>&copy;</small> 2026 <strong>James Gober.</strong></sup>
</div>
