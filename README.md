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
    Signed cookies (keyed BLAKE3) and encrypted cookies (XChaCha20-Poly1305), both through crypt-io, carry small client-held state: the cookie name is bound into the MAC, an optional expiry is enforced by the server, an optional binding ties a value to one session, and key rings rotate in stages so no node of a cluster refuses a cookie another node just made. For outbound clients there is a <code>Set-Cookie</code> parser that follows the user-agent algorithm and a bounded cookie jar that fails closed on domain cookies without a public suffix list. The whole API, with the version of each item, is in <a href="./docs/API.md"><code>docs/API.md</code></a>.
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

### **Signed and encrypted cookies** (features `signed`, `encrypted`)
- **Tamper-evident or private** - `Signer` (keyed BLAKE3, 128-bit tag) keeps the value readable; `Sealer` (XChaCha20-Poly1305, 192-bit random nonce) hides it.
- **Bound to the name, optionally to the session** - a value cannot move to another cookie, and with `sign_bound` or `seal_bound` not to another user either.
- **Server-enforced expiry** - `sign_until` and `seal_until` embed an expiry checked on every request, with a clock-skew allowance for clusters.
- **Key rings for clusters** - one signing key and up to seven others, staged rotation (`accept`, switch, drop), fingerprints to compare rings across nodes, per-purpose subkeys from one master.
- **Precise refusals** - `Rejected` says why (`Malformed`, `UnsupportedVersion`, `UnknownKey`, `BadTag`, `Expired`) with a stable code and a severity hint; tags compared in constant time.

### **Client side** (features `client`, `jar`)
- **User-agent parsing** - `parse_set_cookie` and `cookie_date` follow rfc6265bis sections 5.6 and 5.1.1, so a client sees cookies as a browser does.
- **A jar that refuses supercookies** - without a public suffix list, a `Domain` other than the host is refused; `Secure` cookies cannot be shadowed from plain HTTP; nameless cookies cannot plant a prefixed name.
- **Bounded and portable** - per-domain and total limits with expired-first then least-recently-used eviction; state behind a `JarStore` trait; export and import with a checksum, validated as untrusted input.
- **`SameSite` and partitions** - a request context for cross-site navigations, and partitioned cookies kept to their top-level site.

### **Reliability and safety**
- **No unsafe code** - `#![forbid(unsafe_code)]`.
- **No panics** - every fallible call returns `Result`; fuzzed, property-tested, and covered by one attack test per threat.
- **Secrets never print** - `Debug` shows names and lengths, never values; no `Display` for a value.
- **`no_std`** - the core needs neither `std` nor an allocator; one first-party dependency (parse-net), plus crypt-io behind the crypto features.

---

## Installation

```toml
[dependencies]
cookie-net = "0.6"

# signed and encrypted cookies:
cookie-net = { version = "0.6", features = ["signed", "encrypted"] }

# an outbound client:
cookie-net = { version = "0.6", features = ["jar"] }

# no_std, no allocator:
cookie-net = { version = "0.6", default-features = false }
```

| Feature | Default | Adds |
|---|---|---|
| `std` | yes | implies `alloc`; the clock-reading helpers of later versions |
| `alloc` | through `std` | `SetCookie::encode`, `String`-returning signing |
| `signed` | no | `Key`, `KeyRing`, `Signer` (crypt-io; works without `std` given an allocator) |
| `encrypted` | no | `Sealer`; implies `signed` and `std` |
| `client` | no | `parse_set_cookie`, `cookie_date` (no allocator needed) |
| `jar` | no | `Jar` and its types; implies `client` and `alloc` |

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

### **Signed and encrypted state**

```rust
use cookie_net::{self as cookie, Sealer, Signer};

let now = 1_800_000_000;
let signer = Signer::new(signing_key)?;                       // [u8; 32] from key-vault
let v = signer.sign_until("plan_banner", "dismissed", now + 30 * cookie::DAY)?;
assert_eq!(signer.verify("plan_banner", &v, now)?, "dismissed");

let sealer = Sealer::new(sealing_key)?;
let flash = sealer.seal_until("flash", "Payment received.", now + 60)?;
assert_eq!(sealer.open("flash", &flash, now)?.as_str(), Some("Payment received."));
```

### **An outbound client**

```rust
use cookie_net::{Jar, RequestUrl};

let mut jar = Jar::new();
let url = RequestUrl::https("api.example.com", "/oauth/token");
jar.store(&url, "sid=abc; Path=/; Secure; HttpOnly", now);
let header = jar.cookie_header(&RequestUrl::https("api.example.com", "/v1/orders"), now);   // Some("sid=abc")
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

## Performance

Measured against `cookie`, `biscotti`, and `cookie_store` on the same bytes ([`docs/PERFORMANCE.md`](./docs/PERFORMANCE.md), harness in [cookie-net-bench](https://github.com/jamesgober/cookie-net-bench)):

| Operation | cookie-net faster than the best competitor by |
|---|---|
| reading a credential (`get_unique`, `locate`) | 43 to 50% |
| first match, iteration | 48 to 50% |
| writing `Set-Cookie`, session cookies | 62 to 70% |
| signing, verifying | 47%, 33% |
| client `Set-Cookie` parsing | 36% |
| jar `Cookie` header | 56% |
| sealing, opening | about 4 times **slower** than AES-256-GCM: the cipher; XAES-256-GCM is planned |

## Status: optimisation (`0.6.0`)

**Done:** the request side, the response side, the session helpers (0.3); signed and encrypted cookies with key rings, staged rotation, fingerprints, expiry, and session binding (0.4); the client parser, the cookie-date algorithm, the cookie jar with a store trait and export, and `Clear-Site-Data` for cookie-bomb recovery (0.5). Each rule tested with its source; property, counting-allocator, complexity, and attack tests; test vectors; nine fuzz targets.

**0.6:** measured against `cookie`, `biscotti`, and `cookie_store`; signing, verifying, and reading made 24 to 35% faster with the same output.

**Next:** `0.7` hardening: 24-hour fuzzing of every target, the remaining attack tests, a jar soak, `docs/SECURITY.md`. The schedule is in [`dev/ROADMAP.md`](./dev/ROADMAP.md).

**API stability:** the API was locked at `0.2.0`; names change only with a recorded decision in [`dev/PLAN.md`](./dev/PLAN.md). Performance numbers are targets until `0.6` measures them.

---

## What it is not

- **Sessions** (creation, storage, expiry, rotation, revocation) are gate-net's; cookie-net carries the token.
- **CSRF protection** is csrf-sec's. Its tokens are never double-submit cookies, so there is no CSRF cookie here, on purpose.
- **HTTP framing** is http-net's; the shared field grammar is parse-net's.

---

## Documentation

- **[API Reference](./docs/API.md)** - every public item, its version, errors, and examples
- **[Which cookie, when](./docs/COOKIES.md)** - session tokens, signed and sealed state, `SameSite`, the rotation runbook
- **[Formats](./docs/FORMATS.md)** - the byte-exact signed, sealed, and jar export formats, with test vectors
- **[Architecture](./docs/ARCHITECTURE.md)** - modules, data flow, memory, and bounds
- **[Performance](./docs/PERFORMANCE.md)** - measured numbers, method, and the sealing plan
- **[Security](./docs/SECURITY.md)** - the threat model, each defence, its cost, and the test that proves it
- **[Platform notes](./docs/PLATFORM-NOTES.md)** - what each feature needs, the clock, the random source, constant-time code
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
