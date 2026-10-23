# cookie-net - API Reference

> Reference for every public item in `cookie-net`, with signatures, behaviour, the errors each item can return, and examples.
> **Current release: `0.6.0` (optimisation).** This document, locked at `0.2.0`, is the contract for `0.3.0` to `1.0.0`. Each item carries the version that ships it; items marked with a later version than the current release are specified here and not yet in the crate. Names and signatures do not change after `0.2.0` without a decision-log entry in [`../dev/PLAN.md`](../dev/PLAN.md).

<sub>Copyright &copy; 2026 <strong>James Gober</strong>.</sub>

## Table of contents

- [Conventions](#conventions)
  - [Grades, tiers, versions](#grades-tiers-versions)
  - [Inputs and outputs](#inputs-and-outputs)
  - [Time](#time)
  - [Secrets never print](#secrets-never-print)
  - [Feature flags](#feature-flags)
- [Tier 1 at a glance](#tier-1-at-a-glance)
- [Crate root](#crate-root)
  - [`VERSION`](#version)
  - [Lifetime constants](#lifetime-constants)
  - [`CLEAR_SITE_DATA_COOKIES`](#clear_site_data_cookies)
- [Errors](#errors)
  - [`CookieError`](#cookieerror)
  - [`Ambiguous`](#ambiguous)
  - [`Rejected`](#rejected)
- [Limits](#limits)
  - [`Limits`](#limits-1)
  - [`ValueMode`](#valuemode)
- [Reading the `Cookie` header](#reading-the-cookie-header)
  - [`parse`](#parse)
  - [`get`](#get)
  - [`get_unique`](#get_unique)
  - [`get_all`](#get_all)
  - [`Cookies`](#cookies)
  - [`Pair`](#pair)
  - [`Stats`](#stats)
  - [`Lookup` and `Located`](#lookup-and-located)
  - [`Prefix`](#prefix)
  - [The parsing algorithm](#the-parsing-algorithm)
- [Writing `Set-Cookie`](#writing-set-cookie)
  - [`SetCookie`](#setcookie)
  - [`SetCookieBuilder`](#setcookiebuilder)
  - [`SameSite`](#samesite)
  - [Rules checked by `build`](#rules-checked-by-build)
  - [Serialization](#serialization)
- [Session cookies](#session-cookies)
  - [`session_cookie`](#session_cookie)
  - [`elevated_cookie`](#elevated_cookie)
  - [Ending a session](#ending-a-session)
- [Keys](#keys)
  - [`Key`](#key)
  - [`KeyId`, `KeyRole`, `KeyInfo`, `KeyFingerprint`](#keyid-keyrole-keyinfo-keyfingerprint)
  - [`KeyRing`](#keyring)
  - [Rotating keys across a cluster](#rotating-keys-across-a-cluster)
- [Signed cookies](#signed-cookies)
  - [`Signer`](#signer)
  - [`Verified`](#verified)
  - [Signed format v1](#signed-format-v1)
- [Encrypted cookies](#encrypted-cookies)
  - [`Sealer`](#sealer)
  - [`Plaintext`](#plaintext)
  - [`Opened`](#opened)
  - [Sealed format v1](#sealed-format-v1)
- [Verification order and severity](#verification-order-and-severity)
- [Client side: `Set-Cookie` and dates](#client-side-set-cookie-and-dates)
  - [`parse_set_cookie`](#parse_set_cookie)
  - [`SetCookieView`](#setcookieview)
  - [`SameSiteAttr`](#samesiteattr)
  - [`cookie_date`](#cookie_date)
- [Client cookie jar](#client-cookie-jar)
  - [`Jar`](#jar)
  - [`RequestUrl` and `RequestContext`](#requesturl-and-requestcontext)
  - [`PublicSuffix` and `NoSuffixList`](#publicsuffix-and-nosuffixlist)
  - [`JarLimits`](#jarlimits)
  - [`StoreOutcome` and `IgnoreReason`](#storeoutcome-and-ignorereason)
  - [`JarStore` and `MemoryStore`](#jarstore-and-memorystore)
- [Thread safety and sizes](#thread-safety-and-sizes)
- [Use cases](#use-cases)
  - [WASP gateway: the credential locator](#wasp-gateway-the-credential-locator)
  - [Login, rolling tokens, logout](#login-rolling-tokens-logout)
  - [Preferences and flash messages](#preferences-and-flash-messages)
  - [HTTP/2 cookie crumbs](#http2-cookie-crumbs)
  - [An outbound client](#an-outbound-client)
- [Item index](#item-index)

---

## Conventions

### Grades, tiers, versions

Every item has an id (`REQ-3`), a **grade**, a **tier**, and the **version** that ships it.

| Grade | Meaning |
|---|---|
| P0 | the crate's job cannot be done without it |
| P1 | what users of the best cookie libraries expect |
| P2 | strongly wanted by serious users (enterprise, high traffic, security) |
| P3 | after 1.0 is acceptable |

| Tier | Meaning |
|---|---|
| 1 | one plain call: a free function or a one-line constructor, no configuration |
| 2 | configuration and richer views for the next 15% of uses |
| 3 | the full allocation-free surface, for other libraries and the WASP gateway |

The convention in every example is `use cookie_net as cookie;`. The **Cost** columns are the plan's targets, marked [est.]; measured numbers are in [`PERFORMANCE.md`](./PERFORMANCE.md).

### Inputs and outputs

- **Header input** is one `Cookie` field value without its name, as any `&[u8]`-like value: `&[u8]`, `&str`, `&Vec<u8>`, `&String`, `&[u8; N]` (every reading function takes `&H where H: AsRef<[u8]> + ?Sized`). Leading and trailing SP and HTAB are ignored.
- **Names and values come back as `&str`**, borrowed from the header. In the default strict mode every accepted byte is a `cookie-octet` or `tchar`, so a value is always ASCII. Lenient mode ([`ValueMode`](#valuemode)) accepts more bytes and still returns `&str`: a value that is not valid UTF-8 is skipped and counted like any other bad pair.
- **Names are compared byte for byte.** No trimming beyond SP and HTAB around a pair, no case folding, no percent-decoding, no Unicode normalization. `__HOST-sid`, `%5F_Host-sid` and `\u{a0}__Host-sid` are never `__Host-sid` (threats T6, T8, T9 in [`../dev/PLAN.md`](../dev/PLAN.md#9-threats)).
- **Quotes are part of a value.** `a="1"` has the value `"1"`, three bytes (rfc6265bis section 4.1.1). [`Pair::value_unquoted`](#pair) removes one surrounding pair when the caller wants that.
- **Writing goes into a [`parse_net::Sink`](https://docs.rs/parse-net/latest/parse_net/trait.Sink.html)**: a `parse_net::SliceSink` over a stack buffer, a `Vec<u8>` (with `alloc`), or any type of the caller's. A `SetCookie` that exists is valid, so writing it fails only with `CookieError::Full`, and a `SliceSink` holds exactly what it held before after an error.

### Time

Every time is **whole seconds since the Unix epoch, as `u64`**, passed in by the caller: the core never reads a clock (sans-IO). With the `std` feature, `*_now` functions read `SystemTime` for you. Only the client-side [`cookie_date`](#cookie_date) returns `i64`, because the cookie-date algorithm accepts years from 1601.

### Secrets never print

A cookie value can be a bearer token (`__Host-sid`), and a sealed cookie's plaintext is private by definition. So:

- `Debug` on `Pair`, `Cookies`, `Lookup`, `Located`, `SetCookie`, `SetCookieBuilder`, `Verified`, `Plaintext`, `SetCookieView`, `Jar`, and `Key` prints names, lengths, and attributes, never value bytes or key bytes.
- No type implements `Display` for its value. `SetCookie` is turned into bytes only by the explicit [`encode`](#setcookie) family, so `format!("{cookie}")` cannot put a token into a log line.
- Errors carry positions and fixed text, never input bytes.

### Feature flags

| Feature | Default | Adds | Needs |
|---|---|---|---|
| `std` | **yes** | `*_now` functions that read the system clock; implies `alloc` | `std` |
| `alloc` | through `std` | `SetCookie::encode` and the `String`-returning `sign*` and `seal*` functions; `Sink for Vec<u8>` through parse-net | an allocator |
| (no features) | | the request side, the response side, the session helpers, errors, limits: `no_std`, no allocator | parse-net |
| `signed` | no | `Key`, `KeyRing`, `Signer`, and their types | crypt-io (`mac-blake3`, `kdf-hkdf`, `zeroize`); an allocator must exist, because crypt-io links `alloc` (cookie-net's own signing code allocates nothing) |
| `encrypted` | no | `Sealer`, `Plaintext`, `Opened`; implies `signed` and `std` | crypt-io `aead-chacha20` and its OS random source |
| `client` | no | `parse_set_cookie`, `SetCookieView`, `SameSiteAttr`, `cookie_date` | nothing more (`no_std`, no allocator) |
| `jar` | no | `Jar` and its types; implies `client` and `alloc` | |

`no_std` users write `cookie-net = { version = "0.3", default-features = false }`. The README and every example assume the default (`std`).

---

## Tier 1 at a glance

```rust
use cookie_net as cookie;

// Reading: the credential, a preference, every pair
let sid = cookie::get_unique(header, "__Host-sid")?;        // Option<&str>; Err if planted twice
let theme = cookie::get(header, "theme");                    // Option<&str>, first match
for pair in cookie::parse(header) {
    println!("{} ({} bytes)", pair.name(), pair.value().len());   // never log the value
}

// Writing
let set = cookie::SetCookie::new("theme", "dark")?;          // Secure; HttpOnly; SameSite=Lax; Path=/
response.header("set-cookie", set.encode());
let login = cookie::session_cookie("__Host-sid", &token, 12 * cookie::HOUR)?;
let logout = cookie::SetCookie::delete("__Host-sid")?;

// Signed and encrypted (features "signed", "encrypted")
let signer = cookie::Signer::new(signing_key)?;              // [u8; 32]
let value = signer.sign("prefs", "lang=fr")?;                // readable, tamper-evident
let prefs = signer.verify("prefs", raw, now)?;               // &str, or Rejected
let sealer = cookie::Sealer::new(sealing_key)?;
let flash = sealer.seal_until("flash", "Saved.", now + 5 * cookie::MINUTE)?;
let text = sealer.open("flash", raw, now)?;                  // Plaintext, wiped on drop
```

Every Tier 1 line above is one call with no configuration. Everything else in this document is Tier 2 or 3.

---

## Crate root

### `VERSION`

```rust
pub const VERSION: &str;
```

The crate version, populated by Cargo at build time.

```rust
println!("cookie-net {}", cookie_net::VERSION);
```

| Id | Grade | Tier | Ver |
|---|---|---|---|
| ROOT-1 | P0 | 1 | 0.1 |

### Lifetime constants

```rust
pub const MINUTE: u64 = 60;
pub const HOUR: u64 = 3_600;
pub const DAY: u64 = 86_400;
pub const MAX_LIFETIME: u64 = 34_560_000;   // 400 days, the rfc6265bis section 5.5 cap
```

Seconds, so lifetimes read as what they mean: `12 * HOUR`, `now + 5 * MINUTE`. They are `u64` like every time in the crate.

```rust
use cookie_net as cookie;

let c = cookie::SetCookie::builder("theme", "dark").max_age(30 * cookie::DAY).build()?;
assert_eq!(c.max_age(), Some(2_592_000));
# Ok::<(), cookie::CookieError>(())
```

| Id | Grade | Tier | Ver |
|---|---|---|---|
| ROOT-2 | P1 | 1 | 0.3 |

### `CLEAR_SITE_DATA_COOKIES`

```rust
pub const CLEAR_SITE_DATA_COOKIES: &str = "\"cookies\"";
```

The value of a `Clear-Site-Data` response header that tells the browser to drop every cookie for the site (W3C Clear Site Data). It is the recovery for cookie bombing (threat T5): when [`get_unique`](#get_unique) reports `Truncated` or `HeaderTooLong`, answer with this header and the user can sign in again. The server-side session is not affected. The caller decides when to send it; cookie-net never does.

```rust
use cookie_net as cookie;

if let Err(cookie::Ambiguous::Truncated | cookie::Ambiguous::HeaderTooLong) = cookie::get_unique(header, "__Host-sid") {
    response.header("clear-site-data", cookie::CLEAR_SITE_DATA_COOKIES);
}
```

| Id | Grade | Tier | Ver | Cost |
|---|---|---|---|---|
| SES-4 | P2 | 1 | 0.5 | none |

---

## Errors

### `CookieError`

```rust
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CookieError {
    // names and values (rfc6265bis section 4.1.1)
    EmptyName,
    InvalidName { at: u16 },
    InvalidValue { at: u16 },
    TooLarge,
    TokenTooShort,
    // attributes
    AttributeTooLong,
    InvalidPath { at: u16 },
    InvalidDomain,
    InvalidExtension { at: u16 },
    ExtensionNotAllowed,
    TooManyExtensions,
    MaxAgeOutOfRange,
    ExpiresOutOfRange,
    // rules between attributes
    HostPrefix,
    SecurePrefix,
    SameSiteNoneNeedsSecure,
    PartitionedNeedsSecure,
    // reading and writing
    HeaderTooLong,
    Full,
    // keys, signing, sealing
    WeakKey,
    KeyTooShort,
    ContextTooLong,
    DuplicateKeyId,
    RingFull,
    InvalidRetireTime,
    Crypto,
    // the client jar
    InvalidJarData,
    // conversions so `?` works everywhere
    Ambiguous(Ambiguous),
    Rejected(Rejected),
}

impl CookieError {
    pub const fn code(self) -> &'static str;
}
impl core::fmt::Display for CookieError {}
impl core::error::Error for CookieError {}
impl From<Ambiguous> for CookieError {}
impl From<Rejected> for CookieError {}
impl From<parse_net::Full> for CookieError {}
```

One error type for every fallible call, so `?` works in a handler that returns `Result<_, CookieError>`. Every variant exists in every feature combination (no `cfg` in a `match`). `at` is a byte offset into the input that was refused.

| Variant | Returned when | What to do |
|---|---|---|
| `EmptyName` | a cookie name is empty (servers must not produce nameless cookies, rfc6265bis section 4.1.1) | give the cookie a name |
| `InvalidName { at }` | a name byte is not a `tchar`: SP, HTAB, CR, LF, `;`, `=`, `,`, `"`, `(`, `)`, `[`, `]`, `@`, `:`, `/`, `\`, `?`, `{`, `}`, any control, any byte above 0x7E | use letters, digits, and ``!#$%&'*+-.^_`|~`` |
| `InvalidValue { at }` | a value byte is not a `cookie-octet` (CTL, SP, `"` inside, `,`, `;`, `\`, any byte above 0x7E), or a value opens a quote it does not close | encode the value first (base64url, or percent-encoding through url-lib) |
| `TooLarge` | name plus value is over 4096 bytes (rfc6265bis sections 5.6 and 5.7: user agents ignore the cookie); for signed and sealed values, the encoded result is | store less in the cookie; keep large state on the server |
| `TokenTooShort` | a session or elevated token is shorter than 22 bytes (128 bits in base64url) | pass the session token, not a user id or an empty string |
| `AttributeTooLong` | a `Path`, `Domain`, or extension value is over 1024 bytes (rfc6265bis section 5.6: user agents ignore it) | shorten it |
| `InvalidPath { at }` | `Path` does not start with `/`, or holds a CTL or `;` (`path-value`, section 4.1.1) | pass an absolute path such as `/app` |
| `InvalidDomain` | `Domain` is not a host name of LDH labels with at least one dot: a leading dot, a single label (`localhost`, `com`), an IP literal, an empty label, a label over 63 bytes | pass the bare registrable domain (`example.com`), or leave `Domain` unset for a host-only cookie |
| `InvalidExtension { at }` | an extension attribute holds a CTL or `;` (`extension-av`, section 4.1.1), is empty, or its name (the part before `=`) is not a `token` | use a token name such as `Priority=High` |
| `ExtensionNotAllowed` | an extension attribute is named like a defined one (`Expires`, `Max-Age`, `Domain`, `Path`, `Secure`, `HttpOnly`, `SameSite`, `Partitioned`, any case) | use the typed setter instead |
| `TooManyExtensions` | more than 8 extension attributes | use fewer |
| `MaxAgeOutOfRange` | `Max-Age` is 0 or over 34,560,000 (400 days, section 5.5); for `elevated_cookie`, outside 60 to 3600 | use `delete` to remove a cookie; cap lifetimes at `MAX_LIFETIME` |
| `ExpiresOutOfRange` | `Expires` is more than 400 days after the `now` given; a signed or sealed expiry is before 2020-01-01 or after 2156 (a time in milliseconds, say) | pass seconds, within 400 days |
| `HostPrefix` | the name starts with `__Host-` (any case) without `Secure`, with a `Path` other than `/`, or with `Domain` (sections 4.1.3.2 and 5.4); `session_cookie` and `elevated_cookie` with a name that does not start with `__Host-` | keep the defaults; do not call `insecure`, `path`, or `domain` |
| `SecurePrefix` | the name starts with `__Secure-` (any case) without `Secure` (section 4.1.3.1) | do not call `insecure` |
| `SameSiteNoneNeedsSecure` | `SameSite=None` without `Secure` (section 5.7: the cookie is ignored) | do not call `insecure` |
| `PartitionedNeedsSecure` | `Partitioned` without `Secure` (draft-cutler-httpbis-partitioned-cookies sections 2.3 and 3.1) | do not call `insecure` |
| `HeaderTooLong` | `Cookies::with_limits` or `Cookies::from_lines` got more bytes than `Limits::max_header_len` | answer `431`, or raise the limit |
| `Full` | the sink has no room | give a larger buffer; `encoded_len` says how large |
| `WeakKey` | all 32 key bytes are equal (an unset or zeroed key) | load the real key |
| `KeyTooShort` | `Key::derive` got a master shorter than 32 bytes | use a 32-byte or longer master |
| `ContextTooLong` | `Key::derive` got a context over 200 bytes | use a short service name |
| `DuplicateKeyId` | two keys in a ring share an id | give every key its own id |
| `RingFull` | a ring holds more than 8 keys, or no signing key (all removed with `without`) | drop retired keys past their time with `KeyRing::without`; keep one signing key |
| `InvalidRetireTime` | a retire time is after 2156 (a time in milliseconds, say) | pass seconds |
| `Crypto` | crypt-io reported a failure, such as the OS random source failing while sealing (fail closed: nothing was written) | retry; alert if it repeats |
| `InvalidJarData` | `Jar::import` got bytes with a wrong magic, version, checksum, length, or field; nothing was imported | export again; never edit the bytes |
| `Ambiguous(_)`, `Rejected(_)` | only through `?` on [`Ambiguous`](#ambiguous) and [`Rejected`](#rejected) | see those types |

`code()` returns a stable snake_case identifier (`"host_prefix"`, `"invalid_value"`, `"ambiguous.duplicate"`, `"rejected.bad_tag"`) for metrics and events. Codes never change within a major version. When the stack's error-code library (error-core) is published, a mapping to its numbered codes is added behind a feature, without changing these strings.

`Display` prints fixed text with the offset, never input bytes: `cookie value: byte 3 is not allowed (rfc6265bis 4.1.1)`.

```rust
use cookie_net::{CookieError, SetCookie};

assert_eq!(SetCookie::new("sid", "a;Domain=evil.example").unwrap_err(), CookieError::InvalidValue { at: 1 });
assert_eq!(SetCookie::new("", "x").unwrap_err(), CookieError::EmptyName);
assert_eq!(CookieError::HostPrefix.code(), "host_prefix");
```

| Id | Item | Grade | Tier | Ver |
|---|---|---|---|---|
| ERR-1 | `CookieError` and its variants | P0 | 1 | 0.3; the key variants (`WeakKey` to `Crypto`) and `Rejected(_)` since 0.4 |
| ERR-3 | `Display`, `Error`, `From` conversions | P0 | 1 | 0.3 |
| ERR-4 | `code` | P1 | 2 | 0.3 |

### `Ambiguous`

```rust
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Ambiguous {
    Duplicate { count: u16 },   // the name appears `count` times (2 or more)
    Truncated,                  // more than `max_pairs` pairs: a duplicate could hide past the limit
    HeaderTooLong,              // over `max_header_len`: nothing was read
}
impl Ambiguous { pub const fn code(self) -> &'static str; }
impl core::fmt::Display for Ambiguous {}
impl core::error::Error for Ambiguous {}
```

Why [`get_unique`](#get_unique) could not give one answer. For a credential every variant means "treat the request as signed out". A `__Host-` name can exist only once per host, so `Duplicate` on one is a planted cookie (threats T3, T7), not a glitch.

```rust
use cookie_net::{self as cookie, Ambiguous};

let h = "__Host-sid=real; theme=dark; __Host-sid=planted";
assert_eq!(cookie::get_unique(h, "__Host-sid"), Err(Ambiguous::Duplicate { count: 2 }));
assert_eq!(cookie::get_unique(h, "theme"), Ok(Some("dark")));
assert_eq!(cookie::get_unique(h, "lang"), Ok(None));
```

| Id | Grade | Tier | Ver |
|---|---|---|---|
| ERR-2 | P0 | 1 | 0.3 |

### `Rejected`

```rust
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Rejected {
    Malformed,            // wrong length, bad base64url, non-canonical encoding
    UnsupportedVersion,   // a format version this build does not know
    UnknownKey,           // the key id is not in the ring, or its retire time has passed
    BadTag,               // forged, altered, moved from another cookie name, or bound to another session
    Expired,              // the embedded expiry has passed (plus the skew allowance)
}
impl Rejected {
    pub const fn code(self) -> &'static str;
    pub const fn severity_hint(self) -> u8;
}
impl core::fmt::Display for Rejected {}
impl core::error::Error for Rejected {}
```

Why a signed or sealed cookie was refused. Clients never learn the reason: treat every `Rejected` as "cookie absent", and report the reason as an event.

| Variant | Most likely | `severity_hint` (0 to 40, higher is worse; the scale WASP's gates use) |
|---|---|---|
| `Malformed` | tampering or truncation | 10 |
| `UnsupportedVersion` | tampering, or a cookie from a newer deployment | 5 |
| `UnknownKey` | an old cookie after its key left the ring | 1 |
| `BadTag` | forgery, or a value moved between names or sessions | 40 |
| `Expired` | an old tab, or client clock games | 1 |

```rust
use cookie_net::Rejected;

assert_eq!(Rejected::BadTag.severity_hint(), 40);
assert_eq!(Rejected::Expired.code(), "expired");
```

| Id | Grade | Tier | Ver |
|---|---|---|---|
| SGN-6 | P0 | 2 | 0.4 |

---

## Limits

### `Limits`

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Limits { /* private */ }

impl Limits {
    pub const DEFAULT: Limits;
    pub const fn new() -> Limits;                                   // DEFAULT
    pub const fn max_header_len(self, bytes: usize) -> Limits;      // 1 to 65,536; default 8,192
    pub const fn max_pairs(self, n: u16) -> Limits;                 // 1 to 1,024; default 64
    pub const fn max_name_len(self, bytes: u16) -> Limits;          // 1 to 4,096; default 256
    pub const fn max_value_len(self, bytes: u16) -> Limits;         // 0 to 4,096; default 4,096
    pub const fn value_mode(self, mode: ValueMode) -> Limits;       // default Strict
    pub const fn header_len(&self) -> usize;   // the getters, same names without `max_`
    pub const fn pairs(&self) -> u16;
    pub const fn name_len(&self) -> u16;
    pub const fn value_len(&self) -> u16;
    pub const fn mode(&self) -> ValueMode;
}
impl Default for Limits {}
```

Budgets for reading a `Cookie` header. Each one is checked before the work it governs: the header length before any scan, the pair count as pairs are accepted. A value outside a setter's range is brought to the nearest end of the range (a `const` setter cannot fail); the getters show what is in force. `max_name_len` plus `max_value_len` never lets a pair over 4096 bytes through, whatever the settings (rfc6265bis section 5.6).

| Bound | Default | Why |
|---|---|---|
| header length, all lines together | 8,192 bytes | common front-end limits [est.]; decision CN-10 |
| pairs | 64 | above typical per-site counts [est.] |
| name length | 256 bytes | [est.] |
| value length | 4,096 bytes | the rfc6265bis name-plus-value limit |

```rust
use cookie_net::{Cookies, Limits, ValueMode};

const STRICT_SMALL: Limits = Limits::DEFAULT.max_header_len(4096).max_pairs(16);
const THIRD_PARTY_FRIENDLY: Limits = Limits::DEFAULT.value_mode(ValueMode::Lenient);

let cookies = Cookies::with_limits("a=1; b=2", &STRICT_SMALL)?;
assert_eq!(cookies.iter().count(), 2);
assert_eq!(Limits::DEFAULT.max_pairs(5000).pairs(), 1024);
# Ok::<(), cookie_net::CookieError>(())
```

| Id | Grade | Tier | Ver | Cost |
|---|---|---|---|---|
| LIM-1 | P0 | 2 | 0.3 | n/a |

### `ValueMode`

```rust
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub enum ValueMode {
    #[default] Strict,   // *cookie-octet, or DQUOTE *cookie-octet DQUOTE (rfc6265bis section 4.2.1)
    Lenient,             // any byte except CTL (HTAB allowed) and ';', and valid UTF-8
}
```

Strict is the default (decision CN-5): cookie-net's own cookies are always `cookie-octet`s. Lenient matches what user agents store when a page's scripts write JSON or spaces into `document.cookie`; use it on hosts that share cookies with third-party scripts. Names are `token`s in both modes.

```rust
use cookie_net::{Cookies, Limits, ValueMode};

let h = r#"consent={"ads":false}; sid=abc"#;
assert_eq!(Cookies::new(h).get("consent"), None);   // strict: skipped and counted
let lenient = Cookies::with_limits(h, &Limits::DEFAULT.value_mode(ValueMode::Lenient))?;
assert_eq!(lenient.get("consent"), Some(r#"{"ads":false}"#));
# Ok::<(), cookie_net::CookieError>(())
```

| Id | Grade | Tier | Ver |
|---|---|---|---|
| LIM-2 | P1 | 2 | 0.3 |

---

## Reading the `Cookie` header

### `parse`

```rust
pub fn parse<H: AsRef<[u8]> + ?Sized>(header: &H) -> Cookies<'_>;
```

Every pair in the header, with `Limits::DEFAULT`. Never fails: a header over the length limit yields no pairs and `stats().too_long` is `true`; pairs that break the grammar are skipped and counted (decision D-003: one stale cookie must not lock a user out). Order is the header's order, which is the browser's (longer paths first, then older cookies), but rfc6265bis section 4.2.2 says servers SHOULD NOT rely on it.

```rust
use cookie_net as cookie;

let names: Vec<&str> = cookie::parse("a=1; bad name=2; b=").iter().map(|p| p.name()).collect();
assert_eq!(names, ["a", "b"]);
assert_eq!(cookie::parse("a=1; bad name=2; b=").stats().skipped, 1);
```

| Id | Grade | Tier | Ver | Cost [est.] |
|---|---|---|---|---|
| REQ-1 | P0 | 1 | 0.3 | 5 ns per pair plus 0.3 ns per byte |

### `get`

```rust
pub fn get<'a, H: AsRef<[u8]> + ?Sized>(header: &'a H, name: &str) -> Option<&'a str>;
```

The value of the first pair named exactly `name`, byte for byte. Stops at the first match. For preferences and other cookies where a duplicate does no harm; for credentials use [`get_unique`](#get_unique).

```rust
use cookie_net as cookie;

assert_eq!(cookie::get("theme=dark; lang=fr", "lang"), Some("fr"));
assert_eq!(cookie::get("Theme=dark", "theme"), None);           // names are case-sensitive
assert_eq!(cookie::get("a=\"1\"", "a"), Some("\"1\""));        // quotes are part of the value
```

| Id | Grade | Tier | Ver | Cost [est.] |
|---|---|---|---|---|
| REQ-2 | P0 | 1 | 0.3 | 10 ns (300-byte header, 6 pairs, target 3rd) |

### `get_unique`

```rust
pub fn get_unique<'a, H: AsRef<[u8]> + ?Sized>(header: &'a H, name: &str) -> Result<Option<&'a str>, Ambiguous>;
```

The value of the only pair named `name`: `Ok(None)` when there is none, [`Ambiguous`](#ambiguous) when there are two or more, when the pair limit cut the scan short, or when the header is too long. Scans the whole header, because a duplicate can be anywhere. Use it for every credential and for any cookie whose duplicate means an attack.

```rust
use cookie_net::{self as cookie, Ambiguous};

assert_eq!(cookie::get_unique("__Host-sid=t0k3n; theme=dark", "__Host-sid"), Ok(Some("t0k3n")));
// a sibling subdomain planted `sid` with Domain=example.com: a different name, so no effect
assert_eq!(cookie::get_unique("sid=evil; __Host-sid=t0k3n", "__Host-sid"), Ok(Some("t0k3n")));
// two values for one `__Host-` name can only be an attack
assert_eq!(cookie::get_unique("__Host-sid=a; __Host-sid=b", "__Host-sid"), Err(Ambiguous::Duplicate { count: 2 }));
```

| Id | Grade | Tier | Ver | Cost [est.] |
|---|---|---|---|---|
| REQ-3 | P0 | 1 | 0.3 | 25 ns (300 bytes, 6 pairs), the full scan |

### `get_all`

```rust
pub fn get_all<'a, 'n, H: AsRef<[u8]> + ?Sized>(header: &'a H, name: &'n str) -> GetAll<'a, 'n>;
pub struct GetAll<'a, 'n> { /* private */ }
impl<'a> Iterator for GetAll<'a, '_> { type Item = &'a str; }
```

Every value of `name`, in header order, for cookies that legitimately repeat (one name set on several paths).

```rust
use cookie_net as cookie;

let v: Vec<&str> = cookie::get_all("cart=2; theme=dark; cart=1", "cart").collect();
assert_eq!(v, ["2", "1"]);
```

| Id | Grade | Tier | Ver | Cost |
|---|---|---|---|---|
| REQ-4 | P1 | 1 | 0.3 | as REQ-1 |

### `Cookies`

```rust
#[derive(Clone, Copy)]
pub struct Cookies<'a> { /* header or lines, limits */ }

impl<'a> Cookies<'a> {
    pub fn new<H: AsRef<[u8]> + ?Sized>(header: &'a H) -> Cookies<'a>;      // what `parse` returns
    pub fn with_limits<H: AsRef<[u8]> + ?Sized>(header: &'a H, limits: &Limits) -> Result<Cookies<'a>, CookieError>;
    pub fn from_lines(lines: &'a [&'a [u8]], limits: &Limits) -> Result<Cookies<'a>, CookieError>;
    pub fn iter(&self) -> Iter<'a>;
    pub fn get(&self, name: &str) -> Option<&'a str>;
    pub fn get_unique(&self, name: &str) -> Result<Option<&'a str>, Ambiguous>;
    pub fn get_all<'n>(&self, name: &'n str) -> GetAll<'a, 'n>;
    pub fn locate(&self, name: &str) -> Located<'a>;
    pub fn scan(&self, f: impl FnMut(Pair<'a>) -> core::ops::ControlFlow<()>) -> Stats;
    pub fn stats(&self) -> Stats;
    pub fn is_empty(&self) -> bool;
}
impl<'a> IntoIterator for Cookies<'a> { type Item = Pair<'a>; type IntoIter = Iter<'a>; }
impl<'a> IntoIterator for &Cookies<'a> { type Item = Pair<'a>; type IntoIter = Iter<'a>; }
pub struct Iter<'a> { /* private */ }
impl<'a> Iterator for Iter<'a> { type Item = Pair<'a>; }
impl core::fmt::Debug for Cookies<'_> {}   // pair count and names only
```

A `Cookie` header and the limits to read it with. It is a small `Copy` view; nothing is stored or allocated. Each `iter`, `get`, or `stats` re-scans the header, which costs less than keeping spans for the usual 1 to 10 pairs [est.].

- `with_limits` returns `HeaderTooLong` before scanning anything.
- `from_lines` treats several `Cookie` field lines as one header joined by `"; "`, without copying. HTTP/2 splits the header into such "crumbs" (RFC 9113 section 8.2.3); the lengths are summed for `max_header_len`, and an empty line adds nothing.
- `scan` makes one pass and calls `f` for each accepted pair; `ControlFlow::Break(())` stops early. The returned `Stats` count the pairs seen up to that point.
- `locate` is the one-pass credential lookup the WASP gateway uses ([`Located`](#lookup-and-located)).

```rust
use cookie_net::{Cookies, Limits};

let lines: [&[u8]; 2] = [b"__Host-sid=t0k3n", b"theme=dark"];
let cookies = Cookies::from_lines(&lines, &Limits::DEFAULT)?;
assert_eq!(cookies.get_unique("__Host-sid")?, Some("t0k3n"));
assert_eq!(cookies.iter().count(), 2);
# Ok::<(), cookie_net::CookieError>(())
```

```rust
use core::ops::ControlFlow;
use cookie_net::Cookies;

let mut analytics = 0;
let stats = Cookies::new("_ga=1; _gid=2; sid=x").scan(|pair| {
    if pair.name().starts_with('_') { analytics += 1; }
    ControlFlow::Continue(())
});
assert_eq!((analytics, stats.pairs), (2, 3));
```

| Id | Item | Grade | Tier | Ver | Cost [est.] |
|---|---|---|---|---|---|
| REQ-1 | `Cookies::new`, `iter`, `Iter` | P0 | 1 | 0.3 | as `parse` |
| REQ-5 | `with_limits` | P0 | 2 | 0.3 | 1 ns before the scan |
| REQ-8 | `from_lines` | P1 | 2 | 0.3 | as REQ-1 |
| REQ-9 | `scan` | P1 | 3 | 0.3 | 4 ns per pair |
| REQ-12 | `Debug` redaction | P0 | 2 | 0.3 | n/a |

### `Pair`

```rust
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Pair<'a> { /* name, value */ }

impl<'a> Pair<'a> {
    pub const fn name(&self) -> &'a str;
    pub const fn value(&self) -> &'a str;            // quotes included when present
    pub fn value_unquoted(&self) -> &'a str;         // without one surrounding DQUOTE pair
    pub fn prefix(&self) -> Prefix;
}
impl core::fmt::Debug for Pair<'_> {}                // `Pair { name: "sid", value: 43 bytes }`
```

One accepted cookie pair, borrowed from the header.

```rust
use cookie_net::{self as cookie, Prefix};

let pair = cookie::parse("__Host-sid=\"t0k3n\"").iter().next().unwrap();
assert_eq!((pair.name(), pair.value(), pair.value_unquoted()), ("__Host-sid", "\"t0k3n\"", "t0k3n"));
assert_eq!(pair.prefix(), Prefix::Host);
assert_eq!(format!("{pair:?}"), r#"Pair { name: "__Host-sid", value: 7 bytes }"#);
```

| Id | Item | Grade | Tier | Ver | Cost [est.] |
|---|---|---|---|---|---|
| REQ-1 | `name`, `value` | P0 | 1 | 0.3 | n/a |
| REQ-10 | `value_unquoted`, `prefix` | P1 | 2 | 0.3 | 1 ns |
| REQ-12 | `Debug` redaction | P0 | 2 | 0.3 | n/a |

### `Stats`

```rust
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct Stats {
    pub pairs: u16,                 // accepted
    pub skipped: u16,               // broke the grammar or a length limit (not empty pairs)
    pub empty: u16,                 // ";;" or a trailing ';'
    pub loose_separators: u16,      // ';' without one SP after it, or with more whitespace
    pub prefixed_duplicates: u16,   // extra occurrences of `__Host-` or `__Secure-` names (first 16 distinct names tracked)
    pub truncated: bool,            // stopped at `max_pairs`
    pub too_long: bool,             // over `max_header_len`: nothing was read
}
```

Facts for customs-sec and sentinel-sec. Computing them is part of the scan; `prefixed_duplicates` is found in linear time (decision D-039), never by comparing every pair with every other.

```rust
use cookie_net as cookie;

let s = cookie::parse("a=1;b=2; ; bad name=3; __Host-x=1; __Host-x=2").stats();
assert_eq!((s.pairs, s.skipped, s.empty, s.loose_separators, s.prefixed_duplicates), (4, 1, 1, 1, 1));
```

| Id | Grade | Tier | Ver | Cost |
|---|---|---|---|---|
| REQ-6 | P1 | 2 | 0.3 | part of the scan; prefixed-duplicate check under 1 ns per prefixed pair [est.] |

### `Lookup` and `Located`

```rust
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Lookup<'a> {
    Missing,
    One(&'a str),
    Many { first: &'a str, count: u16 },
    Truncated,
    HeaderTooLong,
}

#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Located<'a> {
    pub lookup: Lookup<'a>,
    pub shadows: u16,   // pairs whose name differs from the target only by case or by a prefix
    pub stats: Stats,
}
impl Located<'_> {
    pub const fn severity_hint(&self) -> u8;
}
impl core::fmt::Debug for Lookup<'_> {}    // values shown as lengths
impl core::fmt::Debug for Located<'_> {}

pub fn locate<'a, H: AsRef<[u8]> + ?Sized>(header: &'a H, name: &str, limits: &Limits) -> Located<'a>;
```

Everything the gateway needs about one credential cookie, in one pass with no allocation. `lookup` is the answer; `get_unique` is `lookup` reduced to a `Result`.

`shadows` counts **shadow names**: pairs whose name is not `name` but equals it, ignoring ASCII case, once a `__Host-` or `__Secure-` prefix is removed from either side. For `__Host-sid` that is `__host-sid`, `__HOST-SID`, `sid`, `SID`, `__Secure-sid`. cookie-net never sets those names, so their presence is evidence of a cookie-tossing attempt or a prefix-bypass probe (decision D-040, the 0.3 defence idea).

`severity_hint` (0 to 40, higher is worse): `One` with no shadows 0; `Missing` 0; `Many` on a prefixed name 30, on another name 10; `Truncated` or `HeaderTooLong` 10; plus 5 when `shadows > 0`, capped at 40.

```rust
use cookie_net::{self as cookie, Limits, Lookup};

let found = cookie::locate("sid=evil; __Host-sid=t0k3n", "__Host-sid", &Limits::DEFAULT);
assert_eq!(found.lookup, Lookup::One("t0k3n"));
assert_eq!(found.shadows, 1);
assert_eq!(found.severity_hint(), 5);
```

| Id | Item | Grade | Tier | Ver | Cost [est.] |
|---|---|---|---|---|---|
| REQ-7 | `locate`, `Lookup`, `Located`, `severity_hint` | P0 | 3 | 0.3 | as REQ-3, plus under 1 ns per pair for shadows |
| REQ-13 | `shadows` | P2 | 3 | 0.3 | included above |

### `Prefix`

```rust
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Prefix { None, Secure, Host }
impl Prefix {
    pub fn of(name: &str) -> Prefix;   // `__Host-` / `__Secure-`, ASCII case-insensitive (rfc6265bis section 5.4)
}
```

```rust
use cookie_net::Prefix;

assert_eq!(Prefix::of("__Host-sid"), Prefix::Host);
assert_eq!(Prefix::of("__secure-x"), Prefix::Secure);   // user agents compare prefixes case-insensitively
assert_eq!(Prefix::of("_Host-sid"), Prefix::None);
```

| Id | Grade | Tier | Ver | Cost [est.] |
|---|---|---|---|---|
| REQ-11 | P0 | 3 | 0.3 | 2 ns |

### The parsing algorithm

The server-side grammar is rfc6265bis section 4.2.1: `cookie-pair *( ";" SP cookie-pair )`. For each line (one, or each of `from_lines`):

```
 0 total length > max_header_len                    ─▶ too long: nothing read
 1 skip SP / HTAB
 2 find the next ';' (parse-net scan::find_byte)    ─▶ the pair is the bytes before it
 3 trim SP / HTAB at the end of the pair; an empty pair is counted in `empty`, not `skipped`
 4 split at the first '='; no '='                   ─▶ skipped (a nameless cookie)
 5 name: 1 to max_name_len bytes, every byte tchar  else skipped
 6 value, strict:  *cookie-octet, or DQUOTE *cookie-octet DQUOTE (quotes kept)
          lenient: any byte except CTL (HTAB allowed) and ';', valid UTF-8
          longer than max_value_len, or name + value > 4096 ─▶ skipped
 7 accepted ─▶ counted; one more than max_pairs     ─▶ stop, truncated
 8 the separator: "; " is the standard; ';' with no SP, or with more whitespace, is accepted and counted
```

- `,` is not a separator (RFC 2965 allowed it; rfc6265bis does not). In strict mode `a=1, b=2` is one skipped pair, never a pair named ` b` (threat T11).
- `$Version=1`, `$Path=/` are ordinary pairs named `$Version` and `$Path`, never attributes (threat T12).
- Every step is linear; each byte is touched a constant number of times.

---

## Writing `Set-Cookie`

### `SetCookie`

```rust
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SetCookie<'a> { /* validated name, value, attributes */ }

impl<'a> SetCookie<'a> {
    pub fn new(name: &'a str, value: &'a str) -> Result<SetCookie<'a>, CookieError>;
    pub fn builder(name: &'a str, value: &'a str) -> SetCookieBuilder<'a>;
    pub fn delete(name: &'a str) -> Result<SetCookie<'a>, CookieError>;

    pub fn write_to(&self, out: &mut impl parse_net::Sink) -> Result<(), CookieError>;   // only Full
    pub fn encoded_len(&self) -> usize;
    pub fn encode_into<'b>(&self, buf: &'b mut [u8]) -> Result<&'b str, CookieError>;   // only Full
    #[cfg(feature = "alloc")]
    pub fn encode(&self) -> alloc::string::String;

    pub const fn name(&self) -> &'a str;
    pub const fn value(&self) -> &'a str;
    pub const fn max_age(&self) -> Option<u64>;
    pub const fn expires(&self) -> Option<u64>;
    pub const fn path(&self) -> &'a str;
    pub const fn domain(&self) -> Option<&'a str>;
    pub const fn same_site(&self) -> SameSite;
    pub const fn is_secure(&self) -> bool;
    pub const fn is_http_only(&self) -> bool;
    pub const fn is_partitioned(&self) -> bool;
    pub const fn is_deletion(&self) -> bool;
}
impl core::fmt::Debug for SetCookie<'_> {}   // attributes shown, value as its length
```

One `Set-Cookie` field value that is valid by construction (decision D-002): the only ways to get one are `new`, `delete`, `SetCookieBuilder::build`, and the session helpers, and each checks every [rule](#rules-checked-by-build). Writing it cannot fail except for room.

- `new` uses the defaults: `Secure; HttpOnly; SameSite=Lax; Path=/`, host-only (no `Domain`), and no `Max-Age`, so the browser drops it when it closes (decision D-001).
- `delete` writes a cookie that removes `name` from a browser: an empty value and `Expires=Thu, 01 Jan 1970 00:00:00 GMT`, with the same default attributes. It removes any cookie that was set with the defaults, including every `__Host-` cookie (rfc6265bis section 3.1: removal works only when name, path, and domain match). To remove a cookie set with another `Path` or `Domain`, use the builder: `SetCookie::builder(name, "").path("/app").delete().build()`.
- `encode`, `encode_into`, and `write_to` produce the same bytes; `encoded_len` is exact, so a caller can size a buffer once. There is no `Display`, on purpose ([Secrets never print](#secrets-never-print)).

```rust
use cookie_net::SetCookie;

let c = SetCookie::new("theme", "dark")?;
assert_eq!(c.encode(), "theme=dark; Path=/; Secure; HttpOnly; SameSite=Lax");

let gone = SetCookie::delete("__Host-sid")?;
assert_eq!(gone.encode(), "__Host-sid=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Secure; HttpOnly; SameSite=Lax");
# Ok::<(), cookie_net::CookieError>(())
```

```rust
use cookie_net::SetCookie;
use parse_net::SliceSink;

let c = SetCookie::new("theme", "dark")?;
let mut buf = [0u8; 128];
let mut out = SliceSink::new(&mut buf);
c.write_to(&mut out)?;                                   // no allocation
assert_eq!(out.len(), c.encoded_len());
# Ok::<(), cookie_net::CookieError>(())
```

| Id | Item | Grade | Tier | Ver | Cost [est.] |
|---|---|---|---|---|---|
| SET-1 | `new` | P0 | 1 | 0.3 | 20 ns |
| SET-15 | `write_to` | P0 | 1 | 0.3 | 30 ns for a typical cookie |
| SET-16 | `encoded_len`, `encode_into` | P1 | 3 | 0.3 | 30 ns, no allocation |
| SET-17 | `encode` | P1 | 1 | 0.3 | 60 ns |
| SET-18 | `delete` | P0 | 1 | 0.3 | 25 ns |
| SET-19 | getters, `Debug` redaction | P0 | 2 | 0.3 | n/a |

### `SetCookieBuilder`

```rust
#[derive(Clone, Copy)]
pub struct SetCookieBuilder<'a> { /* fields */ }

impl<'a> SetCookieBuilder<'a> {
    pub fn max_age(self, secs: u64) -> Self;                   // 1 to MAX_LIFETIME
    pub fn expires(self, at: u64, now: u64) -> Self;           // Unix seconds; at most 400 days after `now`
    pub fn domain(self, domain: &'a str) -> Self;              // bare domain, written lowercase
    pub fn path(self, path: &'a str) -> Self;                  // starts with '/'
    pub fn same_site(self, same_site: SameSite) -> Self;
    pub fn partitioned(self) -> Self;                          // CHIPS
    pub fn insecure(self) -> Self;                             // drops Secure: for http://localhost only
    pub fn script_readable(self) -> Self;                      // drops HttpOnly
    pub fn extension(self, attribute: &'a str) -> Self;        // up to 8, e.g. "Priority=High"
    pub fn delete(self) -> Self;                               // empty value, Expires in 1970, no Max-Age
    pub fn build(self) -> Result<SetCookie<'a>, CookieError>;
}
impl core::fmt::Debug for SetCookieBuilder<'_> {}
```

Setters never fail and can be called in any order; a later call to the same setter replaces the earlier one. `build` checks every rule in the order of the [table below](#rules-checked-by-build) and returns the first one broken. The opt-outs have plain names on purpose: `insecure` and `script_readable` should stand out in review.

```rust
use cookie_net::{self as cookie, SameSite, SetCookie};

let c = SetCookie::builder("__Secure-pref", "compact")
    .domain("Example.COM")
    .max_age(30 * cookie::DAY)
    .same_site(SameSite::Strict)
    .build()?;
assert_eq!(c.encode(), "__Secure-pref=compact; Path=/; Domain=example.com; Max-Age=2592000; Secure; HttpOnly; SameSite=Strict");

// rules refuse what a browser would silently drop or what an attacker could use
assert_eq!(SetCookie::builder("__Host-sid", "x").domain("example.com").build().unwrap_err(), cookie::CookieError::HostPrefix);
assert_eq!(SetCookie::builder("embed", "1").same_site(SameSite::None).insecure().build().unwrap_err(), cookie::CookieError::SameSiteNoneNeedsSecure);
# Ok::<(), cookie::CookieError>(())
```

```rust
use cookie_net::SetCookie;

// a third-party widget cookie, partitioned per top-level site
let c = SetCookie::builder("widget", "1").same_site(cookie_net::SameSite::None).partitioned().build()?;
assert!(c.encode().ends_with("SameSite=None; Partitioned"));

// local development over plain HTTP
let dev = SetCookie::builder("theme", "dark").insecure().build()?;
assert!(!dev.is_secure());
# Ok::<(), cookie_net::CookieError>(())
```

| Id | Item | Grade | Tier | Ver | Cost [est.] |
|---|---|---|---|---|---|
| SET-2 | `builder`, `build` | P0 | 2 | 0.3 | 25 ns |
| SET-7 | `path` | P0 | 2 | 0.3 | 0.5 ns per byte |
| SET-8 | `domain` | P1 | 2 | 0.3 | 20 ns |
| SET-10 | `max_age` | P0 | 2 | 0.3 | 1 ns |
| SET-11 | `expires` | P1 | 2 | 0.3 | 10 ns (IMF-fixdate through parse-net `HttpDate`) |
| SET-12 | `partitioned` | P1 | 2 | 0.3 | 1 ns |
| SET-13 | `insecure`, `script_readable` | P1 | 2 | 0.3 | 1 ns |
| SET-14 | `extension` | P2 | 2 | 0.3 | 0.5 ns per byte |
| SET-18 | builder `delete` | P0 | 2 | 0.3 | n/a |

### `SameSite`

```rust
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub enum SameSite { Strict, #[default] Lax, None }
```

`Lax` is the default: a top-level `GET` from another site (a link in an email) carries the cookie; cross-site `POST`, `fetch`, and frames do not. `Strict` never leaves the site. `None` is sent everywhere and requires `Secure`. cookie-net always writes the attribute, so the 6265bis "Lax-allowing-unsafe" relaxation (section 5.6.7.2, for cookies with no `SameSite`) never applies to its cookies.

| Id | Grade | Tier | Ver |
|---|---|---|---|
| SET-3 | P0 | 1 | 0.3 |

### Rules checked by `build`

In this order (the first one broken is returned):

| # | Rule | Error | Source |
|---|---|---|---|
| 1 | name is a non-empty `token` | `EmptyName`, `InvalidName { at }` | rfc6265bis 4.1.1 |
| 2 | value is `*cookie-octet` or `DQUOTE *cookie-octet DQUOTE` | `InvalidValue { at }` | 4.1.1 |
| 3 | name plus value at most 4096 bytes | `TooLarge` | 5.6 step 5, 5.7 step 4 |
| 4 | `Path`, `Domain`, each extension at most 1024 bytes | `AttributeTooLong` | 5.6 |
| 5 | `Path` starts with `/`, no CTL, no `;` | `InvalidPath { at }` | 4.1.1 `path-value`, 5.6.4 |
| 6 | `Domain` is LDH labels with a dot, no leading dot, no IP literal, labels 1 to 63 bytes | `InvalidDomain` | 4.1.2.3, 5.6.3 |
| 7 | extension: `*av-octet` with a `token` name (the part before `=`), not a defined attribute name, at most 8 | `InvalidExtension { at }`, `ExtensionNotAllowed`, `TooManyExtensions` | 4.1.1 `extension-av` |
| 8 | `Max-Age` 1 to 34,560,000 | `MaxAgeOutOfRange` | 5.5, 4.1.1 (`max-age-av` starts with a non-zero digit) |
| 9 | `Expires` at most 400 days after `now` | `ExpiresOutOfRange` | 5.5 |
| 10 | `__Host-` (any case): `Secure`, `Path=/`, no `Domain` | `HostPrefix` | 4.1.3.2, 5.4 |
| 11 | `__Secure-` (any case): `Secure` | `SecurePrefix` | 4.1.3.1 |
| 12 | `SameSite=None` needs `Secure` | `SameSiteNoneNeedsSecure` | 5.7 |
| 13 | `Partitioned` needs `Secure` | `PartitionedNeedsSecure` | CHIPS 2.3, 3.1 |

A deletion (`delete`) skips rules 2, 8, and 9 (its value and expiry are fixed) and keeps every other rule, so a deletion of a `__Host-` cookie is still a valid `__Host-` cookie. Every rule has a test that cites its section, and a property test checks that no builder input produces a cookie that breaks rules 10 to 13 (threats T1, T2, T21).

| Id | Item | Grade | Tier | Ver | Cost [est.] |
|---|---|---|---|---|---|
| SET-4 | name rule | P0 | 1 | 0.3 | 0.5 ns per byte |
| SET-5 | value rule | P0 | 1 | 0.3 | 0.5 ns per byte |
| SET-6 | size rules | P0 | 1 | 0.3 | 1 ns |
| SET-9 | prefix rules | P0 | 1 | 0.3 | 2 ns |

### Serialization

One canonical form for each `SetCookie`, so tests compare bytes:

```
name=value; Path=/; Domain=example.com; Max-Age=3600; Expires=Wed, 21 Oct 2026 18:38:00 GMT; Secure; HttpOnly; SameSite=Lax; Partitioned; ext1; ext2=v
```

- Attribute names in the canonical case of rfc6265bis, `"; "` between attributes, no spaces around `=`.
- `Path` is always written (default `/`). `Domain`, `Max-Age`, `Expires` only when set. `Expires` is IMF-fixdate (RFC 9110 section 5.6.7) through parse-net.
- A deletion writes `Expires=Thu, 01 Jan 1970 00:00:00 GMT` and never `Max-Age=0`, because `max-age-av` must start with a non-zero digit.

| Id | Item | Grade | Tier | Ver |
|---|---|---|---|---|
| SET-20 | typed `Priority` (a Chromium-only attribute) | P3 | 2 | after 1.0 (use `extension("Priority=High")` until then) |

---

## Session cookies

WASP's session cookies, decided with gate-net's session design (decisions CN-7, CN-8, CN-11 in [`../dev/PLAN.md`](../dev/PLAN.md#14-decision-log)):

| Cookie | Attributes, fixed by the helper | Value | Signed or encrypted |
|---|---|---|---|
| `__Host-sid` | `Secure; HttpOnly; SameSite=Lax; Path=/`, no `Domain`, `Max-Age` = the session's absolute lifetime (WASP: 12 hours) | gate-net's token: 32 CSPRNG bytes, base64url (43 characters) | no: a lookup key only |
| `__Host-sudo` | `Secure; HttpOnly; SameSite=Strict; Path=/`, no `Domain`, `Max-Age` 60 to 3600 (recommended 300 to 900) | a separate random token for the elevated state | no |
| CSRF | none: csrf-sec tokens go in a form field or a request header, **never in a cookie** | | |

Session tokens are opaque random values: nothing in them needs protecting and the server record is the truth, so they are not signed or encrypted cookies. `__Host-` makes a cookie host-only, `Secure`, and `Path=/`, so a sibling subdomain cannot set or overwrite it (cookie tossing). That is also why csrf-sec never compares a token with a cookie: a double-submit cookie can be planted by a sibling subdomain; a session-bound token cannot.

### `session_cookie`

```rust
pub fn session_cookie<'a>(name: &'a str, token: &'a str, max_age: u64) -> Result<SetCookie<'a>, CookieError>;
```

The `Set-Cookie` for a session token: `Secure; HttpOnly; SameSite=Lax; Path=/`, host-only, `Max-Age=max_age`. Refuses a name without the `__Host-` prefix (`HostPrefix`), a token shorter than 22 bytes (`TokenTooShort`), a token that is not `cookie-octet`s (`InvalidValue`), and `max_age` outside 1 to `MAX_LIFETIME` (`MaxAgeOutOfRange`). Issue a new token at every login (session fixation defence) and at every roll (gate-net rolling tokens).

```rust
use cookie_net as cookie;

let token = "Zk3J9qL0wX7aP2mT8sV1cR5dY4hN6bE0uK9gF3jQ2oA";
let set = cookie::session_cookie("__Host-sid", token, 12 * cookie::HOUR)?;
assert_eq!(set.encode(), format!("__Host-sid={token}; Path=/; Max-Age=43200; Secure; HttpOnly; SameSite=Lax"));
assert_eq!(cookie::session_cookie("sid", token, cookie::HOUR).unwrap_err(), cookie::CookieError::HostPrefix);
assert_eq!(cookie::session_cookie("__Host-sid", "42", cookie::HOUR).unwrap_err(), cookie::CookieError::TokenTooShort);
# Ok::<(), cookie::CookieError>(())
```

For a browser-session cookie with no `Max-Age`, `SetCookie::new("__Host-sid", token)` already has the same attributes.

| Id | Grade | Tier | Ver | Cost [est.] |
|---|---|---|---|---|
| SES-1 | P0 | 1 | 0.3 | 25 ns |
| SES-5 | P2 | 1 | 0.3 | token floor: 1 ns |

### `elevated_cookie`

```rust
pub fn elevated_cookie<'a>(name: &'a str, token: &'a str, max_age: u64) -> Result<SetCookie<'a>, CookieError>;
```

As `session_cookie` with `SameSite=Strict`, so an elevated action never starts from another site, and `max_age` limited to 60 to 3600 seconds (`MaxAgeOutOfRange` otherwise). `Path=/` is forced by the `__Host-` prefix: paths do not isolate cookies anyway (RFC 6265 section 8.5), and `__Host-` blocks subdomain tossing, which a path cannot (decision CN-7).

```rust
use cookie_net as cookie;

let sudo = cookie::elevated_cookie("__Host-sudo", "pX4vB8nM2kL6qW0eR9tY3uI7oP5aS1dF", 10 * cookie::MINUTE)?;
assert!(sudo.encode().ends_with("Max-Age=600; Secure; HttpOnly; SameSite=Strict"));
# Ok::<(), cookie::CookieError>(())
```

| Id | Grade | Tier | Ver | Cost [est.] |
|---|---|---|---|---|
| SES-2 | P1 | 1 | 0.3 | 25 ns |

### Ending a session

`SetCookie::delete("__Host-sid")` and `SetCookie::delete("__Host-sudo")` remove the cookies; their attributes satisfy the `__Host-` rules, so browsers accept the removal. Correctness never depends on the browser obeying it: the server revokes the session first.

| Id | Grade | Tier | Ver |
|---|---|---|---|
| SES-3 | P0 | 1 | 0.3 (through `SetCookie::delete`; the separate `clear_host` of the specification was folded into it, decision D-024) |

---

## Keys

Features `signed` or `encrypted`. Keys are 32 bytes, handed to cookie-net by the caller (WASP: from key-vault). cookie-net never depends on key-vault and never generates keys: a key generated at boot invalidates every signed cookie at every restart and differs between the nodes of a cluster (decision D-032).

### `Key`

```rust
#[derive(Clone)]
pub struct Key { /* 32 bytes, wiped on drop */ }
impl Key {
    pub fn from_bytes(bytes: [u8; 32]) -> Key;
    pub fn derive(master: &[u8], context: &[u8]) -> Result<Key, CookieError>;   // KeyTooShort, ContextTooLong, Crypto
}
impl From<[u8; 32]> for Key {}
impl core::fmt::Debug for Key {}   // "Key(..)"
```

Every function that takes a key takes `impl Into<Key>`, so a `[u8; 32]` works directly. `derive` is HKDF-SHA-256 (crypt-io) with `info = "cookie-net v1 key" 0x00 || context`, for one master in key-vault serving several services (context = the service name, at most 200 bytes). A master shorter than 32 bytes is refused.

`Signer` and `Sealer` each derive their own subkey from any key they are given (`"cookie-net v1 signed"` and `"cookie-net v1 sealed"`), so the same key can feed both and signing and sealing still never share key material (decision D-019).

```rust
use cookie_net::{Key, Sealer, Signer};

let master = vault_secret();                          // 32 or more bytes from key-vault
let key = Key::derive(&master, b"wasp-web")?;
let signer = Signer::new(key.clone())?;
let sealer = Sealer::new(key)?;                       // different subkey, same source
# Ok::<(), cookie_net::CookieError>(())
```

| Id | Item | Grade | Tier | Ver | Cost [est.] |
|---|---|---|---|---|---|
| KEY-1 | `Key`, `from_bytes`, `From`, redacted `Debug`, wipe on drop | P0 | 1 | 0.4 | n/a |
| KEY-2 | `derive` | P1 | 2 | 0.4 | 1 µs (boot only) |

### `KeyId`, `KeyRole`, `KeyInfo`, `KeyFingerprint`

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct KeyId(pub u8);

#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KeyRole {
    Signing,                  // signs (or seals) new cookies and verifies
    Accepted,                 // verifies only, with no end: staged on every node before it signs
    Retired { until: u64 },   // verifies only while now < until
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct KeyInfo { /* id, role, fingerprint */ }
impl KeyInfo {
    pub const fn id(&self) -> KeyId;
    pub const fn role(&self) -> KeyRole;
    pub const fn fingerprint(&self) -> KeyFingerprint;
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeyFingerprint([u8; 8]);
impl KeyFingerprint { pub const fn as_bytes(&self) -> &[u8; 8]; }
impl core::fmt::Display for KeyFingerprint {}   // 16 lowercase hex digits
```

The same names and meanings as csrf-sec, so one key runbook serves both crates. A fingerprint is eight bytes of keyed BLAKE3 over a fixed label under the key's subkey: it reveals nothing that helps forge a cookie, but two nodes holding the same key under the same id show the same fingerprint. Compare fingerprints across a cluster to catch a misdeployed ring before it shows up as a wave of `BadTag` refusals.

Never reuse a key id while cookies made under the old key may still be presented.

| Id | Item | Grade | Tier | Ver |
|---|---|---|---|---|
| KEY-5 | `KeyId`, `KeyRole`, `KeyInfo` | P0 | 2 | 0.4 |
| KEY-6 | `KeyFingerprint` | P2 | 2 | 0.4 |

### `KeyRing`

```rust
#[derive(Clone)]
pub struct KeyRing { /* up to 8 keys in a fixed array; no allocation */ }
impl KeyRing {
    pub fn new(id: KeyId, key: impl Into<Key>) -> KeyRing;                        // the signing key
    pub fn accept(self, id: KeyId, key: impl Into<Key>) -> KeyRing;               // staged
    pub fn retired(self, id: KeyId, key: impl Into<Key>, until: u64) -> KeyRing;  // verifies until `until`
    pub fn rotated(self, id: KeyId, key: impl Into<Key>, retire_old_at: u64) -> KeyRing;
    pub fn without(self, id: KeyId) -> KeyRing;
    pub fn signing_key(&self) -> KeyId;
}
impl core::fmt::Debug for KeyRing {}   // ids and roles, never key bytes
```

One signing key and up to seven others. The ring methods never fail, so a ring reads as one chain; `Signer::with_ring` and `Sealer::with_ring` check it and return `DuplicateKeyId`, `RingFull`, `WeakKey`, or `InvalidRetireTime`. `rotated` makes `id` the signing key and turns the previous signing key into `Retired { until: retire_old_at }`; an `Accepted` entry with the same id is replaced (promoted). Set `retire_old_at` at least one cookie lifetime plus the skew allowance after the moment the old key stops signing.

```rust
use cookie_net::{KeyId, KeyRing, Signer};

let ring = KeyRing::new(KeyId(2), key_2)
    .retired(KeyId(1), key_1, retire_at);
let signer = Signer::with_ring(ring)?;
assert_eq!(signer.signing_key(), KeyId(2));
# Ok::<(), cookie_net::CookieError>(())
```

| Id | Item | Grade | Tier | Ver |
|---|---|---|---|---|
| KEY-3 | `new`, `accept`, `retired`, `without`, `signing_key`; checks in `with_ring` | P0 | 2 | 0.4 |
| KEY-4 | `rotated` | P1 | 2 | 0.4 |

### Rotating keys across a cluster

Signed and sealed cookies verify on any node that holds the same ring (they carry no node-local state). A rotation that changes every node at once would refuse, for a moment, cookies signed by nodes that already switched. So rotation has three steps, each a ring deployed to every node:

1. **Stage**: `KeyRing::new(KeyId(1), k1).accept(KeyId(2), k2)`. Every node now verifies `k2`; none signs with it. Check fingerprints across nodes.
2. **Switch**: `KeyRing::new(KeyId(1), k1).accept(KeyId(2), k2).rotated(KeyId(2), k2, t)` (or written out: `new(KeyId(2), k2).retired(KeyId(1), k1, t)`). New cookies use `k2`; old ones verify until `t`.
3. **Drop**: after `t`, `KeyRing::new(KeyId(2), k2)`. Old cookies are now `UnknownKey`.

No step logs anyone out. `Verified::role` shows which role verified a cookie, which tells an operator when step 3 is safe.

---

## Signed cookies

Feature `signed`. For small client-held state that must not be forged (preferences, a cart id, a one-time notice). The value stays readable; signing proves integrity, not secrecy.

### `Signer`

```rust
pub struct Signer { /* ring of derived subkeys, skew */ }
impl Signer {
    pub fn new(key: impl Into<Key>) -> Result<Signer, CookieError>;                // KeyId(0); WeakKey
    pub fn with_ring(ring: KeyRing) -> Result<Signer, CookieError>;
    pub fn with_skew(self, secs: u64) -> Signer;                                   // default 60, at most 3600

    #[cfg(feature = "alloc")] pub fn sign(&self, name: &str, value: &str) -> Result<String, CookieError>;
    #[cfg(feature = "alloc")] pub fn sign_until(&self, name: &str, value: &str, expires: u64) -> Result<String, CookieError>;
    #[cfg(feature = "alloc")] pub fn sign_bound(&self, name: &str, value: &str, bound_to: &[u8]) -> Result<String, CookieError>;
    pub fn sign_into(&self, name: &str, value: &str, expires: Option<u64>, bound_to: &[u8],
                     out: &mut impl parse_net::Sink) -> Result<(), CookieError>;
    pub const fn signed_len(&self, value_len: usize) -> usize;                     // value_len + 30

    pub fn verify<'a, R: AsRef<[u8]> + ?Sized>(&self, name: &str, raw: &'a R, now: u64) -> Result<&'a str, Rejected>;
    pub fn verify_bound<'a, R: AsRef<[u8]> + ?Sized>(&self, name: &str, raw: &'a R, bound_to: &[u8], now: u64) -> Result<&'a str, Rejected>;
    pub fn verify_detailed<'a, R: AsRef<[u8]> + ?Sized>(&self, name: &str, raw: &'a R, bound_to: &[u8], now: u64) -> Result<Verified<'a>, Rejected>;
    #[cfg(feature = "std")] pub fn verify_now<'a, R: AsRef<[u8]> + ?Sized>(&self, name: &str, raw: &'a R) -> Result<&'a str, Rejected>;

    pub fn signing_key(&self) -> KeyId;
    pub fn keys(&self) -> impl Iterator<Item = KeyInfo> + '_;
    pub fn fingerprint(&self, id: KeyId) -> Option<KeyFingerprint>;
}
impl core::fmt::Debug for Signer {}   // ids, roles, fingerprints
```

- **The name is inside the MAC**, so a signed value cannot be moved to another cookie (threat T15).
- **`sign_until`** embeds an expiry that the server checks on every verification, whatever the browser does with `Max-Age` (threat T16). `expires` is Unix seconds from 2020-01-01 to 2156 (`ExpiresOutOfRange` otherwise).
- **`sign_bound` / `verify_bound`** add a binding, such as a digest of the session id, to the MAC input without storing it in the cookie. A bound value verifies only with the same binding, so a valid signed cookie cannot be replayed into another user's browser by a sibling subdomain (cookie tossing of signed state), and it dies with the session (decision D-023, the 0.4 defence idea). An empty binding is the same as no binding.
- **Skew**: an expiry is accepted while `now < expires + skew`, so nodes whose clocks differ by up to the skew agree. Default 60 seconds, the same as csrf-sec.
- `value` must be `cookie-octet`s with no surrounding quotes (`InvalidValue`), and the name plus the signed value at most 4096 bytes (`TooLarge`), both checked before any MAC work.
- Verification takes no lock and touches no shared state; the tag is compared in constant time through crypt-io `Tag<16>::ct_eq` (threat T18). No allocation.

```rust
use cookie_net::{self as cookie, Rejected, Signer};

let signer = Signer::new(*b"an example key, 32 bytes long!!!")?;
let value = signer.sign("prefs", "lang=fr")?;
assert_eq!(value.len(), 30 + "lang=fr".len());
assert!(value.ends_with("lang=fr"));                     // readable, not secret

assert_eq!(signer.verify("prefs", &value, now)?, "lang=fr");
assert_eq!(signer.verify("theme", &value, now), Err(Rejected::BadTag));   // moved to another name
let mut forged = value.clone().into_bytes();
*forged.last_mut().unwrap() = b'x';
assert_eq!(signer.verify("prefs", &forged, now), Err(Rejected::BadTag));
# Ok::<(), cookie::CookieError>(())
```

```rust
use cookie_net::{self as cookie, SetCookie};

// a cart id bound to the session and valid for one day
let v = signer.sign_bound("cart", "c-81731", session_digest)?;
let set = SetCookie::builder("cart", &v).max_age(cookie::DAY).build()?;

// on a later request: a missing or refused cart is an empty cart
let cart = cookie::get(header, "cart")
    .and_then(|raw| signer.verify_bound("cart", raw, session_digest, now).ok());
# Ok::<(), cookie::CookieError>(())
```

| Id | Item | Grade | Tier | Ver | Cost [est.] |
|---|---|---|---|---|---|
| SGN-1 | `new`, `with_ring`, `with_skew` | P0 | 1 | 0.4 | 2 µs per key (subkey derivation, once) |
| SGN-2 | `sign`, `sign_into` | P0 | 1 | 0.4 | 120 ns for a 64-byte value |
| SGN-3 | `sign_until` (server-enforced expiry) | P1 | 1 | 0.4 | n/a |
| SGN-4 | `verify` | P0 | 1 | 0.4 | 120 ns |
| SGN-5 | `verify_now` | P1 | 1 | 0.4 | as SGN-4 |
| SGN-7 | `verify_detailed`, `Verified` | P1 | 2 | 0.4 | as SGN-4 |
| SGN-8 | `signed_len` | P2 | 3 | 0.4 | n/a |
| SGN-9 | `sign_bound`, `verify_bound` | P2 | 2 | 0.4 | 5 ns plus 1 ns per 16 binding bytes |
| SGN-10 | `signing_key`, `keys`, `fingerprint` | P2 | 2 | 0.4 | n/a |

### `Verified`

```rust
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Verified<'a> {
    pub value: &'a str,
    pub key: KeyId,
    pub role: KeyRole,          // Retired or Accepted during a rotation
    pub expires: Option<u64>,
}
impl core::fmt::Debug for Verified<'_> {}   // value as its length
```

```rust
let v = signer.verify_detailed("prefs", raw, &[], now)?;
if matches!(v.role, KeyRole::Retired { .. }) { metrics.count("cookie.retired_key"); }
```

### Signed format v1

```
 header (22 bytes) = version 0x01 | key id (1) | expires (4, big-endian, seconds since 2020-01-01T00:00:00Z; 0 = none) | tag (16)
 cookie value      = base64url_nopad(header) (30 characters) || value (unchanged)
 tag               = first 16 bytes of keyed BLAKE3(signing subkey,
                       "cookie-net/v1/signed" 0x00 | version | key id | expires
                       | u16be(len name) | name | u32be(len binding) | binding | value)
```

128-bit tag: a forgery succeeds with probability 2^-128 per attempt, the tag length csrf-sec uses. Overhead 30 characters; expiry year limit 2156. The byte-exact layout, the subkey derivation, and test vectors are in [`FORMATS.md`](./FORMATS.md), so another implementation can interoperate.

---

## Encrypted cookies

Feature `encrypted` (needs `std`: crypt-io draws nonces from the OS). For small client-held state that must also stay private (a flash message with a name in it, a return URL).

### `Sealer`

```rust
pub struct Sealer { /* ring of derived subkeys, skew */ }
impl Sealer {
    pub fn new(key: impl Into<Key>) -> Result<Sealer, CookieError>;
    pub fn with_ring(ring: KeyRing) -> Result<Sealer, CookieError>;
    pub fn with_skew(self, secs: u64) -> Sealer;

    pub fn seal<P: AsRef<[u8]> + ?Sized>(&self, name: &str, plaintext: &P) -> Result<String, CookieError>;
    pub fn seal_until<P: AsRef<[u8]> + ?Sized>(&self, name: &str, plaintext: &P, expires: u64) -> Result<String, CookieError>;
    pub fn seal_bound<P: AsRef<[u8]> + ?Sized>(&self, name: &str, plaintext: &P, bound_to: &[u8]) -> Result<String, CookieError>;
    pub fn seal_into(&self, name: &str, plaintext: &[u8], expires: Option<u64>, bound_to: &[u8],
                     scratch: &mut Vec<u8>, out: &mut impl parse_net::Sink) -> Result<(), CookieError>;
    pub const fn sealed_len(&self, plaintext_len: usize) -> usize;   // ceil((46 + n) * 4 / 3)
    pub const fn max_plaintext(&self, name_len: usize) -> usize;     // floor((4096 - L) * 3 / 4) - 46

    pub fn open<R: AsRef<[u8]> + ?Sized>(&self, name: &str, raw: &R, now: u64) -> Result<Plaintext, Rejected>;
    pub fn open_bound<R: AsRef<[u8]> + ?Sized>(&self, name: &str, raw: &R, bound_to: &[u8], now: u64) -> Result<Plaintext, Rejected>;
    pub fn open_into<R: AsRef<[u8]> + ?Sized>(&self, name: &str, raw: &R, bound_to: &[u8], now: u64,
                     out: &mut Vec<u8>) -> Result<Opened, Rejected>;
    pub fn open_now<R: AsRef<[u8]> + ?Sized>(&self, name: &str, raw: &R) -> Result<Plaintext, Rejected>;

    pub fn signing_key(&self) -> KeyId;
    pub fn keys(&self) -> impl Iterator<Item = KeyInfo> + '_;
    pub fn fingerprint(&self, id: KeyId) -> Option<KeyFingerprint>;
}
impl core::fmt::Debug for Sealer {}
```

- XChaCha20-Poly1305 with a random 192-bit nonce per cookie (decision CN-3): a busy site issues many cookies under one key, and 192-bit random nonces never collide in practice, where 96-bit ones must stay well below 2^32 messages per key.
- The cookie name, the header fields, and the binding are associated data, so a sealed value cannot move to another name or session (threat T15). Expiry, binding, and skew behave as for `Signer`.
- `TooLarge` (plaintext over `max_plaintext`) is returned before any crypto. `Crypto` is returned if the random source fails, and nothing is written (threat T26, fail closed).
- `open_into` writes into the caller's `Vec`, which crypt-io clears first and wipes on authentication failure; once `out` has capacity, opening allocates nothing. `open` returns an owned [`Plaintext`](#plaintext) that is wiped on drop.

```rust
use cookie_net::{self as cookie, Sealer};

let sealer = Sealer::new(*b"another example key, 32 bytes!!!")?;
let v = sealer.seal_until("flash", "Saved your address, Ana.", now + 5 * cookie::MINUTE)?;
let set = cookie::SetCookie::builder("flash", &v).max_age(5 * cookie::MINUTE).build()?;

let text = sealer.open("flash", &v, now)?;
assert_eq!(text.as_str(), Some("Saved your address, Ana."));
assert!(sealer.open("flash", &v, now + 10 * cookie::MINUTE).is_err());   // expired
# Ok::<(), cookie::CookieError>(())
```

```rust
// steady state with no allocation per request
let mut plain = Vec::with_capacity(512);
let opened = sealer.open_into("flash", raw, &[], now, &mut plain)?;
render_flash(&plain);
```

| Id | Item | Grade | Tier | Ver | Cost [est.] |
|---|---|---|---|---|---|
| SEAL-1 | `new`, `with_ring`, `with_skew` | P1 | 1 | 0.4 | 2 µs per key, once |
| SEAL-2 | `seal`, `seal_into` | P1 | 1 | 0.4 | 0.5 to 1.5 µs for 64 bytes, dominated by the OS random call |
| SEAL-3 | `seal_until` | P1 | 1 | 0.4 | n/a |
| SEAL-4 | `open`, `open_into` | P1 | 1 | 0.4 | 250 ns for 64 bytes |
| SEAL-5 | `open_now` | P1 | 1 | 0.4 | as SEAL-4 |
| SEAL-6 | `Opened`, `Plaintext` with redacted `Debug` | P1 | 2 | 0.4 | n/a |
| SEAL-7 | `sealed_len`, `max_plaintext` | P2 | 3 | 0.4 | n/a |
| SEAL-8 | `seal_bound`, `open_bound` | P2 | 2 | 0.4 | as SGN-9 |
| SEAL-9 | `signing_key`, `keys`, `fingerprint` | P2 | 2 | 0.4 | n/a |

### `Plaintext`

```rust
pub struct Plaintext { /* owned bytes, wiped on drop */ }
impl Plaintext {
    pub fn as_bytes(&self) -> &[u8];
    pub fn as_str(&self) -> Option<&str>;
    pub fn len(&self) -> usize;
    pub fn is_empty(&self) -> bool;
}
impl core::ops::Deref for Plaintext { type Target = [u8]; }
impl core::fmt::Debug for Plaintext {}   // "Plaintext(24 bytes)"
```

cookie-net's own type rather than a re-exported `Zeroizing`, so no third-party type is part of the public API (decision D-037).

### `Opened`

```rust
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Opened { pub key: KeyId, pub role: KeyRole, pub expires: Option<u64> }
```

What `open_into` reports besides the plaintext, which is in the caller's buffer.

### Sealed format v1

```
 bytes        = version 0x02 | key id (1) | expires (4) | nonce (24) | ciphertext (n) | tag (16)
 cookie value = base64url_nopad(bytes)
 AEAD         = XChaCha20-Poly1305 (crypt-io Crypt::xchacha20_poly1305), random nonce from crypt-io
 AAD          = "cookie-net/v1/sealed" 0x00 | version | key id | expires
                | keyed BLAKE3(sealing subkey, u16be(len name) | name | u32be(len binding) | binding)
```

The AAD carries a 32-byte digest of the name and binding, so it is 59 bytes, fixed, and built on the stack (decision D-053). Overhead 46 bytes before encoding. The byte-exact layout and vectors are in [`FORMATS.md`](./FORMATS.md).

---

## Verification order and severity

Both formats, chosen so the reason is accurate and the work is bounded:

```
 1 length within bounds (signed: at least 30; sealed: at least the encoded length of 46 bytes; at most 4096)   else Malformed
 2 decode base64url (30 characters for signed; the whole value for sealed, into a 3072-byte stack buffer)
                                                          bad alphabet or non-canonical ─▶ Malformed
 3 version known                                          else UnsupportedVersion
 4 key id in the ring (Signing, Accepted, or Retired with now < until)   else UnknownKey
 5 MAC verifies in constant time / AEAD opens             else BadTag
 6 expires = 0 or now < expires + skew                    else Expired
 7 pass, reporting the key and its role
```

The MAC is checked before expiry, so a forged expired cookie reports `BadTag`, not `Expired`. Severity hints are in [`Rejected`](#rejected).

---

## Client side: `Set-Cookie` and dates

Feature `client`. For outbound HTTP clients (fetch-net, oauth-net), which must treat cookies as a user agent does. These functions follow the rfc6265bis user-agent algorithms exactly, which are more lenient than the server grammar on purpose; names and values here are bytes, because a client keeps what a server sent.

### `parse_set_cookie`

```rust
pub fn parse_set_cookie<L: AsRef<[u8]> + ?Sized>(line: &L) -> Option<SetCookieView<'_>>;
```

The rfc6265bis section 5.6 algorithm: `None` means a user agent ignores the whole line (a CTL other than HTAB anywhere; an empty name and value; name plus value over 4096). Without `=` the name is empty and the value is the whole pair (a nameless cookie). Attributes are split at `;` and `=`, trimmed, and matched case-insensitively; a later attribute replaces an earlier one; an attribute value over 1024 bytes is ignored; unknown attributes are counted.

```rust
use cookie_net::{parse_set_cookie, SameSiteAttr};

let v = parse_set_cookie("id=a3fWa; Max-Age=2592000; Domain=.Example.com; secure; SameSite=lax").unwrap();
assert_eq!((v.name, v.value), (&b"id"[..], &b"a3fWa"[..]));
assert_eq!(v.max_age, Some(2_592_000));
assert_eq!(v.domain, Some(&b"Example.com"[..]));   // leading dot removed; lowercased when stored
assert!(v.secure);
assert_eq!(v.same_site, SameSiteAttr::Lax);
assert!(parse_set_cookie("a=b\x01c").is_none());
```

| Id | Grade | Tier | Ver | Cost [est.] |
|---|---|---|---|---|
| CLI-1 | P2 | 1 | 0.5 | 80 ns for a 120-byte line |

### `SetCookieView`

```rust
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SetCookieView<'a> {
    pub name: &'a [u8],
    pub value: &'a [u8],
    pub expires: Option<i64>,         // from cookie_date
    pub max_age: Option<i64>,         // seconds; 0 or less means "expire now"; capped at MAX_LIFETIME
    pub domain: Option<&'a [u8]>,     // leading '.' removed
    pub path: Option<&'a [u8]>,       // None also when the value does not start with '/'
    pub secure: bool,
    pub http_only: bool,
    pub same_site: SameSiteAttr,
    pub partitioned: bool,
    pub unknown_attributes: u8,       // saturating
}
impl core::fmt::Debug for SetCookieView<'_> {}   // value as its length
```

`Max-Age` must be `-` or a digit followed by digits, else it is ignored (section 5.6.2); larger values saturate and are capped at 400 days.

| Id | Grade | Tier | Ver |
|---|---|---|---|
| CLI-4 | P2 | 2 | 0.5 |

### `SameSiteAttr`

```rust
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub enum SameSiteAttr { Strict, Lax, None, #[default] Default }
```

`Default` means absent or an unknown value; the jar treats it as `Lax` (section 5.6.7).

| Id | Grade | Tier | Ver |
|---|---|---|---|
| CLI-2 | P2 | 2 | 0.5 |

### `cookie_date`

```rust
pub fn cookie_date<V: AsRef<[u8]> + ?Sized>(value: &V) -> Option<i64>;
```

The lenient cookie-date algorithm of rfc6265bis section 5.1.1 (RFC 6265 section 5.1.1), different from HTTP-date on purpose and needed only here: tokens split on delimiters; the first matching time, day-of-month, month, and year tokens; two-digit years 70 to 99 add 1900 and 0 to 69 add 2000; years before 1601, invalid days, and invalid times fail.

```rust
use cookie_net::cookie_date;

assert_eq!(cookie_date("Wed, 09 Jun 2021 10:18:14 GMT"), Some(1_623_233_894));
assert_eq!(cookie_date("09-Jun-21 10:18:14"), Some(1_623_233_894));
assert_eq!(cookie_date("Jun 9 2021 10:18"), None);   // no seconds: the time token does not match
assert_eq!(cookie_date("Wed, 09 Jun 1600 10:18:14 GMT"), None);
```

| Id | Grade | Tier | Ver | Cost [est.] |
|---|---|---|---|---|
| CLI-3 | P2 | 3 | 0.5 | 60 ns |

---

## Client cookie jar

Feature `jar`. A bounded store that follows the rfc6265bis storage model (section 5.7) and retrieval (section 5.8.3) for a non-browser client.

### `Jar`

```rust
pub struct Jar<P: PublicSuffix = NoSuffixList, S: JarStore = MemoryStore> { /* store, limits, suffixes */ }

impl Jar<NoSuffixList, MemoryStore> {
    pub fn new() -> Self;
}
impl<P: PublicSuffix> Jar<P, MemoryStore> {
    pub fn with_public_suffix(suffixes: P) -> Self;
}
impl<P: PublicSuffix, S: JarStore> Jar<P, S> {
    pub fn with_store(suffixes: P, store: S) -> Self;
    pub fn with_limits(self, limits: JarLimits) -> Self;

    pub fn store<L: AsRef<[u8]> + ?Sized>(&mut self, url: &RequestUrl<'_>, set_cookie: &L, now: u64) -> StoreOutcome;
    pub fn store_all<'l, I: IntoIterator<Item = &'l [u8]>>(&mut self, url: &RequestUrl<'_>, lines: I, now: u64) -> usize;

    pub fn cookie_header(&mut self, url: &RequestUrl<'_>, now: u64) -> Option<String>;
    pub fn cookie_header_for(&mut self, url: &RequestUrl<'_>, cx: &RequestContext<'_>, now: u64) -> Option<String>;
    pub fn write_cookie_header(&mut self, url: &RequestUrl<'_>, cx: &RequestContext<'_>, now: u64,
                               out: &mut impl parse_net::Sink) -> Result<usize, CookieError>;

    pub fn remove_expired(&mut self, now: u64) -> usize;
    pub fn clear(&mut self);
    pub fn clear_domain(&mut self, domain: &str) -> usize;
    pub fn len(&self) -> usize;
    pub fn is_empty(&self) -> bool;
    pub fn cookies(&self) -> impl Iterator<Item = &StoredCookie> + '_;

    pub fn export(&self) -> Vec<u8>;
    pub fn import(&mut self, bytes: &[u8], now: u64) -> Result<usize, CookieError>;   // InvalidJarData
}
impl Default for Jar<NoSuffixList, MemoryStore> {}
impl<P: PublicSuffix, S: JarStore> core::fmt::Debug for Jar<P, S> {}   // counts and limits, never values
```

- `store` applies the steps of section 5.7 that apply to a non-browser client, in order, including: ignore an empty name with an empty value; ignore a nameless cookie whose value starts with a prefix (step 22, threat T7); refuse `Secure` from a non-secure origin; leave secure cookies alone (a non-secure origin cannot overwrite or shadow a `Secure` cookie, threat T25); domain-match; the public suffix check; prefix requirements; `SameSite=None` and `Partitioned` need `Secure`; replacing a cookie keeps its creation time; expiry capped at 400 days. Every ignore has an [`IgnoreReason`](#storeoutcome-and-ignorereason).
- `cookie_header` builds the `Cookie` header for a request (section 5.8.3): host-only or domain-match, path-match, `Secure` only over secure channels, `SameSite` against the context, longer paths first then earlier creation, `"; "` between pairs; it updates last-access times. `None` when no cookie applies. It uses `RequestContext::same_site()`; `cookie_header_for` takes the context.
- `write_cookie_header` writes the same bytes into a sink and returns how many cookies it holds; nothing is written when the sink reports too little room.
- A nameless cookie is sent as its value alone (section 5.8.3).
- Partitioned cookies are stored under the request host as their partition key (a non-browser client is its own top-level site) and sent only when the context's `top_level_site` (default: the request host) is the same, so they never cross partitions.
- `export` writes the cookies in creation order in the format of [`FORMATS.md`](./FORMATS.md#jar-export-format-v1), with a BLAKE3 checksum; `import` checks the bytes as untrusted input (the checksum catches corruption; a re-checksummed edit is still validated field by field), skips cookies expired at `now`, and applies the jar's bounds. Exported bytes hold cookie values, so treat them as secrets.
- Memory is bounded by [`JarLimits`](#jarlimits), never by input. When a domain or the jar is over its limit, expired cookies go first, then the least recently accessed.

```rust
use cookie_net::{Jar, RequestUrl, StoreOutcome};

let mut jar = Jar::new();
let login = RequestUrl::https("app.example.com", "/login");
assert_eq!(jar.store(&login, "sid=abc; Path=/; Secure; HttpOnly", now), StoreOutcome::Stored);
assert_eq!(jar.store(&login, "tracker=1; Domain=com", now), StoreOutcome::Ignored(cookie_net::IgnoreReason::DomainNotAllowed));

let api = RequestUrl::https("app.example.com", "/api/orders");
assert_eq!(jar.cookie_header(&api, now).as_deref(), Some("sid=abc"));
assert_eq!(jar.cookie_header(&RequestUrl::http("app.example.com", "/"), now), None);   // Secure over HTTP
```

| Id | Item | Grade | Tier | Ver | Cost [est.] |
|---|---|---|---|---|---|
| JAR-1 | `Jar::new`, `Default` | P2 | 1 | 0.5 | n/a |
| JAR-3 | `store`, `StoreOutcome` | P2 | 1 | 0.5 | 300 ns |
| JAR-4 | `store_all` | P2 | 1 | 0.5 | as JAR-3 |
| JAR-5 | `cookie_header`, `cookie_header_for`, `write_cookie_header` | P2 | 1 | 0.5 | 1 µs for 20 cookies |
| JAR-7 | `with_limits`, eviction | P2 | 2 | 0.5 | n/a |
| JAR-8 | `remove_expired`, `clear`, `clear_domain`, `len`, `is_empty` | P2 | 2 | 0.5 | linear |
| JAR-9 | partitioned storage | P2 | 2 | 0.5 | n/a |
| JAR-13 | `with_store`, `cookies` | P2 | 2 | 0.5 | n/a |

### `RequestUrl` and `RequestContext`

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequestUrl<'a> { /* secure, host, path */ }
impl<'a> RequestUrl<'a> {
    pub const fn https(host: &'a str, path: &'a str) -> Self;
    pub const fn http(host: &'a str, path: &'a str) -> Self;
    pub const fn new(secure: bool, host: &'a str, path: &'a str) -> Self;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequestContext<'a> { /* private */ }
impl<'a> RequestContext<'a> {
    pub const fn same_site() -> Self;                              // the default for a non-browser client
    pub const fn cross_site() -> Self;
    pub const fn navigation(self, safe_method: bool) -> Self;      // a top-level navigation (Lax cookies go with safe methods)
    pub const fn top_level_site(self, site: &'a str) -> Self;      // the partition key
}
impl Default for RequestContext<'_> {}                             // same_site()
```

The jar takes a URL as its parts, already parsed (by url-lib when it exists): `host` is the host without a port, in ASCII (punycode for international names), with no trailing dot (it is compared case-insensitively); `path` is the request path without the query (an empty path is `/`). An IP-address host only ever gets host-only cookies.

| Id | Grade | Tier | Ver |
|---|---|---|---|
| JAR-6 | P2 | 2 | 0.5 |

### `PublicSuffix` and `NoSuffixList`

```rust
pub trait PublicSuffix {
    fn is_public_suffix(&self, domain: &str) -> bool;
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct NoSuffixList;
impl PublicSuffix for NoSuffixList {}   // every domain is a public suffix: fail closed
```

The public suffix list is about 200 KB and changes often, so it is not bundled (decision CN-6). With the default `NoSuffixList` the jar **fails closed**: a `Domain` equal to the request host makes a host-only cookie, and any other `Domain` value ignores the cookie. That prevents a site from setting a cookie for `co.uk` or `github.io` (supercookies, threat T22), at the cost of not sharing cookies across sibling subdomains unless the caller supplies a list.

```rust
use cookie_net::{Jar, PublicSuffix};

struct MyList(/* loaded from publicsuffix.org */);
impl PublicSuffix for MyList {
    fn is_public_suffix(&self, domain: &str) -> bool { lookup(domain) }
}
let jar = Jar::with_public_suffix(MyList(/* ... */));
```

| Id | Grade | Tier | Ver |
|---|---|---|---|
| JAR-2 | P2 | 2 | 0.5 |

### `JarLimits`

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct JarLimits { /* private */ }
impl JarLimits {
    pub const DEFAULT: JarLimits;                          // 50 per domain, 3000 total
    pub const fn per_domain(self, n: u16) -> Self;         // 1 to 1,000
    pub const fn total(self, n: u32) -> Self;              // 1 to 1,000,000
}
```

The defaults are the rfc6265bis section 6.1 minimums. Each cookie is at most 4096 bytes of name and value (section 5.6), so the jar's memory is bounded by `total * (4096 + attributes)`.

### `StoreOutcome` and `IgnoreReason`

```rust
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum StoreOutcome { Stored, Replaced, Removed, Ignored(IgnoreReason) }

#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IgnoreReason {
    Malformed,              // the 5.6 algorithm ignores the line
    NamelessPrefixed,       // step 22: a nameless cookie whose value starts with __Host- or __Secure-
    SecureFromInsecure,     // Secure attribute from a non-secure origin
    WouldShadowSecure,      // a non-secure origin would overwrite or shadow a Secure cookie
    DomainMismatch,         // Domain does not domain-match the request host
    DomainNotAllowed,       // a public suffix, or any foreign Domain with NoSuffixList
    HostPrefix,
    SecurePrefix,
    SameSiteNoneNeedsSecure,
    PartitionedNeedsSecure,
    Expired,                // already expired, and nothing stored to remove
}
```

| Id | Grade | Tier | Ver |
|---|---|---|---|
| JAR-3 | P2 | 1 | 0.5 |

### `JarStore` and `MemoryStore`

```rust
pub trait JarStore {
    fn len(&self) -> usize;
    fn is_empty(&self) -> bool { self.len() == 0 }
    fn get(&self, index: usize) -> Option<&StoredCookie>;
    fn get_mut(&mut self, index: usize) -> Option<&mut StoredCookie>;
    fn push(&mut self, cookie: StoredCookie);
    fn swap_remove(&mut self, index: usize) -> Option<StoredCookie>;
    fn clear(&mut self);
}
#[derive(Clone, Debug, Default)]
pub struct MemoryStore { /* a Vec */ }
impl JarStore for MemoryStore {}

#[non_exhaustive]
#[derive(Clone, PartialEq, Eq)]
pub struct StoredCookie {
    pub name: Vec<u8>, pub value: Vec<u8>,
    pub domain: String,            // lowercase; the request host for a host-only cookie
    pub path: Vec<u8>,
    pub expiry: Option<u64>,       // None: a session cookie
    pub creation: u64, pub last_access: u64,
    pub host_only: bool, pub secure: bool, pub http_only: bool,
    pub same_site: SameSiteAttr,
    pub partition: Option<String>,
    /* creation order, private */
}
impl core::fmt::Debug for StoredCookie {}   // value as its length
```

The portfolio's enterprise rule puts stateful parts behind a trait, so state can live in memory, on disk, or be shared (decision D-035). A store only holds and indexes; the jar applies every rule and every bound, so a store cannot weaken them. A durable store writes through on `push` and `swap_remove`; a shared one does the same against its backend. Export and import move a whole jar between processes or nodes.

| Id | Item | Grade | Tier | Ver |
|---|---|---|---|---|
| JAR-12 | `JarStore`, `MemoryStore` | P1 | 3 | 0.5 |
| JAR-10 | export and import with version and checksum | P2 | 2 | 0.5 |
| JAR-11 | `SharedJar` (sharded, `loom`-tested) for concurrent clients | P3 | 2 | after 1.0 |

---

## Thread safety and sizes

| Type | `Send + Sync` | Notes |
|---|---|---|
| `Limits`, `JarLimits`, `Cookies`, `Pair`, `Stats`, `Lookup`, `Located`, `SetCookie`, `SetCookieBuilder`, `SetCookieView` | yes | `Copy` views; no interior mutability |
| `Key`, `KeyRing`, `Signer`, `Sealer` | yes | immutable after construction; rotation builds a new value the application swaps in (WASP: a `Snapshot`), so verification never locks |
| `Plaintext` | yes | owned |
| `Jar` | yes | mutates through `&mut self`; no internal locking |

Every row is checked by a test. Sizes on 64-bit targets, measured at 0.3: `Pair` 32 bytes, `Cookies` 48, `Lookup` 24, `Located` 40, `Stats` 12, `Limits` 16, `SetCookie` 232 (eight extension slots), `SetCookieBuilder` 256. `Signer` and `Sealer` about 400 [est.] (eight subkeys, wiped on drop).

---

## Use cases

### WASP gateway: the credential locator

```rust
use cookie_net::{self as cookie, Limits, Lookup};

const COOKIE_LIMITS: Limits = Limits::DEFAULT;

fn authenticate(cookie_header: Option<&[u8]>, events: &mut Events) -> Identity {
    let Some(header) = cookie_header else { return Identity::Guest };
    let found = cookie::locate(header, "__Host-sid", &COOKIE_LIMITS);
    if found.severity_hint() > 0 {
        events.raise("cookie.credential", found.severity_hint(), found.stats);
    }
    match found.lookup {
        Lookup::One(token) => sessions.get(digest(token)).map_or(Identity::Guest, Identity::User),
        _ => Identity::Guest,   // Missing, Many, Truncated, HeaderTooLong: fail closed
    }
}
```

### Login, rolling tokens, logout

```rust
use cookie_net::{self as cookie, SetCookie};

// login: a new token every time (session fixation defence)
let token = gates.login(&user)?;
response.header("set-cookie", cookie::session_cookie("__Host-sid", &token, 12 * cookie::HOUR)?.encode());

// a roll every 15 minutes: the same helper with the new token
response.header("set-cookie", cookie::session_cookie("__Host-sid", &rolled, 12 * cookie::HOUR)?.encode());

// sudo mode after a second factor
response.header("set-cookie", cookie::elevated_cookie("__Host-sudo", &sudo, 10 * cookie::MINUTE)?.encode());

// logout: revoke on the server first, then clear both cookies
gates.logout(&session)?;
response.header("set-cookie", SetCookie::delete("__Host-sid")?.encode());
response.header("set-cookie", SetCookie::delete("__Host-sudo")?.encode());
```

### Preferences and flash messages

```rust
use cookie_net::{self as cookie, SetCookie};

// an unsigned preference: harmless if a user edits it
response.header("set-cookie", SetCookie::builder("theme", "dark").max_age(365 * cookie::DAY).build()?.encode());
let theme = cookie::get(header, "theme").unwrap_or("light");

// a signed preference the server relies on
let v = signer.sign("plan_banner", "dismissed")?;
response.header("set-cookie", SetCookie::builder("plan_banner", &v).max_age(30 * cookie::DAY).build()?.encode());

// a private flash message for the next page only
let v = sealer.seal_until("flash", "Payment received.", now + 60)?;
response.header("set-cookie", SetCookie::builder("flash", &v).max_age(60).build()?.encode());
// next request: read, show, delete
if let Some(raw) = cookie::get(header, "flash") {
    if let Ok(text) = sealer.open("flash", raw, now) { show(text.as_str()); }
    response.header("set-cookie", SetCookie::delete("flash")?.encode());
}
```

### HTTP/2 cookie crumbs

```rust
use cookie_net::{Cookies, Limits};

let lines: Vec<&[u8]> = head.fields("cookie").collect();      // each crumb as its own field line
let cookies = Cookies::from_lines(&lines, &Limits::DEFAULT)?;
let sid = cookies.get_unique("__Host-sid")?;
```

### An outbound client

```rust
use cookie_net::{Jar, RequestUrl};

let mut jar = Jar::new();
let url = RequestUrl::https("api.example.com", "/oauth/token");
let response = http.post(&url, body, jar.cookie_header(&url, now).as_deref())?;
jar.store_all(&url, response.fields("set-cookie"), now);
```

---

## Item index

| Group | Items | Ver |
|---|---|---|
| ROOT | `VERSION` (0.1), `MINUTE`, `HOUR`, `DAY`, `MAX_LIFETIME` | 0.3 |
| ERR | `CookieError`, `Ambiguous`, `code`, `Display`, `Error`, `From` | 0.3 |
| LIM | `Limits`, `ValueMode` | 0.3 |
| REQ | `parse`, `get`, `get_unique`, `get_all`, `GetAll`, `Cookies`, `Iter`, `Pair`, `Stats`, `Lookup`, `Located`, `locate`, `Prefix` | 0.3 |
| SET | `SetCookie`, `SetCookieBuilder`, `SameSite` | 0.3 |
| SES | `session_cookie`, `elevated_cookie` (0.3), `CLEAR_SITE_DATA_COOKIES` (0.5) | 0.3, 0.5 |
| KEY | `Key`, `KeyId`, `KeyRole`, `KeyInfo`, `KeyFingerprint`, `KeyRing` | 0.4 |
| SGN | `Signer`, `Verified`, `Rejected` | 0.4 |
| SEAL | `Sealer`, `Plaintext`, `Opened` | 0.4 |
| CLI | `parse_set_cookie`, `SetCookieView`, `SameSiteAttr`, `cookie_date` | 0.5 |
| JAR | `Jar`, `RequestUrl`, `RequestContext`, `PublicSuffix`, `NoSuffixList`, `JarLimits`, `StoreOutcome`, `IgnoreReason`, `JarStore`, `MemoryStore`, export and import | 0.5 |
| after 1.0 | typed `Priority` (SET-20), `SharedJar` (JAR-11) | |
