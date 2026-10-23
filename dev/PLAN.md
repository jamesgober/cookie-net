# cookie-net - Project Plan

> The design, strategy, and decision record for `cookie-net`. A living document: every design decision, idea, or open question about cookie-net is written here or in [`ROADMAP.md`](./ROADMAP.md) before it is acted on.
>
> **Read order:** [`../REPS.md`](../REPS.md) &rarr; [`DIRECTIVES.md`](./DIRECTIVES.md) &rarr; **this file** &rarr; [`ROADMAP.md`](./ROADMAP.md) &rarr; [`../docs/API.md`](../docs/API.md) (the locked API).
>
> **Status:** `0.6.0`, optimisation. API approved by James on 2026-10-23 at `0.2.0`. Rewritten from the crate's specification (decision D-004). The public API is in `docs/API.md`; this file holds the reasons.

---

## Contents

1. [Purpose](#1-purpose)
2. [Position in the stack](#2-position-in-the-stack)
3. [Scope](#3-scope)
4. [Requirements](#4-requirements)
5. [Session cookies](#5-session-cookies)
6. [Design principles](#6-design-principles)
7. [Architecture](#7-architecture)
8. [Approved exceptions](#8-approved-exceptions)
9. [Threats](#9-threats)
10. [Performance](#10-performance)
11. [Testing](#11-testing)
12. [Ideas](#12-ideas)
13. [Open decisions and requests](#13-open-decisions-and-requests)
14. [Decision log](#14-decision-log)

---

## 1. Purpose

cookie-net reads the `Cookie` request header and writes `Set-Cookie` response headers, following RFC 6265 and its revision draft-ietf-httpbis-rfc6265bis (draft 22, submitted for publication), with secure defaults and rules that make an invalid cookie impossible to build. On top of that:

- **signed cookies**: keyed BLAKE3 through crypt-io, bound to the cookie name, with key ids, rotation, an optional server-enforced expiry, and an optional session binding;
- **encrypted cookies**: XChaCha20-Poly1305 through crypt-io, with the name and header as associated data;
- **session-cookie helpers** for WASP's `__Host-sid` and `__Host-sudo`, which carry opaque tokens and are deliberately neither signed nor encrypted;
- a **client side**: the rfc6265bis `Set-Cookie` parsing and cookie-date algorithms, and a bounded cookie jar for outbound clients.

Parsing is zero-copy and allocation-free; the server-side core is `no_std` without an allocator.

### 1.1 What it is not

| Not | Where that lives |
|---|---|
| sessions: creation, storage, expiry, rotation, revocation, binding | gate-net and WASP's gates |
| CSRF protection | csrf-sec. cookie-net supplies only the cookie attributes csrf-sec's third layer relies on. csrf-sec tokens are never double-submit cookies, so there is no CSRF cookie helper here, on purpose (D-015) |
| HTTP framing and header storage | http-net (h2-net later) |
| the HTTP field grammar (tokens, OWS, HTTP-date, host syntax, byte classes) | parse-net |
| cryptographic primitives | crypt-io; never written in-house |
| key custody | key-vault, through the caller: cookie-net receives key bytes and never depends on key-vault (D-007) |
| base64url | encode-lib (planned); a private interim module until it ships (D-008) |
| URL parsing for the jar | url-lib (planned); the jar takes host, path, and scheme as parts |
| the public suffix list data | outside the crate; the jar takes a `PublicSuffix` implementation (D-010) |

---

## 2. Position in the stack

| Consumer | Uses |
|---|---|
| WASP gateway-io (authentication) | `locate(header, "__Host-sid", &limits)` on every request, before any service code |
| WASP gates (login, logout, elevation, rolling tokens) | `session_cookie`, `elevated_cookie`, `SetCookie::delete` |
| WASP web service and web-net | `SetCookie` for preferences and flash messages; `Signer` and `Sealer` for small client-held state |
| gate-net | session cookie names, attributes, and lifetimes; reads tokens through the same locator |
| csrf-sec (indirectly) | relies on `__Host-` and `SameSite=Lax` on the session cookie |
| customs-sec, sentinel-sec | `Stats`, `Located` (duplicates, shadows, truncation), `Rejected` reasons with severity hints |
| fetch-net, oauth-net (planned) | `parse_set_cookie`, `Jar` |

| Dependency | Why | Kind |
|---|---|---|
| `parse-net` 0.6 | `tchar`, `cookie-octet`, `av-octet` byte classes, `scan::find_byte`, `HttpDate` formatting for `Expires`, host syntax for `Domain`, the `Sink` writers | required, first party, zero dependencies, published |
| `crypt-io` 1.1 | keyed BLAKE3, `Tag<16>::ct_eq`, HKDF-SHA-256, XChaCha20-Poly1305 (`encrypt_with_aad_into`, `decrypt_with_aad_into`), wiping | optional (`signed`, `encrypted`); the audited-crypto exception |
| `encode-lib` (planned) | base64url without padding | optional, when published (D-008) |

No third-party runtime dependency of cookie-net's own; no async runtime.

---

## 3. Scope

| Area | In scope | Version |
|---|---|---|
| Request side | strict `Cookie` parsing with budgets, zero-copy pairs, first, unique, and all matches, HTTP/2 crumbs, statistics, the one-pass credential locator with shadow names | 0.3 |
| Response side | `SetCookie` with every rfc6265bis attribute, `Partitioned`, validated extensions, prefix rules, size limits, deletion, writing into any `Sink` | 0.3 |
| Session helpers | `__Host-sid` and `__Host-sudo` writers with fixed attributes | 0.3 |
| Signed and encrypted cookies | keys, rings, staged rotation, fingerprints, expiry, binding | 0.4 |
| Client side | `Set-Cookie` and cookie-date algorithms, the jar with a store trait, export and import | 0.5 |
| Defence helpers | `Clear-Site-Data: "cookies"` for cookie-bomb recovery | 0.5 |

Out of scope: session ids and their randomness (gate-net); CSRF tokens (csrf-sec, never in cookies); public suffix data (the caller, or a future data crate, CN-6); browser-only behaviour (third-party cookie policy, `document.cookie`); `Cookie2` and `Set-Cookie2` (RFC 2965, obsolete: legacy `$Version` input is read as ordinary pairs).

---

## 4. Requirements

### 4.1 Functional

| Id | Requirement | API |
|---|---|---|
| FR-1 | Parse a `Cookie` header into pairs without copying or allocating | REQ-1 to REQ-4 |
| FR-2 | Check every budget before the work it governs; report truncation instead of dropping silently | REQ-5, LIM-1 |
| FR-3 | Skip and count pairs that break the grammar (D-003) | REQ-1, REQ-6 |
| FR-4 | A unique lookup that reports duplicates and truncation, for credentials | REQ-3, REQ-7 |
| FR-5 | Several `Cookie` field lines read as one header without copying | REQ-8 |
| FR-6 | Never trim, normalize, or decode names; compare byte for byte | REQ-1, T6 to T9 |
| FR-7 | `Set-Cookie` defaults `Secure; HttpOnly; SameSite=Lax; Path=/`, host-only (D-001) | SET-1 to SET-3 |
| FR-8 | Impossible to build a cookie that breaks a prefix rule, `SameSite=None` or `Partitioned` without `Secure`, the 4096 and 1024 byte limits, or the 400-day cap (D-002) | SET-4 to SET-14 |
| FR-9 | Refuse CR, LF, NUL, `;`, and every other forbidden byte at build time | SET-4, SET-5, T1 |
| FR-10 | Write into any `Sink`, with the exact length available first | SET-15 to SET-17 |
| FR-11 | Deletion cookies that match the original's name, path, domain, and prefix | SET-18 |
| FR-12 | WASP's session and elevated cookie writers with fixed attributes | SES-1 to SES-3, SES-5 |
| FR-13 | Signed values bound to the name, with a key id; constant-time verification; a precise reason | SGN-1 to SGN-8 |
| FR-14 | Encrypted values with the name and header as associated data | SEAL-1 to SEAL-7 |
| FR-15 | Key rotation without logging anyone out, staged across a cluster | KEY-3 to KEY-6 |
| FR-16 | Signing and sealing never share key material | KEY-2, D-019 |
| FR-17 | Optional server-enforced expiry in signed and encrypted values | SGN-3, SEAL-3 |
| FR-18 | Optional session binding of signed and encrypted values | SGN-9, SEAL-8 |
| FR-19 | `Set-Cookie` parsed exactly as rfc6265bis section 5.6 says user agents do | CLI-1 to CLI-4 |
| FR-20 | Storage and retrieval per sections 5.7 and 5.8.3, bounded, failing closed on domain cookies without a suffix list | JAR-1 to JAR-12 |
| FR-21 | Facts for attack detection: skipped pairs, duplicates of prefixed names, shadow names, truncation, key roles, reasons with severity hints, stable codes | REQ-6, REQ-7, REQ-13, SGN-6, ERR-4 |

### 4.2 Non-functional

| Id | Requirement | Checked by |
|---|---|---|
| NFR-1 | No allocation when parsing, looking up, writing into a `SliceSink`, signing into a `SliceSink`, or verifying | counting-allocator tests |
| NFR-2 | Linear time in the header length; no quadratic duplicate detection (D-039) | 8 KiB headers of 1-byte pairs |
| NFR-3 | `get_unique` for `__Host-sid` in a 300-byte header with 6 pairs at most 25 ns [est.], and at least 20% faster than the best Rust competitor | criterion, 0.6 |
| NFR-4 | Constant-time tag comparison; keys wiped on drop; no key, token, or cookie value in `Debug`, `Display`, or errors | tests, `Debug` output tests |
| NFR-5 | No panics on any input | fuzzing, property tests, clippy denies |
| NFR-6 | The core is `no_std` without an allocator; `signed` works without `std` given an allocator (D-033); `encrypted` needs `std` | CI feature matrix |
| NFR-7 | No third-party runtime dependency of cookie-net's own; crypt-io only behind features | `cargo tree` in CI |
| NFR-8 | `Signer`, `Sealer`, `KeyRing`, `Limits`, and every view are `Send + Sync`; verification takes no lock and touches no shared counter | compile-time assertions |
| NFR-9 | The same inputs and `now` give the same bytes on every platform, except the random nonce of sealed values | cross-platform vector tests |
| NFR-10 | Every rfc6265bis rule cookie-net enforces is cited in rustdoc with its section | doc review |

### 4.3 Enterprise and distributed

cookie-net is a **stateless** crate on the server side and holds state only in the client jar.

| Point | How it is met |
|---|---|
| Deterministic, no process-local assumptions | no clock reads in the core (`now` is a parameter), no global state, no random keys (D-032); the same ring verifies the same cookie on every node |
| Distributed keys | rings are plain values built from configuration; staged rotation (`accept`, then switch, then drop) means no node ever refuses a cookie another node just signed; fingerprints let an operator compare rings across nodes before a switch (D-020) |
| Clock skew | an expiry is accepted while `now < expires + skew`, default 60 seconds, configurable, the same as csrf-sec (D-031) |
| Concurrency | every server-side type is immutable and `Send + Sync`; rotation swaps a new value in; nothing locks |
| Observable | facts are returned as values at no cost when unused: `Stats`, `Located` with `severity_hint`, `Rejected` reasons, key roles, stable `code()` strings; the caller (WASP's gateway) forwards them to the event bridge, so cookie evidence reaches every other security component (D-027) |
| Operable | every budget is configurable with a secure default (`Limits`, `JarLimits`); overload is refused cleanly (`HeaderTooLong`, `Truncated`), never a crash |
| Stateful part (the jar) | state behind `JarStore` with an in-memory default, export and import with a version and checksum, bounded memory, eviction defined (D-035) |
| Long-lived systems | semantic versioning, `#[non_exhaustive]` on every extensible type (D-038), `docs/STABILITY-1.0.md` by 1.0 |

---

## 5. Session cookies

Session security is designed in gate-net (its `dev/SESSIONS.md`); cookie-net carries the tokens.

| Cookie | Attributes (fixed by the helper) | Content | Signed or encrypted |
|---|---|---|---|
| `__Host-sid` | `Secure; HttpOnly; SameSite=Lax; Path=/`, no `Domain`, `Max-Age` = the session's absolute lifetime (WASP: 12 hours) | 32 random bytes, base64url; a lookup key only, never trusted | no |
| `__Host-sudo` (elevated sub-session) | `Secure; HttpOnly; SameSite=Strict; Path=/`, no `Domain`, `Max-Age` 60 to 3600 (recommended 300 to 900) | a separate random token for sensitive actions | no |

There is no CSRF cookie (D-015): csrf-sec tokens are session-bound MACs carried in form fields and request headers. Session tokens are opaque random values, so they are not signed or encrypted: nothing in them needs protecting and the server record is the truth. Signed and encrypted cookies are for small non-session state.

- `__Host-` makes the cookie host-only, `Secure`, and `Path=/`, so a sibling subdomain cannot set or overwrite it (cookie tossing). A tossed duplicate shows up as `Ambiguous::Duplicate` / `Lookup::Many`, and a tossed look-alike (`sid`, `__host-sid`) as a shadow name (D-040).
- `SameSite=Lax` on `__Host-sid`: links from email arrive signed in; cross-site `POST`, `fetch`, and frames do not. `SameSite=Strict` on `__Host-sudo`: elevated actions never start from another site.
- `Path=/` on `__Host-sudo` (D-011): gate-net's design scoped the elevated cookie to the sensitive paths, which the `__Host-` prefix forbids; paths do not isolate cookies anyway (RFC 6265 section 8.5), while `__Host-` blocks subdomain tossing.
- `Max-Age` = the absolute lifetime (D-012), so a browser left open drops the token; the server enforces idle and absolute limits regardless.
- Login and every gate-net token roll issue a new `__Host-sid`; logout revokes server-side, then writes `SetCookie::delete("__Host-sid")`.
- Reading cost: `locate` about 25 ns for a 300-byte header [est.]; it must scan the whole header to find duplicates. First-match `get` stays near 10 ns [est.].

---

## 6. Design principles

1. **Strict where we write, careful where we read.** Everything written conforms to the server grammar of rfc6265bis section 4.1.1 exactly. What is read comes from browsers that store whatever servers sent, so a pair that breaks the grammar is skipped and counted, never repaired and never fatal (D-003). Security-sensitive reads use the unique lookup, which fails closed.
2. **Names are bytes.** Compared byte for byte; no trimming beyond SP and HTAB, no case folding, no percent-decoding, no Unicode normalization. Every known prefix bypass relies on a server that does one of those.
3. **Invalid cookies cannot be built.** A `SetCookie` that exists is valid; writing it can only run out of room.
4. **Crypto is crypt-io's.** cookie-net frames bytes (version, key id, expiry, lengths) and calls crypt-io for MAC, AEAD, HKDF, and constant-time comparison.
5. **Sessions are opaque.** Session cookies carry random tokens the server looks up.
6. **Sans-IO and explicit time.** No clock reads in the core; `std` adds `*_now` conveniences.
7. **Simple first.** Every common use is one call with no configuration (Tier 1); names read without the docs; one error type works with `?` everywhere (D-034).
8. **Secrets never print.** Cookie values are bearer tokens: no `Display` for values, redacted `Debug`, positions instead of bytes in errors (D-025).

---

## 7. Architecture

### 7.1 Modules

```
src/
  lib.rs        crate docs, Tier 1 functions, VERSION, constants, feature gates
  error.rs      CookieError, Ambiguous, Rejected, codes
  limits.rs     Limits, ValueMode (request side); JarLimits (client side, feature "jar")
  name.rs       name and value classification, Prefix (shared by both sides)
  request.rs    Cookies, Pair, Iter, GetAll, Stats, Lookup, Located, the scanner
  response.rs   SetCookie, SetCookieBuilder, SameSite, the rules, serialization
  session.rs    session_cookie, elevated_cookie, CLEAR_SITE_DATA_COOKIES
  keys.rs       Key, KeyId, KeyRole, KeyInfo, KeyFingerprint, KeyRing          feature "signed"
  signed.rs     Signer, Verified                                               feature "signed"
  sealed.rs     Sealer, Plaintext, Opened                                      feature "encrypted"
  b64.rs        base64url, private, until encode-lib ships (D-008)             feature "signed"
  client/
    set_cookie.rs  rfc6265bis section 5.6 parsing                             feature "client"
    date.rs        rfc6265bis section 5.1.1 cookie-date                        feature "client"
    jar.rs         storage model, retrieval, JarStore, MemoryStore             feature "jar"
```

IMF-fixdate for `Expires` comes from parse-net's `HttpDate`; `client/date.rs` is only the lenient cookie-date algorithm, which has no other consumer.

### 7.2 Feature flags

| Feature | Default | Adds | Needs |
|---|---|---|---|
| `std` | yes (D-016) | `*_now` functions; implies `alloc` | |
| `alloc` | through `std` | `SetCookie::encode`, `String`-returning `sign*` and `seal*` | an allocator |
| (none) | | request side, response side, session helpers, errors, limits: `no_std`, no allocator | parse-net |
| `signed` | no | keys and `Signer` | crypt-io `mac-blake3`, `kdf-hkdf`, `zeroize`; an allocator (D-033) |
| `encrypted` | no | `Sealer`; implies `signed` and `std` | crypt-io `aead-chacha20`, `std` |
| `client` | no | `parse_set_cookie`, `cookie_date` | |
| `jar` | no | `Jar`; implies `client` and `alloc` | |

crypt-io is used with `default-features = false` and only the features above, so Argon2, AES-GCM, SHA-512, and the stream module never enter the tree.

### 7.3 Bounds

| Bound | Default | Source |
|---|---|---|
| `Cookie` header length, all lines together | 8,192 bytes (1 to 65,536) | CN-10 |
| pairs | 64 (1 to 1,024) | [est.] |
| name length | 256 bytes | [est.] |
| value length | 4,096 bytes | rfc6265bis section 5.6 |
| extension attributes when writing | 8 | output bound |
| key ring | 8 keys, fixed array | |
| decoded sealed value | 3,072 bytes on the stack | 4,096 characters of base64url |
| jar | 50 per domain, 3,000 total, 4,096 bytes per cookie | rfc6265bis sections 6.1 and 5.6 |

Limits setters clamp to their range instead of failing (D-041); getters show what is in force.

### 7.4 Formats and keys

Signed format v1 (22-byte header, 30 characters, then the value) and sealed format v1 (46 bytes of overhead, all base64url) are in `docs/API.md`; the byte-exact form, the subkey derivations, and test vectors go into `docs/FORMATS.md` at 0.4. The MAC input and the AAD both carry a domain-separation label, the version, the key id, the expiry, the length-prefixed name, and the length-prefixed binding (D-023), so a value cannot move between names, sessions, versions, or keys.

Keys: `Key` (32 bytes, wiped on drop, `Debug` prints `Key(..)`), `Key::derive(master, context)` (HKDF-SHA-256, master at least 32 bytes), and per-purpose subkeys derived inside `Signer` and `Sealer` (D-019). Rings follow csrf-sec's vocabulary (D-020): one `Signing` key, `Accepted` keys staged on every node before they sign, `Retired { until }` keys that verify until a time.

---

## 8. Approved exceptions

| Rule | Exception | Reason |
|---|---|---|
| REPS "MUST use tokio for async runtime" | cookie-net uses no async runtime | a known mistake in REPS for this portfolio: cores are sans-IO and work with any driver; cookie-net does no I/O at all (D-036) |
| REPS zero third-party dependencies | crypt-io (and the audited RustCrypto and `blake3` crates under it) behind the `signed` and `encrypted` features | cryptography is never written in-house |

---

## 9. Threats

Every row has an attack test that must fail to get through (0.3 to 0.7); costs are estimates until measured.

| Id | Threat | Defence | Test | Cost [est.] |
|---|---|---|---|---|
| T1 | header injection: CR, LF, NUL in a name, value, path, domain, or extension | every byte validated at build; a `SetCookie` cannot hold a forbidden byte | each byte 0x00 to 0x1F and 0x7F in each field | 0.5 ns per byte |
| T2 | attribute injection: `;` in a value adding `Domain=` or `SameSite=None` | `;` is neither `cookie-octet` nor `av-octet` | `;` in value and path refused | none |
| T3 | cookie tossing: a sibling or parent-domain page plants `sid` or a second `__Host-sid` | `__Host-` on every credential; `get_unique` reports duplicates; shadow names counted; csrf-sec tokens never compared to a cookie | tossed duplicate is ambiguous; parent-domain `sid` beside `__Host-sid` is a shadow | 25 ns per lookup |
| T4 | oversized cookies or headers | write-side `TooLarge`; read-side `HeaderTooLong` before scanning; oversize pairs skipped | 4097-byte pair refused; 8193-byte header too long | 1 ns |
| T5 | cookie bombing from a hostile subdomain (per-user denial of service) | budgets with truncation reported; the locator fails closed to guest; `CLEAR_SITE_DATA_COOKIES` for recovery; an event to sentinel-sec | bombed header truncated, never a panic; `Truncated` is never `One` | none until it happens |
| T6 | whitespace trimming of names (U+00A0 before `__Host-`, as in Hono CVE-2026-39410) | names never trimmed beyond SP and HTAB, never Unicode-trimmed; non-`tchar` names skipped | NBSP- and Unicode-space-prefixed names are not host cookies | none |
| T7 | nameless cookie carrying a prefixed name (`Set-Cookie: =__Host-sid=x`) | rfc6265bis 5.7 step 22 in the jar; on old user agents the planted pair is a duplicate | jar ignores it; planted duplicate detected | none |
| T8 | case variants of prefixes (`__HOST-sid`) | names compared byte for byte; prefix rules applied case-insensitively when writing; case variants counted as shadows | case variant not matched | none |
| T9 | percent-decoded names (`%5F_Host-sid`) | names never decoded | not decoded | none |
| T10 | quotes stripped by one component and not another | quotes are part of the value; `value_unquoted` is explicit | quoted value kept | none |
| T11 | comma as a separator (RFC 2965) | `,` is not a separator | `a=1, b=2` is one skipped pair | none |
| T12 | `$Version`, `$Path` read as attributes | ordinary names | plain pairs | none |
| T13 | duplicate names on different paths | `get` documented as order-dependent; credentials use `get_unique` | two paths are ambiguous | none |
| T14 | tampering with signed or sealed values | MAC / AEAD | every single-bit flip of every byte is `BadTag` or `Malformed` | 120 ns verify |
| T15 | moving a value to another cookie name | the name is in the MAC input and the AAD | under another name: `BadTag` | none |
| T16 | replay of old signed state | optional server-enforced expiry; key retirement; optional session binding | expired and retired-key tests | 4 bytes per cookie |
| T17 | key compromise | key ids, staged rotation, per-purpose subkeys, short expiries | rotation tests | operational |
| T18 | timing attack on tag comparison | crypt-io `Tag<16>::ct_eq`; AEAD checks inside crypt-io | dudect-style smoke test in CI, long run before 1.0 | none |
| T19 | session cookie over HTTP or read by scripts | `Secure` and `HttpOnly` fixed; `__Host-` requires `Secure` | session cookie attributes fixed | none |
| T20 | CSRF | `SameSite=Lax` default, `Strict` for elevation; csrf-sec covers unsafe methods | default is Lax | none |
| T21 | `SameSite=None` or `Partitioned` without `Secure` | refused at build | both refused | none |
| T22 | `Domain` set to a public suffix, an IP, or a single label | IP and single label refused at build; public suffixes fail closed in the jar | single label refused; supercookie refused without a list | none |
| T23 | secrets in logs | redacted `Debug`, no `Display` for values, positions in errors | `Debug` never contains the value, over random values | none |
| T24 | memory exhaustion in the jar | `JarLimits`, eviction, 4096-byte cookie cap | one-hour soak with random `Set-Cookie` streams: flat memory | bounded |
| T25 | a non-secure origin overwriting a `Secure` cookie in the jar | "leave secure cookies alone" | insecure cannot shadow secure | none |
| T26 | random-source failure while sealing | crypt-io returns an error; nothing written; `Crypto` | failing random source (if crypt-io exposes a hook; else documented) | none |
| T27 | a valid signed value of one user tossed into another user's browser | optional session binding (`sign_bound`) | bound value under another binding: `BadTag` | 5 ns |
| T28 | a credential issued with an empty or tiny token by a caller bug | `session_cookie` and `elevated_cookie` refuse tokens under 22 bytes | `TokenTooShort` | 1 ns |

---

## 10. Performance

Targets on the reference machine, estimates until 0.6, compared through the competitors' public APIs including their allocations. Each comparable row must be at least 20% faster than the best Rust competitor at equal or stronger security (`biscotti` and `cookie` for the server side, `cookie_store` for the jar), or carry a recorded plan.

| Operation | Input | Target [est.] | Competitor [est.] |
|---|---|---|---|
| `get` | 300 bytes, 6 pairs, target 3rd | 10 ns | `cookie::Cookie::split_parse` then find, 60 ns |
| `get_unique` / `locate` | same, full scan | 25 ns | `split_parse` full, 90 ns; `biscotti::RequestCookies`, 150 ns |
| full iteration | 6 pairs | 35 ns | same |
| `SetCookie::new` + `write_to` | `theme=dark`, defaults | 40 ns | `cookie` build + `to_string`, 150 ns |
| `session_cookie` + `write_to` | 43-character token | 50 ns | as above |
| `Signer::sign_into` | 64-byte value | 120 ns | `cookie::SignedJar::add` (HMAC-SHA-256), 400 ns |
| `Signer::verify` | 64-byte value | 120 ns | `SignedJar::get`, 400 ns |
| `Sealer::seal_into` | 64 bytes | 0.5 to 1.5 µs | `PrivateJar::add` (AES-256-GCM), 0.5 to 1 µs; the OS random call dominates both |
| `Sealer::open_into` | 64 bytes | 250 ns | `PrivateJar::get`, 300 ns |
| `parse_set_cookie` | 120-byte line | 80 ns | `cookie::Cookie::parse`, 200 ns |
| `Jar::write_cookie_header` | 20 cookies | 1 µs | `cookie_store`, 3 µs |

Sealing cost is dominated by crypt-io's OS random call per nonce; a buffered CSPRNG belongs in crypt-io, proposed there if 0.6 shows it matters (D-013). Verification and lookup never lock, so they scale with cores.

---

## 11. Testing

- Unit tests for every function and every `Ok` and `Err` path (`test_<subject>_<condition>_<expected>`); every `CookieError` and `Rejected` variant produced by a test.
- Integration tests: WASP-shaped flows (login sets `__Host-sid`, a request locates it, logout deletes it), csrf-sec's expectations of the session cookie, HTTP/2 crumbs split at every `"; "` boundary give the same pairs as the joined header.
- Property tests: parse never panics or allocates; every `SetCookie` that builds round-trips through `parse_set_cookie` with the same attributes; no builder input breaks a prefix, `SameSite=None`, or `Partitioned` rule; jar output parses back to the same pairs; sign then verify passes; every single-bit change fails; a value never verifies under another name, key, binding, or after its expiry.
- Fuzz targets (cargo-fuzz, corpus outside the repository): `cookie_header`, `cookie_lines`, `locate`, `set_cookie_build`, `parse_set_cookie`, `cookie_date`, `signed_verify`, `sealed_open`, `jar_ops`. One hour each at the version that adds them, 24 hours each before 1.0.
- Counting-allocator tests for every NFR-1 claim; a dudect-style constant-time smoke test for the tag path.
- Conformance: one test per enforced rfc6265bis rule, cited by section; web-platform-tests `cookies/` cases as data for the client parser, cookie-date, and the jar; the RFC 6265 date examples; the CHIPS examples.
- The full edge-case lists for the `Cookie` header, the builder, signed and sealed values, and the client are in the crate specification and are copied into the test files at the version that adds each area.

---

## 12. Ideas

At least one new defence idea per version, as hypothesis, method, and expected cost.

| Version | Idea | Hypothesis | Method | Cost [est.] |
|---|---|---|---|---|
| 0.2 | **Staged rotation as the only rotation** | a rotation that touches every node at once refuses cookies for the seconds the rollout takes; staging (`accept` everywhere first) removes that window entirely | `KeyRing::accept`, fingerprints in `keys()`, the three-step runbook in `docs/API.md`; a two-node simulation test at 0.4 | none at run time |
| 0.3 | **Prefixed-duplicate signal** | a duplicated `__Host-` name is never benign, so reporting it as its own fact gives sentinel-sec a near-zero false-positive tossing detector | `Stats::prefixed_duplicates`, `Lookup::Many` on prefixed names, severity 30; measure false positives on staging traffic | under 1 ns per prefixed pair |
| 0.3 | **Shadow names** | cookie-net never sets `sid`, `__host-sid`, or `__Secure-sid` beside `__Host-sid`, so any of them in a request is a tossing attempt or a prefix-bypass probe, visible even when the real cookie is intact | `Located::shadows` (case-insensitive compare and prefix strip against the target, per pair); severity plus 5; count on staging traffic to confirm the false-positive rate is near zero | under 1 ns per pair |
| 0.3 | **Token floor in session helpers** | a session cookie with an empty or short token is always a bug and sometimes a vulnerability (a user id written as the token) | `TokenTooShort` under 22 bytes | 1 ns |
| 0.4 | **Server-enforced expiry in signed state** | browsers honour `Max-Age`, attackers replay old values; an expiry under the MAC removes stale replay | `sign_until`, `seal_until`, rejection tests | 4 bytes, one comparison |
| 0.4 | **Session-bound client state** | a signed cookie that is valid for one user can be tossed into another user's browser by a sibling subdomain; binding it to the session digest makes that useless and kills the value with the session | `sign_bound`, `seal_bound`, binding in the MAC input and AAD | 5 ns plus 1 ns per 16 bytes of binding |
| 0.5 | **Cookie-bomb recovery** | answering a `Truncated` or `HeaderTooLong` request with `Clear-Site-Data: "cookies"` restores the user's access without operator action | `CLEAR_SITE_DATA_COOKIES` and a WASP integration test with a bombed header | one header on rare requests |
| later | **Device Bound Session Credentials** | gate-net plans DBSC as an upgrade path; its `Sec-Session-*` headers may need cookie-side helpers | watch the standard; decide when gate-net builds it | n/a |

---

## 13. Open decisions and requests

### 13.1 The specification's open decisions

| Id | Question | Outcome |
|---|---|---|
| CN-1 | Publish 0.1.0 now to claim the name? | published 2026-10-23, decided by James (D-043) |
| CN-2 | Signed-cookie MAC | keyed BLAKE3, 128-bit tag (D-005) |
| CN-3 | AEAD | XChaCha20-Poly1305 (D-006) |
| CN-4 | base64url before encode-lib | private module copied from csrf-sec, removal recorded (D-008) |
| CN-5 | Default value mode | strict (D-009) |
| CN-6 | Public suffix list | trait plus fail-closed default now (D-010); a separate data crate later only if fetch-net needs cross-subdomain cookies, and creating a crate is James's call |
| CN-7 | `__Host-sudo` path | `__Host-` with `Path=/`, decided by James on 2026-10-21 (D-011) |
| CN-8 | `__Host-sid` browser lifetime | `Max-Age` = absolute lifetime (D-012) |
| CN-9 | crypt-io gaps | proposed to crypt-io in its own pull requests when 0.6 shows they matter (D-013) |
| CN-10 | Default header budget | 8,192 bytes, 64 pairs (D-014) |
| CN-11 | CSRF cookie row | removed (D-015) |

### 13.2 Requests to other crates

| To | Request | Needed by | Status |
|---|---|---|---|
| gate-net (`dev/SESSIONS.md` section 9.3) | the elevated cookie is `__Host-sudo` with `Path=/`, not scoped to the sensitive paths (D-011) | gate-net's next change | recorded; gate-net updates it when it is next worked on |
| gate-net (`dev/SESSIONS.md` table "read the cookie") | reading `__Host-sid` costs about 25 ns with duplicate detection (`locate`), not 10 ns | gate-net's next change | recorded |
| crypt-io | an `alloc`-free build of the MAC and KDF paths, so `signed` works with no allocator (D-033) | before 1.0, if a no-allocator consumer appears | proposal |
| crypt-io | a slice-based in-place AEAD API and a buffered CSPRNG for nonces (D-013) | 0.6, if measured | measured at 0.6: the nonce draw is not the main cost (opening, which draws none, is as slow as sealing); not needed yet |
| crypt-io | XAES-256-GCM (C2SP: 192-bit random nonces over AES-256-GCM with a per-nonce derived key), for sealed format version `0x03` on CPUs with AES instructions (D-073) | before 1.0 | proposal |
| crypt-io | a test hook for a failing random source (T26) | 0.7 | proposal |
| encode-lib | base64url without padding, constant time | when published (D-008) | waiting |
| error-core | numbered codes; cookie-net maps its `code()` strings to them behind a feature (D-027) | when published | waiting |

---

## 14. Decision log

| Id | Date | Decision | Reason |
|---|---|---|---|
| D-001 | 2026-10-13 | Secure defaults are the defaults | a forgotten attribute must fail safe |
| D-002 | 2026-10-13 | Prefix and `SameSite=None` rules enforced when building | invalid cookies are unrepresentable |
| D-003 | 2026-10-13 | Bad pairs skipped and counted, not fatal | one stale cookie must not lock a user out; the count is still a signal |
| D-004 | 2026-10-23 | The crate specification (written 2026-10-21) supersedes this plan's earlier design; this plan was rewritten from it. Differences from the earlier plan: keyed BLAKE3 instead of HMAC-SHA-256; XChaCha20-Poly1305 only; keys from the caller, not key-vault; `get` documented as order-dependent with `get_unique` for credentials; no CSRF cookie; `HttpDate` from parse-net instead of a local `date.rs`; every version 0.1 to 1.0 in the roadmap; a 25 ns read cost for the session cookie (the unique lookup scans the whole header) | the specification was written to the portfolio standard after the plan, with the cross-crate checks |
| D-005 | 2026-10-23 | Signed cookies use keyed BLAKE3 with a 128-bit tag over a domain-separated input (CN-2) | the same primitive and tag length as csrf-sec, one audited path in crypt-io; faster than HMAC-SHA-256 for short inputs [est.]; version, key id, expiry, and name authenticated |
| D-006 | 2026-10-23 | Encrypted cookies use XChaCha20-Poly1305 only (CN-3) | 192-bit random nonces remove the per-key message limit of 96-bit nonces; one algorithm to test |
| D-007 | 2026-10-23 | Keys are passed in by the caller; cookie-net never depends on key-vault | key-vault has third-party dependencies, and custody is the caller's job |
| D-008 | 2026-10-23 | base64url comes from a private module copied from csrf-sec's constant-time `b64.rs`, with its tests, until encode-lib is published; then the module is removed (recorded in ROADMAP) (CN-4) | encode-lib is not on crates.io (checked 2026-10-22); a crate must not depend on csrf-sec for this |
| D-009 | 2026-10-23 | `ValueMode::Strict` is the default (CN-5) | our own cookies are always `cookie-octet`s; hosts that share cookies with third-party scripts opt into lenient |
| D-010 | 2026-10-23 | Public suffixes through a `PublicSuffix` trait; the default `NoSuffixList` fails closed (CN-6) | bundling 200 KB of fast-changing data makes the crate stale and large; failing closed prevents supercookies |
| D-011 | 2026-10-23 | `__Host-sudo` uses `Path=/` (CN-7, decided by James on 2026-10-21); the matching change to gate-net's `dev/SESSIONS.md` is recorded as a request (13.2), not made from here | `__Host-` requires `Path=/`; paths do not isolate cookies (RFC 6265 section 8.5) |
| D-012 | 2026-10-23 | The session cookie's `Max-Age` is the session's absolute lifetime (CN-8); `session_cookie` takes it as a required argument, and `SetCookie::new` gives the browser-session form | a browser left open drops the token; one required number is simpler than an `Option` |
| D-013 | 2026-10-23 | crypt-io gaps (slice-based AEAD, buffered nonces) are proposed to crypt-io when measurements show they matter, never worked around here (CN-9) | crypto stays in crypt-io |
| D-014 | 2026-10-23 | Default `Cookie` budget 8,192 bytes and 64 pairs, configurable (CN-10) | matches common front-end limits [est.] |
| D-015 | 2026-10-23 | No CSRF cookie and no CSRF cookie helper (CN-11) | csrf-sec tokens are session-bound MACs in forms and headers; a double-submit cookie can be planted by a sibling subdomain |
| D-016 | 2026-10-23 | The default feature set is `std` (the specification had none) | the simplified-API mandate: a newcomer's `cargo add cookie-net` gets `encode()` and `verify_now`; `no_std` users turn defaults off, the usual Rust convention; the core is still checked as `no_std` without an allocator in CI |
| D-017 | 2026-10-23 | Names and values are returned as `&str` everywhere on the server side; lenient mode also requires values to be valid UTF-8 (others are skipped and counted) | strict values are ASCII by grammar, so `get(h, "theme") == Some("dark")` reads naturally; one type instead of `&[u8]` plus `_str` variants; the cost is one UTF-8 check per returned value [est. 0.1 ns per byte] |
| D-018 | 2026-10-23 | Every reading function takes `&H where H: AsRef<[u8]> + ?Sized` | `&str`, `&[u8]`, `&String`, `&Vec<u8>` all work with no conversion; the parameter is inferred, never named |
| D-019 | 2026-10-23 | `Signer` and `Sealer` derive their own subkeys from any key (HKDF-SHA-256, labels `cookie-net v1 signed` and `cookie-net v1 sealed`); the `Purpose` parameter of the specification is removed; `Key::derive(master, context)` separates services | the same key can feed both and they still never share key material; one fewer concept and one fewer way to misuse the API |
| D-020 | 2026-10-23 | Key rings use csrf-sec's vocabulary and behaviour: `KeyId(u8)`, `KeyRole::{Signing, Accepted, Retired { until }}`, `KeyFingerprint`, `KeyInfo`; ring methods never fail and the checks run in `with_ring` | one key runbook for the stack; staged keys make rotation safe across a cluster; fingerprints catch misdeployed rings |
| D-021 | 2026-10-23 | `Rejected` is one enum of reasons (the specification had `Rejected { reason: Reason }`) | one type to match; room to grow through `#[non_exhaustive]` |
| D-022 | 2026-10-23 | `verify` returns the value; `verify_detailed` returns `Verified` with the key, role, and expiry. `open` returns an owned `Plaintext`; `open_into` returns `Opened` metadata with the plaintext in the caller's buffer | Tier 1 returns what the caller wants; the details stay one call away |
| D-023 | 2026-10-23 | Format v1 carries a length-prefixed binding in the MAC input and AAD (empty when unused); `sign_bound`, `verify_bound`, `seal_bound`, `open_bound` expose it | the binding must be in the format from the first release to avoid a v2; it stops signed-state tossing between users (T27) |
| D-024 | 2026-10-23 | The specification's `clear_host` is folded into `SetCookie::delete(name)`, which writes the default attributes and so satisfies `__Host-`; the builder has `delete()` for cookies set with another path or domain | two names for one thing is harder to read |
| D-025 | 2026-10-23 | `SetCookie` is serialized only through `encode` (`String`), `encode_into`, `write_to`, and `encoded_len`; no `Display` and no `to_string` | `format!` and `to_string` would put a session token into a log line by accident; clippy also refuses an inherent `to_string` |
| D-026 | 2026-10-23 | One `Cookies` type reads a single header or several lines (`from_lines`); the specification's separate `CookieHeader` is dropped | one type with one lifetime; returned values borrow for the shorter of the lines array and the bytes, which is what callers hold anyway |
| D-027 | 2026-10-23 | Facts are returned as values (`Stats`, `Located`, `Rejected`, `KeyRole`) with stable `code()` strings and severity hints; cookie-net has no event dependency, and the caller forwards facts to the event bridge. A mapping to error-core's numbered codes comes behind a feature when that crate is published | zero cost when unused, `no_std`; security evidence still reaches every other component through the caller |
| D-028 | 2026-10-23 | Every time is `u64` Unix seconds passed in by the caller, including `Expires` on the builder (`expires(at, now)`), and the lifetime constants are `u64`; parse-net's `HttpDate` is used internally, not in the public API | one time type across the crate; `now + 5 * MINUTE` type-checks; parse-net version changes do not leak into cookie-net's API beyond `Sink` |
| D-029 | 2026-10-23 | `session_cookie` and `elevated_cookie` refuse tokens under 22 bytes (`TokenTooShort`) | 22 base64url characters are 128 bits; anything shorter is a caller bug (T28) |
| D-030 | 2026-10-23 | `Clear-Site-Data` support is the constant `CLEAR_SITE_DATA_COOKIES`, not a writer function | a constant is simpler and cannot fail |
| D-031 | 2026-10-23 | Expiry checks accept `now < expires + skew`, skew 60 seconds by default, 0 to 3600 configurable | nodes' clocks differ; the same default as csrf-sec; the effect is bounded by the skew |
| D-032 | 2026-10-23 | No key-generation API | a key generated at boot differs between nodes and changes at every restart, which logs everyone out of signed state; keys come from persisted configuration |
| D-033 | 2026-10-23 | `signed` works without `std` but needs an allocator, because crypt-io always links `alloc`; cookie-net's signing code allocates nothing (counting-allocator test) | crypt-io 1.1 declares `extern crate alloc` unconditionally (csrf-sec has the same note); an `alloc`-free crypt-io is a request, not a workaround |
| D-034 | 2026-10-23 | `CookieError` has `Ambiguous(_)` and `Rejected(_)` variants with `From` conversions, and `From<parse_net::Full>` | `?` works on every cookie-net call in a handler that returns `CookieError` |
| D-035 | 2026-10-23 | The jar's state goes behind a `JarStore` trait with a `MemoryStore` default, added at 0.5 as a defaulted type parameter; export and import (versioned, BLAKE3-checksummed) move from P3 to P2 and ship at 0.5 | the portfolio's enterprise rule: stateful parts sit behind a trait and can be persisted or shared; a defaulted parameter changes no existing code |
| D-036 | 2026-10-23 | REPS's "MUST use tokio" clause does not apply | recorded as the standard asks: the stack's cores are sans-IO with no async runtime |
| D-037 | 2026-10-23 | Opened plaintext is cookie-net's own `Plaintext` type, wiped on drop, instead of crypt-io's re-exported `Zeroizing` | no third-party type in the public API |
| D-038 | 2026-10-23 | Every extensible enum and every result struct is `#[non_exhaustive]` (`CookieError`, `Ambiguous`, `Rejected`, `ValueMode`, `SameSite`, `Prefix`, `Lookup`, `Located`, `Stats`, `Verified`, `Opened`, `KeyRole`, `SetCookieView`, `SameSiteAttr`, `StoreOutcome`, `IgnoreReason`) | variants and fields can be added in minor releases |
| D-039 | 2026-10-23 | `Stats::prefixed_duplicates` is computed in linear time: prefixed names go into a fixed open-addressed table of 64 slots (FNV-1a hash, exact compare on a match); names past the first 64 distinct prefixed ones are not tracked, so the count can only be low, never high | NFR-2: no pairwise comparison, no allocation, 1 KiB of stack; a site with more than 64 distinct prefixed cookies does not exist in practice, and a flood of distinct prefixed names still shows in `pairs` and `truncated`. Complexity tests confirm linear time |
| D-040 | 2026-10-23 | `locate` returns `Located { lookup, shadows, stats }` (the specification returned `Lookup`), with `severity_hint`; `Stats` gains `too_long` | one pass gives the gateway every fact it scores; shadow names are the 0.3 defence idea |
| D-041 | 2026-10-23 | `Limits` and `JarLimits` setters are `const` and clamp to their documented ranges | `const` configuration cannot fail; the getters show what is in force |
| D-042 | 2026-10-23 | `Signer::new`, `Sealer::new`, and `with_ring` refuse a key whose 32 bytes are all equal (`WeakKey`) | catches an unset or zeroed key at boot, as csrf-sec does |
| D-043 | 2026-10-23 | 0.1.0 published from the scaffold commit before 0.2.0 (CN-1, decided by James); the API in `docs/API.md` approved by James the same day | claims the name; every version ships through the release routine |
| D-044 | 2026-10-23 | The 0.2 exit item "gate-net and the WASP gates confirm the session helpers" moves to 0.8 | neither consumer has code yet; the helpers follow gate-net's written design and the X-6 decision, and 0.8 is where the gates are built on cookie-net |
| D-045 | 2026-10-23 | parse-net `0.6.1` is the minimum version | 0.6.0 refused some `If-None-Match` lists (fixed in 0.6.1); cookie-net uses only the byte classes, `find_byte`, `HttpDate`, and the sinks, which are unchanged since 0.3 |
| D-046 | 2026-10-23 | A deletion still applies rule 3 (name at most 4096 bytes); `docs/API.md` said it skipped it | a deletion with an over-long name would be ignored by browsers, which is exactly what rule 3 refuses |
| D-047 | 2026-10-23 | `Domain` is also refused over 253 bytes and when its last label is all digits | DNS names are at most 253 bytes; no top-level domain is numeric, so the rule refuses IPv4 addresses without a separate parser |
| D-048 | 2026-10-23 | Shadow names compare ignoring ASCII case after removing a prefix from either side, so `SID` is a shadow of `__Host-sid` | a case variant of the bare name is as much a probe as one of the prefixed name; the cost is the same one comparison |
| D-049 | 2026-10-23 | `SetCookie` is 232 bytes (eight inline extension slots) and stays `Copy` | no allocation and no lifetime juggling for extensions; cookies are built and written in place, so the size costs a copy of under 256 bytes at most [est. under 10 ns] |
| D-050 | 2026-10-23 | Doctests that call `encode` are gated on `alloc` with hidden lines; unit and integration tests use `encode_into`, so every test runs without default features | the rendered examples stay one line, and `cargo test --no-default-features` still checks the `no_std` path |
| D-051 | 2026-10-23 | CI gains a bare-metal `thumbv7em-none-eabi` build (no features, and `alloc`), a dependency-tree check (only parse-net), a fuzz-target build, and a weekly 20-minute fuzz run of every target | NFR-6 and NFR-7 checked on every push; fuzz targets cannot rot between the one-hour runs |
| D-052 | 2026-10-23 | An extension attribute's name (the part before `=`) must be a `token`; `x Max-Age=0` and ` Path=/` are refused as `InvalidExtension` | found by the `set_cookie_build` fuzz target: `extension-av` allows spaces, so `x Max-Age=0` is one unknown attribute to a user agent but could be read as two words by another parser; refusing it removes the differential at no cost to real attributes (`Priority=High`) |
| D-053 | 2026-10-23 | The sealed AAD carries a 32-byte keyed BLAKE3 digest (under the sealing subkey) of the length-prefixed name and binding, not the name and binding themselves | crypt-io's AEAD takes the AAD as one slice; a fixed 59-byte AAD is built on the stack with no allocation, whatever the name and binding lengths; the digest binds both as firmly (collision resistance of BLAKE3) |
| D-054 | 2026-10-23 | `Key::derive` takes a context of at most 200 bytes; a new `CookieError::ContextTooLong` refuses longer ones | the HKDF info (label, 0x00, context) is assembled in a stack buffer; contexts are service names |
| D-055 | 2026-10-23 | A signed value must be plain `cookie-octet`s, without the quoted form | the signed value is the 30 header characters followed by the value, so a quoted value would put `"` in the middle of the cookie value, which no `SetCookie` accepts |
| D-056 | 2026-10-23 | `RingFull` also reports a ring left with no signing key (every key removed with `without`) | one error for "this ring cannot sign"; no new variant for a case a deployment hits only by mistake |
| D-057 | 2026-10-23 | An expiry of exactly 2020-01-01T00:00:00Z is refused (`ExpiresOutOfRange`) | it would encode as 0, which means "no expiry" |
| D-058 | 2026-10-23 | When a sealed value authenticates but has expired, the plaintext already written to the caller's buffer is wiped (dropped through `Zeroizing`) before `Expired` is returned | the tag is checked before the expiry (so a forgery reports `BadTag`), which means decryption has happened; the buffer's capacity is lost only on this rare path |
| D-059 | 2026-10-23 | `Signer` and `Sealer` validate the cookie name (a non-empty token of at most 4096 bytes) when signing or sealing | a value signed for a name no cookie can have is a caller bug; the MAC input's u16 length prefix also needs the bound |
| D-060 | 2026-10-23 | CI builds `signed` for `thumbv7em-none-eabi` with no default features | NFR-6: signing works without `std`; linking needs an allocator, which a bare-metal application provides |
| D-061 | 2026-10-23 | `JarStore` is index-based: `len`, `get`, `get_mut`, `push`, `swap_remove`, `clear` (plus a default `is_empty`) | the jar applies every rule and bound itself, so a store only holds and indexes and cannot weaken them; a durable or shared store writes through on `push` and `swap_remove`; the shape fits a `Vec` with no overhead |
| D-062 | 2026-10-23 | `NoSuffixList` reports every domain as a public suffix | the fail-closed behaviour (a `Domain` equal to the host becomes host-only, any other is refused) then falls out of the rfc6265bis public-suffix step itself, with no special case |
| D-063 | 2026-10-23 | A partitioned cookie is stored with the request host as its partition key and sent only when the context's `top_level_site` (default: the request host) is the same | a non-browser client is its own top-level site; `store` keeps its signature, and an embedding context still cannot read another partition |
| D-064 | 2026-10-23 | `IgnoreReason::Expired` is added (an already expired cookie with nothing to remove); `HttpOnlyFromNonHttp` is dropped from the locked API | every outcome of `store` has a reason; a variant `store` can never return would only mislead |
| D-065 | 2026-10-23 | `Jar::export` and `Jar::import` use the format in `docs/FORMATS.md` with a BLAKE3 checksum through crypt-io (`hash-blake3` only, under `jar`); `import` validates every field as untrusted input and fails with the new `CookieError::InvalidJarData` | the checksum catches corruption, not tampering, so validation cannot rely on it; one audited hash in the tree rather than an in-house checksum |
| D-066 | 2026-10-23 | Export writes cookies in creation order | the store reorders cookies on removal, and import assigns creation order afresh, so the export order is what keeps the `Cookie` header order after a round trip |
| D-067 | 2026-10-23 | The jar scans its store linearly (eviction counts only the domain just written); a per-domain index is 0.6 work, measured first | correctness and bounded memory first; 3,000 cookies at most keep a scan in the tens of microseconds [est.], and the 0.6 benchmark against `cookie_store` decides the index |
| D-068 | 2026-10-23 | Hosts are compared ASCII case-insensitively; the jar expects ASCII hosts (punycode for international names) | `RequestUrl` takes parts from any parser; lowercasing once per call makes `EXAMPLE.com` and `example.com` one host, and an export refuses anything but lowercase ASCII domains |
| D-069 | 2026-10-23 | `Jar::with_store` and `Jar::cookies` are added to the locked jar API | a custom store needs a constructor, and operators and tests need to inspect what a jar holds without a `Cookie` header |
| D-070 | 2026-10-23 | Keyed BLAKE3 inputs of up to 512 bytes (every real cookie) are assembled in a stack buffer and hashed in one call; longer ones stream | measured at 0.6: one call costs about a third of the same bytes fed through seven `update` calls; output unchanged (pinned vectors); sign went from parity with the `cookie` crate's HMAC-SHA-256 to 45% faster, verify to 31% faster |
| D-071 | 2026-10-23 | The scanner checks each `Cookie` line as UTF-8 once and slices names and values out of it as `str` (a line that is not UTF-8 falls back to a check per pair) | measured at 0.6: two `from_utf8` calls per pair were a third of the scan; `get`, `get_unique`, `locate`, and iteration became 30 to 40% faster. Pair boundaries are ASCII bytes, so the slices are always on character boundaries, and `str::get` checks it anyway |
| D-072 | 2026-10-23 | The prefixed-duplicate table has 16 slots (was 64; D-039) | a 1 KiB zero-fill per `locate` and `stats` call cost more than the scan of a typical header; no real site has 16 distinct prefixed cookies, and the credential's own duplicate detection does not use the table |
| D-073 | 2026-10-23 | Sealing and opening (rows C8, C9) stay on XChaCha20-Poly1305 for 0.6 and are recorded as a shortfall: about 4 times slower than the `cookie` crate's AES-256-GCM for 64-byte values on a CPU with AES instructions. The plan: ask crypt-io for XAES-256-GCM and add it as sealed format version `0x03`, chosen by default where AES instructions exist, with XChaCha20-Poly1305 kept for CPUs without them | the cost is the cipher (crypt-io's ChaCha20-Poly1305 alone measures the same), not cookie-net; AES-256-GCM with 96-bit random nonces, as the `cookie` crate uses, is limited to about 2^32 messages per key, which a busy cluster can reach, so it is not equal security; XAES-256-GCM keeps 192-bit random nonces at AES speed. Cryptography stays in crypt-io (D-013) |
| D-074 | 2026-10-23 | Comparisons with other crates live in the separate public repository cookie-net-bench, measured with a ratio tool that holds steady under load: the two sides alternate in short rounds timed with the thread's own CPU time, and the medians are compared. criterion gives the absolute numbers; cookie-net's own `benches/` is the regression baseline | the shared machine runs at a load near its core count, which moves wall-clock results by up to 2 times between runs; alternating rounds and thread CPU time make the ratios repeatable to a few percent; competitors never enter cookie-net's dependency tree |
| D-078 | 2026-10-23 | The security job audits the dependency versions a consumer on current Rust resolves, not the 1.85-filtered ones. RUSTSEC-2026-0385 (`ctutils` before 0.4.4: masks and `u128` comparisons not constant time) is fixed only in releases that need Rust 1.87, so a 1.85 or 1.86 build still resolves `ctutils` 0.4.2; cookie-net keeps its 1.85 MSRV | cookie-net never runs the affected code: `ctutils` arrives through `digest` 0.11, whose only use is `Mac::verify*`; cookie-net compares tags with crypt-io's `Tag::ct_eq` (built on `subtle`), does not enable `mac-hmac`, and uses HMAC only inside HKDF, which computes and never verifies. Consumers on Rust 1.87 or later get the fix automatically; raising the MSRV for unreachable code would break 1.85 users for nothing. Re-checked at every release; reported to crypt-io, whose own HMAC verify does reach it |
