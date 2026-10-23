# cookie-net - Security

> The threat model: what cookie-net defends against, how, what each defence costs, and the test that proves it. The numbers T1 to T30 are the threat table of [`../dev/PLAN.md`](../dev/PLAN.md#9-threats). To report a vulnerability, open a private security advisory on the [repository](https://github.com/jamesgober/cookie-net/security/advisories/new).

<sub>Copyright &copy; 2026 <strong>James Gober</strong>.</sub>

## Contents

- [Scope](#scope)
- [Assumptions](#assumptions)
- [Threats and defences](#threats-and-defences)
- [What cookie-net does not defend](#what-cookie-net-does-not-defend)
- [Hardening evidence](#hardening-evidence)
- [Operating guidance](#operating-guidance)

## Scope

cookie-net reads `Cookie` headers, writes `Set-Cookie` headers, signs and encrypts small cookie values, and, for outbound clients, parses `Set-Cookie` and keeps a cookie jar. Everything it reads is treated as hostile: it comes from browsers that store whatever any server (or a hostile sibling subdomain) sent.

## Assumptions

- The HTTP engine (http-net) has already refused field lines with CR, LF, or NUL and bounded the head; cookie-net still refuses those bytes itself.
- Keys come from persisted configuration (key-vault), are 32 random bytes or derived from a master of at least 32 bytes, and are the same on every node of a cluster.
- Clocks across a cluster are synchronised to within the skew allowance (60 seconds by default). A clock that reads before 2020 fails closed: the `*_now` functions then refuse every expiring value and every retired key ([PLATFORM-NOTES.md](./PLATFORM-NOTES.md#clock)).
- The caller treats every `Rejected` and every `Ambiguous` as "cookie absent" and never shows the reason to the client.
- Session tokens are random (gate-net: 32 bytes from the OS); cookie-net checks only that they are at least 22 bytes.

## Threats and defences

| Id | Threat | Defence | Test (must fail to get through) | Cost |
|---|---|---|---|---|
| T1 | header injection through CR, LF, NUL in any `Set-Cookie` field | every byte of every field validated when building; a `SetCookie` cannot hold one | `test_t1_*` (every control byte in every field), fuzz `set_cookie_build` | 0.5 ns per byte [est.] |
| T2 | attribute injection through `;` | `;` is neither a `cookie-octet` nor an `av-octet`; extension names must be tokens | `test_t2_*` | none |
| T3 | cookie tossing: a sibling or parent-domain page plants a credential | `__Host-` on every credential; `get_unique` and `locate` report duplicates; shadow names counted; csrf-sec never compares tokens with a cookie | `test_t3_*` | part of the scan (row C2 of [PERFORMANCE.md](./PERFORMANCE.md)) |
| T4 | oversized cookies and headers | `TooLarge` when writing; `HeaderTooLong` before any scan; oversize pairs skipped | `test_t4_*` | 1 ns |
| T5 | cookie bombing | budgets with truncation reported; the locator fails closed; `CLEAR_SITE_DATA_COOKIES` for recovery | `test_t5_*` | none until it happens |
| T6 | Unicode or whitespace before a prefixed name (the Hono CVE-2026-39410 class) | names never trimmed beyond SP and HTAB, never Unicode-trimmed; non-token names skipped | `test_t6_*` | none |
| T7 | a nameless cookie planting `__Host-sid=` | the jar ignores nameless prefixed cookies (rfc6265bis 5.7 step 22); a planted duplicate is reported | `test_t7_*`, jar `NamelessPrefixed` unit tests | none |
| T8 | case variants of prefixes | names compared byte for byte; prefix rules applied case-insensitively when writing; case variants counted as shadows | `test_t8_*` | none |
| T9 | percent-decoded names | names never decoded | `test_t9_*` | none |
| T10 | quotes stripped by one component and not another | quotes are part of the value | `test_t10_*` | none |
| T11 | `,` as a separator | not a separator | `test_t11_*` | none |
| T12 | `$Version` and friends read as attributes | ordinary names | `test_t12_*` | none |
| T13 | one name on several paths | `get` documented as order-dependent; `get_unique` for credentials | `test_t13_*` | none |
| T14 | tampering with signed or sealed values | 128-bit keyed BLAKE3 tag; XChaCha20-Poly1305 | `test_t14_*` (every byte of a value changed, truncated, extended), property tests; fuzz `signed_verify`, `sealed_open` | sign 221 ns, verify 261 ns (thread CPU time, rows C6 and C7); sealing about 4 times AES-256-GCM (rows C8, C9) |
| T15 | moving a value to another cookie name | the name is in the MAC input and in the associated data | `test_t15_*`, property tests | none |
| T16 | replay of old signed state | optional server-enforced expiry; key retirement; optional session binding | `test_t16_*` | 4 bytes per cookie |
| T17 | key compromise | key ids, staged rotation, per-purpose subkeys, short expiries | `test_t17_*`, `test_two_node_staged_rotation_refuses_nothing` | operational |
| T18 | timing attack on tag comparison | crypt-io `Tag<16>::ct_eq` (constant time); AEAD checks inside crypt-io; base64url decoding without data-dependent branches or table lookups | `test_t18_*`, the constant-time smoke test in `tests/crypto.rs` | none |
| T19 | a session cookie sent over HTTP or read by scripts | `Secure` and `HttpOnly` fixed by the helpers; `__Host-` requires `Secure` | `test_t19_*` | none |
| T20 | CSRF | `SameSite=Lax` by default, `Strict` for elevation; csrf-sec covers unsafe methods | `test_t20_*` | none |
| T21 | `SameSite=None` or `Partitioned` without `Secure` | refused when building and when storing in the jar | `test_t21_*`, jar unit tests | none |
| T22 | `Domain` set to a public suffix, an IP address, or a single label | refused when building; the jar fails closed without a suffix list | `test_t22_*`, `test_supercookie_refused_without_a_list` | none |
| T23 | secrets in logs | `Debug` prints lengths, never values or keys; no `Display` for values; errors carry positions | `test_t23_*`, property tests over random values | none |
| T24 | memory exhaustion in the jar | `JarLimits`, eviction, 4096 bytes per cookie | `test_t24_*`, `tests/soak.rs` (one hour, flat resident memory) | bounded |
| T25 | a non-secure origin overwriting a `Secure` cookie in the jar | "leave secure cookies alone" | `test_t25_*`, `test_insecure_origin_cannot_toss_over_a_secure_cookie` | none |
| T26 | a random-source failure while sealing | crypt-io returns an error; nothing is written; `Crypto` is returned | documented: crypt-io 1.1 has no hook to make its random source fail; requested (PLAN 13.2) | none |
| T27 | a valid signed value of one user tossed into another user's browser | optional session binding (`sign_bound`, `seal_bound`) | `test_t27_*`, property tests | 5 ns [est.] |
| T28 | a credential written with an empty or tiny token by a caller bug | `session_cookie` and `elevated_cookie` refuse tokens under 22 bytes | `test_t28_*` | 1 ns |
| T29 | an extension attribute read differently by two parsers (`x Max-Age=0`) | extension names must be tokens | `test_t29_*`; found by fuzzing at 0.3 | none |
| T30 | a tampered jar export | a BLAKE3 checksum plus field-by-field validation as untrusted input | `test_t30_*` (every byte of an export changed), a re-checksummed forgery refused (jar unit tests); fuzz `jar_ops` | none |

## What cookie-net does not defend

- **Stolen session tokens.** A copied `__Host-sid` is a valid bearer token until the server revokes it; binding, rolling, and revocation are gate-net's.
- **CSRF on its own.** `SameSite` is one layer; csrf-sec is the defence.
- **Tossing of non-prefixed cookies.** Without `__Host-`, a sibling subdomain can set a cookie of the same name; cookie-net reports duplicates but cannot tell which one is genuine.
- **Old browsers** that ignore prefixes or `SameSite`; the server-side checks still hold.
- **Key custody.** cookie-net never stores keys; protecting them is the caller's (key-vault).
- **Advisories in code it does not call.** CI audits the dependency tree on every change. One advisory is known and unreachable: RUSTSEC-2026-0385 (`ctutils` before 0.4.4) is fixed only in releases that need Rust 1.87, so a build on Rust 1.85 or 1.86 still resolves the old version. It reaches the tree through `digest`'s MAC verification, which cookie-net never calls; tags are compared with crypt-io's `Tag::ct_eq` (dev/PLAN.md D-078).

## Hardening evidence

- Fuzzing: every parser and decoder has a target (`cookie_header`, `cookie_lines`, `locate`, `set_cookie_build`, `signed_verify`, `sealed_open`, `parse_set_cookie`, `cookie_date`, `jar_ops`), each run for 24 hours on the 0.7.0 code (the release notes record the run). One issue was found at 0.3 (T29) and fixed; one timeout at 0.6 was the shared machine stalling and did not reproduce.
- Property tests for every invariant of `dev/DIRECTIVES.md` section 4: no builder input breaks a prefix, `SameSite=None`, or `Partitioned` rule; no serialized cookie holds a forbidden byte; any changed bit of a signed or sealed value is refused; a sealed value never opens under another name.
- Counting-allocator tests prove that reading, writing into a stack buffer, signing, verifying, and opening into a reused buffer allocate nothing.
- Complexity tests prove linear time on 64 KiB adversarial headers.
- `#![forbid(unsafe_code)]`. Library code cannot panic by construction: clippy denies `unwrap`, `expect`, `panic!`, `todo!`, `unimplemented!`, `unreachable!`, `dbg!`, and print macros outside tests, and CI runs clippy with warnings as errors. Indexing is bounds-checked by the language; fuzzing finds no panic.
- A one-hour jar soak (`tests/soak.rs`) streams random `Set-Cookie` lines for 500 hosts with export and import and checks that resident memory stays flat.

## Operating guidance

- Read every credential with `get_unique` or `locate`; send `locate`'s `severity_hint` and `Rejected::severity_hint` to the event bridge.
- Keep every credential cookie `__Host-`; never set `Domain` on one.
- Rotate keys in three steps (stage, switch, drop), comparing fingerprints across nodes before the switch ([COOKIES.md](./COOKIES.md#rotation-runbook)).
- Run NTP on every node; keep the skew allowance at or below 60 seconds.
- Treat jar exports as secrets: they hold cookie values.
