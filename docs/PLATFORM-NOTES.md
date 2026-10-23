# cookie-net - Platform notes

> What cookie-net needs from the platform for each feature, which platforms CI proves, and the platform behaviour that matters for security: the clock, the random source, constant-time code, and byte order.

<sub>Copyright &copy; 2026 <strong>James Gober</strong>.</sub>

## Contents

- [Tested platforms](#tested-platforms)
- [What each feature needs](#what-each-feature-needs)
- [Clock](#clock)
- [Random source](#random-source)
- [Constant-time code](#constant-time-code)
- [Byte order and word size](#byte-order-and-word-size)
- [Line endings and text](#line-endings-and-text)

## Tested platforms

| Platform | What CI runs |
|---|---|
| Linux x86_64 (`ubuntu-latest`) | format, clippy (default, all features, no default features), every test, doctests, docs with warnings as errors; Rust stable and 1.85 |
| macOS (`macos-latest`, Apple silicon) | the same |
| Windows x86_64 (`windows-latest`) | the same |
| `thumbv7em-none-eabi` (32-bit Arm, no operating system) | builds with no features, with `alloc`, and with `signed`; clippy with no features |
| Linux x86_64, nightly | every fuzz target builds |

Before each release the same gate also runs locally on Windows and on Linux (WSL), stable and 1.85, plus `cargo package` in a fresh target directory. Fuzzing runs on Linux only (libFuzzer).

Other targets that Rust and crypt-io support should work; they are not proven by CI. In particular the test suite runs on 64-bit targets only. The 32-bit Arm build proves that the code compiles for 32 bits, not that every test passes there.

## What each feature needs

| Feature | Allocator | Operating system | Notes |
|---|---|---|---|
| none (`default-features = false`) | no | no | reading `Cookie`, writing `Set-Cookie` into a caller's buffer, session helpers; parse-net is the only dependency |
| `alloc` | yes | no | `SetCookie::encode` and the `String` forms |
| `std` (default) | yes | yes | adds the `*_now` functions, which read the system clock |
| `signed` | yes | no | keyed BLAKE3 and HKDF through crypt-io; the caller passes `now` |
| `encrypted` | yes | yes | XChaCha20-Poly1305 needs a random nonce for every seal, drawn from the operating system |
| `client` | no | no | `parse_set_cookie`, `cookie_date` |
| `jar` | yes | no | the jar and its export checksum (BLAKE3) |

## Clock

- Every time-dependent function takes `now` (Unix seconds) from the caller, except the `*_now` forms (feature `std`), which read `SystemTime::now()`.
- **A clock before 2020-01-01 fails closed.** That date is the epoch of the expiry encoding, so such a clock is certainly wrong; a device that boots without a real-time clock or NTP reads 1970 plus its uptime. It reads as the far future, so `verify_now` and `open_now` refuse every value that carries an expiry and every retired key. Values without an expiry still verify, because nothing about them depends on time (dev/PLAN.md D-075).
- A clock that is wrong but after 2020 cannot be detected. Deployments must run NTP; the skew allowance (60 seconds by default) covers drift between synchronised nodes, not an unsynchronised one.
- Expiry inside signed and sealed values is 4 bytes of seconds since 2020-01-01, so the latest expiry is early 2156. An expiry outside that range is refused with `ExpiresOutOfRange` when signing.

## Random source

- Only sealing draws randomness: a 192-bit nonce per value, from the operating system's random source through crypt-io (feature `std` of crypt-io, which uses the `getrandom` crate). Signing, verifying, opening, reading, and writing are deterministic.
- If the random source fails, crypt-io returns an error, nothing is written, and cookie-net returns `CookieError::Crypto`. crypt-io has no hook to make it fail on purpose, so this path is reviewed and documented, not tested (threat T26).
- crypt-io 1.2 added a `getrandom` feature that gives a random source without `std`. Using it would let `encrypted` work on targets with an allocator and a random source but no operating system; it is recorded as an idea in dev/PLAN.md, not a promise.

## Constant-time code

- **Tag comparison** uses crypt-io's `Tag<16>::ct_eq`; the AEAD tag check is inside crypt-io.
- **base64url decoding** of signed and sealed values has no branches or table lookups that depend on the data, so the time to decode does not depend on the bytes of a tag.
- **BLAKE3** (through crypt-io and the `blake3` crate) picks its SIMD code once per process from the CPU's features (SSE2 to AVX-512 on x86_64, NEON on aarch64); every path is constant time with respect to the key and the data.
- **XChaCha20-Poly1305** is software arithmetic with no secret-dependent branches or lookups on every target. That is the reason it stays the sealing cipher on CPUs without AES instructions, where a software AES would leak through cache timing (dev/PLAN.md D-073).
- Reading `Cookie` headers is not constant time and does not need to be: the header is the client's own data, and `locate` reports duplicates by count, not by comparing secrets.

## Byte order and word size

- Every integer in a wire format (signed and sealed headers, the jar export) is big-endian and written byte by byte, so values and exports move between little- and big-endian machines unchanged.
- The base64url decoder packs characters into a `u64` with explicit little-endian conversion, so its result is the same on every byte order.
- Sizes are `usize` in the API and bounded by `Limits` (at most 8192 bytes for a header and 4096 for a pair by default), so nothing approaches the 32-bit range. The jar export stores counts as 32-bit integers; a jar with more than 2^32 cookies cannot exist under `JarLimits`.

## Line endings and text

- cookie-net never reads or writes files; there is no newline translation anywhere.
- Header bytes are handled as bytes. `Cookie` values must be UTF-8 to be returned as `&str`; other pairs are skipped (and counted). Non-ASCII bytes are never trimmed, case-folded, or normalised, on any platform or locale.
