<h1 align="center">
    <img width="90px" height="auto" src="https://raw.githubusercontent.com/jamesgober/jamesgober/main/media/icons/hexagon-3.svg" alt="Triple Hexagon">
    <br><b>CHANGELOG</b>
</h1>
<p>
  All notable changes to <code>cookie-net</code> will be documented in this file. The format is based on <a href="https://keepachangelog.com/en/1.1.0/">Keep a Changelog</a>,
  and this project adheres to <a href="https://semver.org/spec/v2.0.0.html/">Semantic Versioning</a>.
</p>

---

## [Unreleased]

---

## [0.9.0] - 2026-11-11

Beta: every finding of the adversarial review fixed, each with a test that
failed before its fix (`tests/review_09.rs`).

### Added

- `Jar::store_for`: storing with a request context. A cross-site response's
  cookie is ignored unless it is `SameSite=None` or the request was a
  top-level navigation (rfc6265bis section 5.7 step 18), and a partitioned
  cookie is kept under the context's top-level site.
- `IgnoreReason::CrossSite` and `IgnoreReason::InvalidRequestUrl`.
- `SetCookieView::has_path`.

### Fixed

- `Jar::cookie_header` returned `None` for the whole request when one stored
  cookie was not UTF-8; it now leaves that cookie out.
- `Jar::import` added duplicates, did not check records against the storage
  rules, kept times from the file, and cost records times jar size. It now
  replaces by identity, refuses records no jar could have stored, skips
  domain cookies its suffix list refuses, caps times, and applies the limits
  once in `n log n`.
- A default path over 1024 bytes, or with a control character, made the
  whole export unimportable; such cookies are refused when storing, and a
  path with `;` round-trips.
- An IP-address host could get a domain cookie with a suffix list;
  `Domain=.` was ignored instead of host-only; expired cookies blocked a
  replacement or gave it their creation time; cookies of equal path length
  went by insertion, not creation; a `__Host-` cookie whose `Path` fell back
  to `/` was refused.
- The `Cookie` parser skipped pairs with spaces or tabs around `=`, which
  rfc6265bis allows.
- `SetCookieView::unknown_attributes` counted empty segments.
- `Sealer` built a cookie over 4096 bytes for names over 4035 bytes, and
  `sealed_len` could overflow.

---

## [0.8.0] - 2026-11-11

Alpha: a simpler API, parse-net 0.9, and documentation that runs.

### Changed

- **Breaking:** `Cookies::new` is no longer public; `cookie_net::parse` is the
  one way to read a whole header (`Cookies::with_limits` and
  `Cookies::from_lines` are unchanged).
- **Breaking:** `SameSiteAttr` is removed. `SetCookieView::same_site` and
  `StoredCookie::same_site` are `Option<SameSite>`, where `None` means absent
  or an unknown value (`SameSiteAttr::Default` before).
- **Breaking:** parse-net 0.9 (was 0.6.1). `Sink`, `SliceSink`, and `Full`
  come from parse-net 0.9 now.
- `docs/API.md` is a task-oriented tour of the API, with a migration note
  from 0.7. Every example in it and in the README is compiled and run as a
  doctest.

### Fixed

- **Security:** the jar evicted the least recently used cookie without
  regard to `Secure`, so a plain-HTTP origin could store enough cookies for a
  domain to evict a `Secure` cookie and then replace it (threat T25).
  Eviction now removes expired cookies, then non-secure ones, then secure
  ones, as rfc6265bis section 5.7 requires. Present since 0.5.
- `Sealer::open_into` wipes the buffer's whole capacity before opening, and
  keeps its capacity on every failure; an early failure used to leave an
  earlier plaintext in the spare capacity, and `Expired` dropped the
  allocation.
- Five documentation statements that did not match the code.

The signed, sealed, and jar export formats are unchanged: cookies and
exports made by 0.7 keep working. The 0.9 review's other findings, in the
jar and in edge cases, are listed in `dev/ROADMAP.md` and fixed in 0.9.0.

---

## [0.7.1] - 2026-11-02

Dependency floor. No API or format change.

### Changed

- Requires crypt-io 1.2.2 (was 1.1). crypt-io now builds HMAC and HKDF itself,
  so `ctutils` and RUSTSEC-2026-0385 leave the dependency tree on every
  toolchain, including Rust 1.85 and 1.86. Output is byte-identical; the
  pinned format vectors pass unchanged.
- CI audits both the MSRV resolution and the newest resolution.

---

## [0.7.0] - 2026-10-25

Hardening: every threat proven by a test, every parser fuzzed for a day.

### Added

- `docs/SECURITY.md`: the threat model T1 to T30, with each defence, its
  cost, and the test that proves it; what cookie-net does not defend; the
  hardening evidence; operating guidance.
- `docs/PLATFORM-NOTES.md`: what each feature needs from the platform, the
  platforms CI proves, the clock, the random source, constant-time code, and
  byte order.
- Attack tests for T14 to T30 (`tests/threats_crypto_client.rs`).
- A jar soak (`tests/soak.rs`, ignored, Linux): random `Set-Cookie` streams
  for 500 hosts with export and import, checking that resident memory stays
  flat. One hour: 48 million operations, peak resident memory 18 to 19 MiB.
- Every fuzz target run for at least 24 hours on this code with no findings.

### Changed

- `verify_now` and `open_now` treat a system clock before 2020-01-01 as the
  far future, so expiring values and retired keys are refused. A clock
  before 1970 used to read as 0, which accepted them.
- Clippy denies `unwrap`, `expect`, `panic!`, `todo!`, `unimplemented!`,
  `unreachable!`, `dbg!`, and print macros in library code; the two
  remaining debug assertions are gone, so fuzz and release builds run the
  same code.
- Local fuzz runs use a 60-second timeout and fork mode, because the shared
  build machine's clock steps produce false timeouts (D-079).

### Fixed

- Five intra-doc links to items behind a feature (`SetCookie::encode`
  twice, `Sealer::with_ring`, `Signer::sign_until`, `Signer::sign_bound`) broke
  `cargo doc` with warnings as errors for builds without `alloc` or
  `encrypted`. CI now builds the docs for every feature set.

---

## [0.6.0] - 2026-10-23

Optimisation: measured against the best Rust crates, and made faster where
it fell short.

### Added

- `docs/PERFORMANCE.md`: measured ratios against `cookie`, `biscotti`, and
  `cookie_store` for every operation in the plan, the machine, the method
  (alternating rounds timed with thread CPU time, because the shared machine
  runs near full load), criterion results, and the plan for sealing.
- `benches/cookies.rs`: criterion benchmarks of every hot path, the
  regression baseline (feature `encrypted` and `jar`).
- The comparison harness, the public repository cookie-net-bench.

### Changed

- Signing and verifying hash inputs of up to 512 bytes in one keyed BLAKE3
  call from a stack buffer: sign 35% and verify 33% faster, the same bytes
  (the format vectors are unchanged).
- The `Cookie` scanner checks each line as UTF-8 once and slices names and
  values from it: `get`, `get_unique`, `locate`, and iteration 24 to 33%
  faster.
- The prefixed-duplicate table has 16 slots instead of 64 (`Stats` tracks
  the first 16 distinct prefixed names).
- `dev/PLAN.md` decisions D-070 to D-074; the crypt-io request for
  XAES-256-GCM.

---

## [0.5.0] - 2026-10-23

Feature complete: the client side and the cookie jar.

### Added

- Client parsing (feature `client`): `parse_set_cookie` (the rfc6265bis
  section 5.6 user-agent algorithm), `SetCookieView`, `SameSiteAttr`, and
  `cookie_date` (the section 5.1.1 algorithm). No allocator needed.
- The cookie jar (feature `jar`): `Jar` with `store`, `store_all`,
  `cookie_header`, `cookie_header_for`, `write_cookie_header`,
  `remove_expired`, `clear`, `clear_domain`, `cookies`, `export`, `import`;
  `RequestUrl`, `RequestContext`, `JarLimits`, `StoreOutcome`,
  `IgnoreReason`, `PublicSuffix`, `NoSuffixList` (fail closed),
  `JarStore`, `MemoryStore`, `StoredCookie`. The section 5.7 storage steps
  (secure-origin rules, "leave secure cookies alone", prefixes, nameless
  prefixed cookies, `SameSite=None` and `Partitioned` need `Secure`, the
  400-day cap), section 5.8.3 retrieval, partitioned cookies, and bounded
  memory with expired-first then least-recently-used eviction.
- `CLEAR_SITE_DATA_COOKIES` for cookie-bomb recovery;
  `CookieError::InvalidJarData`.
- `docs/ARCHITECTURE.md`; the jar export format in `docs/FORMATS.md`.
- Tests: builder output round-trips through the client parser; jar headers
  read back through the server parser; user-agent behaviour cases; a
  bounded-memory stream; export tampering. Fuzz targets `parse_set_cookie`,
  `cookie_date`, `jar_ops`, one hour each clean.
- Example `04_client_jar`.

### Changed

- `dev/PLAN.md` decisions D-061 to D-069.

---

## [0.4.0] - 2026-10-23

Signed and encrypted cookies.

### Added

- Keys (feature `signed`): `Key` (wiped on drop, `Key::derive` from a
  master with HKDF-SHA-256), `KeyId`, `KeyRole` (`Signing`, `Accepted`,
  `Retired`), `KeyRing` (`new`, `accept`, `retired`, `rotated`, `without`),
  `KeyInfo`, `KeyFingerprint`.
- `Signer` (feature `signed`): keyed BLAKE3 with a 128-bit tag over the
  version, key id, expiry, name, binding, and value; `sign`, `sign_until`,
  `sign_bound`, `sign_into`, `verify`, `verify_bound`, `verify_detailed`,
  `verify_now`, `with_skew`, `keys`, `fingerprint`; `Verified`.
- `Sealer` (feature `encrypted`): XChaCha20-Poly1305 with a random 192-bit
  nonce and the name, header, and binding as associated data; `seal`,
  `seal_until`, `seal_bound`, `seal_into`, `open`, `open_bound`, `open_into`,
  `open_now`, `sealed_len`, `max_plaintext`; `Plaintext` (wiped on drop) and
  `Opened`.
- `Rejected` with `code()` and `severity_hint()`; `CookieError` variants
  `WeakKey`, `KeyTooShort`, `ContextTooLong`, `DuplicateKeyId`, `RingFull`,
  `InvalidRetireTime`, `Crypto`, `Rejected(_)`.
- `docs/FORMATS.md` (byte-exact formats, derivations, test vectors) and
  `docs/COOKIES.md` (which cookie to use when, the rotation runbook).
- Tests: every single-bit change refused; values never verify under another
  name, key, or binding; a two-node staged-rotation simulation; pinned
  vectors; counting-allocator and constant-time smoke tests. Fuzz targets
  `signed_verify` and `sealed_open`, one hour each clean.
- Example `03_signed_and_sealed`; CI builds `signed` for bare metal.

### Changed

- crypt-io 1.1 is an optional dependency behind `signed` and `encrypted`,
  with its default features off.
- `dev/PLAN.md` decisions D-053 to D-060.

---

## [0.3.0] - 2026-10-23

Plain cookies: the request side, the response side, and the session helpers.

### Added

- Reading the `Cookie` header (rfc6265bis section 4.2.1): `parse`, `get`,
  `get_unique`, `get_all`, `locate`; `Cookies` over one header or several
  field lines (HTTP/2 crumbs) with `iter`, `scan`, `stats`; `Pair`, `Stats`,
  `Lookup`, `Located` with shadow names and `severity_hint`, `Prefix`.
  Zero-copy, no allocation, linear time; bad pairs skipped and counted.
- `Limits` (header length, pairs, name and value length) and `ValueMode`
  (strict by default, lenient for hosts that share cookies with scripts).
- Writing `Set-Cookie`: `SetCookie` (`new`, `delete`, `write_to`,
  `encode_into`, `encode`, `encoded_len`, getters), `SetCookieBuilder` with
  the thirteen rules, `SameSite`. Canonical serialization; `Domain` written
  lowercase; deletions with `Expires` in 1970.
- Session helpers: `session_cookie` and `elevated_cookie` for `__Host-`
  tokens, with a 22-byte token floor.
- `CookieError` with stable `code()` strings, `Ambiguous`, and the
  constants `MINUTE`, `HOUR`, `DAY`, `MAX_LIFETIME`.
- Tests: one per rfc6265bis rule with its section; attack tests for threats
  T1 to T13, T19 to T23, and T28; property tests; counting-allocator tests;
  complexity tests; WASP-shaped flows. Fuzz targets `cookie_header`,
  `cookie_lines`, `locate`, `set_cookie_build`, each run for one hour clean;
  `set_cookie_build` first found extension names with spaces (`x Max-Age=0`),
  now refused: an extension's name must be a token.
- Examples `01_quick_start` and `02_sessions`.
- CI: a bare-metal `thumbv7em-none-eabi` build, a dependency-tree check, a
  fuzz-target build, and a weekly fuzz workflow.

### Changed

- parse-net 0.6.1 is now a dependency (the only one).
- README rewritten from the portfolio template with the Tier 1 quick start.
- `docs/API.md`: measured type sizes, the shadow-name rule, and the rules a
  deletion skips; `dev/PLAN.md` decisions D-045 to D-051.

---

## [0.2.0] - 2026-10-23

The design lock: the public API through 1.0, written down before the code. No
cookie code yet.

### Added

- `docs/API.md`: every public item from `0.3.0` to `1.0.0` with its id, grade,
  tier, shipping version, signature, behaviour, every error it can return, cost
  target, and examples: reading the `Cookie` header (`get`, `get_unique`,
  `locate` with shadow names), writing `Set-Cookie` with the rfc6265bis rules
  checked at build time, the session helpers, keys and staged rotation, signed
  and encrypted cookies with expiry and session binding, the client parser and
  cookie jar, and five use cases.
- Feature flags declared ahead of their code: `std` (default), `alloc`,
  `signed`, `encrypted`, `client`, `jar`. The crate root is `no_std`.

### Changed

- `dev/PLAN.md` rewritten from the crate specification: requirements, the
  enterprise and distributed design, session cookies (no CSRF cookie;
  `__Host-sudo` on `Path=/`), architecture, threats T1 to T28, performance
  targets, testing, defence ideas, requests to other crates, and decisions
  D-004 to D-042. Signed cookies move from HMAC-SHA-256 to keyed BLAKE3,
  encrypted cookies to XChaCha20-Poly1305, and keys are passed in by the
  caller instead of read from key-vault.
- `dev/ROADMAP.md`: every version from 0.1 to 1.0 with exit criteria.
- `dev/PLAN.md` section on the session cookies (merged before this release):
  `__Host-sid`, `__Host-sudo`, and why session tokens are opaque rather than
  signed or encrypted.
- README: scope and status brought in line with the plan.

---

## [0.1.0] - 2026-10-13

The scaffold and the plan. No functional code yet.

### Added

- Crate manifest (edition 2024, MSRV 1.85, no dependencies), `Apache-2.0 OR MIT`
  license, README, REPS, CI (Linux, macOS, Windows on stable and 1.85; audit
  and deny), `deny.toml`, `clippy.toml`, `rustfmt.toml`, `.gitattributes`.
- `dev/PLAN.md` (purpose, scope, architecture, threats, ecosystem, open
  decisions, decision log), `dev/DIRECTIVES.md`, and `dev/ROADMAP.md`.

[Unreleased]: https://github.com/jamesgober/cookie-net/compare/v0.9.0...HEAD
[0.9.0]: https://github.com/jamesgober/cookie-net/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/jamesgober/cookie-net/compare/v0.7.1...v0.8.0
[0.7.1]: https://github.com/jamesgober/cookie-net/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/jamesgober/cookie-net/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/jamesgober/cookie-net/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/jamesgober/cookie-net/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/jamesgober/cookie-net/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/jamesgober/cookie-net/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/jamesgober/cookie-net/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/jamesgober/cookie-net/releases/tag/v0.1.0
