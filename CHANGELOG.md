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

[Unreleased]: https://github.com/jamesgober/cookie-net/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/jamesgober/cookie-net/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/jamesgober/cookie-net/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/jamesgober/cookie-net/releases/tag/v0.1.0
