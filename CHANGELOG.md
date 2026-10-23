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

[Unreleased]: https://github.com/jamesgober/cookie-net/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/jamesgober/cookie-net/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/jamesgober/cookie-net/releases/tag/v0.1.0
