# cookie-net - Roadmap

> Path from scaffold to a stable 1.0. Hard parts are front-loaded; each version has hard exit criteria and ships through the release routine (local gate on Windows and Linux, stable and 1.85; a pull request with green CI on every platform; squash-merge; tag; GitHub pre-release; `cargo doc`; `cargo publish`).
> Design and decisions: [`PLAN.md`](./PLAN.md). The locked API, with the version of every item: [`../docs/API.md`](../docs/API.md).
>
> **Anti-deferral rule:** no listed task moves to a later version unless this file records the move and the reason.

## Dependencies

| Needed | For | State (2026-10-22) |
|---|---|---|
| parse-net 0.6 (published) | 0.3: byte classes, `find_byte`, `HttpDate`, host syntax, `Sink` | published, 0.6.1 |
| crypt-io 1.1 (published) | 0.4: keyed BLAKE3, `Tag<16>`, HKDF, XChaCha20-Poly1305 | published, 1.1.0 |
| encode-lib | 0.4: base64url | not published; the private interim module is used (PLAN D-008) |
| url-lib | 0.5: optional, the jar takes URL parts | not needed |

## v0.1.0 - Scaffold (built 2026-10-13)

- [x] Manifest, README, CHANGELOG, REPS, dual license, CI, deny, clippy, rustfmt, DIRECTIVES, ROADMAP, PLAN.
- [x] Session cookie section merged (PR #1, 2026-10-23).
- [x] Published 0.1.0 to claim the name (2026-10-23, PLAN CN-1, D-043).

Exit: crate on crates.io; CI green on every platform (done).

## v0.2.0 - Design lock

- [x] `docs/API.md`: every public item with signature, behaviour, errors, grade, tier, version, cost, and examples.
- [x] `dev/PLAN.md` rewritten from the specification; its differences recorded as decisions (D-004 to D-042).
- [x] Open decisions CN-1 to CN-11 closed (CN-1 by James).
- [x] James approved the API (2026-10-23); 0.2.0 published the same day.
- [ ] gate-net and the WASP gates confirm the session helpers match gate-net's session design (requests recorded in PLAN 13.2). **Moved to 0.8 (alpha)**, where the WASP gates are built on cookie-net: neither has code yet, and the helpers follow gate-net's written design and James's X-6 decision.

Exit: the API is approved (done). Then the release routine for 0.2.0 (no code beyond `VERSION`).

## v0.3.0 - Plain cookies (request side, response side, sessions)

- [x] ROOT-2; ERR-1 to ERR-4; LIM-1, LIM-2.
- [x] REQ-1 to REQ-13: `parse`, `get`, `get_unique`, `get_all`, `Cookies` (single header and lines), `Pair`, `Stats`, `locate`, `Located` with shadow names, `Prefix`, redacted `Debug`.
- [x] SET-1 to SET-19: `SetCookie`, the builder, `SameSite`, every rule of the rules table with a test citing its rfc6265bis section, canonical serialization, deletion.
- [x] SES-1 to SES-3, SES-5: `session_cookie`, `elevated_cookie`, deletion of `__Host-` cookies, the token floor.
- [x] `Send + Sync` assertions; `no_std` build of the core without an allocator in CI (`thumbv7em-none-eabi`).
- [x] README rewritten from the template with the Tier 1 quick start; examples `01_quick_start`, `02_sessions`.

Exit: every rule has a test citing its section; a property test shows no builder input breaks a prefix, `SameSite=None`, or `Partitioned` rule; counting-allocator tests pass; the crumb-split test passes; the prefixed-duplicate complexity test is linear; fuzz targets `cookie_header`, `cookie_lines`, `locate`, `set_cookie_build` run one hour clean. **Met 2026-10-23.**

## v0.4.0 - Signed and encrypted

- [x] KEY-1 to KEY-6: `Key`, `derive`, `KeyId`, `KeyRole`, `KeyInfo`, `KeyFingerprint`, `KeyRing` with `accept`, `retired`, `rotated`, `without`.
- [x] SGN-1 to SGN-10: `Signer` with expiry, binding, skew, `Verified`, `Rejected` with codes and severity hints.
- [x] SEAL-1 to SEAL-9: `Sealer`, `Plaintext`, `Opened`.
- [x] Private `b64` module copied from csrf-sec with its tests. **Removal:** replaced by encode-lib in the first cookie-net version after encode-lib is published; the formats do not change.
- [x] `docs/FORMATS.md` with byte-exact layouts and test vectors; `docs/COOKIES.md` (which cookie to use when, the `__Host-` rule, `SameSite` choices, why there is no CSRF cookie, the rotation runbook, cookie-bomb recovery).

Exit: every single-bit change of a signed or sealed value is refused; a value never verifies under another name, key, or binding; staged rotation in a two-node simulation refuses nothing, and retired keys become `UnknownKey` after their time; the constant-time smoke test passes; fuzz targets `signed_verify`, `sealed_open` run one hour clean. **Met 2026-10-23.**

## v0.5.0 - Feature complete (client side, defence helpers)

- [ ] CLI-1 to CLI-4: `parse_set_cookie`, `SetCookieView`, `SameSiteAttr`, `cookie_date`.
- [ ] JAR-1 to JAR-10, JAR-12: `Jar`, `RequestUrl`, `RequestContext`, `PublicSuffix`, `NoSuffixList`, `JarLimits`, `StoreOutcome`, `IgnoreReason`, partitioned storage, `JarStore` and `MemoryStore`, export and import.
- [ ] SES-4: `CLEAR_SITE_DATA_COOKIES`.
- [ ] `docs/ARCHITECTURE.md`.

Exit: every P0, P1, P2 item exists with doctests; web-platform-tests-derived cases pass for the client parser and the jar; fuzz targets `parse_set_cookie`, `cookie_date`, `jar_ops` run one hour clean.

## v0.6.0 - Optimisation

- [ ] criterion benchmarks against `cookie`, `biscotti`, and `cookie_store` for every row of PLAN section 10, in a separate comparison repository (competitors never enter this crate's dependency tree); `docs/PERFORMANCE.md` with method and hardware.

Exit: each comparable row is at least 20% faster than the best competitor, or has a recorded plan; no regression over 5%.

## v0.7.0 - Hardening

- [ ] Fuzz 24 hours per target; attack tests for T1 to T28; jar soak (one hour, flat memory); `docs/SECURITY.md`, `docs/PLATFORM-NOTES.md`.

Exit: no open finding; every threat proven by a test.

## v0.8.0 - Alpha

- [ ] gate-net and the WASP gate owners confirm the session helpers (moved from 0.2).
- [ ] The WASP gateway credential locator and the gates (login, logout, elevation, rolling tokens) built on cookie-net in a local build; web-net preferences and flash messages on `Signer` and `Sealer`.

Exit: the end-to-end WASP login flow is green with cookie-net; csrf-sec's expectations of the session cookie verified.

## v0.9.0 - Beta and release candidates

- [ ] gate-net and web-net use it end to end (DIRECTIVES definition of done, item 10); fetch-net uses the jar if it exists by then; API frozen except fixes.

Exit: an adversarial review with every finding fixed test-first.

## v1.0.0 - Stable

- [ ] The full audit in `docs/STABILITY-1.0.md`; API frozen until 2.0. Only with James's go-ahead.

## After 1.0

- SET-20 typed `Priority`; JAR-11 `SharedJar`.
