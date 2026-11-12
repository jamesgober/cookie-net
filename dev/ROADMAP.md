# cookie-net - Roadmap

> Path from scaffold to a stable 1.0. Hard parts are front-loaded; each version has hard exit criteria and ships through the release routine (local gate on Windows and Linux, stable and 1.85; a pull request with green CI on every platform; squash-merge; tag; GitHub pre-release; `cargo doc`; `cargo publish`).
> Design and decisions: [`PLAN.md`](./PLAN.md). The locked API, with the version of every item: [`../docs/API.md`](../docs/API.md).
>
> **Anti-deferral rule:** no listed task moves to a later version unless this file records the move and the reason.

## Dependencies

| Needed | For | State (2026-10-22) |
|---|---|---|
| parse-net 0.9 (published) | 0.3: byte classes, `find_byte`, `HttpDate`, host syntax, `Sink` | published; 0.9.3 required from 0.8 (D-085) |
| crypt-io 1.2 (published) | 0.4: keyed BLAKE3, `Tag<16>`, HKDF, XChaCha20-Poly1305 | published; 1.2.2 required from 0.7.1 (D-081) |
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
- [ ] gate-net and the sign-in gates confirm the session helpers match gate-net's session design (requests recorded in PLAN 13.2). **Moved to 0.8 (alpha)**, where the sign-in gates are built on cookie-net: neither has code yet, and the helpers follow gate-net's written design and James's X-6 decision.

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

- [x] CLI-1 to CLI-4: `parse_set_cookie`, `SetCookieView`, `SameSiteAttr`, `cookie_date`.
- [x] JAR-1 to JAR-10, JAR-12, JAR-13: `Jar`, `RequestUrl`, `RequestContext`, `PublicSuffix`, `NoSuffixList`, `JarLimits`, `StoreOutcome`, `IgnoreReason`, partitioned storage, `JarStore` and `MemoryStore`, export and import, `with_store` and `cookies`.
- [x] SES-4: `CLEAR_SITE_DATA_COOKIES`.
- [x] `docs/ARCHITECTURE.md`.

Exit: every P0, P1, P2 item exists with doctests; web-platform-tests-derived cases pass for the client parser and the jar; fuzz targets `parse_set_cookie`, `cookie_date`, `jar_ops` run one hour clean. **Met 2026-10-23.**

## v0.6.0 - Optimisation

- [x] criterion benchmarks against `cookie`, `biscotti`, and `cookie_store` for every row of PLAN section 10, in the separate repository cookie-net-bench, with a ratio tool that holds steady under load (D-074); `docs/PERFORMANCE.md` with method and hardware.
- [x] The jar's per-domain index: not needed; the jar is 57% faster than `cookie_store` with a linear scan (D-067 stands).
- [x] In-crate criterion benches as the regression baseline.
- [x] Optimisations: one-shot keyed BLAKE3 (D-070), one UTF-8 check per line (D-071), a smaller prefixed-duplicate table (D-072).

Exit: each comparable row is at least 20% faster than the best competitor, or has a recorded plan; no regression over 5%. **Met 2026-10-23**: every row but C8 and C9 is 20% or more faster; C8 and C9 (sealing) have the recorded plan of D-073.

**Moved, with reason:** the C8 and C9 target moves to the version after crypt-io ships XAES-256-GCM (D-073); the fix is a cipher crypt-io must provide, and cookie-net never implements cryptography itself.

## v0.7.0 - Hardening

- [x] Fuzz 24 hours per target: all nine, no findings (D-079 for the false timeouts the loaded machine produced).
- [x] Attack tests for T1 to T30 (`tests/threats.rs`, `tests/threats_crypto_client.rs`); T26 documented, because crypt-io has no hook for a failing random source.
- [x] No panic paths in library code, enforced by clippy (D-076); the clock fails closed (D-075).
- [x] Jar soak (one hour, flat memory; D-077): 48 million operations, peak resident memory 19.0 MiB in the second quarter and 18.4 MiB in the last.
- [x] `docs/SECURITY.md`, `docs/PLATFORM-NOTES.md`.

Exit: no open finding; every threat proven by a test. **Met 2026-10-25.**

## v0.7.1 - Dependency floor

- [x] Require crypt-io 1.2.2, which removes `ctutils` from the tree for every toolchain; audit both the MSRV and the newest resolution in CI (D-081).

Exit: `cargo audit` clean on both resolutions. **Met 2026-11-02.**

## v0.8.0 - Alpha

- [x] Move to parse-net 0.9, a breaking change because `Sink` and `Full` are in the public API (D-082, D-085).
- [x] The simplicity audit against the API standard: `Cookies::new` and `SameSiteAttr` removed as duplicates, with a migration note in `docs/API.md` (D-083).
- [x] `docs/API.md` rewritten as a task-oriented tour; it and the README run as doctests (D-084).
- [x] The consumers confirm the session helpers: web-net 0.9.0 and gatekeeper-io 0.4.1 pass their full test suites on cookie-net 0.8 with only the version requirement changed (D-085). gatekeeper-io's own cookie code was on 0.8 (its 18 sign-in tests cover sign-in, sign-out, the second factor, and CSRF); its web-net adapter still pulled web-net's cookie-net 0.7.1 beside it, which works because no cookie-net type crosses between the two.
- [x] csrf-sec's expectations of the session cookie (`__Host-`, `SameSite=Lax` or stricter, `Secure`, `HttpOnly`, no CSRF cookie) checked against csrf-sec 0.9.4 by `test_csrf_layer_three_expectations`.

- [x] Fixed before release from the 0.9 review (D-086): jar eviction now removes non-secure cookies before secure ones, so a plain-HTTP origin can no longer flood a domain to evict a `Secure` cookie and replace it (threat T25, high); `Sealer::open_into` wipes the buffer's whole capacity and keeps it on every outcome; five documentation statements corrected.

**Moved, with reason:** the review's other findings, all medium or low and present since 0.4 or 0.5, are the 0.9.0 work (D-086). None touches what web-net or gatekeeper-io use. They are:
  - the jar's `cookie_header` returns `None` for every cookie when one stored value is not UTF-8;
  - `Jar::import` adds duplicates instead of replacing, does not re-apply the storage rules (prefixes, `Secure` needs, suffixes, the 400-day cap, `last_access` from the file), costs time proportional to records times jar size, and refuses a whole export when one default path holds `;` or passes 1024 bytes;
  - `store` takes no request context, so a cross-site response's `Lax` or `Strict` cookie is stored, and partitioned cookies are keyed by the setting host;
  - an IP-address host can get a domain cookie when a suffix list is supplied; `Domain=.` is ignored instead of stored host-only;
  - expired cookies still in the store block a replacement as `WouldShadowSecure` or donate their creation time; cookies are ordered by insertion, not creation;
  - a `__Host-` cookie whose `Path` falls back to the default path `/` is refused;
  - `Sealer::seal` with a name over 4035 bytes builds a cookie over 4096 bytes; `sealed_len` overflows for absurd lengths;
  - the strict `Cookie` parser skips pairs with spaces around `=`, which rfc6265bis allows; `unknown_attributes` counts empty segments.

**Moved, with reason:** web-net preferences and flash messages on `Signer` and `Sealer` move to 0.9 consumer adoption. web-net 0.9.0 has no preferences or flash messages yet; cookie-net cannot build them for it.

Exit: the end-to-end login flow is green with cookie-net; csrf-sec's expectations of the session cookie verified. **Met 2026-11-11** (gatekeeper-io's login, sign-out, and elevation tests on cookie-net 0.8).

## v0.9.0 - Beta

- [x] Every finding of the adversarial review (three independent reviews at 0.8: standards conformance, attacks, edge cases) fixed test-first: each has a regression test in `tests/review_09.rs` that failed on 0.8.0 (D-086, D-087).
- [x] The consumers use it end to end: web-net 0.9 (`get_unique`, `SetCookie`) and gatekeeper-io (sign-in, sign-out, and elevation through `session_cookie`, `SetCookie::delete`, `get_unique`), whose suites pass on cookie-net 0.8 (D-085). fetch-net does not exist yet, so the jar has no consumer.
- [x] API frozen except fixes: 0.9 adds `Jar::store_for`, two `IgnoreReason` variants, and `SetCookieView::has_path`, all needed by review fixes (D-087).

Exit: an adversarial review with every finding fixed test-first. **Met 2026-11-11.**

**Moved, with reason:** web-net preferences and flash messages on `Signer` and `Sealer` stay with web-net; cookie-net is ready for them and cannot build them for it.

## v0.9.x - Pre-1.0 polish

After the beta and before any 1.0 release candidate (D-080). Nothing accepted during 0.x becomes final without being looked at again here.

- [ ] **Revisit every accepted gap, deferred item, known issue, and missed target.** Each is fixed, or kept with its reason restated and checked against the current state of the crates it depends on. The list as of 0.7.0:
  - Sealing (rows C8, C9) about 4 times slower than AES-256-GCM, waiting on XAES-256-GCM in crypt-io (D-073, the "Moved, with reason" note under 0.6).
  - T26, a failing random source while sealing: documented, not tested, waiting on a crypt-io hook (PLAN 13.2).
  - `signed` needs an allocator because crypt-io's MAC and KDF paths do (D-033).
  - The private base64url copy, until encode-lib is published (D-008).
  - error-core codes behind a feature, once error-core is published (D-027).
  - The public suffix list: trait and fail-closed default only (CN-6, D-010); a data crate is James's call.
  - The long constant-time run for the tag path, promised "before 1.0" in PLAN section 9 (T18).
  - The requests to gate-net (`SESSIONS.md` 9.3 and the read cost) and to crypt-io in PLAN 13.2: done, or still open.
  - Every cost in `docs/API.md` and PLAN still marked [est.]: measured, or the estimate kept with its reason.
  - Tests run on 64-bit targets only; 32-bit and bare metal are build-only (`docs/PLATFORM-NOTES.md`).
  - The jar's linear scan instead of a per-domain index (D-067), rechecked against real consumer jar sizes.
  - The PLAN section 12 ideas not yet built (`encrypted` without `std`, Device Bound Session Credentials) and the staging false-positive measurements for the prefixed-duplicate and shadow-name signals: built, measured, or moved after 1.0 with a reason.
  - Anything added after 0.7.0.
- [ ] **A fresh performance pass against the competitors.** Rerun cookie-net-bench (equivalence tests, criterion, and the ratio tool) on the final code against the current releases of `cookie`, `biscotti`, and `cookie_store`; profile and tune every row that is under the 20% rule or has regressed by more than 5%; update `docs/PERFORMANCE.md`.
- [ ] **The security and edge-case review again.** Every threat T1 to T30 and any added since, every edge-case list from the specification, the RFC 6265bis drafts published since 0.7, new advisories against the dependency tree, and the cookie-handling CVEs of other frameworks since 0.7; then fuzz every target for 24 hours on the final code.
- [ ] **The 1.0 readiness note for James** (`dev/READINESS-1.0.md`): what was fixed, what is still open and why, the measured numbers, and a recommendation for each open item.

Exit: every item above is fixed or written up in the readiness note; no open item is left out of the note.

## v1.0.0 - Stable

- [ ] Release candidates, then the full audit in `docs/STABILITY-1.0.md`; API frozen until 2.0. Only with James's go-ahead, after he has read the readiness note.

## After 1.0

- A typed `Priority` attribute (a Chromium-only attribute; `extension("Priority=High")` until then); a `SharedJar` (sharded, `loom`-tested) for concurrent clients.
