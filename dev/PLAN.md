# cookie-net - Project Plan

> The design, strategy, and decision record for `cookie-net`. A living document: every design decision, idea, or open question about cookie-net is written here or in [`ROADMAP.md`](./ROADMAP.md) before it is acted on.
>
> **Read order:** [`../REPS.md`](../REPS.md) &rarr; [`DIRECTIVES.md`](./DIRECTIVES.md) &rarr; **this file** &rarr; [`ROADMAP.md`](./ROADMAP.md).
>
> **Status:** scaffold, `0.1.0`. Design lock is `0.2.0`.

---

## 1. Purpose

cookie-net reads `Cookie` request headers and writes `Set-Cookie` response headers per RFC 6265bis, with secure defaults, and provides signed and encrypted cookies. It carries tokens; it does not manage sessions (gate-net does).

## 2. Parsing

- Server-side parsing of the `Cookie` header into name and value pairs, zero-copy.
- Budgets: header length, cookie count, name and value lengths.
- Pairs that break the grammar are skipped and counted (browsers send what they stored; one bad cookie must not lock a user out), and the count is available to the caller as a signal.
- Duplicate names: all are exposed in order; the convenience getter returns the first (the most specific path, per browser ordering) and documents why.

## 3. Serialization

| Attribute | Default |
|---|---|
| `Secure` | on |
| `HttpOnly` | on |
| `SameSite` | `Lax` |
| `Path` | `/` |
| `Domain` | unset (host-only) |
| `Max-Age` / `Expires` | session cookie unless set; `Expires` written as IMF-fixdate |
| `Partitioned` | opt-in |

Rules enforced at build time, not hoped for:

- `__Host-` prefix requires `Secure`, `Path=/`, and no `Domain`.
- `__Secure-` prefix requires `Secure`.
- `SameSite=None` requires `Secure`.
- Names and values are validated; CR, LF, `;`, and control characters are refused (header injection).

## 4. Signed and encrypted cookies

| Kind | Construction |
|---|---|
| signed | HMAC-SHA-256 (crypt-io) over the name and value; the tag and a key id appended; constant-time verification |
| encrypted | AEAD (ChaCha20-Poly1305 or AES-256-GCM, crypt-io) with the cookie name as associated data, so a value cannot be moved to another cookie; random nonce; key id prefix |
| key rotation | several keys active; new cookies use the newest; old ones verify until their key is retired |

Keys come from key-vault and are zeroized after use. Encodings use base64url (the encodings crate, planned).

## 5. Threats

| Threat | Defence |
|---|---|
| tampering | signatures and AEAD |
| cookie swapping between names | name as associated data |
| injection through values | strict validation on write |
| session cookies leaking over plain HTTP or to scripts | `Secure` and `HttpOnly` by default, `__Host-` prefix |
| cross-site request forgery | `SameSite=Lax` default (gate-net's CSRF token is the second layer) |
| oversized headers | budgets |

## 6. Architecture

```
src/
  lib.rs      crate docs, Tier-1 entry points
  parse.rs    Cookie header parsing
  build.rs    SetCookie builder and serialization
  date.rs     IMF-fixdate formatting and parsing
  sealed.rs   signed and encrypted cookies, key rotation
  error.rs    CookieError (#[non_exhaustive])
```

## 7. Dependencies

`crypt-io` and `key-vault` for signed and encrypted cookies (behind a feature, so plain parsing stays dependency-free); the encodings crate (planned) for base64url.

## 8. Testing

RFC 6265bis cases as data; property tests (round trips, no panics, prefix rules hold for any builder input); signed and encrypted cookies refuse any single-bit change; rotation tests; fuzz target for parsing.

## 9. Open decisions

| Id | Question | Recommendation |
|---|---|---|
| O-1 | Publish `0.1.0` to crates.io to claim the name? | yes |

## 10. Decision log

| Id | Date | Decision | Reason |
|---|---|---|---|
| D-001 | 2026-10-13 | Secure defaults are the defaults | a forgotten attribute must fail safe |
| D-002 | 2026-10-13 | Prefix and `SameSite=None` rules enforced when building | invalid cookies are unrepresentable |
| D-003 | 2026-10-13 | Bad pairs skipped and counted, not fatal | one stale cookie must not lock a user out; the count is still a signal |
