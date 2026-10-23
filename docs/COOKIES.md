# cookie-net - Which Cookie, When

> A guide to choosing and running cookies with cookie-net: session tokens, plain cookies, signed and sealed cookies, the `__Host-` rule, `SameSite`, why there is no CSRF cookie, key rotation, and cookie-bomb recovery.

<sub>Copyright &copy; 2026 <strong>James Gober</strong>.</sub>

## Contents

- [Choosing a kind](#choosing-a-kind)
- [Session cookies](#session-cookies)
- [The `__Host-` rule](#the-__host--rule)
- [`SameSite`](#samesite)
- [Why there is no CSRF cookie](#why-there-is-no-csrf-cookie)
- [Signed and sealed state](#signed-and-sealed-state)
- [Keys](#keys)
- [Rotation runbook](#rotation-runbook)
- [Cookie-bomb recovery](#cookie-bomb-recovery)
- [Reading credentials](#reading-credentials)

## Choosing a kind

| What the cookie holds | Kind | Why |
|---|---|---|
| a session | `session_cookie("__Host-sid", token, max_age)` with a random token | the server record is the truth; nothing in the cookie needs protecting |
| an elevated (sudo) state | `elevated_cookie("__Host-sudo", token, max_age)` | a separate token, `SameSite=Strict`, 1 to 60 minutes |
| a harmless preference (theme, language) | `SetCookie::new` | a user who edits it only changes their own view |
| a preference the server relies on (a dismissed banner, a chosen plan) | `Signer::sign` | readable, but cannot be forged or moved to another cookie |
| state that must also stay private (a flash message with a name, a return URL) | `Sealer::seal` | encrypted and authenticated |
| state that belongs to one session (a cart id) | `sign_bound` or `seal_bound` with a digest of the session id | cannot be replayed into another user's browser |
| anything large, or anything the server must be able to revoke | none: keep it on the server | cookies are at most 4096 bytes and live in the user's browser |

## Session cookies

- The token is 32 random bytes from the operating system, base64url (43 characters), issued by gate-net. cookie-net refuses a token under 22 bytes, which catches a user id or an empty string passed by mistake.
- Issue a new token at every login (session fixation defence) and at every roll.
- `Max-Age` is the session's absolute lifetime (WASP: 12 hours), so a browser left open drops the token; the server enforces idle and absolute limits anyway.
- Logout revokes the session on the server first, then sends `SetCookie::delete("__Host-sid")`. Correctness never depends on the browser obeying the removal.

## The `__Host-` rule

A `__Host-` cookie must be `Secure`, have `Path=/`, and have no `Domain`. Browsers then keep it host-only, and no sibling or parent domain can set or overwrite it. Every credential cookie uses it; `session_cookie` refuses any other name.

Paths do not isolate cookies (RFC 6265 section 8.5), so the elevated cookie is `__Host-sudo` on `Path=/` too, not a cookie scoped to the sensitive paths.

## `SameSite`

| Value | Sent with | Use |
|---|---|---|
| `Lax` (the default) | same-site requests and top-level `GET` navigations from other sites | the session cookie: links from email arrive signed in |
| `Strict` | same-site requests only | the elevated cookie: elevated actions never start from another site |
| `None` | every request; requires `Secure` | embedded third-party widgets, usually with `Partitioned` |

cookie-net always writes the attribute, so the browser's "Lax-allowing-unsafe" relaxation for cookies without one never applies.

## Why there is no CSRF cookie

csrf-sec tokens are session-bound MACs carried in a form field or a request header, never compared with a cookie. A double-submit cookie can be planted by a sibling subdomain (cookie tossing); a token bound to the session on the server cannot. The session cookie's `__Host-` prefix and `SameSite=Lax` are csrf-sec's third layer of defence; cookie-net enforces both.

## Signed and sealed state

- Signed values are keyed BLAKE3 with a 128-bit tag; the cookie name is inside the MAC. Sealed values are XChaCha20-Poly1305 with the name in the associated data. The formats are in [FORMATS.md](./FORMATS.md).
- Put an expiry inside (`sign_until`, `seal_until`) for anything that should end: the server checks it on every request, whatever the browser does with `Max-Age`.
- Bind to the session (`sign_bound`, `seal_bound`) for anything that belongs to one user: a valid signed value from one user's browser then fails in another's.
- Treat every `Rejected` as "cookie absent", and send its `code()` and `severity_hint()` to the event bridge. `BadTag` (severity 40) is forgery or tossing; `UnknownKey` and `Expired` (1) are normal after a rotation or an old tab.
- A signed value is readable by the user. Never sign something they must not see.

## Keys

- Keys are 32 bytes from persisted configuration (key-vault). cookie-net never generates keys: a key made at boot differs between nodes and changes at every restart, which refuses every cookie the other nodes made.
- One master can serve several services: `Key::derive(master, b"service-name")`. `Signer` and `Sealer` derive their own subkeys from whatever key they get, so the same key can feed both.
- An all-equal key (an unset or zeroed buffer) is refused at boot.

## Rotation runbook

Signed and sealed cookies verify on any node that holds the same ring. Rotate in three deployments, each to every node:

1. **Stage.** `KeyRing::new(KeyId(1), k1).accept(KeyId(2), k2)`. Every node verifies `k2`; none signs with it. Compare `fingerprint(KeyId(2))` across nodes before going on.
2. **Switch.** `KeyRing::new(KeyId(2), k2).retired(KeyId(1), k1, t)`, with `t` at least the longest cookie lifetime plus the skew after this deployment. New cookies use `k2`; old ones verify until `t`.
3. **Drop.** After `t`: `KeyRing::new(KeyId(2), k2)`. Old cookies are now `UnknownKey`.

No step logs anyone out. `verify_detailed` and `open_into` report the role of the key that verified each cookie; when `Retired` stops appearing, step 3 is safe. Never reuse a key id while cookies made under the old key may still be presented. After a key compromise, skip the wait: switch and drop at once, and accept that cookies made under the old key are refused.

## Cookie-bomb recovery

A hostile subdomain can set many large cookies on the parent domain, so every request from that user exceeds the header limits. cookie-net reports it instead of failing: `get_unique` returns `Ambiguous::Truncated` or `Ambiguous::HeaderTooLong`, and `locate` returns `Lookup::Truncated` or `Lookup::HeaderTooLong`. Treat the request as signed out, report the event, and (from 0.5) answer with `Clear-Site-Data: "cookies"` so the browser drops the site's cookies and the user can sign in again.

## Reading credentials

- Use `get_unique` or `locate`, never `get`, for a credential: a duplicate of a `__Host-` name is a planted cookie.
- `locate` also counts shadow names (`sid`, `__host-sid`, `__Secure-sid` beside `__Host-sid`). cookie-net never sets those, so a request carrying one is a tossing attempt or a prefix-bypass probe; its `severity_hint` rises by 5.
- Never log a cookie value. `Debug` output of every cookie-net type shows lengths instead.
