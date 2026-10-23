# cookie-net - Architecture

> How the crate is put together: modules, data flow, where each rule is enforced, memory, and what is shared between parts. The reasons are in [`../dev/PLAN.md`](../dev/PLAN.md); the API in [`API.md`](./API.md).

<sub>Copyright &copy; 2026 <strong>James Gober</strong>.</sub>

## Contents

- [Layers](#layers)
- [Modules](#modules)
- [Reading the `Cookie` header](#reading-the-cookie-header)
- [Writing `Set-Cookie`](#writing-set-cookie)
- [Signed and sealed values](#signed-and-sealed-values)
- [The client side](#the-client-side)
- [Memory and bounds](#memory-and-bounds)
- [Features and dependencies](#features-and-dependencies)
- [What is not here](#what-is-not-here)

## Layers

```
                      ┌──────────────────────────────────────────────┐
   server side        │ request.rs   Cookie header ─▶ Pair, Stats,   │  no_std, no allocator
   (core)             │              Lookup / Located                │
                      │ response.rs  SetCookieBuilder ─▶ SetCookie   │
                      │              ─▶ any parse_net::Sink          │
                      │ session.rs   __Host- helpers                 │
                      ├──────────────────────────────────────────────┤
   crypto             │ keys.rs      Key, KeyRing ─▶ Slots (subkeys) │  feature signed
   (crypt-io)         │ signed.rs    Signer: keyed BLAKE3            │  (allocator for crypt-io)
                      │ sealed.rs    Sealer: XChaCha20-Poly1305      │  feature encrypted (std)
                      │ b64.rs       constant-time base64url         │
                      ├──────────────────────────────────────────────┤
   client side        │ client/set_cookie.rs, client/date.rs         │  feature client, no allocator
                      │ client/jar.rs  Jar over a JarStore           │  feature jar (alloc)
                      └──────────────────────────────────────────────┘
   shared             error.rs (one CookieError), limits.rs, name.rs (byte classes, prefixes)
```

Every layer below the core is optional. The core is sans-IO: no clock reads (time is a parameter), no allocation, no global state.

## Modules

| Module | Holds | Notes |
|---|---|---|
| `error.rs` | `CookieError`, `Ambiguous`, `Rejected` | every variant in every feature mode; stable `code()` strings; `Display` never prints input bytes |
| `limits.rs` | `Limits`, `ValueMode` | `const` setters that clamp |
| `name.rs` | prefix detection, `tchar` and `cookie-octet` checks | byte classes come from parse-net's table |
| `request.rs` | the scanner, `Cookies`, `Pair`, `Stats`, `Lookup`, `Located` | one scanner behind every entry point |
| `response.rs` | `SetCookie`, `SetCookieBuilder`, `SameSite` | the thirteen rules live in `build` |
| `session.rs` | `session_cookie`, `elevated_cookie`, `CLEAR_SITE_DATA_COOKIES` | thin layers over the builder |
| `keys.rs` | `Key`, `KeyRing`, `KeyRole`, fingerprints, `Slots` | `Slots` is the checked ring with per-purpose subkeys |
| `signed.rs`, `sealed.rs` | `Signer`, `Sealer`, `Verified`, `Opened`, `Plaintext` | formats in [`FORMATS.md`](./FORMATS.md) |
| `b64.rs` | base64url without padding, constant time | copied from csrf-sec until encode-lib exists |
| `client/` | `parse_set_cookie`, `cookie_date`, `Jar` | user-agent algorithms, deliberately more lenient than the server grammar |

## Reading the `Cookie` header

```
 header (or HTTP/2 crumbs) ─▶ length check (before any scan)
   ─▶ Scanner: per line, find ';' (parse-net find_byte) ─▶ trim ─▶ split at '='
        ─▶ name: tchar, ≤ max_name_len         else skipped++
        ─▶ value: strict or lenient, ≤ limits  else skipped++
        ─▶ accepted: pairs++ (one more than max_pairs: truncated, stop)
   ─▶ Iter (pairs) │ stats() │ get / get_unique │ locate (+ shadows, + prefixed-duplicate table)
```

- `Cookies` is a 48-byte `Copy` view; each query re-scans, which is cheaper than storing spans for the usual handful of pairs [est.].
- The prefixed-duplicate check uses a 16-slot open-addressed table on the stack (FNV-1a, exact compare), so detection is linear.
- Names are compared byte for byte; shadow names compare ignoring ASCII case after removing a prefix.

## Writing `Set-Cookie`

```
 SetCookie::builder ─▶ setters (never fail) ─▶ build: rules 1 to 13 in order ─▶ SetCookie (valid by construction)
   ─▶ emit: name=value; Path; Domain (lowercased in 64-byte chunks); Max-Age; Expires (parse-net HttpDate);
            Secure; HttpOnly; SameSite; Partitioned; extensions
   ─▶ write_to (checks the sink's room first) │ encode_into │ encode │ encoded_len (a CountSink pass)
```

There is one emitter; every output path and the length come from it, so they cannot disagree.

## Signed and sealed values

```
 KeyRing (raw keys, roles) ─▶ Slots::derive: checks (ids, weak keys, retire times, count)
     ─▶ per key: HKDF subkey for the purpose ("signed" or "sealed"), fingerprint
 Signer::sign_into:  check name and value ─▶ header (version, id, expiry) ─▶ keyed BLAKE3 tag ─▶ base64url(header) || value
 Signer::verify:     length ─▶ base64url ─▶ version ─▶ key (role, retire time) ─▶ Tag::ct_eq ─▶ expiry + skew
 Sealer::seal_into:  size check ─▶ AAD (label, header, digest of name and binding) ─▶ crypt-io AEAD into scratch ─▶ base64url in chunks
 Sealer::open_into:  length ─▶ base64url into a stack buffer ─▶ version ─▶ key ─▶ AEAD open ─▶ expiry (wipes the output if expired)
```

`Signer` and `Sealer` are immutable after construction and hold only subkeys (wiped on drop). Rotation builds a new value; nothing locks.

## The client side

- `parse_set_cookie` follows rfc6265bis section 5.6 step by step and returns a borrowed `SetCookieView`.
- `cookie_date` is the section 5.1.1 tokenizer; calendar arithmetic comes from parse-net.
- `Jar` applies the section 5.7 storage steps and the section 5.8.3 retrieval over a `JarStore`. The jar owns every rule and bound; a store only holds and indexes cookies, so a custom store (durable, shared) cannot weaken them. Eviction after each store looks at the domain just written, then the whole jar: expired cookies first, then the least recently used.

## Memory and bounds

| Part | Memory | Bounded by |
|---|---|---|
| reading | none; a 256-byte stack table for `stats`, `scan`, `locate` | `Limits` |
| writing | none; `SetCookie` is 232 bytes on the stack | the 4096 and 1024 byte rules |
| signing | none per call | the 4096-byte cookie limit |
| sealing | the caller's scratch `Vec` (reused) and a 3 KiB stack buffer when opening | the 4096-byte cookie limit |
| jar | one owned record per cookie | `JarLimits` (per domain and in all) and 4096 bytes of name and value per cookie |

## Features and dependencies

| Feature | Adds | Pulls |
|---|---|---|
| (none) | the server side | parse-net (zero dependencies) |
| `alloc`, `std` (default) | `String` outputs, clock helpers | nothing more |
| `signed` | keys, `Signer` | crypt-io with `mac-blake3`, `kdf-hkdf`, `zeroize` |
| `encrypted` | `Sealer` | crypt-io `aead-chacha20`, `std` |
| `client` | client parsing | nothing more |
| `jar` | `Jar` | crypt-io `hash-blake3` (the export checksum) |

## What is not here

Sessions (gate-net), CSRF tokens (csrf-sec, never in cookies), HTTP framing (http-net), the shared field grammar (parse-net), cryptographic primitives (crypt-io), key custody (key-vault, through the caller), URL parsing (url-lib), and the public suffix list (the caller, through `PublicSuffix`).
