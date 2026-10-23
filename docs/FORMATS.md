# cookie-net - Signed and Sealed Formats

> The byte-exact formats of signed (`Signer`) and sealed (`Sealer`) cookie values, version 1, with the key derivations and test vectors, so another implementation can interoperate. Any change to these layouts gets a new version byte; old versions keep verifying until their keys retire.

<sub>Copyright &copy; 2026 <strong>James Gober</strong>.</sub>

## Contents

- [Conventions](#conventions)
- [Keys and subkeys](#keys-and-subkeys)
- [Signed format v1](#signed-format-v1)
- [Sealed format v1](#sealed-format-v1)
- [Verification order](#verification-order)
- [Test vectors](#test-vectors)

## Conventions

- `||` is concatenation; `u16be(n)` and `u32be(n)` are big-endian integers; quoted strings are ASCII bytes; `0x00` is one zero byte.
- **base64url** is RFC 4648 section 5 without padding. Decoding accepts canonical text only: the unused low bits of the last character must be zero, so one value has exactly one text form.
- **Expiry** is 4 bytes, big-endian, seconds since 2020-01-01T00:00:00Z (Unix 1,577,836,800); `0` means none. The latest expiry is early 2156. It is checked by the server as `now < expires + skew` (skew 60 seconds by default).
- **Key id** is one byte. A ring holds up to 8 keys.

## Keys and subkeys

| Step | Computation |
|---|---|
| a key from a master (`Key::derive`) | `HKDF-SHA-256(ikm = master, salt = none, info = "cookie-net v1 key" 0x00 \|\| context, length 32)`; the master is at least 32 bytes, the context at most 200 |
| the signing subkey of a key | `HKDF-SHA-256(ikm = key, salt = none, info = "cookie-net v1 signed", length 32)` |
| the sealing subkey of a key | `HKDF-SHA-256(ikm = key, salt = none, info = "cookie-net v1 sealed", length 32)` |
| a fingerprint | the first 8 bytes of `keyed-BLAKE3(subkey, "cookie-net/v1 key fingerprint")` |

A key whose 32 bytes are all equal is refused. The two subkeys of one key never coincide, so one key can feed both a `Signer` and a `Sealer`.

## Signed format v1

```
header (22 bytes) = 0x01 || key id (1) || expiry (4) || tag (16)
tag               = first 16 bytes of keyed-BLAKE3(signing subkey,
                      "cookie-net/v1/signed" 0x00 || 0x01 || key id || expiry
                      || u16be(len name) || name || u32be(len binding) || binding || value)
cookie value      = base64url(header) (30 characters) || value
```

- `value` is the value itself, unchanged and readable; it must be `cookie-octet`s (rfc6265bis section 4.1.1) with no surrounding quotes.
- `name` is the cookie name the value is set under, so a value cannot move to another cookie.
- `binding` is caller data (a digest of the session id, say) that is not stored in the cookie; empty when unused. Its length prefix keeps it apart from the name.
- The length of a signed value is `len(value) + 30`; name plus signed value is at most 4096 bytes.

## Sealed format v1

```
bytes        = 0x02 || key id (1) || expiry (4) || nonce (24) || ciphertext (n) || tag (16)
AEAD         = XChaCha20-Poly1305 (draft-irtf-cfrg-xchacha) under the sealing subkey
nonce        = 24 random bytes from the operating system, per cookie
AAD          = "cookie-net/v1/sealed" 0x00 || 0x02 || key id || expiry
               || keyed-BLAKE3(sealing subkey, u16be(len name) || name || u32be(len binding) || binding)
cookie value = base64url(bytes)
```

- The AAD carries a 32-byte digest of the name and binding rather than the name and binding themselves, so it has a fixed length of 59 bytes and is built on the stack.
- The length of a sealed value of `n` plaintext bytes is `ceil((46 + n) * 4 / 3)` characters; for a name of `L` bytes the largest plaintext is `floor((4096 - L) * 3 / 4) - 46`.

## Verification order

Both formats, so the reason is accurate and the work is bounded:

| Step | Check | Refusal |
|---|---|---|
| 1 | length: signed at least 30 characters, sealed at least 62; both at most 4096 | `Malformed` |
| 2 | canonical base64url (the 30 header characters; the whole sealed value, into a 3072-byte stack buffer) | `Malformed` |
| 3 | version byte (`0x01` signed, `0x02` sealed) | `UnsupportedVersion` |
| 4 | key id in the ring: `Signing`, `Accepted`, or `Retired` with `now < until` | `UnknownKey` |
| 5 | tag in constant time (`Tag<16>::ct_eq`), or AEAD authentication | `BadTag` |
| 6 | expiry: none, or `now < expires + skew` | `Expired` |

The tag is checked before the expiry, so a forged expired value reports `BadTag`.

## Test vectors

Key: the 32 ASCII bytes `an example key, 32 bytes long!!!`, under `KeyId(0)` unless stated. The same vectors run in `tests/vectors.rs`.

| Case | Input | Output |
|---|---|---|
| signing fingerprint | | `a61431af66c98393` |
| sealing fingerprint | | `d55b16096c4e8786` |
| signed, no expiry | name `prefs`, value `lang=fr` | `AQAAAAAAhfXF4159Jdt-UI1cyLRlBQlang=fr` |
| signed, expiry | name `prefs`, value `lang=fr`, expires 1,800,000,000 | `AQANPfEAhdsBFt9CEWgSKtEHwEA57glang=fr` |
| signed, binding | name `cart`, value `c-81731`, binding `session-digest` | `AQAAAAAADU2S5JDhYllf0TPv6lTLiAc-81731` |
| signed, key id 7, empty value | name `prefs`, value empty | `AQcAAAAAhZgoFuZTF4B7mPpB7mWYrQ` |
| derived key fingerprint | master `0x42 ^ i` for i in 0..32, context `wasp-web`, signing fingerprint | `aa76cfb6e1d139f8` |

Sealed values carry a random nonce, so each sealing gives a new value; these two open to `Saved.` under the cookie name `flash`:

| Case | Value |
|---|---|
| no expiry | `AgAAAAAAzGjJwQDAVhz2jWtZvKYe-3dsf_AHgYGeiTeQ0Hhrq4PMphuNs2yOW4JW3vGsMA` |
| expires 1,800,000,000 | `AgANPfEA4tMKDOdxtSjBrgzj-FcQeXwwoTaN4xLq31PS2OBrq2b1HdbSZe2J3u-wl0PQ2g` |
