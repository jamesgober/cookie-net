# cookie-net fuzz targets

| Target | Input | Checks |
|---|---|---|
| `cookie_header` | one `Cookie` header, strict and lenient | no panic; every accepted name is a token and every value passes its mode; counts within the limits; `get`, `get_unique`, and `locate` agree |
| `cookie_lines` | lines split at `0xFF` | `Cookies::from_lines` yields the same pairs as the lines joined by `"; "` |
| `locate` | a name, `0x00`, a header | `locate` agrees with `get_unique` and `get_all`; shadows never include the name itself |
| `signed_verify` | a name, a binding, a raw value | verification never panics; a value that verifies re-signs to the same bytes; a value signed here verifies and any change is refused |
| `sealed_open` | a name, a binding, a raw value | opening never panics and never accepts bytes nobody sealed; a value sealed here opens to the same plaintext and any change is refused |
| `parse_set_cookie` | a `Set-Cookie` line; a name, `0x00`, a value | the section 5.6 limits hold; a line written by `SetCookie` parses back to the same name, value, and flags |
| `cookie_date` | an `Expires` value | an accepted date is after 1601 and reads back the same from its IMF-fixdate |
| `jar_ops` | store and retrieve operations separated by `0xFF` | the jar keeps its bounds, its headers read back, and export then import gives the same headers |
| `set_cookie_build` | builder inputs separated by `0x00` | a cookie that builds has no control byte, round-trips its name and value through the reader, and keeps every prefix and `Secure` rule |

Run with a corpus outside the repository; the seeds here are read, never written:

```
cargo +nightly fuzz run cookie_header ~/fuzz-corpus/cookie-net/cookie_header fuzz/seeds/cookie_header
```
