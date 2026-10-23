# cookie-net fuzz targets

| Target | Input | Checks |
|---|---|---|
| `cookie_header` | one `Cookie` header, strict and lenient | no panic; every accepted name is a token and every value passes its mode; counts within the limits; `get`, `get_unique`, and `locate` agree |
| `cookie_lines` | lines split at `0xFF` | `Cookies::from_lines` yields the same pairs as the lines joined by `"; "` |
| `locate` | a name, `0x00`, a header | `locate` agrees with `get_unique` and `get_all`; shadows never include the name itself |
| `set_cookie_build` | builder inputs separated by `0x00` | a cookie that builds has no control byte, round-trips its name and value through the reader, and keeps every prefix and `Secure` rule |

Run with a corpus outside the repository; the seeds here are read, never written:

```
cargo +nightly fuzz run cookie_header ~/fuzz-corpus/cookie-net/cookie_header fuzz/seeds/cookie_header
```
