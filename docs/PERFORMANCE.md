# cookie-net - Performance

> Measured numbers, the method behind them, and the plan for the one shortfall. The comparison harness is the separate repository [cookie-net-bench](https://github.com/jamesgober/cookie-net-bench); cookie-net's own `benches/` is the regression baseline (a change that slows a hot path by more than 5% is refused).

<sub>Copyright &copy; 2026 <strong>James Gober</strong>.</sub>

## Contents

- [Summary](#summary)
- [Machine and method](#machine-and-method)
- [Ratios against the best competitor](#ratios-against-the-best-competitor)
- [criterion results](#criterion-results)
- [What changed in 0.6](#what-changed-in-06)
- [The sealing shortfall](#the-sealing-shortfall)
- [Reproducing](#reproducing)

## Summary

Every comparable operation is at least 20% faster than the best Rust competitor, at equal or stronger security, except sealing and opening encrypted cookies (rows C8 and C9), which are about four times slower than the `cookie` crate's AES-256-GCM because of the cipher. That shortfall has a recorded plan: XAES-256-GCM through crypt-io ([below](#the-sealing-shortfall)).

## Machine and method

| Item | Value |
|---|---|
| CPU | AMD Ryzen 9 9950X3D, 16 cores, 32 threads |
| OS | Ubuntu under WSL 2 on Windows 11 |
| Toolchain | rustc 1.99.0, release settings of cookie-net (`opt-level = 3`, fat LTO, one codegen unit) |
| Competitors | `cookie` 0.18.2 (features `secure`), `biscotti` 0.4.4 (percent-encoding off), `cookie_store` 0.22.0, pinned by the harness's `Cargo.lock` |
| Load | the machine is shared by up to ten build sessions; the load average was 36 to 48 on 32 threads during these runs |

Because of the load, wall-clock times on this machine move by up to two times between runs. The 20% rule is therefore decided by the harness's `ratio` tool: cookie-net and the competitor run in alternating short rounds (so drift hits both equally), each round is timed with the thread's own CPU time (so time spent descheduled is not counted), and the medians of 501 rounds are compared. Its ratios repeat within a few percent; its absolute numbers still include the cost of sharing cores with other processes, so they are higher than on an idle machine. A run on an idle machine for the absolute targets of the plan is still to be done.

Every pair of functions timed is proven to do the same work by the harness's equivalence tests: the same values, the same attribute sets, round trips, the same jar output.

## Ratios against the best competitor

Thread CPU time per call, median of 501 alternating rounds, 2026-10-23.

| Row | Operation | cookie-net | Best competitor | cookie-net faster by | 20% rule |
|---|---|---|---|---|---|
| C1 | first value in a 6-pair, 300-byte header | 106 ns | `cookie` 204 ns | 48% | meets |
| C2 | the only value, whole header (`get_unique`) | 222 ns | `cookie` 441 ns | 50% | meets |
| C2 | the same with shadows and statistics (`locate`) | 261 ns | `cookie` 457 ns | 43% | meets |
| C2 | `get_unique` against biscotti | 225 ns | `biscotti` 703 ns | 68% | meets |
| C3 | every pair | 226 ns | `cookie` 456 ns | 50% | meets |
| C4 | `theme=dark` with the defaults, into a stack buffer | 56 ns | `cookie` 186 ns | 70% | meets |
| C4 | the same as a `String` | 73 ns | `cookie` 189 ns | 62% | meets |
| C5 | the session cookie | 91 ns | `cookie` 239 ns | 62% | meets |
| C6 | sign a 64-byte value | 221 ns | `cookie` `SignedJar` 414 ns | 47% | meets |
| C7 | verify a 64-byte value | 261 ns | `cookie` `SignedJar` 389 ns | 33% | meets |
| C8 | seal a 64-byte value | 1,909 ns | `cookie` `PrivateJar` 477 ns | about 4 times slower | **short**, plan below |
| C9 | open a 64-byte value | 1,775 ns | `cookie` `PrivateJar` 452 ns | about 4 times slower | **short**, plan below |
| C10 | parse a 120-byte `Set-Cookie` line | 334 ns | `cookie` 521 ns | 36% | meets |
| C11 | `Cookie` header for 20 of 100 stored cookies | 848 ns | `cookie_store` 1,937 ns | 56% | meets |

Security is equal or stronger in every row. In C6 and C7 cookie-net binds the cookie name, key id, and expiry into the MAC, where `SignedJar` signs the value only (a signed value can move to another cookie). In C8 and C9 cookie-net uses 192-bit random nonces; `PrivateJar` uses 96-bit ones, which limits a key to about 2^32 messages.

## criterion results

criterion's wall-clock medians from the same harness, taken while the machine was at a load near 40 (with fuzzers of this session running too), so the absolute times are three to four times what an idle machine gives; the ratios agree with the table above.

| Row | cookie-net | `cookie` | other |
|---|---|---|---|
| C1 | 403 ns | 699 ns | `biscotti` 2,560 ns |
| C2 | 863 ns (`locate` 1,005 ns) | 1,714 ns | `biscotti` 2,600 ns |
| C3 | 905 ns | 1,674 ns | |
| C4 | 191 ns (`String` 249 ns) | 588 ns | `biscotti` 991 ns |
| C5 | 338 ns | 801 ns | |
| C6 | 836 ns | 1,416 ns | |
| C7 | 951 ns | 1,432 ns | |
| C8 | 7,114 ns | 1,787 ns | |
| C9 | 6,615 ns | 1,461 ns | |
| C10 | 1,207 ns | 1,518 ns | |
| C11 | 1,067 ns | | `cookie_store` 2,387 ns |

## What changed in 0.6

| Change | Effect (ratio tool, before and after) | Decision |
|---|---|---|
| Keyed BLAKE3 inputs up to 512 bytes hashed in one call from a stack buffer instead of seven `update` calls | sign 340 to 221 ns, verify 387 to 261 ns: from parity with `SignedJar` to 47% and 33% faster | D-070 |
| Each `Cookie` line checked as UTF-8 once; names and values sliced from it | `get` 140 to 106 ns, `get_unique` 330 to 222 ns, iteration 320 to 226 ns | D-071 |
| The prefixed-duplicate table cut from 64 to 16 slots | `locate` and `stats` no longer zero 1 KiB per call | D-072 |

No output byte changed: the pinned format vectors and every test pass unchanged.

## The sealing shortfall

The time is in the cipher. crypt-io's XChaCha20-Poly1305 (and plain ChaCha20-Poly1305) costs about four times its AES-256-GCM for 64-byte messages on this CPU, which has AES and carry-less multiply instructions; cookie-net's own framing adds little on top. Opening, which draws no random nonce, is as slow as sealing, so the operating-system random call is not the cause.

AES-256-GCM with 96-bit random nonces is not an equal replacement: a key must stay well under about 2^32 messages, which a busy cluster can reach. The plan (decision D-073):

1. Ask crypt-io for XAES-256-GCM (the C2SP construction: a per-nonce key derived with AES, then AES-256-GCM, giving 192-bit random nonces at AES speed).
2. Add it to cookie-net as sealed format version `0x03`, the default where the CPU has AES instructions; keep XChaCha20-Poly1305 (version `0x02`) for CPUs without them, where software AES would not be constant time. Old cookies keep opening.
3. Re-measure C8 and C9 against the 20% rule.

## Reproducing

```
git clone https://github.com/jamesgober/cookie-net-bench
cd cookie-net-bench
cargo test --release --test equivalence      # both sides do the same work
cargo run --release --bin ratio -- 501        # the table above (Linux)
scripts/run.sh                                # criterion, with a results file
```

cookie-net's own regression baseline: `cargo bench --features encrypted,jar` in this repository.
