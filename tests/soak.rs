//! The jar soak (threat T24): a stream of cookies for many hosts (stored,
//! replaced, expired, read, exported, imported) for `COOKIE_NET_SOAK_SECS`
//! seconds (default 60; 0.7 runs it for 3600), checking that the jar keeps
//! its bounds and that resident memory stays flat: the peak of the last
//! quarter of the run may not exceed the peak of the second quarter (the
//! first is warm-up) by more than 10% plus 1 MiB. Export and import run every
//! 20 000 operations, so every quarter holds two jars at once several times. Linux
//! only (it reads `/proc/self/statm`). Run with:
//!
//! `COOKIE_NET_SOAK_SECS=3600 cargo test --release --features jar --test soak -- --ignored --nocapture`

#![cfg(all(feature = "jar", target_os = "linux"))]

use std::time::{Duration, Instant};

use cookie_net::{Jar, JarLimits, RequestUrl};

fn resident_bytes() -> u64 {
    let statm = std::fs::read_to_string("/proc/self/statm").unwrap_or_default();
    let pages: u64 = statm
        .split_whitespace()
        .nth(1)
        .and_then(|p| p.parse().ok())
        .unwrap_or(0);
    pages * 4096
}

#[test]
#[ignore = "long-running; run explicitly"]
fn test_jar_soak_memory_flat() {
    let secs: u64 = std::env::var("COOKIE_NET_SOAK_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(60);
    let limits = JarLimits::DEFAULT.per_domain(50).total(3000);
    let mut jar = Jar::new().with_limits(limits);
    let mut seed = 0x9e37_79b9_7f4a_7c15u64;
    let mut next = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let start = Instant::now();
    let total = Duration::from_secs(secs);
    let mut quarter_peak = [0u64; 4];
    let mut now = 1_800_000_000u64;
    let mut ops = 0u64;
    while start.elapsed() < total {
        for _ in 0..1000 {
            let r = next();
            now += r % 3;
            let host = format!("h{}.example", r % 500);
            let url = RequestUrl::new(r & 1 == 0, &host, "/a/b");
            let size = 1 + (r >> 20) % 2000;
            let line = format!(
                "c{}={}; Max-Age={}; Path={}",
                (r >> 8) % 120,
                "v".repeat(usize::try_from(size).unwrap_or(1)),
                1 + (r >> 40) % 7200,
                if r & 2 == 0 { "/" } else { "/a" },
            );
            jar.store(&url, &line[..], now);
            if r % 5 == 0 {
                let _ = jar.cookie_header(&url, now);
            }
            if r % 997 == 0 {
                jar.remove_expired(now);
            }
            if ops % 20_000 == 19_999 {
                let bytes = jar.export();
                let mut copy = Jar::new().with_limits(limits);
                copy.import(&bytes, now).unwrap();
                jar = copy;
            }
            assert!(jar.len() <= 3000);
            ops += 1;
        }
        let quarter = (start.elapsed().as_secs_f64() * 4.0 / total.as_secs_f64()) as usize;
        let slot = &mut quarter_peak[quarter.min(3)];
        *slot = (*slot).max(resident_bytes());
    }
    let [_, second, _, last] = quarter_peak;
    println!(
        "soak: {secs} s, {ops} operations, jar {} cookies, resident peak per quarter {:?} KiB",
        jar.len(),
        quarter_peak.map(|b| b / 1024)
    );
    assert!(
        last <= second + second / 10 + (1 << 20),
        "resident memory grew from {second} to {last} bytes"
    );
}
