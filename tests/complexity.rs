//! Complexity tests (NFR-2): every reading entry point, fed adversarial
//! headers of 4 KiB and 64 KiB with every limit raised to its maximum, takes
//! time that grows no faster than about the input (within 2 times the size
//! ratio). A quadratic walker would take 16 times the ratio.
//!
//! Timing is the best of several runs, and a case that misses the bound is
//! measured again (up to three times) before it fails, so a busy machine does
//! not fail the test.

use std::{
    hint::black_box,
    time::{Duration, Instant},
};

use cookie_net::{Cookies, Limits, ValueMode};

const FULL: Limits = Limits::DEFAULT
    .max_header_len(65_536)
    .max_pairs(1024)
    .max_name_len(4096);

fn best(f: &dyn Fn()) -> Duration {
    (0..7)
        .map(|_| {
            let t = Instant::now();
            for _ in 0..20 {
                f();
            }
            t.elapsed()
        })
        .min()
        .unwrap_or_default()
}

fn linear(name: &str, make: fn(usize) -> String, run: fn(&str)) {
    let (small, large) = (make(4 << 10), make(64 << 10));
    let ratio = large.len() as f64 / small.len() as f64;
    for attempt in 0..3 {
        let a = best(&|| run(&small));
        let b = best(&|| run(&large));
        let grew = b.as_secs_f64() / a.as_secs_f64().max(1e-9);
        if grew <= 2.0 * ratio {
            return;
        }
        if attempt == 2 {
            panic!("{name}: {grew:.1}x for {ratio:.1}x more input");
        }
    }
}

fn fill(unit: &str, len: usize) -> String {
    let mut s = String::with_capacity(len + unit.len());
    while s.len() + unit.len() <= len {
        s.push_str(unit);
    }
    s
}

fn every_entry_point(h: &str) {
    let c = Cookies::with_limits(h, &FULL).unwrap();
    black_box(c.stats());
    black_box(c.get("zz"));
    let _ = black_box(c.get_unique("__Host-a"));
    black_box(c.locate("__Host-a"));
    let l = Cookies::with_limits(h, &FULL.value_mode(ValueMode::Lenient)).unwrap();
    black_box(l.iter().count());
}

#[test]
fn test_one_byte_pairs_are_linear() {
    linear("a=;", |n| fill("a=;", n), every_entry_point);
}

#[test]
fn test_distinct_prefixed_duplicates_are_linear() {
    // the prefixed-duplicate table full, every name compared against it
    linear(
        "prefixed",
        |n| {
            let mut s = String::new();
            let mut i = 0u32;
            while s.len() + 24 <= n {
                s.push_str(&format!("__Host-{i}=1; "));
                i += 1;
            }
            s
        },
        every_entry_point,
    );
}

#[test]
fn test_separators_and_skipped_pairs_are_linear() {
    linear(";;", |n| fill(";", n), every_entry_point);
    linear("skipped", |n| fill("bad name=1; ", n), every_entry_point);
    linear(
        "one long value",
        |n| format!("a={}", "v".repeat(n.min(4094))),
        every_entry_point,
    );
    linear(
        "shadows",
        |n| fill("__host-A=1; A=1; __Secure-a=1; ", n),
        every_entry_point,
    );
}
