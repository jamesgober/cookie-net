#![no_main]

use cookie_net::{Cookies, Limits, Pair};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let lines: Vec<&[u8]> = data.split(|&b| b == 0xff).collect();
    let limits = Limits::DEFAULT.max_header_len(65_536).max_pairs(1024);
    let Ok(split) = Cookies::from_lines(&lines, &limits) else { return };
    let joined = lines.join(&b"; "[..]);
    let Ok(whole) = Cookies::with_limits(&joined, &limits) else { return };
    let a: Vec<Pair<'_>> = split.iter().collect();
    let b: Vec<Pair<'_>> = whole.iter().collect();
    assert_eq!(a, b);
    assert_eq!(split.stats().pairs, whole.stats().pairs);
    assert_eq!(split.stats().skipped, whole.stats().skipped);
});
