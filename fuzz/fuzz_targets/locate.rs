#![no_main]

use cookie_net::{Ambiguous, Limits, Lookup};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some(at) = data.iter().position(|&b| b == 0) else { return };
    let Ok(name) = core::str::from_utf8(&data[..at]) else { return };
    let header = &data[at + 1..];
    let found = cookie_net::locate(header, name, &Limits::DEFAULT);
    let all: Vec<&str> = cookie_net::get_all(header, name).collect();
    match (found.lookup, cookie_net::get_unique(header, name)) {
        (Lookup::Missing, Ok(None)) => assert!(all.is_empty()),
        (Lookup::One(v), Ok(Some(u))) => assert!(v == u && all == [v]),
        (Lookup::Many { first, count }, Err(Ambiguous::Duplicate { count: c })) => {
            assert!(count == c && usize::from(count) == all.len() && all[0] == first);
        }
        (Lookup::Truncated, Err(Ambiguous::Truncated)) => assert!(found.stats.truncated),
        (Lookup::HeaderTooLong, Err(Ambiguous::HeaderTooLong)) => assert!(found.stats.too_long),
        (l, u) => panic!("locate {l:?} and get_unique {u:?} disagree"),
    }
    assert!(usize::from(found.shadows) + all.len() <= usize::from(found.stats.pairs));
    assert!(found.severity_hint() <= 40);
});
