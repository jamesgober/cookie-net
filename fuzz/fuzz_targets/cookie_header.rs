#![no_main]

use cookie_net::{Ambiguous, Cookies, Limits, Lookup, ValueMode};
use libfuzzer_sys::fuzz_target;

fn check(data: &[u8], limits: &Limits) {
    let Ok(cookies) = Cookies::with_limits(data, limits) else {
        assert!(data.len() > limits.header_len());
        return;
    };
    let stats = cookies.stats();
    assert!(stats.pairs <= limits.pairs());
    let mut n = 0u16;
    for pair in cookies.iter() {
        n += 1;
        let name = pair.name().as_bytes();
        assert!(!name.is_empty() && name.len() <= usize::from(limits.name_len()));
        assert!(name.iter().all(|&b| parse_net::class::is_tchar(b)));
        let value = pair.value().as_bytes();
        assert!(value.len() <= usize::from(limits.value_len()));
        assert!(name.len() + value.len() <= 4096);
        assert!(!value.contains(&b';'));
        if limits.mode() == ValueMode::Strict {
            assert!(value.is_ascii() && !value.contains(&b' '));
        }
        // the first match and the unique lookup agree with the iteration
        // (checked for the first 16 pairs, so the oracle stays linear)
        if n > 16 {
            continue;
        }
        let first = cookies.get(pair.name());
        assert!(first.is_some());
        match cookies.get_unique(pair.name()) {
            Ok(Some(v)) => assert_eq!(Some(v), first),
            Ok(None) => panic!("an iterated name was not found"),
            Err(Ambiguous::Duplicate { count }) => assert!(count >= 2),
            Err(Ambiguous::Truncated) => assert!(stats.truncated),
            Err(e) => panic!("unexpected {e:?}"),
        }
        match cookies.locate(pair.name()).lookup {
            Lookup::One(v) => assert_eq!(Some(v), first),
            Lookup::Many { first: f, count } => assert!(Some(f) == first && count >= 2),
            Lookup::Truncated => assert!(stats.truncated),
            other => panic!("unexpected {other:?}"),
        }
    }
    assert_eq!(n, stats.pairs);
}

fuzz_target!(|data: &[u8]| {
    check(data, &Limits::DEFAULT);
    check(data, &Limits::DEFAULT.value_mode(ValueMode::Lenient).max_pairs(1024).max_header_len(65_536));
    check(data, &Limits::DEFAULT.max_pairs(2).max_name_len(3).max_value_len(4));
    let _ = cookie_net::parse(data).stats();
});
