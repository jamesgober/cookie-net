#![no_main]

use cookie_net::cookie_date;
use libfuzzer_sys::fuzz_target;
use parse_net::HttpDate;

// Never panics; a date it accepts is in the algorithm's range and, written
// back as an IMF-fixdate, reads as the same time.
fuzz_target!(|data: &[u8]| {
    let Some(t) = cookie_date(data) else { return };
    assert!(t >= -11_644_473_600, "before 1601: {t}");
    if let Ok(d) = HttpDate::from_unix(t) {
        assert_eq!(cookie_date(&d.format()[..]), Some(t));
    }
});
