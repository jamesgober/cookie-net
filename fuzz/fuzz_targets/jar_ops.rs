#![no_main]

use cookie_net::{Cookies, Jar, JarLimits, Limits, RequestContext, RequestUrl, ValueMode};
use libfuzzer_sys::fuzz_target;

const HOSTS: [&str; 4] = ["example.com", "a.example.com", "other.org", "10.0.0.1"];
const PATHS: [&str; 3] = ["/", "/a/b", "/a"];

// Sequences of store and retrieve operations: never panics, keeps its
// bounds, every Cookie header it writes reads back, and export then import
// gives the same headers.
fuzz_target!(|data: &[u8]| {
    let limits = JarLimits::DEFAULT.per_domain(5).total(12);
    let mut jar = Jar::new().with_limits(limits);
    let mut now = 1_800_000_000u64;
    for op in data.split(|&b| b == 0xff) {
        let Some((&ctl, line)) = op.split_first() else { continue };
        let host = HOSTS[usize::from(ctl & 3)];
        let path = PATHS[usize::from((ctl >> 2) % 3)];
        let url = RequestUrl::new(ctl & 0x10 != 0, host, path);
        now += u64::from(ctl >> 5);
        if ctl & 0x20 == 0 {
            let _ = jar.store(&url, line, now);
        }
        assert!(jar.len() <= 12);
        let cx = if ctl & 0x40 != 0 {
            RequestContext::cross_site().navigation(ctl & 0x80 != 0)
        } else {
            RequestContext::default()
        };
        if let Some(h) = jar.cookie_header_for(&url, &cx, now) {
            let read_limits = Limits::DEFAULT
                .value_mode(ValueMode::Lenient)
                .max_header_len(65_536)
                .max_pairs(1024);
            let read = Cookies::with_limits(&h, &read_limits).unwrap();
            assert!(usize::from(read.stats().pairs) <= jar.len());
        }
    }
    let exported = jar.export();
    let mut copy = Jar::new().with_limits(limits);
    let n = copy.import(&exported, now).unwrap();
    assert!(n <= jar.len());
    for host in HOSTS {
        let url = RequestUrl::https(host, "/a/b");
        assert_eq!(copy.cookie_header(&url, now), jar.cookie_header(&url, now));
    }
});
