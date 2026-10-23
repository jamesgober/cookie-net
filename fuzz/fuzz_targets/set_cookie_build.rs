#![no_main]

use cookie_net::{Cookies, Limits, Prefix, SameSite, SetCookie};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut fields = data.split(|&b| b == 0);
    let mut next = || fields.next().and_then(|f| core::str::from_utf8(f).ok()).unwrap_or("");
    let (name, value, path, domain, ext) = (next(), next(), next(), next(), next());
    let flags = next().bytes().next().unwrap_or(0);
    let max_age = next().parse::<u64>().ok();
    let mut b = SetCookie::builder(name, value);
    if !path.is_empty() { b = b.path(path); }
    if flags & 0x40 != 0 { b = b.domain(domain); }
    if !ext.is_empty() { b = b.extension(ext); }
    if flags & 0x01 != 0 { b = b.insecure(); }
    if flags & 0x02 != 0 { b = b.script_readable(); }
    if flags & 0x04 != 0 { b = b.partitioned(); }
    b = b.same_site(match (flags >> 3) & 3 { 0 => SameSite::Lax, 1 => SameSite::Strict, _ => SameSite::None });
    if flags & 0x20 != 0 { b = b.delete(); }
    if let Some(s) = max_age { b = b.max_age(s); }
    let Ok(c) = b.build() else { return };

    let line = c.encode();
    assert_eq!(line.len(), c.encoded_len());
    assert!(line.bytes().all(|b| (0x20..0x7f).contains(&b)), "control byte in {line:?}");
    let pair = format!("{}={}", c.name(), c.value());
    assert!(line.starts_with(&format!("{pair}; Path=")));
    // the reader gives back exactly what was written
    let limits = Limits::DEFAULT.max_name_len(4096).max_header_len(65_536);
    let read = Cookies::with_limits(&pair, &limits).unwrap();
    assert_eq!(read.get_unique(c.name()), Ok(Some(c.value())));
    // the rules hold
    match Prefix::of(c.name()) {
        Prefix::Host => assert!(c.is_secure() && c.path() == "/" && c.domain().is_none()),
        Prefix::Secure => assert!(c.is_secure()),
        _ => {}
    }
    if c.same_site() == SameSite::None || c.is_partitioned() {
        assert!(c.is_secure());
    }
    assert!(c.max_age().is_none_or(|s| (1..=cookie_net::MAX_LIFETIME).contains(&s)));
    // cookie-net never writes a `Max-Age=0` attribute (the first segment is
    // the cookie's own name and value, which may be `Max-Age=0x`)
    assert!(!line.split("; ").skip(1).any(|attr| attr.starts_with("Max-Age=0")));
});
