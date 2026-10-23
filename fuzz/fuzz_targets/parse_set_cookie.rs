#![no_main]

use cookie_net::{SetCookie, parse_set_cookie};
use libfuzzer_sys::fuzz_target;

// Never panics; what it returns meets the section 5.6 limits; a line written
// by SetCookie parses back to the same name, value, and flags.
fuzz_target!(|data: &[u8]| {
    if let Some(v) = parse_set_cookie(data) {
        assert!(!(v.name.is_empty() && v.value.is_empty()));
        assert!(v.name.len() + v.value.len() <= 4096);
        let no_ctl = |b: &[u8]| !b.iter().any(|&c| (c < 0x20 && c != b'\t') || c == 0x7f);
        assert!(no_ctl(v.name) && no_ctl(v.value));
        assert!(!v.name.contains(&b';') && !v.value.contains(&b';'));
        assert!(v.max_age.is_none_or(|s| s <= 34_560_000));
        assert!(v.path.is_none_or(|p| p.first() == Some(&b'/')));
    }
    let Ok(text) = core::str::from_utf8(data) else { return };
    let mut parts = text.splitn(2, '\0');
    let (name, value) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
    if let Ok(c) = SetCookie::builder(name, value).max_age(60).build() {
        let line = c.encode();
        let v = parse_set_cookie(&line).expect("a built cookie parses");
        assert_eq!((v.name, v.value), (c.name().as_bytes(), c.value().as_bytes()));
        assert!(v.secure && v.http_only);
        assert_eq!(v.max_age, Some(60));
        assert_eq!(v.path, Some(&b"/"[..]));
    }
});
