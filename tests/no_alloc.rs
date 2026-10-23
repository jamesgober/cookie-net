//! Counting-allocator tests: parsing, every lookup, and writing a
//! `SetCookie` into a `SliceSink` allocate nothing (NFR-1).
//!
//! The allocator counts allocations made by this thread only, so the test
//! harness running other tests in parallel cannot disturb the count. The
//! `unsafe` below is in this test crate only; the library forbids it.

use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    hint::black_box,
    ops::ControlFlow,
};

use cookie_net::{self as cookie, Cookies, Limits, SameSite, SetCookie, ValueMode};
use parse_net::SliceSink;

struct Counting;

thread_local! {
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}

// SAFETY: every call is forwarded unchanged to the system allocator, which
// upholds the `GlobalAlloc` contract; the only addition is a thread-local
// counter increment, which does not allocate.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let _ = ALLOCATIONS.try_with(|n| n.set(n.get() + 1));
        // SAFETY: the caller's layout is passed through as received.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: `ptr` was allocated by `System` with this layout.
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let _ = ALLOCATIONS.try_with(|n| n.set(n.get() + 1));
        // SAFETY: forwarded unchanged; `ptr` came from `System`.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

fn allocations(f: impl FnOnce()) -> usize {
    let before = ALLOCATIONS.with(Cell::get);
    f();
    ALLOCATIONS.with(Cell::get) - before
}

const HEADERS: &[&str] = &[
    "",
    "__Host-sid=Zk3J9qL0wX7aP2mT8sV1cR5dY4hN6bE0uK9gF3jQ2oA; theme=dark; lang=fr; _ga=GA1.2.3; _gid=GA1.4.5; consent=yes",
    "a=1;b=2; ; bad name=3; __Host-x=1; __Host-x=2; sid=evil; __host-sid=x",
    "a=\"1\"; b=\"2; c=x y; d=\u{e9}; $Version=1",
];

#[test]
fn test_reading_allocates_nothing() {
    let lenient = Limits::DEFAULT.value_mode(ValueMode::Lenient);
    for h in HEADERS {
        let n = allocations(|| {
            let c = cookie::parse(*h);
            black_box(c.iter().count());
            black_box(c.stats());
            black_box(cookie::get(*h, "theme"));
            let _ = black_box(cookie::get_unique(*h, "__Host-sid"));
            black_box(cookie::get_all(*h, "a").count());
            black_box(cookie::locate(*h, "__Host-sid", &Limits::DEFAULT));
            black_box(c.scan(|p| {
                black_box(p.value_unquoted());
                black_box(p.prefix());
                ControlFlow::Continue(())
            }));
            let l = Cookies::with_limits(*h, &lenient).unwrap();
            black_box(l.iter().count());
            let lines: [&[u8]; 2] = [h.as_bytes(), b"x=1"];
            black_box(
                Cookies::from_lines(&lines, &Limits::DEFAULT)
                    .unwrap()
                    .locate("x"),
            );
        });
        assert_eq!(n, 0, "{h:?}");
    }
}

#[test]
fn test_building_and_writing_allocates_nothing() {
    let mut buf = [0u8; 1024];
    let n = allocations(|| {
        let token = "Zk3J9qL0wX7aP2mT8sV1cR5dY4hN6bE0uK9gF3jQ2oA";
        let cookies = [
            SetCookie::new("theme", "dark").unwrap(),
            cookie::session_cookie("__Host-sid", token, 12 * cookie::HOUR).unwrap(),
            cookie::elevated_cookie("__Host-sudo", token, 600).unwrap(),
            SetCookie::delete("__Host-sid").unwrap(),
            SetCookie::builder("w", "1")
                .domain("Example.COM")
                .path("/app")
                .max_age(60)
                .expires(1_792_607_880, 1_792_600_000)
                .same_site(SameSite::None)
                .partitioned()
                .extension("Priority=High")
                .build()
                .unwrap(),
        ];
        for c in &cookies {
            let mut out = SliceSink::new(&mut buf);
            c.write_to(&mut out).unwrap();
            black_box(out.len());
            black_box(c.encoded_len());
        }
        black_box(cookies[0].encode_into(&mut buf).unwrap());
        black_box(SetCookie::new("a b", "x").unwrap_err());
    });
    assert_eq!(n, 0);
}

#[cfg(feature = "encrypted")]
#[test]
fn test_signing_verifying_and_opening_allocate_nothing() {
    use cookie_net::{Sealer, Signer};
    let signer = Signer::new(*b"an example key, 32 bytes long!!!").unwrap();
    let sealer = Sealer::new(*b"another example key, 32 bytes!!!").unwrap();
    let signed = signer
        .sign_until("prefs", "lang=fr", 1_800_000_000)
        .unwrap();
    let sealed = sealer.seal("flash", "Saved.").unwrap();
    let mut plain = Vec::with_capacity(64);
    let mut scratch = Vec::with_capacity(128);
    let mut buf = [0u8; 256];
    // warm the scratch buffer once
    sealer
        .seal_into(
            "flash",
            b"Saved.",
            None,
            &[],
            &mut scratch,
            &mut SliceSink::new(&mut buf),
        )
        .unwrap();
    let n = allocations(|| {
        let mut out = SliceSink::new(&mut buf);
        signer
            .sign_into("prefs", "lang=fr", Some(1_800_000_000), b"sid", &mut out)
            .unwrap();
        black_box(signer.verify("prefs", &signed, 1_700_000_000).unwrap());
        black_box(
            signer
                .verify("prefs", "garbage-garbage-garbage-garbage", 0)
                .unwrap_err(),
        );
        black_box(
            sealer
                .open_into("flash", &sealed, &[], 0, &mut plain)
                .unwrap(),
        );
        let mut out = SliceSink::new(&mut buf);
        sealer
            .seal_into("flash", b"Saved.", None, &[], &mut scratch, &mut out)
            .unwrap();
        black_box(out.len());
    });
    assert_eq!(n, 0);
}

#[cfg(feature = "client")]
#[test]
fn test_client_parsing_allocates_nothing() {
    let n = allocations(|| {
        black_box(cookie_net::parse_set_cookie(
            "id=a3fWa; Max-Age=2592000; Domain=.Example.com; Secure; SameSite=lax; Expires=Wed, 09 Jun 2021 10:18:14 GMT",
        ));
        black_box(cookie_net::cookie_date("Wednesday, 09-Jun-21 10:18:14 GMT"));
        black_box(cookie_net::parse_set_cookie("\x01"));
    });
    assert_eq!(n, 0);
}
