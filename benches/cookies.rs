//! cookie-net's own benchmarks: the regression baseline for every hot path
//! (a change that slows one by more than 5% is refused). Comparisons with
//! other crates live in the separate cookie-net-bench repository, so they
//! never enter this crate's dependency tree.

use std::hint::black_box;

use cookie_net::{
    self as cookie, Jar, Limits, RequestContext, RequestUrl, Sealer, SetCookie, Signer,
    parse_set_cookie,
};
use criterion::{Criterion, criterion_group, criterion_main};
use parse_net::SliceSink;

const HEADER: &str = "__Host-sid=Zk3J9qL0wX7aP2mT8sV1cR5dY4hN6bE0uK9gF3jQ2oA; _ga=GA1.2.1234567890.1700000000; theme=dark; _gid=GA1.2.987654321.1700000000; consent=analytics%3Dno%2Cads%3Dno%2Cversion%3D3; lang=fr-CA; _fbp=fb.1.1700000000000.1234567890";
const VALUE_64: &str = "lang=fr-CA|tz=America/Toronto|layout=compact|beta=1|v=20261023xx";
const NOW: u64 = 1_800_000_000;

fn reading(c: &mut Criterion) {
    let mut g = c.benchmark_group("read");
    g.bench_function("get", |b| {
        b.iter(|| cookie::get(black_box(HEADER), "theme"))
    });
    g.bench_function("get_unique", |b| {
        b.iter(|| cookie::get_unique(black_box(HEADER), "__Host-sid"))
    });
    g.bench_function("locate", |b| {
        b.iter(|| cookie::locate(black_box(HEADER), "__Host-sid", &Limits::DEFAULT))
    });
    g.bench_function("iterate", |b| {
        b.iter(|| cookie::parse(black_box(HEADER)).iter().count())
    });
    g.bench_function("stats", |b| {
        b.iter(|| cookie::parse(black_box(HEADER)).stats())
    });
    g.finish();
}

fn writing(c: &mut Criterion) {
    let mut g = c.benchmark_group("write");
    let mut buf = [0u8; 256];
    g.bench_function("set_cookie_default", |b| {
        b.iter(|| {
            let c = SetCookie::new(black_box("theme"), black_box("dark")).unwrap();
            c.write_to(&mut SliceSink::new(&mut buf)).unwrap();
        })
    });
    g.bench_function("session_cookie", |b| {
        b.iter(|| {
            let c = cookie::session_cookie(
                "__Host-sid",
                black_box("Zk3J9qL0wX7aP2mT8sV1cR5dY4hN6bE0uK9gF3jQ2oA"),
                43_200,
            )
            .unwrap();
            c.write_to(&mut SliceSink::new(&mut buf)).unwrap();
        })
    });
    g.finish();
}

fn crypto(c: &mut Criterion) {
    let signer = Signer::new(*b"an example key, 32 bytes long!!!").unwrap();
    let signed = signer.sign("prefs", VALUE_64).unwrap();
    let sealer = Sealer::new(*b"an example key, 32 bytes long!!!").unwrap();
    let sealed = sealer.seal("flash", VALUE_64).unwrap();
    let mut g = c.benchmark_group("crypto");
    let mut buf = [0u8; 256];
    g.bench_function("sign_64", |b| {
        b.iter(|| {
            signer
                .sign_into(
                    "prefs",
                    black_box(VALUE_64),
                    None,
                    &[],
                    &mut SliceSink::new(&mut buf),
                )
                .unwrap()
        })
    });
    g.bench_function("verify_64", |b| {
        b.iter(|| {
            signer
                .verify("prefs", black_box(&signed), NOW)
                .unwrap()
                .len()
        })
    });
    let (mut scratch, mut out) = (Vec::with_capacity(256), Vec::with_capacity(256));
    g.bench_function("seal_64", |b| {
        b.iter(|| {
            out.clear();
            sealer
                .seal_into(
                    "flash",
                    black_box(VALUE_64.as_bytes()),
                    None,
                    &[],
                    &mut scratch,
                    &mut out,
                )
                .unwrap();
        })
    });
    let mut plain = Vec::with_capacity(128);
    g.bench_function("open_64", |b| {
        b.iter(|| {
            sealer
                .open_into("flash", black_box(&sealed), &[], NOW, &mut plain)
                .unwrap()
        })
    });
    g.finish();
}

fn client(c: &mut Criterion) {
    let line = "id=a3fWa; Expires=Wed, 21 Oct 2026 07:28:00 GMT; Max-Age=2592000; Domain=example.com; Path=/; Secure; HttpOnly; SameSite=Lax";
    let mut g = c.benchmark_group("client");
    g.bench_function("parse_set_cookie", |b| {
        b.iter(|| parse_set_cookie(black_box(line)).map(|v| v.value.len()))
    });
    g.bench_function("cookie_date", |b| {
        b.iter(|| cookie::cookie_date(black_box("Wed, 21 Oct 2026 07:28:00 GMT")))
    });
    let mut jar = Jar::new();
    let url = RequestUrl::https("shop.example.com", "/account/orders");
    for i in 0..20 {
        let path = if i % 3 == 0 { "/account" } else { "/" };
        jar.store(
            &url,
            &format!("c{i}=value-{i:04}-abcdefgh; Path={path}; Secure; HttpOnly")[..],
            NOW,
        );
    }
    for h in [
        "a.example.org",
        "b.example.org",
        "c.example.net",
        "d.example.net",
    ] {
        for i in 0..20 {
            jar.store(
                &RequestUrl::https(h, "/"),
                &format!("o{i}=x{i}; Path=/; Secure")[..],
                NOW,
            );
        }
    }
    let mut out = Vec::with_capacity(1024);
    g.bench_function("jar_header_20_of_100", |b| {
        b.iter(|| {
            out.clear();
            jar.write_cookie_header(&url, &RequestContext::default(), NOW, &mut out)
                .unwrap()
        })
    });
    g.bench_function("jar_store", |b| {
        b.iter(|| jar.store(&url, black_box("c5=new-value; Path=/; Secure"), NOW))
    });
    g.finish();
}

criterion_group!(benches, reading, writing, crypto, client);
criterion_main!(benches);
