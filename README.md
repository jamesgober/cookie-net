<h1 align="center">
    <img width="99" alt="Rust logo" src="https://raw.githubusercontent.com/jamesgober/rust-collection/72baabd71f00e14aa9184efcb16fa3deddda3a0a/assets/rust-logo.svg">
    <br>
    <b>cookie-net</b>
    <br>
    <sub><sup>HTTP COOKIES</sup></sub>
</h1>

<div align="center">
    <a href="https://crates.io/crates/cookie-net"><img alt="Crates.io" src="https://img.shields.io/crates/v/cookie-net"></a>
    <a href="https://crates.io/crates/cookie-net"><img alt="Downloads" src="https://img.shields.io/crates/d/cookie-net?color=%230099ff"></a>
    <a href="https://docs.rs/cookie-net"><img alt="docs.rs" src="https://img.shields.io/docsrs/cookie-net"></a>
    <a href="https://github.com/jamesgober/cookie-net/actions"><img alt="CI" src="https://github.com/jamesgober/cookie-net/actions/workflows/ci.yml/badge.svg"></a>
    <a href="https://github.com/rust-lang/rfcs/blob/master/text/2495-min-rust-version.md"><img alt="MSRV" src="https://img.shields.io/badge/MSRV-1.85%2B-blue"></a>
</div>

<br>

<div align="left">
    <p>
        <strong>cookie-net</strong> reads the <code>Cookie</code> header and writes <code>Set-Cookie</code> headers, following RFC 6265bis. Secure defaults are the defaults: <code>Secure</code>, <code>HttpOnly</code>, and <code>SameSite=Lax</code> unless a cookie says otherwise, and the <code>__Host-</code> prefix for session cookies.
    </p>
    <p>
        Signed cookies detect tampering; encrypted cookies also hide their content. The primitives come from crypt-io (keyed BLAKE3 and XChaCha20-Poly1305), the keys from the caller, and key rotation is staged so no node of a cluster ever refuses a cookie another node just signed.
    </p>
    <br>
    <hr>
    <p>
        <strong>MSRV is 1.85+</strong> (Rust 2024 edition). <code>#![forbid(unsafe_code)]</code>.
    </p>
    <blockquote>
        <strong>Status: design lock (<code>0.2.0</code>).</strong> The public API through <code>1.0</code> is written down in <a href="./docs/API.md"><code>docs/API.md</code></a>, the reasons in <a href="./dev/PLAN.md"><code>dev/PLAN.md</code></a>, and the schedule in <a href="./dev/ROADMAP.md"><code>dev/ROADMAP.md</code></a>. The code arrives with <code>0.3.0</code>.
    </blockquote>
</div>

<hr>
<br>

## Scope

`Cookie` header parsing (zero-copy, bounded, with duplicate detection for credentials), `Set-Cookie` writing with every attribute and every rfc6265bis rule enforced at build time, session-cookie helpers for `__Host-` tokens, signed (keyed BLAKE3) and encrypted (XChaCha20-Poly1305) cookies with expiry, session binding, and staged key rotation, and a client side (`Set-Cookie` parsing and a bounded cookie jar). Sessions themselves are gate-net's job, and CSRF tokens are csrf-sec's (never a cookie); cookie-net only carries the session token.

See [`docs/API.md`](./docs/API.md) for the API and [`dev/PLAN.md`](./dev/PLAN.md) for the full scope, what is deliberately left to other crates, the threats, and the decision log.

<hr>
<br>

## Contributing

See <a href="./dev/DIRECTIVES.md"><code>dev/DIRECTIVES.md</code></a> for engineering standards and the definition of done. Before a PR: `cargo fmt --all`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-features` must be clean.

<br>

<div id="license">
    <h2>License</h2>
    <p>Licensed under either of</p>
    <ul>
        <li><b>Apache License, Version 2.0</b>: see <a href="./LICENSE-APACHE">LICENSE-APACHE</a></li>
        <li><b>MIT License</b>: see <a href="./LICENSE-MIT">LICENSE-MIT</a></li>
    </ul>
    <p>at your option.</p>
</div>

<div align="center">
  <h2></h2>
  <sup>COPYRIGHT <small>&copy;</small> 2026 <strong>James Gober.</strong></sup>
</div>
