//! Signed and encrypted cookies, and a staged key rotation. Run with
//! `cargo run --example 03_signed_and_sealed --features encrypted`.

use cookie_net::{self as cookie, CookieError, Key, KeyId, KeyRing, Sealer, SetCookie, Signer};

fn main() -> Result<(), CookieError> {
    let now = 1_800_000_000;
    // one master from key-vault; each service derives its own key
    let master: Vec<u8> = (0u8..32).map(|i| i.wrapping_mul(37) ^ 0x5a).collect();
    let key = Key::derive(&master, b"wasp-web")?;
    let signer = Signer::new(key.clone())?;
    let sealer = Sealer::new(key)?;

    // a signed preference: readable, cannot be forged or moved
    let v = signer.sign_until("plan_banner", "dismissed", now + 30 * cookie::DAY)?;
    let set = SetCookie::builder("plan_banner", &v)
        .max_age(30 * cookie::DAY)
        .build()?;
    println!("signed value has {} bytes", set.value().len());
    let header = format!("plan_banner={v}");
    let read =
        cookie::get(&header, "plan_banner").map(|raw| signer.verify("plan_banner", raw, now));
    assert_eq!(read, Some(Ok("dismissed")));

    // a private flash message for the next page
    let flash = sealer.seal_until("flash", "Payment received.", now + 60)?;
    let text = sealer.open("flash", &flash, now + 1)?;
    assert_eq!(text.as_str(), Some("Payment received."));

    // staged rotation: stage, switch, drop
    let k1 = *b"an example key, 32 bytes long!!!";
    let k2 = *b"the second key, 32 bytes long!!!";
    let staged = Signer::with_ring(KeyRing::new(KeyId(1), k1).accept(KeyId(2), k2))?;
    let switched =
        Signer::with_ring(KeyRing::new(KeyId(2), k2).retired(KeyId(1), k1, now + cookie::DAY))?;
    let old = staged.sign("prefs", "v1")?;
    let new = switched.sign("prefs", "v2")?;
    assert!(staged.verify("prefs", &new, now).is_ok()); // a staged node accepts the new key
    assert!(switched.verify("prefs", &old, now).is_ok()); // a switched node keeps the old one
    println!(
        "key 2 fingerprint on both nodes: {} {}",
        staged
            .fingerprint(KeyId(2))
            .map(|f| f.to_string())
            .unwrap_or_default(),
        switched
            .fingerprint(KeyId(2))
            .map(|f| f.to_string())
            .unwrap_or_default()
    );
    Ok(())
}
