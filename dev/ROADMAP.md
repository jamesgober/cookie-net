# cookie-net - Roadmap

> Path from scaffold to a stable 1.0. Hard parts are front-loaded; each phase has hard exit criteria.
> Design and decisions: [`PLAN.md`](./PLAN.md).
>
> **Anti-deferral rule:** no listed hard task moves to a later phase unless this file records the move and the reason.

## v0.1.0 - Scaffold (DONE, 2026-10-13)
- [x] Manifest, README, CHANGELOG, REPS, dual license, CI, deny, clippy, rustfmt, DIRECTIVES, ROADMAP, PLAN.

## v0.2.0 - Design lock
Exit: parse, builder, and sealed-cookie APIs written in `docs/API.md` and approved.

## v0.3.0 - Plain cookies
Exit: RFC 6265bis cases pass; prefix and SameSite rules cannot be violated through the builder.
- [ ] Cookie header parsing with budgets; Set-Cookie builder; IMF-fixdate.

## v0.4.0 - Signed and encrypted
Exit: any single-bit change is refused; rotation keeps old cookies valid until their key retires.
- [ ] HMAC and AEAD cookies over crypt-io and key-vault; key ids and rotation.

## v1.0.0 - Stable
- [ ] Frozen after web-net and gate-net have used it end to end.
