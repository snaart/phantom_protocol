<!--
Thanks for contributing to Phantom Protocol! Please fill out the sections below.
See CONTRIBUTING.md for the full contributor guide.
-->

## Summary

<!-- What does this PR change, and why? Link any related issue (e.g. "Closes #123"). -->

## Type of change

- [ ] Bug fix (non-breaking)
- [ ] New feature (non-breaking)
- [ ] Breaking change (API / FFI ABI / wire format)
- [ ] Documentation only
- [ ] CI / build / supply-chain
- [ ] Refactor / internal cleanup

## Checklist

- [ ] `cargo fmt --manifest-path core/Cargo.toml --check` passes
- [ ] `cargo clippy --manifest-path core/Cargo.toml --lib -- -D warnings` passes
- [ ] `cargo test --manifest-path core/Cargo.toml --lib` passes
- [ ] New public functions have at least one positive **and** one negative test
- [ ] `cargo deny check` passes (if dependencies changed)
- [ ] `CHANGELOG.md` `[Unreleased]` updated for any user-visible change
- [ ] No `.unwrap()` / `.expect()` / `panic!` / `unreachable!` / `todo!` /
      `unimplemented!` in production crates (or justified with `// PANIC-SAFETY:`)
- [ ] Every new `unsafe { }` block carries a `// SAFETY:` comment

## Security-sensitive changes

<!--
If this PR touches any of the codeowner-reviewed paths below, describe which
documented security invariant is affected and how it is preserved. Otherwise
write "N/A".
  - core/src/crypto/
  - core/src/transport/handshake.rs
  - core/src/transport/session.rs
  - core/src/transport/udp_transport.rs
  - core/src/transport/legs/mimic_tls/
  - core/src/security/
-->

## Wire / ABI impact

<!-- Does this change the wire format (WIRE_VERSION), the public Rust API, or the
FFI ABI? If so, describe the bump. Otherwise write "None". -->
