# Contributing to Phantom Core

Thank you for your interest in contributing.

## Quick start

```bash
git clone <repo>
cd phantom_core_rust
cargo build   --manifest-path core/Cargo.toml
cargo test    --manifest-path core/Cargo.toml --lib
cargo clippy  --manifest-path core/Cargo.toml --lib -- -D warnings
cargo fmt     --manifest-path core/Cargo.toml --check
```

Loopback integration tests are gated and run with `-- --ignored`:

```bash
cargo test --manifest-path core/Cargo.toml --test tcp_integration -- --ignored
```

### Pre-commit hooks (optional)

A `.pre-commit-config.yaml` at the repo root wires up [`pre-commit`](https://pre-commit.com)
to run `cargo fmt --check`, `cargo clippy --lib`, `tests/bindings/check_versions.sh`,
and standard hygiene hooks (whitespace, EOL, large-file guard) on every
local commit. Install once:

```bash
pip install pre-commit
pre-commit install
```

Skip on a specific commit with `git commit --no-verify`. The CI workflow
runs the same checks (plus heavier `cargo deny` / `cargo audit` /
full-cross-target gates), so the local hook is an early-feedback layer,
not a replacement.

## Style

- Rust 2021 edition.
- `rustfmt` per [`.rustfmt.toml`](.rustfmt.toml). Every PR must pass `cargo fmt --check`.
- `clippy` per [`.clippy.toml`](.clippy.toml). Every PR must pass
  `cargo clippy --workspace --all-targets -- -D warnings`.
- No `.unwrap()` / `.expect()` / `panic!` / `unreachable!` / `todo!` / `unimplemented!`
  in production crates (the `#![deny(clippy::unwrap_used, ...)]` lints enforce
  this). Where unavoidable, justify with a `// PANIC-SAFETY:` comment.
- Every `unsafe { }` block must have a `// SAFETY:` comment explaining the
  invariants being upheld.

## Security-sensitive changes

Files in these paths require **codeowner review** before merge:

- `core/src/crypto/`
- `core/src/transport/handshake.rs`
- `core/src/transport/legs/faketls.rs`
- `core/src/transport/session.rs`
- `core/src/security/`

The documented security invariants in [`SECURITY.md`](SECURITY.md) and
[`docs/security/threat-model.md`](docs/security/threat-model.md) must be preserved.

## Adding a dependency

1. Check it is not already supplied indirectly.
2. Prefer crates with active maintenance, RustSec coverage, and a permissive
   license (Apache-2.0, MIT, BSD).
3. Run `cargo deny check` locally; the CI must pass.
4. For cryptographic crates: review constant-time properties and side-channel
   posture.
5. If introducing `unsafe`, document the rationale in the PR description.

## Tests

- New public functions need at least one positive and one negative test.
- Security invariants must be covered by tests in `core/tests/` (especially
  `tcp_integration.rs` and the upcoming `security_invariants.rs`).
- Concurrency-sensitive code should have a loom test where practical.

## Commit messages

Use imperative mood. Keep the subject line concise and explain the *why* in
the body; note any user-visible change in `CHANGELOG.md`.

## License

By contributing, you agree that your contributions will be licensed under
Apache License 2.0 (see [`LICENSE`](LICENSE)).
