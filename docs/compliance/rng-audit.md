# RNG / DRBG Audit

This document inventories every random-bytes source in `core/src/` and maps
each to its concrete OS / platform backend. The audit's purpose is twofold:

1. Confirm that every cryptographic byte (key material, nonce, challenge,
   cookie salt, session ID) originates from a CSPRNG.
2. Document the FIPS 140-3 build's SP 800-90A-validated DRBG. The
   `--features fips` build's DRBG swap (`aws_lc_rs::rand::SystemRandom`)
   is **shipped**, and the old `thread_rng()` entropy fallbacks were
   removed outright on every build — see the "FIPS-mode RNG" section
   below.

## Backends per target

| Target | Primary syscall | Failure mode | Notes |
| --- | --- | --- | --- |
| `x86_64-unknown-linux-gnu` | `getrandom(2)` syscall (Linux ≥ 3.17). On older kernels falls back to `/dev/urandom`. | Returns `EAGAIN` if entropy pool not initialized very early in boot. | `getrandom`'s `linux_disable_fallback` is unset — fallback path remains for legacy environments. |
| `aarch64-unknown-linux-gnu` / `-musl` | Same as above. | Same. | |
| `x86_64-apple-darwin` / `aarch64-apple-darwin` | `getentropy(2)` (BSD-style). | Returns `EIO` only on syscall misuse, never for entropy starvation. | macOS guarantees a seeded CSPRNG before user space starts. |
| `aarch64-apple-ios` / `-ios-sim` | `SecRandomCopyBytes` via `getentropy(2)` shim. | Same. | |
| `x86_64-pc-windows-msvc` / `aarch64-pc-windows-msvc` | `BCryptGenRandom(BCRYPT_USE_SYSTEM_PREFERRED_RNG)` via getrandom. | Cannot fail under normal operation. | CNG's system DRBG is SP 800-90A AES-CTR. |
| `wasm32-unknown-unknown` (browser) | `crypto.getRandomValues` via `getrandom` **0.4**'s `wasm_js` backend (declared in the wasm-only Cargo block). The separate `js`-featured `getrandom02` alias (0.2) serves `ring` / the rand_core-0.6 ecosystem, not `crypto::rng::OsRng`. | Throws `QuotaExceededError` only for unreasonable lengths (`> 65536` per call). Phantom Protocol calls request `≤ 32` bytes per primitive — never hit. | Browser-provided CSPRNG (typically based on the platform PRNG). |
| `wasm32-wasip2` | WASI Preview 2 `wasi:random/random.get-random-bytes` (via the `wasi = 0.14` bindings). | Host-guaranteed; no in-guest failure path. | Host-provided entropy; the guest builds `std,wasi-leg` without `bindings`. |
| `thumbv7em-none-eabihf` (Cortex-M, embedded) | **OE-supplied** — the shipped `RngProvider` trait (`crypto/rng.rs`, Phase 3.8) is the seam; a downstream HAL plugs in a hardware TRNG driver or an externally-seeded software DRBG. | OE responsibility. | See "Embedded path" below. |

## RNG call sites

Sites are named by file (relative to `core/src/`) and the enclosing item, never
by line number: a line number goes stale the moment anything is inserted above
it, and it goes stale silently, still resolving to some line of unrelated code.
To re-derive this inventory, run
`grep -rnE 'getrandom::|OsRng|fill_bytes|next_u64|rand::' core/src` and read
off the enclosing function of each production hit.

Sites that pull cryptographic entropy:

| Site (file :: item) | Bytes | Purpose | Backend used |
| --- | --- | --- | --- |
| `crypto/hybrid_kem.rs` :: `HybridSecretKey::generate` | 32 (X25519 secret seed; default build) | KEM keygen; ML-KEM-768 keygen (`MlKem768::generate_keypair`) draws internally via ml-kem's `getrandom` feature | `crate::crypto::rng::OsRng` |
| `crypto/hybrid_kem.rs` :: `HybridKeyPackage::encapsulate` | 32 (ephemeral X25519 seed; default build) | KEM encapsulate (classical half); the ML-KEM-768 encapsulation draws internally via ml-kem's `getrandom` feature | `crate::crypto::rng::OsRng` |
| `crypto/hybrid_sign.rs` :: `HybridSigningKey::generate_with_provider` (first draw) | 32 (Ed25519 seed) | Hybrid signing key — a long-term server identity, or the client's ephemeral per-handshake key | injected `RngProvider` (`HybridSigningKey::generate` passes `OsRng`) |
| `crypto/hybrid_sign.rs` :: `HybridSigningKey::generate_with_provider` (second draw) | 32 (ML-DSA-65 seed) | Same key, ML-DSA-65 half | injected `RngProvider` (`HybridSigningKey::generate` passes `OsRng`) |
| `transport/types.rs` :: `SessionId::random` | 32 bytes | Session ID | `crate::crypto::rng::OsRng` (panics on CSPRNG failure) |
| `transport/handshake.rs` :: `HandshakeServer::with_signing_key_and_cache` | 32 bytes | Server master secret (HMAC base for cookie + PoW bucket secrets); every `HandshakeServer` constructor funnels through this function | `getrandom::fill`, propagates error |
| `transport/handshake.rs` :: `HandshakeServer::process_client_hello` | 32 bytes | Server handshake nonce (`server_nonce`) | `getrandom::fill`, propagates error |
| `transport/handshake.rs` :: `HandshakeClient::new` | 32 bytes | Client handshake nonce | `getrandom::fill`, propagates error |
| `transport/path.rs` :: `PathRegistry::issue_challenge` | 32 bytes | Path-validation challenge | `crate::crypto::rng::OsRng` |
| `api/udp_transport.rs` :: `UdpClientTransport::connect` | 8 bytes | Initial PhantomUDP `ConnId` | `getrandom::fill`, propagates error |

Under `--features fips` the two `crypto/hybrid_kem.rs` rows change shape: the
classical half is ECDH-P-256, generated by `aws-lc-rs` itself
(`PrivateKey::generate` in `HybridSecretKey::generate`,
`EphemeralPrivateKey::generate` over a `SystemRandom` in
`HybridKeyPackage::encapsulate`), so those bytes come from the AWS-LC CTR_DRBG
and no seed is drawn from `OsRng`. The ML-KEM-768 draws are the same on both
builds.

`rand` is **not** a production dependency — it is dev-only
(`core/Cargo.toml :: [dev-dependencies]`).

Sites that pull **non-cryptographic** entropy (handle/jitter/test only):

| Site (file :: item) | Purpose | Note |
| --- | --- | --- |
| `api/session.rs` :: `new_session_id` | 16-byte display handle for a session | Non-secret identifier; still drawn from the `OsRng` seam |
| `transport/shaping.rs` :: `random_jitter` | Traffic-shaping timing jitter | Non-cryptographic; drawn from the `OsRng` seam |
| `transport/legs/mimic_tls/` (`client_hello.rs`, `server_hello.rs`, `theater.rs`) | TLS `random`, legacy session id, key-share filler, GREASE values, extension-order shuffle, and the lengths and bytes of the opaque theater records (feature `mimicry`) | Public by design (`key-management.md` §5); drawn from an injected `&dyn RngProvider`, which `MimicTlsLeg::connect` / `MimicTlsLeg::accept` supply as `OsRng` |
| `test_harness/mod.rs` :: `NetworkSimulator::effective_latency` | Latency jitter sample | Test-only (`rand`, under `#[cfg(test)]`) |
| `test_harness/mod.rs` :: `NetworkSimulator::should_drop_packet` | Simulated loss decision | Test-only (`rand`, under `#[cfg(test)]`) |

## Fallback chain semantics

**There are no fallback chains.** Earlier revisions of this crate used a
`getrandom` → `rand::thread_rng()` entropy-downgrade fallback; it was
removed when the `RngProvider` seam landed. `rand` is no longer a
production dependency at all (dev-only). Production sites either propagate
the `getrandom` error as a `Result` or route through
`crate::crypto::rng::OsRng`, whose documented failure model is **panic on a
broken CSPRNG** — a loud fail is preferred over silently biased keys.
This already satisfies the FIPS prohibition on entropy-quality fallbacks;
no `#[cfg(not(feature = "fips"))]` gating is involved.

## Failure-mode policy

Sites that **propagate** RNG errors as `Result`:
- `transport/handshake.rs` :: `HandshakeServer::with_signing_key_and_cache` —
  server-side master secret, fatal at `HandshakeServer` construction
  (`HandshakeError::RngError`).
- `transport/handshake.rs` :: `HandshakeServer::process_client_hello` —
  server handshake nonce, fatal for that handshake only; the failure goes
  through `fail_and_reinsert`, so a consumed resumption ticket is put back.
- `transport/handshake.rs` :: `HandshakeClient::new` — client-side nonce,
  fatal at handshake start.
- `api/udp_transport.rs` :: `UdpClientTransport::connect` — initial
  PhantomUDP `ConnId`, fatal at client transport construction
  (`CoreError::RngError`).

Sites that route through the `RngProvider` seam
(`crate::crypto::rng::OsRng`, panic-on-CSPRNG-failure — no entropy
fallback on any build):
- `transport/types.rs` :: `SessionId::random` (session ID).
- `transport/legs/mimic_tls/` (TLS-Hello random — takes an injected
  `&dyn RngProvider`).
- `transport/path.rs` :: `PathRegistry::issue_challenge` (path challenge).
- `crypto/hybrid_kem.rs` :: `HybridSecretKey::generate` /
  `HybridKeyPackage::encapsulate` and `crypto/hybrid_sign.rs` ::
  `HybridSigningKey::generate_with_provider` (key seeds).

Because the seam has no fallback branch at all, the FIPS prohibition on
entropy-downgrade chains is satisfied structurally rather than by `#[cfg]`
gating.

## FIPS-mode RNG (shipped under `--features fips`)

The `--features fips` build's RNG posture is **shipped**:

1. **DRBG.** The OS-direct backend is replaced by an SP 800-90A DRBG:
   `crypto::rng::OsRng`'s `RngProvider` impl is cfg-split — `getrandom` on
   the default build, `aws_lc_rs::rand::SystemRandom` under `--features
   fips` (CTR_DRBG inside the AWS-LC-FIPS module, SP 800-90A § 10.2.1).
   This is the recommended path in `docs/compliance/fips-readiness.md`.

2. **Single seam for the swap.** The `RngProvider` trait
   (`crypto/rng.rs`, Phase 3.8) is the abstraction seam — call sites that
   route through `OsRng` pick up the fips substitution automatically,
   without touching each construction site. That covers most sites but not
   all of them: the four direct `getrandom::fill` calls and ml-kem's
   internal draws are outside the seam (see "Status of near-term actions",
   item 1).

3. **No entropy fallbacks at all.** The `thread_rng()` fallbacks were
   removed outright (not cfg-gated) when the `RngProvider` seam landed, and
   `rand` is no longer a production dependency — so there is nothing for
   the fips build to compile out.

4. **Power-on self-test.** The DRBG is exercised transitively by the
   shipped POST (`crypto::self_tests::run_post` — hybrid KEM / sign keygen
   pull from the RNG); see `docs/compliance/self-tests.md`.

5. **Continuous health check.** SP 800-90B requires a continuous test on
   the entropy source. `aws-lc-rs` provides this in its FIPS mode; a test
   failure surfaces as a fatal error.

## Embedded path

`thumbv7em-none-eabihf` and other Cortex-M targets do not have `getrandom`
out of the box. Phase 3.4 (EmbeddedLeg) must select one of:

- **Hardware TRNG.** Most STM32 / nRF / ESP chips ship one; a thin driver
  feeds a chip-specific peripheral into a software DRBG (HMAC-SHA-256 in
  the simplest case).
- **External seed.** For deeply embedded devices without TRNG, seed a
  software DRBG from a per-device factory-programmed secret + a monotonic
  counter. **Not suitable for crypto** without an attached secure element;
  document this as a deliberate limitation.

The trait surface for this should be folded into the existing `Runtime`
trait (Phase 3.1) or a sibling `RngBackend` trait.

## Status of near-term actions

1. ⏳ Most RNG call sites route through the `crate::crypto::rng` module
   (`RngProvider` / `OsRng`), so for them the FIPS swap is a single
   cfg-split in that one file. **Four do not.** The `getrandom::fill`
   calls in `HandshakeServer::with_signing_key_and_cache`,
   `HandshakeServer::process_client_hello`, `HandshakeClient::new` and
   `UdpClientTransport::connect` read the OS CSPRNG directly, so a
   `--features fips` build still takes the cookie/PoW master secret, both
   handshake nonces and the bootstrap connection id from `getrandom`
   rather than from the AWS-LC CTR_DRBG. ML-KEM-768 key generation and
   encapsulation likewise draw through ml-kem's `getrandom` feature on
   every build. Closing the first half means routing those four sites
   through `OsRng`; until that lands, the fips build's DRBG claim covers
   the seam and not every byte of entropy the handshake consumes.
2. ✅ `thread_rng` fallbacks are gone from production code on **every**
   build — they were deleted with the `RngProvider` seam, and `rand` is now
   a dev-dependency only.
3. ⏳ A CI smoke test that grep-checks for `rand::thread_rng` /
   `rand::random` outside of `test_harness/` is not yet wired.

## References

- NIST SP 800-90A Rev. 1 — Recommendation for Random Number Generation
  Using Deterministic Random Bit Generators.
- NIST SP 800-90B — Recommendation for the Entropy Sources Used for
  Random Bit Generation.
- `getrandom` crate documentation — https://docs.rs/getrandom
- `aws-lc-rs` FIPS mode — https://github.com/aws/aws-lc-rs
