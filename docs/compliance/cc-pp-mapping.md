# Common Criteria Protection Profile Mapping

**Scope.** This document maps the `phantom_core` library against the
**NIAP PP-Module for VPN Client v2.5** layered on the **PP for Application
Software v1.4**. It is the primary artifact for a NIAP CC evaluation
submission. A CC consultant or CCEVS-accredited laboratory should treat it
as the starting Security Target skeleton: each row below corresponds to a
claim or gap that will appear in the formal ST.

**Target PP chosen.** PP-Module VPN Client v2.5 + PP App v1.4. Phantom Core
is a transport *library* that downstream applications embed; it is not an
independent binary. The VPN Client module is the closest NIAP match for a
post-quantum-secure L4/L6 session layer. Alternative: PP for Network Devices
v3.0e would apply if Phantom is deployed as a server-side gateway binary —
evaluators targeting that posture should treat §3 as the starting point and
add FMT_SMF / FMT_MSA families. This document does not cover the ND PP.

**Evaluator's intended workflow.**
1. Confirm the TOE boundary (§2) against the delivered source tree.
2. Walk §3 row by row; map each evidence pointer to the corresponding source
   file. Unanswered cells are gaps; §5 lists the planned remediation.
3. Verify §4 assurance documents exist and are current.
4. Use §6 to open the NIAP CCEVS portal and engage an accredited lab.

---

## TOE Boundary

### In Scope

- `core/` — the `phantom_core` Rust library (`std` build, default features
  `["compression-zstd", "std"]`). This is the software TOE.
- `tests/bindings/{swift,kotlin,c,python}` — the UniFFI-generated consumer
  FFI surfaces, treated as part of the TOE boundary for the purposes of
  interface testing.
- CI pipeline artifacts: SLSA-3 build-provenance attestations produced by
  `.github/workflows/release.yml` (actions/attest-build-provenance@v2).

### Out of Scope

- The downstream embedder application that calls `PhantomSession::connect_*`
  / `PhantomListener::bind`. The TOE is the library; the calling application
  is the operational environment (OE).
- Any binary produced from `core/` (cdylib, staticlib, WASM blob). The TOE
  is the *source* + compiled artifact; binary packaging is OE responsibility.
- `cli/` harness — a developer convenience tool, not a shipping component.
- `fuzz/` harnesses — quality tooling, not part of the operational boundary.
- `examples/wasm-demo/` — a reference demo, not a shipped component.
- Platform key stores (iOS Keychain, Android Keystore, DPAPI, TPM) — OE.

### Boundary Diagram

```
 ┌─────────────────────────────────────────────────────────────────┐
 │  Operating Environment                                          │
 │                                                                 │
 │   ┌──────────────────┐         ┌──────────────────┐            │
 │   │  Embedder App    │         │  OS / Platform   │            │
 │   │  (iOS, Android,  │         │  - Key store     │            │
 │   │   Linux, WASM)   │         │  - Network stack │            │
 │   └────────┬─────────┘         └────────┬─────────┘            │
 │            │ UniFFI / Rust API           │ syscalls             │
 └────────────┼─────────────────────────────┼────────────────────-┘
              │                             │
 ┌────────────▼─────────────────────────────▼─────────────────────┐
 │  TOE: phantom_core (core/)                                     │
 │                                                                 │
 │  ┌──────────┐  ┌──────────┐  ┌──────────────┐  ┌───────────┐  │
 │  │ api/     │  │transport/│  │  crypto/     │  │security/  │  │
 │  │session   │  │handshake │  │ hybrid_kem   │  │replay_    │  │
 │  │listener  │  │session   │  │ hybrid_sign  │  │window     │  │
 │  │tcp_trans │  │legs/     │  │ adaptive_    │  │replay_    │  │
 │  └──────────┘  └──────────┘  │ crypto       │  │protection │  │
 │                               │ kdf / pow    │  └───────────┘  │
 │                               └──────────────┘                 │
 └────────────────────────────────────────────────────────────────┘
```

---

## Phantom Protocol Summary (for evaluators)

Phantom Core implements a bespoke post-quantum session protocol, not TLS.
Understanding the protocol is necessary to evaluate the FCS and FTP claims.
The full specification is in `docs/protocol/PROTOCOL.md`.

### Handshake (1-RTT)

```
Client                                         Server
  |                                               |
  |-- ClientHello (version, nonce, KEM pubkey, ---->
  |   Ed25519+ML-DSA-65 pubkey, [cookie/PoW])     |
  |                                               |-- cookie/PoW gate
  |                                               |-- KEM encapsulate
  |                                               |-- derive shared secret
  |                                               |-- sign transcript
  |<-- ServerHello (KEM ciphertext, server pubkey, sig, session_id) -----
  |                                               |
  |-- KEM decapsulate                             |
  |-- verify server signature                     |
  |-- derive session key (HKDF over shared secret)|
  |                        [data pump active on both sides]
```

The server identity pin (`HybridVerifyingKey`, hybrid Ed25519+ML-DSA-65)
is passed to `connect_with_transport` as a required parameter
(`api/session.rs:182`). There is no mechanism to skip pinning in the
public API. Clients obtain the pin via `PhantomListener::verifying_key_bytes()`
distributed out-of-band.

### 0-RTT Extension (folded into `ClientHello.early_data`)

```
Client (has prior resumption_hint)              Server
  |                                               |
  |-- ClientHello (AEAD-sealed early_data) ----->
  |                                               |-- try_resume (one-shot)
  |                                               |-- decrypt early_data
  |<-- ServerHello (early_data_accepted) ---------|
```

`SessionCache::try_resume` (`transport/session_cache.rs:132`) consumes
the ticket on first call — a replayed ClientHello finds no ticket and falls
back to 1-RTT + cookie/PoW gate. See `session_cache.rs:215-233` for the
one-shot anti-replay test.

### Session Data (post-handshake)

All application data is wrapped in a single `PhantomPacket` frame:

- Every outbound packet has `PacketFlags::ENCRYPTED` set
  (`api/session.rs:906`).
- Every inbound packet is AEAD-decrypted before delivery; packets without
  `ENCRYPTED` that carry non-empty payloads are silently dropped
  (`api/session.rs:1141-1150`).
- Rekey: `Session::rekey()` derives the next epoch key via
  `HKDF-Expand(current, "phantom-rekey-v1", 32)` and performs an `ArcSwap`
  store — the old `CryptoState` is zeroed when the last reader drops it
  (`transport/session.rs:147-148`). Epoch counter saturates at `u8::MAX`.
- Per-stream replay window (`security/replay_window.rs`) with 1024-bit
  bitmap, checked *after* AEAD verify per RFC 4303 §3.4.3 discipline.

### DoS Gate

A stateless cookie-over-HMAC-SHA-256 + optional proof-of-work gate sits
in front of the KEM computation on the server. The server issues a
`HelloRetryRequest` with a cookie and/or PoW challenge; a valid response in
the subsequent `ClientHello` bypasses the gate. Resuming clients with a
valid `ResumptionTicket` skip the cookie/PoW gate
(`transport/handshake.rs:369-379`).

### Transport Legs

The `SessionTransport` trait (`transport/session_transport.rs`) decouples
the session from the wire:

| Leg | File | Notes |
|-----|------|-------|
| TCP (length-prefixed) | `api/tcp_transport.rs` | Default; 4-byte BE length prefix |
| KCP-over-UDP | `transport/legs/kcp.rs` | Reliable UDP, non-wasm |
| FakeTLS-over-TCP | `transport/legs/faketls.rs` | DPI obfuscation; outer AEAD is public-seed only |
| WebSocket | `transport/legs/websocket.rs` | wasm32 only |
| EmbeddedLeg | `transport/legs/embedded/` | feature `embedded`; bare-metal `embedded-io-async` |

---

## Security Functional Requirements (SFR) Mapping

### FCS — Cryptographic Support

#### FCS_CKM: Cryptographic Key Management

| SFR | Title | Implementation | Status | Notes / Evidence |
|-----|-------|---------------|--------|-----------------|
| FCS_CKM.1.1 | Keygen — asymmetric (signing) | `crypto/hybrid_sign.rs:47-70` — `HybridSigningKey::generate` produces Ed25519 + ML-DSA-65 keypair via `OsRng`. `crypto/rng.rs:150` provides the `RngProvider` abstraction. | ✅ | Ed25519 (FIPS 186-5). ML-DSA-65 (FIPS 204). Both halves generated independently and stored in `HybridSigningKey`. |
| FCS_CKM.1.2 | Keygen — asymmetric (KEM / key establishment) | `crypto/hybrid_kem.rs:47` — ephemeral X25519 secret + ML-KEM-768 decapsulation key per handshake. | 🔄 | X25519 is not FIPS-approved. FIPS build (Phase 5.1) must replace with ECDH P-256. ML-KEM-768 is FIPS 203. |
| FCS_CKM.2.1 | Key establishment — hybrid KEM | `transport/handshake.rs` — `process_client_hello`: server encapsulates into client's ML-KEM-768 public key; X25519 DH runs in parallel; combined shared secret via HKDF (`kdf.rs`). | 🔄 | Both KEM legs must succeed. X25519 gap (see above). Evidence: `core/tests/security_invariants.rs:48` (`tampered_ciphertext_is_rejected`). |
| FCS_CKM.3.1 | Key distribution (server public key) | `api/listener.rs` — `PhantomListener::verifying_key_bytes()` exposes the public verifying key bytes for out-of-band distribution to clients. Private key never leaves the process. | ✅ | `key-management.md §1` documents the distribution responsibility. |
| FCS_CKM.4.1 | Key destruction / zeroization | `crypto/hybrid_sign.rs:39` — `#[derive(ZeroizeOnDrop)]` on `HybridSigningKey`. `transport/session.rs` — `CryptoState` zeroed on drop. `transport/handshake.rs` — client nonce + server master secret zeroed on drop. | ✅ | `key-management.md` §Storage classes table. All heap-resident secrets zeroed; ring `LessSafeKey` interior noted as partial (ring does not expose its interior for zeroize — documented gap). |

#### FCS_COP: Cryptographic Operations

| SFR | Title | Implementation | Status | Notes / Evidence |
|-----|-------|---------------|--------|-----------------|
| FCS_COP.1(1) | AES-256-GCM encryption | `crypto/adaptive_crypto.rs:11,38-63` — `CipherSuite::Aes256Gcm` uses `ring::aead::AES_256_GCM`. `AEAD_MAX_INVOCATIONS = 2^48` enforced at line 33 (`NonceExhausted` error). | ✅ | Hardware-accelerated via AES-NI / ARMv8 crypto. Nonce exhaustion guard satisfies NIST SP 800-38D §8.3. |
| FCS_COP.1(2) | ChaCha20-Poly1305 encryption | `crypto/adaptive_crypto.rs:41-55` — `CipherSuite::ChaCha20Poly1305` via `ring`. Available as software fallback on platforms without AES-NI. | 🔄 | Not FIPS-approved. Must be removed from `fips` feature build (Phase 5.1). Remains in non-FIPS builds as OE-policy choice. |
| FCS_COP.1(3) | SHA-256 hashing | Transitively via `hkdf`, `hmac` crates (both backed by `sha2`). Used in HKDF-SHA-256, HMAC-SHA-256 cookie derivation (`transport/handshake.rs:1163-1200`), session-ID derivation (`handshake.rs:1035`). | ✅ | FIPS 180-4. |
| FCS_COP.1(4) | HMAC-SHA-256 (integrity / cookie) | `transport/handshake.rs:1149-1200` — per-bucket HMAC over client IP + port. Constant-time comparison in `cookie_pow_gate` (class A, `constant-time-audit.md §Cookie validation`). | ✅ | FIPS 198-1. Negative evidence: `security_invariants.rs:207` (`cookie_tampering_yields_retry_not_success`). |
| FCS_COP.1(5) | HKDF-SHA-256 (key derivation) | `crypto/kdf.rs` — `derive_early_data_keying`, session-key label `"phantom-traffic-v1"`, rekey label `"phantom-rekey-v1"`, cookie/PoW bucket derivation (`handshake.rs:1135-1200`). | ✅ | NIST SP 800-56C. KDF labels documented in `docs/protocol/PROTOCOL.md §4`. CAVP vectors: `core/tests/cavp.rs`. |
| FCS_COP.1(6) | ML-KEM-768 encap / decap | `crypto/hybrid_kem.rs` — `ml-kem` crate (RustCrypto, pure-Rust, FIPS 203). Both encapsulate and decapsulate exercised per handshake. | ✅ | FIPS 203. CAVP vectors: `core/tests/cavp.rs`. |
| FCS_COP.1(7) | ML-DSA-65 sign / verify | `crypto/hybrid_sign.rs:100-155` — `HybridSigningKey::sign` + `HybridVerifyingKey::verify`. Both halves must succeed; one-failure-is-failure policy enforced at `hybrid_sign.rs:145`. | ✅ | FIPS 204. Negative: `security_invariants.rs:146` (`server_identity_mismatch_aborts_handshake`). |
| FCS_COP.1(8) | Ed25519 sign / verify | `crypto/hybrid_sign.rs:100-155` — `ed25519-dalek` with FIPS 186-5 EdDSA. Paired with ML-DSA-65 in every hybrid operation. | ✅ | FIPS 186-5. |

#### FCS_RBG: Random Bit Generation

| SFR | Title | Implementation | Status | Notes / Evidence |
|-----|-------|---------------|--------|-----------------|
| FCS_RBG_EXT.1.1 | DRBG seeding and operation | `crypto/rng.rs:126-160` — `RngProvider` trait; default `OsRng` delegates to `getrandom` (Linux: `getrandom(2)`, macOS: `getentropy(2)`, Windows: `BCryptGenRandom`, browser: `window.crypto.getRandomValues`). | 🔄 | OS-provided CSPRNG satisfies intent but is not a formally validated SP 800-90A DRBG. FIPS build (Phase 5.3) must substitute `aws-lc-rs::rand::SystemRandom` (AES-CTR DRBG). `rng-audit.md` §Backends per target has per-platform detail. |
| FCS_RBG_EXT.1.2 | DRBG use for key material | All cryptographic key generation sites use `OsRng` or a `getrandom` direct call. Call site inventory: `rng-audit.md §RNG call sites`. | ✅ | Non-cryptographic entropy (test jitter, `test_harness/mod.rs:131`) is explicitly separated. |

#### FCS_TLSC / FCS_IPSEC: Protocol equivalence

| SFR | Title | Implementation | Status | Notes / Evidence |
|-----|-------|---------------|--------|-----------------|
| FCS_TLSC_EXT.1 | TLS Client | Phantom does not implement TLS. It implements its own post-quantum session protocol. | N/A | The Phantom protocol is the trusted channel (see `FTP_DIT.1` below). Evaluators should treat §3 of `docs/protocol/PROTOCOL.md` as the protocol specification in lieu of a TLS profile claim. The `legs/faketls.rs` leg presents a TLS 1.3 ClientHello to deep-packet inspection but the *inner* session is Phantom, not TLS. |
| FCS_HTTPS_EXT.1 | HTTPS for management | Phantom does not expose an HTTPS management interface. The WebSocket leg (`legs/websocket.rs`) carries the Phantom session; it is not an independent HTTPS service. | N/A | `docs/protocol/PROTOCOL.md §11` and `docs/operations/wasm.md` describe the WebSocket transport. Metrics exposition (`transport/metrics.rs:369` `to_prometheus_text()`) is a library function — the embedder mounts it on an HTTP server. The HTTP server is OE. |
| FCS_STO_EXT.1 | Key storage | `key-management.md §Storage at rest`: Phantom Core does not persist any key material. All key bytes exist only in process memory. Long-term server signing key (`HybridSigningKey`) is heap-resident; ephemeral KEM keys are dropped after handshake. | 🔄 | Platform key-store integration (iOS Keychain, Android Keystore) is OE responsibility. A future `SigningKeyBackend` trait is planned but not on the current roadmap. Evaluators must confirm the embedder's key-storage posture. |

---

### FTP — Trusted Path / Channels

| SFR | Title | Implementation | Status | Notes / Evidence |
|-----|-------|---------------|--------|-----------------|
| FTP_ITC.1.1 | Trusted channel between the TOE and remote endpoints | The Phantom session protocol is the trusted channel. After handshake, every application-data packet is AEAD-encrypted (`api/session.rs:906` — `PacketFlags::ENCRYPTED` set unconditionally). Unencrypted application-data packets are dropped on receipt (`api/session.rs:1141-1150`). | ✅ | Security invariant 2 (`SECURITY.md` / `docs/security/threat-model.md`). Negative: `security_invariants.rs:48` (`tampered_ciphertext_is_rejected`), `security_invariants.rs:76` (`tampered_header_is_rejected_via_aad`). |
| FTP_ITC.1.2 | Channel initiation | Clients always initiate via `PhantomSession::connect_with_transport`. Server identity pinning is mandatory: `expected_server_key: HybridVerifyingKey` is a required parameter (`api/session.rs:182`). The handshake passes `Some(&expected_server_key)` to `process_server_hello` — never `None`. | ✅ | Security invariant 1 (`SECURITY.md` / `docs/security/threat-model.md`). Negative: `security_invariants.rs:146` (`server_identity_mismatch_aborts_handshake`). |

---

### FPT — Protection of the TSF

| SFR | Title | Implementation | Status | Notes / Evidence |
|-----|-------|---------------|--------|-----------------|
| FPT_SKP_EXT.1.1 | Protection of TSF data in transit | AEAD on every packet (FTP_ITC.1.1 above). No raw key bytes cross the `SessionTransport` interface after handshake. | ✅ | `api/session.rs:906-912` — encrypt path. `api/session.rs:1141` — decrypt path with flag check. |
| FPT_SKP_EXT.1.2 | Protection of TSF data at rest | Key material is not persisted (see FCS_STO_EXT.1). Zeroize-on-drop on all in-memory secrets. | 🔄 | Partial — ring `LessSafeKey` interior is opaque, input bytes are zeroed but ring does not guarantee interior zeroization. Documented in `key-management.md §Storage classes table`. |
| FPT_TST_EXT.1.1 | TSF self-test | CAVP-style known-answer tests are implemented for all approved primitives: `core/tests/cavp.rs`. Power-on self-tests (POST) are planned in Phase 5.5 at `core/src/crypto/self_tests.rs`. | 🔄 | KAT vectors present and always-on in CI. Formal POST invoked-at-startup mechanism not yet implemented. `self-tests.md` has the Phase 5.5 plan. |
| FPT_AEX_EXT.1 | Anti-exploitation features | `#![deny(unsafe_code)]` at crate root (`core/src/lib.rs:38`). Single remaining `unsafe` opt-in: `transport/udp_transport.rs` (libc GSO / `recvmmsg`). MSRV 1.75 enforced in CI. Fuzz harnesses: `fuzz/` (five targets). | ✅ | Unsafe discipline enforced at `core/src/lib.rs:38` (`#![deny(unsafe_code)]`); contributor lint policy in `CONTRIBUTING.md`. |

---

### FIA — Identification and Authentication

| SFR | Title | Implementation | Status | Notes / Evidence |
|-----|-------|---------------|--------|-----------------|
| FIA_X509_EXT.1 | X.509 certificate validation | Phantom does not use X.509. Server authentication is via pinned `HybridVerifyingKey` (hybrid Ed25519 + ML-DSA-65). | N/A | The evaluator should document this as a protocol deviation and reference `docs/protocol/PROTOCOL.md §5` (Server Authentication). The pinned-key model provides equivalent MITM resistance without a PKI. |
| FIA_SASL_EXT.1 | Authentication during initial connection | The handshake provides mutual authentication: the server signs the transcript with `HybridSigningKey`; the client verifies against the pinned key. The client's freshness is established via the handshake nonce (`handshake.rs:437`). | ✅ | `transport/handshake.rs:860-930` (`process_server_hello`). Negative: `security_invariants.rs:146`. |

---

### FDP — User Data Protection

| SFR | Title | Implementation | Status | Notes / Evidence |
|-----|-------|---------------|--------|-----------------|
| FDP_RIP.1 | Residual information protection | `CryptoState` zeroized on drop. Per-handshake KEM ephemeral keys consumed and dropped after `process_server_hello` (`key-management.md §2`). Session traffic secret zeroed on rekey via `ArcSwap` drop of old `Arc<CryptoState>`. | ✅ | `key-management.md §Storage classes table`. |
| FDP_IFC.1 | Subset information flow control | Replay protection: `security/replay_window.rs` + `security/replay_protection.rs` — per-stream sliding-window bitmap per RFC 4303 §3.4.3. Check occurs *after* AEAD verify (`transport/session.rs:377`). | ✅ | Security invariant 4 (`SECURITY.md` / `docs/security/threat-model.md`). Negative: `security_invariants.rs:267` (`replay_window_rejects_duplicate_sequence`), `security_invariants.rs:407` (`v2_replay_window_rejects_duplicate_sequence`). |

---

### FMT — Security Management

The PP App v1.4 includes lightweight FMT requirements for application
configuration and security-relevant parameters. Phantom's relevant surface:

| SFR | Title | Implementation | Status | Notes |
|-----|-------|---------------|--------|-------|
| FMT_CFG_EXT.1.1 | Secure default configuration | Default features `["compression-zstd", "std"]` enable all security mechanisms. No insecure mode is on-by-default. Listener-side: `PhantomListener::bind()` generates a fresh `HybridSigningKey` automatically. | ✅ | No configuration knob disables AEAD or signature verification in the public API. |
| FMT_MEC_EXT.1.1 | Supported configuration mechanism | Configuration is code-level (`PhantomConfig` struct, `api/config.rs`). No file-based config parser; attack surface is minimal. | ✅ | `PhantomConfig` documented via UniFFI surface. |

---

### FPR — Privacy

The PP VPN Client module adds a lightweight privacy requirement covering
the client's IP address protection. Phantom's position:

| SFR | Title | Implementation | Status | Notes |
|-----|-------|---------------|--------|-------|
| FPR_ANO_EXT.1 | IP address anonymisation | Phantom encrypts all application-layer payloads but does not anonymise the transport IP header. IP anonymisation (VPN tunnel) is the embedder's responsibility. | N/A | The library provides the authenticated encrypted channel; the routing overlay is OE. Evaluators should document this boundary clearly in the ST. |

---

## Security Assurance Requirements (SAR) Mapping

| SAR | Title | Phantom Core Evidence |
|-----|-------|-----------------------|
| SAR | Title | Evidence Document(s) | Gap / Note |
|-----|-------|---------------------|------------|
| ADV_ARC.1 | Architectural Design | `docs/architecture/ARCHITECTURE.md` — layer overview, module dep map, concurrency topology, encryption boundary, wire framing, error propagation. | None. |
| ADV_FSP.1 | Functional Specification | `core/src/api/` public surface (`session.rs`, `listener.rs`, `tcp_transport.rs`). UniFFI-generated bindings under `tests/bindings/`. `docs/architecture/ARCHITECTURE.md`. | Formal FSP document (separate from ARCHITECTURE.md) is not yet written. Will be required by the lab. |
| ADV_TDS.1 | TOE Design | `docs/architecture/ARCHITECTURE.md §2-6` (layer descriptions). Source files are the authoritative design artifact. | A structured design document per CC Part 3 ADV_TDS.1 evidence requirements must be produced for the lab. |
| AGD_OPE.1 | Operational User Guidance | `docs/operations/deployment.md`, `docs/operations/kubernetes.md`, `docs/operations/mobile.md`, `docs/operations/wasm.md`, `docs/operations/docker.md`, `docs/operations/systemd.md`. | Helm chart at `docs/operations/helm/`. Grafana / Prometheus dashboards at `docs/observability/grafana/` and `docs/observability/prometheus/`. |
| AGD_PRE.1 | Preparative Procedures | `docs/operations/deployment.md` — installation, configuration, network prerequisites. `docs/operations/perf-tuning.md` — tuning and validation steps. | Ensure the preparative guide is self-contained for the evaluated configuration (`std` build, default features). |
| ALC_DVS.1 | Identification of Security Measures in the Development Environment | `docs/security/incident-response.md` — triage timeline, severity buckets, embargo / disclosure flow. `.github/workflows/` — CI gates enforced on every PR. | Lab will want a written development-security policy; `incident-response.md` covers the incident side but not the development-process side. |
| ALC_CMC.1 | CM Capabilities | Git commit history on `main`. SLSA-3 build provenance: `.github/workflows/release.yml:122-123` (`actions/attest-build-provenance@v2`). Verify: `gh attestation verify --owner <org> <artifact>` or `cosign verify-blob-attestation`. | SLSA-3 attestation (Phase 7.4, commit `fb89465`) is strong supply-chain evidence. |
| ALC_CMS.1 | CM Scope | All source files under `core/` tracked in git. `cargo deny check` (`deny.toml`) enforces license and yanked-crate policy on every CI run. | Dependency version pinning via `Cargo.lock`. |
| ATE_FUN.1 | Functional Testing | `core/tests/security_invariants.rs` — 20 formal negative-security tests (always-on, not `#[ignore]`). `core/tests/property.rs` — proptest harness (AEAD round-trip, AAD-mismatch, replay window). `core/tests/cavp.rs` — 5 CAVP-style KAT vectors. `core/tests/tcp_integration.rs` + `kcp_integration.rs` — loopback end-to-end (run with `-- --ignored`). | Lab will execute the test suite independently. The 20 security invariant tests are the primary ATE_FUN evidence. |
| ATE_COV.1 | Analysis of Coverage | `cargo llvm-cov` with branch coverage (`--lcov --output-path lcov.info`). Coverage workflow: `.github/workflows/coverage.yml`. | Coverage percentage and specific branch coverage for security-critical paths (crypto/, security/) should be documented in the ST. |
| ATE_IND.1 | Independent Testing — Conformance | The lab will independently run `cargo test --manifest-path core/Cargo.toml --test security_invariants` and the property tests. The CAVP vectors in `core/tests/cavp.rs` are independently verifiable against NIST-published vectors. | None beyond providing the source and build instructions. |
| AVA_VAN.1 | Vulnerability Survey | `docs/security/threat-model.md` — STRIDE + LINDDUN analysis, trust-boundary diagram, mitigation-to-file:line traceability. Five libfuzzer fuzz targets in `fuzz/` (four need nightly: `fuzz_aead_decrypt`, `fuzz_client_hello`, `fuzz_packet_parse`, `fuzz_server_hello`; one stable: `fuzz_embedded_framing`). | No public CVE history to date. Lab will conduct independent vulnerability analysis. |
| AVA_VAN.3 | Focused Vulnerability Analysis (EAL3+) | `docs/security/panic-sites.md` — 6 remaining production panic sites with adversarial review checklist. `docs/security/cancel-safety-audit.md` — every `tokio::select!` classified. `docs/compliance/constant-time-audit.md` — every secret comparison. | Required only if evaluation targets EAL3+. Not needed for EAL2. |

---

## Gaps and Remediation

| # | SFR | Gap | Proposed Remediation | Phase |
|---|-----|-----|---------------------|-------|
### Cryptographic Primitive Gaps

| # | SFR | Gap | Proposed Remediation | Phase |
|---|-----|-----|---------------------|-------|
| G-1 | FCS_CKM.1.2 | X25519 classical KEM leg is not FIPS-approved. No FIPS KEM uses X25519. | `fips` feature: replace with ECDH P-256 (sub-option `fips-hybrid`) or drop the classical leg and rely on ML-KEM-768 alone. See `fips-readiness.md §2`. | 5.1 |
| G-2 | FCS_COP.1(2) | ChaCha20-Poly1305 is not FIPS-approved. Currently in `CipherSuite` as a hardware-fallback cipher. | Remove from `CipherSuite` enum when `--features fips` is active. Reference: `crypto/adaptive_crypto.rs:41-55`. | 5.1 |
| G-3 | FCS_CKM.2.1 | Combined KEM shared-secret derivation uses X25519 in both legs. Wire-incompatible change when X25519 is removed. | Coordinate with a deliberate `WIRE_VERSION` / `PROTOCOL_VERSION` bump; the build-side `PROTOCOL_VARIANT` tag already isolates fips ↔ non-fips peers at the handshake. `fips-readiness.md §7`. | 5.1 |

### RNG / DRBG Gaps

| # | SFR | Gap | Proposed Remediation | Phase |
|---|-----|-----|---------------------|-------|
| G-4 | FCS_RBG_EXT.1.1 | `OsRng` / `getrandom` is not a formally validated SP 800-90A DRBG. OS-provided CSPRNGs satisfy the security property but are outside the FIPS module boundary. | Swap `OsRng` → `aws-lc-rs::rand::SystemRandom` under `fips` feature. `rng-audit.md §FIPS-mode requirements §1`. | 5.3 |
| G-5 | FCS_RBG_EXT.1.1 | `thread_rng()` fallback chain at `types.rs:27`, `faketls.rs:320`, `path.rs:225` — FIPS forbids entropy-downgrade fallbacks. | Gate all fallbacks behind `#[cfg(not(feature = "fips"))]`. `rng-audit.md §Fallback chain semantics`. | 5.3 |
| G-6 | FCS_RBG_EXT.1.1 | Embedded target (`thumbv7em-none-eabihf`) has no validated entropy source. `getrandom` is not available. | Downstream HAL must supply a hardware TRNG driver that implements `RngProvider` (`crypto/rng.rs:126`). `rng-audit.md §Embedded path`. | 5.3 / OE |

### Protocol Deviation Gaps (ST-Writing Tasks, No Code Change Required)

| # | SFR | Gap | Resolution |
|---|-----|-----|-----------|
| G-7 | FCS_TLSC_EXT.1 | Phantom is not TLS. The VPN Client PP assumes TLS for channel protection. | Document as an explicit protocol deviation in the Security Target. Reference `docs/protocol/PROTOCOL.md` as the authoritative spec. The evaluator must accept FTP_ITC.1 satisfaction via the Phantom protocol in lieu of TLS. NIAP has accepted custom protocols for equivalent trusted-channel claims in prior evaluations. |
| G-8 | FCS_HTTPS_EXT.1 | No HTTPS management plane. Metrics exposition (`transport/metrics.rs:369`) is a library function; the embedder provides the HTTP server. | ST must scope the metrics HTTP server as an OE responsibility. No code change. |
| G-9 | FIA_X509_EXT.1 | Phantom uses pinned hybrid public keys (`HybridVerifyingKey`), not X.509 PKI. | Not a code gap. Document the pinned-key model as the authentication mechanism in the ST (`transport/handshake.rs:866-930`). |
| G-10 | FPR_ANO_EXT.1 | Transport IP header is not anonymised. Routing overlay is OE. | Document OE obligation in ST. No code change. |

### Key Storage and Zeroization Gaps

| # | SFR | Gap | Proposed Remediation | Phase |
|---|-----|-----|---------------------|-------|
| G-11 | FCS_STO_EXT.1 | No built-in key-store integration. Platform key stores (Keychain, Keystore) are OE. | Optionally introduce a `SigningKeyBackend` trait for HSM / Keychain integration. Document OE obligation in ST. | Post-Phase-7 |
| G-12 | FPT_SKP_EXT.1.2 | `ring::LessSafeKey` does not expose interior bytes for zeroization. Input key bytes are zeroed; ring internals are not guaranteed to be. | Migrate to `aws-lc-rs` under `fips` feature — it provides a Rust-side clear path. Document as a known limitation in the interim. `key-management.md §Storage classes table`. | 5.1 |

### Self-Test Gap

| # | SFR | Gap | Proposed Remediation | Phase |
|---|-----|-----|---------------------|-------|
| G-13 | FPT_TST_EXT.1.1 | Power-on self-tests (POST) are not implemented. CAVP KAT vectors exist in `core/tests/cavp.rs` but are not invoked at module startup. | Implement `core/src/crypto/self_tests.rs::run_self_tests()` called on first `HandshakeServer::new()`. Abort-on-failure as required by FIPS 140-3. Plan in `self-tests.md`. | 5.5 |

---

## Submission Path

**Steps for a NIAP CC evaluation:**

1. **Register the TOE.** Contact NIAP CCEVS (`https://www.niap-ccevs.org`) to
   register the product and confirm the applicable PP list (VPN Client v2.5
   + App Software v1.4).

2. **Engage a CCEVS-accredited lab.** Labs include Booz Allen Hamilton (BAH
   Cyber), Leidos, Lightship Security, UL Transaction Security, and others
   listed at `https://www.niap-ccevs.org/Lab/`. Select a lab experienced
   with network / cryptographic products.

3. **Prepare the Evidence Package.**
   - Security Target (ST): expand this document into a formal ST per
     CC:2022 Part 2/3 requirements.
   - Developer Evidence: source tree + build instructions (`README.md`
     §Quick start + `CONTRIBUTING.md`), CI logs, SLSA-3 attestation artifacts.
   - Test Evidence: `core/tests/security_invariants.rs`, `core/tests/cavp.rs`,
     `core/tests/property.rs` outputs. The lab will likely run these
     independently.
   - Guidance Documents: `docs/operations/` suite (AGD evidence).

4. **Supply-chain evidence.** SLSA-3 provenance attestations are generated
   automatically on tag-triggered releases by `.github/workflows/release.yml`
   (commit `fb89465`, Phase 7.4). Attestation verifiable via:
   `gh attestation verify --owner <org> <artifact>` or
   `cosign verify-blob-attestation`. Submit attestation artifacts alongside
   the binary deliverable.

5. **Timeline.** End-to-end evaluation typically runs 6-12 months from lab
   engagement to NIAP validation decision. Resolving the gaps in §5
   (particularly G-1 through G-5) is a precondition for a successful
   evaluation. Budget gap remediation (Phase 5 work) before engaging a lab.

6. **Parallel FIPS track.** The CC evaluation and FIPS 140-3 CMVP submission
   share the Phase 5 `fips` feature prerequisites. Running them in parallel
   is possible; CMVP typically takes 6-12 months independently.
   Cost guidance: `docs/compliance/fips-readiness.md §6`.

---

## References

| Document | Version / ID | URL |
|----------|-------------|-----|
| PP-Module for VPN Client | v2.5, NIAP-CCEVS | `https://www.niap-ccevs.org/Profile/PP.cfm?PPID=408` |
| PP for Application Software | v1.4, NIAP-CCEVS | `https://www.niap-ccevs.org/Profile/PP.cfm?PPID=394` |
| FIPS 203 (ML-KEM) | Initial Public Draft / Final 2024 | `https://csrc.nist.gov/pubs/fips/203/final` |
| FIPS 204 (ML-DSA) | Initial Public Draft / Final 2024 | `https://csrc.nist.gov/pubs/fips/204/final` |
| FIPS 186-5 (EdDSA / Ed25519) | 2023 | `https://csrc.nist.gov/pubs/fips/186-5/final` |
| NIST SP 800-38D (AES-GCM) | 2007 | `https://csrc.nist.gov/pubs/sp/800/38/d/final` |
| NIST SP 800-90A Rev.1 (DRBG) | 2015 | `https://csrc.nist.gov/pubs/sp/800/90/a/r1/final` |
| RFC 4303 (ESP replay protection) | 2005 | `https://www.rfc-editor.org/rfc/rfc4303` |
| RFC 5869 (HKDF) | 2010 | `https://www.rfc-editor.org/rfc/rfc5869` |
| CC:2022 Part 2 (SFR catalogue) | 2022 | `https://www.commoncriteriaportal.org/cc/` |
| `docs/compliance/fips-readiness.md` | this repo | Primitive inventory, FIPS gap analysis |
| `docs/compliance/constant-time-audit.md` | this repo | Class A/B/C/D constant-time inventory |
| `docs/compliance/rng-audit.md` | this repo | Per-target RNG backend matrix |
| `docs/compliance/key-management.md` | this repo | Key lifecycle per keyed object |
| `docs/compliance/self-tests.md` | this repo | POST / PCT / CST plan (Phase 5.5) |
| `docs/compliance/fips-security-policy.md` | this repo | Draft CMVP security policy |
| `docs/security/threat-model.md` | this repo | STRIDE + LINDDUN, AVA_VAN evidence |
| `docs/protocol/PROTOCOL.md` | this repo | Wire format, handshake state machine |
