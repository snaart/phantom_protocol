# Security Policy

## Reporting a Vulnerability

Please report security vulnerabilities **privately** before disclosing them
publicly. Do not file public GitHub issues for security problems.

- **Email:** ceo@snaart.com
- **Embargo SLA:** 90 days from initial report to public disclosure.
- For ongoing reports, expect an acknowledgement within 5 business days and
  a triage outcome within 14 business days.

Phantom Protocol uses GitHub Security Advisories for public CVE coordination.

## Supported versions

| Version | Status |
| --- | --- |
| `main` | Active development; security fixes land here first. |
| `0.1.x` | Latest pre-1.0 release; security fixes backported. |
| Earlier | Unsupported. |

## Threat model (summary)

Phantom Protocol is a post-quantum-secure L4/L6 transport. The full STRIDE / LINDDUN
analysis lives in `docs/security/threat-model.md`. **Target threat model: TLS-like
guarantees _plus_ resistance to traffic-analysis linkability (unobservability)** — header
protection is a core pre-1.0 requirement, not a deferred hardening. At a glance:

- **In scope:** authenticated key agreement; confidentiality and integrity of application
  data after handshake; downgrade resistance; DoS-resistance, including the
  pre-authentication PhantomUDP surface (a stateless address-validation cookie is required
  before any per-connection state, with bounded demux / reorder buffers and optional PoW);
  outer anti-DPI obfuscation on the FakeTLS leg; and **resistance to passive linkability of a
  connection across network changes** — the committed pre-1.0 mechanism is QUIC-style header
  protection (encrypting the packet number and the variable header fields) plus
  connection-ID rotation, landing in the next wire-format revision.
- **Currently a known gap (being closed):** the on-wire header is presently cleartext, so a
  passive observer can link a connection by its stable connection-ID and classify each
  packet's purpose. The transport is functional but **linkable** until header protection
  ships; see `docs/protocol/PROTOCOL.md` §12.5.
- **Out of scope:** non-repudiation; full traffic-shape unobservability (timing / size
  correlation — length-hiding padding is not yet wired); endpoint compromise; compromise of
  long-lived server signing keys; supply-chain attacks against the build toolchain.

## Cryptographic primitives

| Operation | Primitive | FIPS-approved? |
| --- | --- | --- |
| Classical KEM | X25519 | No (no FIPS-approved KEM that uses X25519) |
| Post-quantum KEM | ML-KEM-768 (`ml-kem` RustCrypto) | Yes (FIPS 203) |
| Classical signature | Ed25519 (`ed25519-dalek`) | Yes (FIPS 186-5) |
| Post-quantum signature | ML-DSA-65 (`ml-dsa` RustCrypto) | Yes (FIPS 204) |
| Symmetric AEAD | AES-256-GCM (`ring`) | Yes (when built against a FIPS-validated cryptographic module) |
| Symmetric AEAD (fallback) | ChaCha20-Poly1305 (`ring`) | No |
| Hash / KDF | HKDF-SHA-256, blake3 KDF | SHA-256 yes; blake3 no |

A FIPS-compliant build profile (`--features fips`) is on the roadmap.

## Security invariants

The implementation enforces (and integration tests verify) the following invariants:

1. **Server identity pinning.** `PhantomSession::connect_with_transport` requires
   the client to supply the expected `HybridVerifyingKey`. Mismatch aborts the
   handshake; never weakened to `Option<...>` without a corresponding caller-side
   enforcement.
2. **No raw user data after handshake.** Every application-data packet has
   `PacketFlags::ENCRYPTED` set and goes through `Session::encrypt_packet`.
   Non-empty unencrypted packets received post-handshake are dropped (stripped-flag
   downgrade defense).
3. **FakeTLS uses per-record counter nonces.** The outer obfuscation layer derives
   `send_key` / `recv_key` / `nonce_prefix` from a public seed
   (`SNI + version`) via `blake3::derive_key` with direction-specific labels, and
   increments a per-direction `u64` counter on each record (preventing the
   Forbidden Attack on AES-GCM).

Future edits must preserve these. See [`docs/security/threat-model.md`](docs/security/threat-model.md)
for the full STRIDE / LINDDUN analysis and per-mitigation file:line traceability.

## Disclosure timeline (template)

```
T+0   Vulnerability reported privately
T+5   Acknowledgement
T+14  Triage outcome (accepted / rejected / clarification needed)
T+30  Fix candidate available (depending on severity)
T+45  Coordinated release across affected branches
T+90  Public disclosure with CVE
```

Phantom Protocol honors longer embargoes for downstream coordination on request.
