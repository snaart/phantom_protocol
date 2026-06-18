# Deferred work — post-0.2.0

This file is the single, honest record of capabilities that are **consciously
deferred past the 0.2.0 release**. Each is either a multi-week sub-project, gated
on infrastructure outside the code tree, or limited by a platform API. None is a
0.2.0 blocker; all are tracked here so the deferral is explicit rather than
implied by silence.

What the protocol does and does not defend against today is in
[`security/threat-model.md`](security/threat-model.md); the wire format is frozen
in [`protocol/PROTOCOL.md`](protocol/PROTOCOL.md).

| Item | Status | Gated on |
| --- | --- | --- |
| Hermetic / reproducible builds (former SLSA v0.1 "L4") | SLSA v1.0 Build **L3** shipped (track top) | external build substrate |
| `no-std` PQ handshake (bare-metal) | framing-only ships | no-std crypto + runtime + QEMU test sub-project |
| WASI **server-side** session | client `WasiLeg` ships | data-pump timer refactor + accept loop |
| **ECN** congestion feedback | loss-feedback half shipped (#142) | ingress ECN readback + a wire field |

---

## 1. Hermetic / reproducible builds (former SLSA v0.1 "L4")

**What ships today (L3 — the top of the SLSA v1.0 build track).** `release.yml`
produces a sigstore-backed in-toto v1 SLSA build-provenance attestation via
`actions/attest-build-provenance` (Phase 7.4). That gives non-falsifiable
provenance tying each release artifact to the workflow, commit, and runner that
built it — **SLSA Build Level 3**, on isolated GitHub-hosted ephemeral runners.
SLSA **v1.0 has no Build L4**; L3 is the highest build level defined, so the
provenance posture is already at the top of the current spec. Verify with
`gh attestation verify --owner <org> <artifact>` or
`cosign verify-blob-attestation`.

**Why the next step is deferred.** The capability beyond L3 — a **hermetic** build
(all inputs declared and fetched ahead of time, no network during the build) on an
isolated, reproducible build platform, with two-party review of every change to
the build definition — was the SLSA **v0.1** "Level 4" notion (retired in v1.0,
now folded into reproducible-builds + source/review tracks). GitHub-hosted runners
cannot *prove* that hermeticity and isolation without an external, dedicated build
substrate (a reproducible-builds pipeline on a controlled builder, or a hermetic
Bazel/Nix remote-exec environment). That substrate is an infrastructure
procurement decision, not a code change.

**What landing it would require.** A pinned, fully-vendored dependency set
(offline `cargo` with a vendored registry); a reproducible toolchain pin
(`rust-toolchain.toml` is in place); a hermetic builder (Nix flake or a Bazel
remote-execution worker) that the provenance can attest as isolated; and the
two-party-review control on the build definition. The code-side prerequisites
(pinned toolchain, `deny.toml`, SLSA-3 provenance) are already in place.

## 2. `no-std` post-quantum handshake on bare metal

**What ships today (framing-only).** The `thumbv7em-none-eabihf` target is a hard
CI gate (`cargo check --lib` under `--no-default-features --features
embedded,no-std`). It compiles the `EmbeddedLeg` framing transport over
`embedded-io-async` — but the PQ handshake, `PhantomSession`, and the crypto core
are `std`-gated **out** on that target. The embedded story today is
"framing-only, bring-your-own-crypto."

**Why a full no-std handshake is deferred.** Running the real hybrid handshake on
bare metal is a multi-week sub-project, not a flag flip: the `ml-kem` / `ml-dsa`
crates and the handshake path allocate and assume an async runtime; a bare-metal
deployment needs a no-std-clean crypto path (static buffers or a vetted
`alloc`-on-MCU allocator), a real embedded executor (Embassy / RTIC) implementing
the `Runtime` trait rather than the `std::thread`-based `EmbeddedRuntime` scaffold,
and a QEMU- or device-hosted integration test to gate it. Each is independently
substantial.

**What landing it would require.** Promote `crypto/kdf.rs`, `security/*`, and the
handshake state machine out of the `std`-gated region module-by-module (the gating
infrastructure already supports this); supply a no-std entropy source via the
existing `RngProvider` seam; ship an `EmbassyRuntime`/`RticRuntime` `Runtime` impl;
and add a QEMU-hosted `thumbv7em` test that drives a full session (the current gate
only proves the framing transport compiles).

## 3. WASI Preview 2 server-side session

**What ships today (client only).** The `wasi-leg` feature ships a client-side
`WasiLeg` (length-prefixed TCP over `wasi:sockets/tcp`) plus a single-task
`WasiRuntime`, gated by the `wasm32-wasip2` hard-CI target and exercised by
`wasi_integration.rs` under Wasmtime. That test round-trips raw bytes through a
TCP echo; it does **not** run a full `PhantomSession` on WASI even client-side.

**Why server-side (and full-session) WASI is deferred.** The shipped data pump
(`run_data_pump`, `core/src/api/session.rs`) drives its timers with
`tokio::time::interval(10ms)` and `tokio::time::sleep` (pacer / jitter) **directly**.
Those panic without a Tokio runtime, and Tokio's time driver is unsupported on
`wasm32-wasip2` — the `WasiRuntime` is a bespoke single-task executor with no Tokio
time driver. So no `PhantomSession` (client or server) can run on WASI until the
pump is refactored. Server-side additionally needs a `WasiLeg` `listen`/`accept`
and a WASI accept loop, neither of which exists.

**What landing it would require.** (1) Refactor the pump's `tokio::time::*` calls to
`Runtime::sleep` (behavior-preserving on native, since `TokioRuntime::sleep`
delegates to `tokio::time`, but it touches the core data plane and is a
touch-with-care change); (2) `WasiLeg` `listen`/`accept`; (3) a WASI accept loop;
(4) the full PQ handshake + pump validated on the single-task `WasiRuntime`; (5)
extend the `wasi-guest` fixture to a full client+server round-trip. Multi-PR
sub-project with integration unknowns comparable to the no-std handshake. The
pump-timer refactor (step 1) is a clean prerequisite if this is revived.

## 4. ECN congestion feedback over UDP

**What ships today (the loss-feedback half).** The retransmit-timer loss-feedback
refinement landed in #142: BBR's loss signal is now fed **exactly once per loss
event, at the retransmission point**, covering both SACK-gap fast-retransmits and
RTO-timeout retransmits. That was the actionable, in-tree half of the original #7
("ECN + retransmit-timer loss-feedback").

**Why ECN itself is deferred.** A working ECN congestion-feedback loop is a
multi-part feature, not a socket flag: (1) mark the ECT(0)/ECT(1) codepoint on
egress datagrams; (2) **read the received ECN codepoint on ingress** — which needs
`IP_RECVTOS` / `IPV6_RECVTCLASS` and `recvmsg` control-message parsing that the
high-level `tokio::net::UdpSocket` API does not surface, so it would be a
**net-new** `unsafe` libc `recvmsg`/cmsg path in `udp_transport.rs` (the module's
only current `unsafe` is a `setsockopt(SO_MAX_PACING_RATE)` call for egress pacing —
there is no ingress cmsg path today), and is platform-specific; (3) a **wire field
to echo ECN counts** back to the peer (AccECN-style), i.e. a `WIRE_VERSION` bump;
and (4) a BBR reaction to CE marks. Each of the ingress readback and the wire
change is non-trivial; ECN is a measurable but not load-bearing congestion
refinement, so it is deferred rather than half-built.

**What landing it would require.** Egress codepoint marking (feasible via
`socket2::Socket::set_tos`); a **net-new** ingress cmsg readback path (a new
`unsafe` `recvmsg` block under the same `// SAFETY:` discipline — there is no
existing ingress path to extend); an AccECN-style ECN-count echo field and the
matching `WIRE_VERSION` bump + wire vectors; and a congestion-controller response
to CE marks with a loss-equivalent backoff. It composes cleanly with the
loss-feedback work already shipped in #142.

---

## See also

- [`security/threat-model.md`](security/threat-model.md) — what the protocol does
  and does not defend against today.
- [`protocol/PROTOCOL.md`](protocol/PROTOCOL.md) — the canonical wire spec
  (a `WIRE_VERSION` bump is named above as a prerequisite for ECN).
- [`../CHANGELOG.md`](../CHANGELOG.md) — shipped changes, including #142 (the
  loss-feedback half of the ECN item).
- [`../.github/workflows/release.yml`](../.github/workflows/release.yml) — the SLSA
  build-provenance pipeline referenced in §1.
