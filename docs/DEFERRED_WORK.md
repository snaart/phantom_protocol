# Deferred work

This file is the single, honest record of capabilities that are **consciously
deferred**, current as of **0.3.1**. Each is either a multi-week sub-project, gated
on infrastructure outside the code tree, or limited by a platform API. None blocks a
release on its own; all are tracked here so the deferral is explicit rather than
implied by silence. Items 1–4 were first recorded against 0.2.0 and are still open;
item 5 was added in 0.3.1.

What the protocol does and does not defend against today is in
[`security/threat-model.md`](security/threat-model.md); the wire format is frozen
in [`protocol/PROTOCOL.md`](protocol/PROTOCOL.md).

| Item | Status | Gated on |
| --- | --- | --- |
| SLSA Build **L3** + hermetic / reproducible builds | signed provenance shipped at Build **L2** | a reusable build workflow, then an external build substrate |
| `no-std` PQ handshake (bare-metal) | framing-only ships | no-std crypto + runtime + QEMU test sub-project |
| WASI **server-side** session | client `WasiLeg` ships | data-pump timer refactor + accept loop |
| **ECN** congestion feedback | loss-feedback half shipped (#142) | ingress ECN readback + a wire field |
| Running the test suite off x86_64 Linux; Android in CI | 13 compile-gate rows, 4 prebuilt artifacts, tests on one platform | self-hosted or hosted runners per OS, an NDK pin, and a test surface that does not assume a Unix host |

---

## 1. SLSA Build L3, then hermetic / reproducible builds

**What ships today — signed provenance at Build L2.** `release.yml` produces a
sigstore-backed in-toto v1 SLSA build-provenance attestation for every release
tarball via `actions/attest-build-provenance`. The provenance names the workflow,
the commit and the runner, it is signed by a Sigstore identity nobody outside a run
of this repository's workflow can obtain, and it is verifiable by a consumer who has
only the tarball:

```bash
gh attestation verify --owner <org> phantom_protocol-<tag>-x86_64-unknown-linux-gnu.tar.gz
# or, without gh:
cosign verify-blob-attestation --bundle <bundle> <artifact>
```

Per GitHub's own documentation of the action, that posture is **SLSA v1.0 Build
Level 2** — provenance exists, it is authentic, and it is produced by a hosted
build service rather than asserted by the publisher. This file previously called it
Level 3 and called Level 3 the top of the track, and both statements were wrong; the
correction is recorded in `CHANGELOG.md`.

**Why L3 is not reached, concretely.** Build L3 requires the provenance signing
identity to be unavailable to the build steps it attests — on GitHub that means the
compile-and-attest sequence lives in a **reusable workflow** that is the sole holder
of that identity, so a change to a calling workflow cannot mint provenance for
something the trusted one did not build. Two properties of `release.yml` stand
between here and there:

- The attest step is **inline in `build-artifacts`**, the same job that runs
  `cargo build` and packages the tarball. The job holds `id-token: write` while
  arbitrary build scripts from the dependency graph are executing in it.
- That job restores a **`Swatinem/rust-cache`** keyed per target and shared with the
  rest of CI, so a build input can come from a cache another workflow wrote. L3's
  isolation requirement is about exactly this: one run must not be able to influence
  another's.

Neither is hard to fix and neither is a code change — it is a workflow refactor
(lift build + package + attest into `.github/workflows/build-artifact.yml`, call it
with `uses:`, and drop the cache restore from the release path so a release compiles
from source every time). It is listed here rather than done because a release
workflow is changed on a release, and this entry is the note that says which change.

**Why hermeticity stays deferred after that.** Beyond L3 — a **hermetic** build (all
inputs declared and fetched ahead of time, no network during the build) on an
isolated, reproducible build platform, with two-party review of every change to the
build definition — was the SLSA **v0.1** "Level 4" notion, retired in v1.0 and now
folded into the reproducible-builds and source/review tracks. GitHub-hosted runners
cannot *prove* that hermeticity and isolation without an external, dedicated build
substrate (a reproducible-builds pipeline on a controlled builder, or a hermetic
Bazel/Nix remote-exec environment). That substrate is an infrastructure procurement
decision, not a code change.

**What landing it would require.** A pinned, fully-vendored dependency set
(offline `cargo` with a vendored registry); a reproducible toolchain pin
(`rust-toolchain.toml` is in place); a hermetic builder (Nix flake or a Bazel
remote-execution worker) that the provenance can attest as isolated; and the
two-party-review control on the build definition. The code-side prerequisites
(pinned toolchain, `deny.toml`, signed build provenance) are already in place.

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
egress datagrams; (2) **read the received ECN codepoint on ingress** — enabling
the option is portable enough (`socket2` exposes `set_recv_tos_v4` /
`set_recv_tclass_v6` without `unsafe`), but reading the value the kernel then
attaches needs `recvmsg` control-message parsing, which the high-level
`tokio::net::UdpSocket` API does not surface at all, so it would be a **net-new**
`unsafe` libc `recvmsg`/cmsg path in `core/src/api/udp_transport.rs`, and is
platform-specific; (3) a **wire field to echo ECN counts** back to the peer
(AccECN-style), i.e. a `WIRE_VERSION` bump; and (4) a BBR reaction to CE marks.
Each of the ingress readback and the wire change is non-trivial; ECN is a
measurable but not load-bearing congestion refinement, so it is deferred rather
than half-built.

**The `unsafe` cost, stated exactly, because it is the largest of the four.**
There is no native `unsafe` in this crate to extend. The two surviving
`#![allow(unsafe_code)]` opt-ins — `transport/legs/websocket.rs` (wasm32-only
wasm-bindgen JS-boundary glue) and `transport/legs/wasi.rs` (WASI-only
`Send`/`Sync` assertions over WIT-bindgen socket handles) — are
cross-language-boundary code, so **no native build compiles any `unsafe` at
all**, and `core/Cargo.toml` names no `libc` dependency on any target (it is
present transitively, under `socket2` and the RNG stack, but nothing in
`core/src` calls it). An earlier version of this note assumed otherwise,
describing a
`setsockopt(SO_MAX_PACING_RATE)` egress-pacing call as the module's existing
`unsafe`; that call and the module holding it (`transport/udp_transport.rs`, a
`pub mod` with no caller anywhere) were both deleted, and the pacing it never
performed is done in userspace by `transport::pacer::Pacer` off the BBR
estimator. So the ingress path would be the crate's *first* native `unsafe`
block, re-opening `#![deny(unsafe_code)]` on the platform every production
deployment runs on, and it would put `libc` back in `core/Cargo.toml` as a
direct, called dependency. That raises the bar for landing ECN; it does not
lower it.

**What landing it would require.** Egress codepoint marking, which needs no
`unsafe` (`socket2::Socket::set_tos_v4` / `set_tclass_v6` — the locked socket2
0.6 spells these per address family; the older single `set_tos` is gone); the
net-new ingress cmsg readback path above, whose `// SAFETY:` discipline has to be
established for it rather than inherited from a native precedent that does not
exist; an AccECN-style ECN-count echo field and the matching `WIRE_VERSION` bump
+ wire vectors; and a congestion-controller response to CE marks with a
loss-equivalent backoff. It composes cleanly with the loss-feedback work already
shipped in #142.

---

## 5. Test execution and artifacts beyond x86_64 Linux (and Android in CI at all)

**What ships today.** `cross.yml` holds thirteen hard-gated rows over twelve
targets, with no `allow_failure` row anywhere, and a row is `cargo check --lib` —
it proves the crate compiles for that target and nothing more.
(`x86_64-unknown-linux-gnu` is the row that appears twice, once with the default
features and once with the ring-free `fips` set.) Four targets ship a prebuilt release
tarball from `release.yml`'s `build-artifacts` job:
`x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`, `x86_64-apple-darwin`,
`aarch64-apple-darwin`. Test code executes in exactly three places:

- **x86_64 Linux** — every job in `ci.yml`: `--lib`, `security_invariants`,
  `property`, the frozen wire vectors, the KATs, the TCP and PhantomUDP loopback
  suites, and the `embedded` / `mimicry` / `telemetry-otel` / `fips` feature jobs.
- **aarch64 macOS** — one test, `bindings.yml`'s `swift` job: a pinned loopback
  round-trip through the generated Swift binding on `macos-latest`. The `drift`
  job also runs there, which regenerates the bindings but executes none of them.
- **wasm32-wasip2 under `wasmtime`** — the guest fixture's two round-trips, run by
  `cross.yml`'s `wasi-integration` job on a Linux host.

**What that leaves.** No unit test and no loopback integration test has ever run
on Windows, iOS, musl, `wasm32-unknown-unknown` or `thumbv7em-none-eabihf`. The
two Windows rows do run on a real `windows-latest` runner, so the claim is about
execution and not about the runner: the crate is compiled there and nothing is
exercised there, and there is no Windows artifact either. The `embedded` feature's
own tests run on the x86_64 Linux host — pure-Rust and target-agnostic by design,
which is why they can, and which is also why passing them says nothing about a
device.

**Android is the widest gap, and the tree does not look like it.** A grep for
"android" across all eight workflow files returns nothing.
`tests/bindings/kotlin/build-jnilibs.sh` cross-builds three ABIs
(`aarch64-linux-android`, `armv7-linux-androideabi`, `x86_64-linux-android`)
against an NDK whose version this repository does not pin, and
`../examples/mobile/android/` is a complete Jetpack Compose application. Both are
hand-run recipes. The Kotlin binding is generated and **type-checked** on Linux —
`tests/bindings/kotlin/run_kotlin_test.sh` says so in its header — and never
executed on any platform, Android included.

**Why it is deferred rather than pending.** Each of the three is a distinct piece
of infrastructure, and the cost is per platform rather than one-off:

- **Windows and macOS test jobs** are the cheapest: `windows-latest` and
  `macos-latest` runners already carry the toolchain, so the work is adding a
  `cargo test` job per OS and then fixing what it finds. The suite has never been
  run on a non-Unix host, so the first honest estimate of that second part is
  "unknown" — path handling, socket options and the loopback suites' timing
  assumptions are all places where a Unix assumption could be baked in, and each
  would have to be found and fixed before the job could be a required context.
- **iOS and Android** need a device or an emulator in CI, which means either a
  hosted macOS runner driving a simulator or a self-hosted device farm, plus an
  NDK pin and a build of the Gradle sample. Android additionally needs the Kotlin
  harness turned from a compile check into something that runs.
- **A prebuilt artifact per target** is a matrix row in `build-artifacts` plus the
  install-name / symbol-table handling that row already needs (see § 1 and
  `../CHANGELOG.md` for the 0.3.1 fixes to both), a Windows `.dll` import-library
  question, and a per-target entry in the release's own artifact shape check.

**What would close it.** In the order that buys the most per row: a
`cargo test --lib` + loopback job on `windows-latest` and one on `macos-latest`,
made required contexts on `main`; then an Android job that builds the three ABIs
against a pinned NDK and runs the Kotlin harness under an emulator; then the
artifact matrix. Until then the honest statement is the one in
`../README.md` under "Platform support", and an adopter outside the four artifact
targets should plan to build the crate and run its suite themselves.

---

## See also

- [`security/threat-model.md`](security/threat-model.md) — what the protocol does
  and does not defend against today.
- [`protocol/PROTOCOL.md`](protocol/PROTOCOL.md) — the canonical wire spec
  (a `WIRE_VERSION` bump is named above as a prerequisite for ECN).
- [`../CHANGELOG.md`](../CHANGELOG.md) — shipped changes, including #142 (the
  loss-feedback half of the ECN item).
- [`../.github/workflows/release.yml`](../.github/workflows/release.yml) — the
  build-provenance pipeline referenced in §1, including the inline attest step and
  the shared cache restore that hold it at Build L2.
- [`../.github/workflows/cross.yml`](../.github/workflows/cross.yml) — the
  thirteen-row compile matrix §5 is about, and the one job in it that executes
  anything (`wasi-integration`).
- [`known-deviations.md`](known-deviations.md) — behaviour that is deliberate and
  has still surprised a consumer, including the platform-coverage entry.
