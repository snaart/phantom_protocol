<!-- SPDX-License-Identifier: Apache-2.0 -->
# Mobile sample apps

Two runnable client sample apps that embed the `phantom_protocol` post-quantum
transport SDK through its UniFFI bindings:

- [`ios/`](ios/) — a SwiftUI app (SwiftPM package) consuming the Swift binding.
- [`android/`](android/) — a Jetpack Compose app (Gradle) consuming the Kotlin binding.

Both demonstrate the same client lifecycle against a running
[`phantom-server`](../../server/):

1. **Pinned connect** — `connectPinned(host, port, pinnedKey)` followed by
   `awaitReady()`. Server identity is pinned unconditionally (Security
   Invariant 1); there is no unpinned path. The second call is not optional:
   `connectPinned*` returns as soon as the socket is connected and runs the
   handshake — the pin check included — on a background task, so a wrong pinned
   key yields a session object whose `send()` succeeds. `awaitReady()` is where
   `ServerIdentityMismatch` is raised, and both samples call it before reporting
   a connection or reading any session state.
2. **0-RTT resumption** — harvest a `ResumptionHint` after the first connect, persist
   it to platform secure storage (iOS Keychain / Android `EncryptedSharedPreferences`),
   and reconnect via `connectPinnedWithResumption(...)`, folding the first request into
   the `ClientHello`. The hint crosses the FFI as an opaque object, so its two 32-byte
   fields are accessor calls (`sessionId()` / `resumptionSecret()`) and no generated
   stringifier can print the secret — the reason it is an object and not a record. On
   Kotlin that also makes each hint an `AutoCloseable` native handle the sample closes
   once it has been stored or used; ARC handles the same lifetime on Swift.
3. **Encrypted send/recv** — a chat UI over `session.send` / `session.recv`.
4. **Connection-state surfacing** — `connectionState()` polled lock-free, including the
   `Migrating` / `Dead` liveness states.
5. **Recovery on network change** — reconnect-with-0-RTT (see the migration note below).

## Not built in CI — verify locally

CI has **no Xcode, Android SDK/NDK, or running server**, so these apps are **not
compiled or run there**. Build and run them yourself; each app's `README.md` has the
exact steps:

- cross-compile the `core` library for the device ABIs,
- generate + drop in the UniFFI binding (Swift sources / Kotlin `.kt`),
- run a `phantom-server` and bake its pinned verifying key into the app bundle
  (via the [`phantom-cli`](../../cli/) `keygen` / `pubkey` subcommands),
- open in Xcode / Android Studio and run.

## Migration: these apps show TCP reconnect; the UDP path does seamless `migrate()`

`PhantomSession.migrate(localAddr)` performs a **real seamless single-socket
migration** (local-socket rebind + path validation, no re-handshake) — but **only on
a session built over the production PhantomUDP transport**, which **is** exposed
through the FFI surface as `connectPinnedUdp` (+ `…WithResumption` / `…WithConfig`;
server side `PhantomUdpListener.bindUdp`). On a **TCP** session (`connectPinned` /
`connectPinnedWithResumption`, `TcpSessionTransport`) `migrate()` returns
`Err(Unsupported)` — TCP is connection-oriented and cannot move its local endpoint
without a new connection, so migration is rejected rather than silently skipped.

These particular sample apps were built on the **TCP** path, so they demonstrate
**reconnect-with-0-RTT resumption** on a Wi-Fi ↔ cellular handover (the working
pattern for a TCP session). The `migrate()` demo button shows the error the TCP
transport now returns. **For seamless single-socket migration, build the client over
the UDP path (`connectPinnedUdp`) and call `migrate()` from the network-change
callback** — see `docs/operations/mobile.md`.

## See also

- [`docs/operations/mobile.md`](../../docs/operations/mobile.md) — the canonical mobile
  embedding guide (build flags, ATS / Network Security Config, background modes, secure
  storage, performance).
- [`tests/bindings/PACKAGING.md`](../../tests/bindings/PACKAGING.md) — how the Swift /
  Kotlin / Python / C packages are produced and published.
