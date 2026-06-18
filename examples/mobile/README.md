<!-- SPDX-License-Identifier: Apache-2.0 -->
# Mobile sample apps

Two runnable client sample apps that embed the `phantom_protocol` post-quantum
transport SDK through its UniFFI bindings:

- [`ios/`](ios/) — a SwiftUI app (SwiftPM package) consuming the Swift binding.
- [`android/`](android/) — a Jetpack Compose app (Gradle) consuming the Kotlin binding.

Both demonstrate the same client lifecycle against a running
[`phantom-server`](../../server/):

1. **Pinned connect** — `connectPinned(host, port, pinnedKey)`. Server identity is
   pinned unconditionally (Security Invariant 1); there is no unpinned path.
2. **0-RTT resumption** — harvest a `ResumptionHint` after the first connect, persist
   it to platform secure storage (iOS Keychain / Android `EncryptedSharedPreferences`),
   and reconnect via `connectPinnedWithResumption(...)`, folding the first request into
   the `ClientHello`.
3. **Encrypted send/recv** — a chat UI over `session.send` / `session.recv`.
4. **Connection-state surfacing** — `connectionState()` polled lock-free, including the
   `Migrating` / `Dead` liveness states.
5. **Recovery on network change** — reconnect-with-0-RTT (see the honesty note below).

## ⚠️ Not built in CI — verify locally

This environment has **no Xcode, Android SDK/NDK, or running server**, so these apps are
**not compiled or run in CI**. They are complete, reviewed source you build and run
yourself. Each app's `README.md` has the exact steps:

- cross-compile the `core` library for the device ABIs,
- generate + drop in the UniFFI binding (Swift sources / Kotlin `.kt`),
- run a `phantom-server` and bake its pinned verifying key into the app bundle
  (via the [`phantom-cli`](../../cli/) `keygen` / `pubkey` subcommands),
- open in Xcode / Android Studio and run.

## Honesty note: migration is *reconnect-with-0-RTT*, not `migrate()`

`PhantomSession.migrate(localAddr)` is on the UniFFI surface, but it is **only
effective on the native UDP transport** (`UdpClientTransport`), which is **not exposed
through the FFI surface**. The FFI connect functions (`connectPinned` /
`connectPinnedWithResumption`) use the **TCP** transport (`TcpSessionTransport`), and on
every non-UDP transport `migrate()` falls back to a **no-op** that returns `Ok` without
rebinding the socket — TCP is connection-oriented and cannot move its local endpoint
without a new connection.

So on a real Wi-Fi ↔ cellular handover these apps **reconnect with 0-RTT resumption**
(the genuinely-working pattern), not `migrate()`. Each app keeps a `migrate()` call
behind a clearly-labelled "no-op over TCP" button for API completeness and logs that
nothing migrated. Seamless single-socket migration over the FFI surface (exposing the
UDP transport) is future work — see `docs/operations/mobile.md`.

## See also

- [`docs/operations/mobile.md`](../../docs/operations/mobile.md) — the canonical mobile
  embedding guide (build flags, ATS / Network Security Config, background modes, secure
  storage, performance).
- [`tests/bindings/PACKAGING.md`](../../tests/bindings/PACKAGING.md) — how the Swift /
  Kotlin / Python / C packages are produced and published.
