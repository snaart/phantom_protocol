# Phantom Protocol — iOS sample app

A small SwiftUI chat client that demonstrates embedding the **Phantom Protocol**
post-quantum transport SDK on iOS via its UniFFI Swift binding. It shows the full
client lifecycle: a **pinned** connect, **0-RTT resumption** from a Keychain-cached
ticket, encrypted send/receive, live **connection-state** surfacing, and
**reconnect-with-0-RTT recovery** on a network-interface change.

> ## Not built in CI — requires Xcode + a running `phantom-server`; verify locally
>
> There is no Xcode in CI, so this sample is **not** compiled by the project's
> pipelines. `swift build` / Xcode resolution will fail until you build the
> `PhantomProtocol.xcframework` and drop in the generated Swift binding (both
> steps below). That is expected. Build and run it on your own machine.

The package is laid out as a Swift Package so the demo logic
(`PhantomDemoKit`) is importable and unit-testable, while the SwiftUI app
(`PhantomDemoApp`) is a thin view layer.

```
examples/mobile/ios/
├── Package.swift
├── Info.plist                         # ATS exception for the non-TLS Phantom port
├── Frameworks/
│   └── PhantomProtocol.xcframework    # YOU BUILD THIS (not committed)
└── Sources/
    ├── PhantomProtocol/               # YOU COPY the generated phantom_protocol.swift here
    ├── PhantomDemoKit/                # ViewModel, Keychain, path monitor, config
    │   └── Resources/
    │       └── phantom_server_pk.bin  # bundled pinned key (placeholder — replace)
    └── PhantomDemoApp/                # @main SwiftUI App + ContentView
```

---

## 1. Build the XCFramework

You need a macOS host with Xcode and the iOS Rust targets:

```sh
rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios \
                  aarch64-apple-darwin x86_64-apple-darwin
```

> **Note:** `core/Cargo.toml` declares `crate-type = ["lib", "cdylib"]`, so a
> plain `cargo build` emits `libphantom_protocol.dylib` + `.rlib` but no
> `libphantom_protocol.a`. The iOS slices are therefore built with
> `cargo rustc … --crate-type staticlib`, which requests the archive per
> invocation. It is kept out of the manifest deliberately: a staticlib is a final
> artifact, so a crate-wide declaration makes cargo require a `#[panic_handler]`
> and a `#[global_allocator]` from the library and breaks the bare-metal
> `thumbv7em-none-eabihf` build. `build-xcframework.sh` already does this.

The repository ships a ready-made script that compiles the slices, `lipo`s the
multi-architecture ones together, stages the UniFFI C header and modulemap, and
assembles the XCFramework:

```sh
# from the repository root
./tests/bindings/swift/build-xcframework.sh

# Compile the generated binding against the result (macOS host)
swift build --package-path tests/bindings/swift
```

Equivalently, by hand:

```sh
# Device (arm64), Apple-silicon simulator, Intel simulator, and the two macOS
# architectures — `Package.swift` declares .iOS and .macOS, and a declared
# platform without a slice resolves fine and then fails to link.
# `cargo rustc --crate-type staticlib` is what produces the .a — see the note above.
for triple in aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios \
              aarch64-apple-darwin x86_64-apple-darwin; do
    cargo rustc --release --target "$triple" --manifest-path core/Cargo.toml --crate-type staticlib
done

# Merge the multi-architecture slices into fat libraries
mkdir -p target/universal-ios-sim/release target/universal-macos/release
lipo -create \
    target/aarch64-apple-ios-sim/release/libphantom_protocol.a \
    target/x86_64-apple-ios/release/libphantom_protocol.a \
    -output target/universal-ios-sim/release/libphantom_protocol.a
lipo -create \
    target/aarch64-apple-darwin/release/libphantom_protocol.a \
    target/x86_64-apple-darwin/release/libphantom_protocol.a \
    -output target/universal-macos/release/libphantom_protocol.a

# Stage the headers. The directory handed to -headers is copied WHOLESALE into
# every slice, so it must hold exactly the FFI header and the modulemap — and the
# modulemap must be named module.modulemap, which is the only name clang looks
# for. Passing tests/bindings/swift/ instead fails twice over: the output lands
# in that same directory, so xcodebuild copies its own half-written framework
# into itself and dies with `the file name "ios-arm64" is invalid`; and the
# modulemap arrives under its generated name, so `canImport(phantom_protocolFFI)`
# is false and the build fails on `cannot find type 'RustBuffer' in scope`.
rm -rf target/xcframework-headers && mkdir -p target/xcframework-headers
cp tests/bindings/swift/phantom_protocolFFI.h target/xcframework-headers/
cp tests/bindings/swift/phantom_protocolFFI.modulemap \
   target/xcframework-headers/module.modulemap

# Assemble the XCFramework
xcodebuild -create-xcframework \
    -library target/aarch64-apple-ios/release/libphantom_protocol.a \
        -headers target/xcframework-headers \
    -library target/universal-ios-sim/release/libphantom_protocol.a \
        -headers target/xcframework-headers \
    -library target/universal-macos/release/libphantom_protocol.a \
        -headers target/xcframework-headers \
    -output tests/bindings/swift/PhantomProtocol.xcframework

# Check the result before shipping it: the gate catches a misnamed modulemap, a
# stray file in Headers and a declared platform with no slice.
./tests/bindings/swift/check_xcframework.sh
```

Then place it where this sample's `Package.swift` expects it:

```sh
cp -R tests/bindings/swift/PhantomProtocol.xcframework \
      examples/mobile/ios/Frameworks/PhantomProtocol.xcframework
```

With that and the generated binding from step 2 in place, the package builds on
the Mac itself against the framework's macOS slice — worth doing before opening
Xcode, since it type-checks `PhantomDemoKit` in a couple of seconds:

```sh
swift build --package-path examples/mobile/ios
swift test  --package-path examples/mobile/ios
```

See also `docs/operations/mobile.md` for the canonical build recipe and the
background/foreground + battery notes.

---

## 2. Copy the generated Swift binding

The `PhantomProtocol` target needs the **UniFFI-generated** Swift source. Copy
it from the repo (regenerate first if the Rust surface changed):

```sh
# from the repository root
./tests/bindings/generate_swift.sh   # regenerates tests/bindings/swift/phantom_protocol.swift

cp tests/bindings/swift/phantom_protocol.swift \
   examples/mobile/ios/Sources/PhantomProtocol/phantom_protocol.swift
```

(The C header + modulemap are already bundled inside the XCFramework from step 1,
so only the `.swift` file needs copying.)

---

## 3. Run a `phantom-server` with a pinned identity

The client **pins** the server's public hybrid verifying key (Security
Invariant 1). Generate a persistent server identity, extract its public key, and
bake the public key into the app bundle.

```sh
# from the repository root

# (a) generate a long-lived server signing key (written 0600)
cargo run --manifest-path cli/Cargo.toml -- keygen --out ./server.key

# (b) print the public verifying-key hex — this is what the client pins
cargo run --manifest-path cli/Cargo.toml -- pubkey --in ./server.key
# -> e.g. 8f3a... (paste below)

# (c) bake the public key as raw bytes into the bundled resource
python3 - <<'PY'
import binascii, pathlib
hex_key = "PASTE_THE_PUBKEY_HEX_FROM_STEP_B"
pathlib.Path("examples/mobile/ios/Sources/PhantomDemoKit/Resources/phantom_server_pk.bin") \
    .write_bytes(binascii.unhexlify(hex_key))
print("wrote", len(binascii.unhexlify(hex_key)), "bytes")
PY

# (d) start the server with that same identity so its ServerHello verifies
cargo run --manifest-path server/Cargo.toml -- \
    --bind 0.0.0.0:4242 --signing-key-file ./server.key
```

The bundled `phantom_server_pk.bin` ships as a 32-byte all-zero **placeholder**;
the loader treats an all-zero blob as "not configured" and falls back to the
`developmentPinnedKeyHex` constant in `PhantomServerConfig.swift`. Either bake the
real bytes (step c) or paste the hex into that constant — pick one.

> **Never** fetch the pinned key over the network at runtime. The whole trust
> model rests on the key being baked into the signed app. Rotating the server
> signing key requires shipping an app update with a new `phantom_server_pk.bin`.

The app reads its endpoint from `PHANTOM_DEMO_HOST` / `PHANTOM_DEMO_PORT`
(defaulting to `127.0.0.1:4242`). On the simulator, `127.0.0.1` reaches a server
running on the same Mac; on a device, set `PHANTOM_DEMO_HOST` to the Mac's LAN IP
(and ensure the ATS host exception in `Info.plist` matches).

---

## 4. Open in Xcode and run

You can either:

- **Open the package directly**: `File ▸ Open` the `examples/mobile/ios` folder
  (Xcode opens it as a Swift Package). Run the `PhantomDemoApp` executable scheme
  on the **My Mac** destination for a quick SwiftUI smoke, or
- **Embed in an iOS App target**: create a new iOS App project, add this folder
  as a local Swift Package dependency, set the App's `@main` to
  `PhantomDemoApp` (or copy `Sources/PhantomDemoApp` into the App target), and
  merge the `NSAppTransportSecurity` keys from this folder's `Info.plist` into the
  App target's `Info.plist`.

Then build and run on a simulator or device. Tap **Connect**, send a message,
and watch the connection-state banner. Tap **Reconnect (0-RTT)** to exercise the
working recovery path (harvest a resumption hint, tear the session down, then
re-establish via `connectPinnedWithResumption`). The **Call migrate() API** button
calls `PhantomSession.migrate(localAddr:)` for API-completeness only; on the TCP
FFI path it returns `Unsupported` — see the migration section below.

---

## What it demonstrates

| Capability        | Where                                                            |
|-------------------|------------------------------------------------------------------|
| Pinned connect    | `PhantomChatViewModel.connect()` → `connectPinned(...)` → `awaitReady()` before anything is reported as connected |
| 0-RTT resumption  | `connect()` → `connectPinnedWithResumption(...)` when a fresh Keychain hint exists; verdict via `earlyDataAccepted()` |
| Encrypted I/O     | `send(_:)` → `session.send(data:)`; recv loop → `session.recv()` |
| Connection state  | banner polls `session.connectionState()` (lock-free); `.migrating`/`.dead` trigger an automatic reconnect-with-0-RTT |
| Recovery on net change | `reconnect()` (harvest hint → tear down → `connect()` → 0-RTT), wired to `NetworkPathMonitor` (Wi-Fi ↔ cellular) |
| migrate() API     | `callMigrateAPI(to:)` → `session.migrate(localAddr:)` — **returns `Unsupported` over TCP**; use `connectPinnedUdp` for real migration (see below) |
| Ticket storage    | `KeychainStore` (Security framework, `kSecAttrAccessibleAfterFirstUnlock`, 1-hour TTL) |

All networking awaits run off the main actor; every `@Published` mutation is on
the main actor. The recv loop and state-poll tasks are cancellation-safe and torn
down on `disconnect()`.

---

## Migration model: reconnect-with-0-RTT on TCP, or `connectPinnedUdp` for real migration

> **This sample app uses TCP (`connectPinned`), where `migrate()` returns
> `Err(Unsupported)`.** For real seamless path migration use `connectPinnedUdp` instead.

The UniFFI surface exposes **both** TCP and UDP entry points:

- `connectPinned` / `connectPinnedWithResumption` — TCP transport
  (`TcpSessionTransport`). TCP is connection-oriented and cannot rebind its local
  address without reconnecting, so `migrate(localAddr:)` returns `Err(Unsupported)`
  on these sessions.
- `connectPinnedUdp` / `connectPinnedUdpWithResumption` / `connectPinnedUdpWithConfig`
  — PhantomUDP transport. On these sessions `migrate(localAddr:)` performs a real
  seamless single-path rebind (path validation + connection-ID continuity, no
  re-handshake), and liveness / `Migrating` / `Dead` transitions are all live.
  The server counterpart is `PhantomUdpListener.bindUdp`.

This sample app was built on the **TCP** path, so it demonstrates the
**reconnect-with-0-RTT resumption** recovery pattern:

1. While connected, the app harvests a fresh `ResumptionHint`
   (`session.resumptionHint()`) and persists it to the Keychain. The hint is an
   FFI object, not a struct: its two 32-byte fields come out through
   `sessionId()` / `resumptionSecret()` — which is what removed the generated
   stringifier that used to print the resumption secret — and it is a reference
   type with no `Equatable`, so tests compare the accessor bytes rather than the
   hints themselves. ARC frees the handle; there is nothing to close by hand.
2. On a network change (`NetworkPathMonitor`) — or when the poller/recv-loop
   observes `.migrating` / `.dead` — the app harvests one more hint, tears the
   old session down, and calls `connect()` again.
3. `connect()` prefers 0-RTT when a fresh hint exists, opening a new session via
   `connectPinnedWithResumption(host:port:pinnedKey:hint:earlyData:)` and folding
   the first request into the new `ClientHello`. The server's verdict is reported
   via `earlyDataAccepted()`.

The **Call migrate() API** button still invokes `session.migrate(localAddr:)` so the
API is demonstrable; on the TCP path it logs the `Unsupported` error it receives.
For real seamless migration, wire up `connectPinnedUdp` and call `migrate()` from
the network-change callback instead.
