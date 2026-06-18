# Phantom Protocol — Android sample app

A single-module Jetpack Compose chat app that exercises the `phantom_protocol`
post-quantum transport SDK through its UniFFI Kotlin binding. It demonstrates a
pinned connect, 0-RTT resumption, **network-change recovery via
reconnect-with-0-RTT**, and hosting the session in a foreground service so it
survives Doze.

> **Why reconnect, not migrate?** The UniFFI surface exposes only
> `connectPinned` / `connectPinnedWithResumption`, and both establish the
> session over the **TCP** transport (`TcpSessionTransport`). On that transport
> `session.migrate(localAddr)` is a **no-op** — it returns success but does not
> rebind the socket or move the path (a TCP socket cannot rebind its local
> address without reconnecting). Real seamless single-socket migration that
> retains keys + connection id exists on the native (Rust) **UDP** transport,
> but that transport is not yet on the FFI surface. So the working mobile
> recovery pattern here is to **reconnect with 0-RTT resumption**: while the
> session is alive the app harvests a fresh `ResumptionHint`, and on a network
> change it opens a new session via `connectPinnedWithResumption`, folding the
> first request into the new ClientHello.

> **Not built in CI.** This sample requires the Android SDK + NDK and a running
> `phantom-server`, none of which exist in the project's CI environment. Build
> and run it locally to verify. Three things must be supplied before it
> compiles and connects: (1) the native `.so` per ABI under `app/src/main/jniLibs/`,
> (2) the generated Kotlin binding under
> `app/src/main/kotlin/uniffi/phantom_protocol/`, and (3) the pinned server key
> at `app/src/main/res/raw/phantom_server_pk`.

---

## 1. Cross-compile the native library (`.so`) per ABI

You need the Android NDK and the three Android Rust targets:

```sh
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
```

Point at the NDK's clang wrappers and build each ABI from the repo root
(`<repo>` = the `phantom_core_rust` checkout):

```sh
export ANDROID_NDK_HOME=$HOME/Library/Android/sdk/ndk/26.1.10909125
# (adjust the host triple "darwin-x86_64" for Linux: "linux-x86_64")
NDK_BIN=$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin

export CC_aarch64_linux_android=$NDK_BIN/aarch64-linux-android24-clang
export CC_armv7_linux_androideabi=$NDK_BIN/armv7a-linux-androideabi24-clang
export CC_x86_64_linux_android=$NDK_BIN/x86_64-linux-android24-clang
# Cargo also reads CARGO_TARGET_<TRIPLE>_LINKER; the CC_* wrappers double as linkers:
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER=$CC_aarch64_linux_android
export CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_LINKER=$CC_armv7_linux_androideabi
export CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER=$CC_x86_64_linux_android

cargo build --release --target aarch64-linux-android   --manifest-path core/Cargo.toml
cargo build --release --target armv7-linux-androideabi --manifest-path core/Cargo.toml
cargo build --release --target x86_64-linux-android    --manifest-path core/Cargo.toml
```

Stage the libraries into the Gradle module's `jniLibs/` (the directory layout
the app's `build.gradle.kts` wires via `jniLibs.srcDirs("src/main/jniLibs")`):

```sh
APP=examples/mobile/android/app/src/main/jniLibs
mkdir -p $APP/arm64-v8a $APP/armeabi-v7a $APP/x86_64
cp target/aarch64-linux-android/release/libphantom_protocol.so   $APP/arm64-v8a/
cp target/armv7-linux-androideabi/release/libphantom_protocol.so $APP/armeabi-v7a/
cp target/x86_64-linux-android/release/libphantom_protocol.so    $APP/x86_64/
```

This mirrors `tests/bindings/kotlin/build-jnilibs.sh` (same targets, different
destination). Full background: `docs/operations/mobile.md`. For the smallest
binary, build with the workspace `release-size` profile
(`--profile release-size`).

## 2. Generate and copy the Kotlin binding

The UniFFI Kotlin binding is a generated artifact and is not checked into this
sample. Regenerate it (the repo script drives `core/src/bin/uniffi-bindgen.rs`),
then copy it under the `uniffi/phantom_protocol/` package path:

```sh
# from the repo root — regenerates tests/bindings/kotlin/uniffi/phantom_protocol/phantom_protocol.kt
./tests/bindings/generate_kotlin.sh

cp tests/bindings/kotlin/uniffi/phantom_protocol/phantom_protocol.kt \
   examples/mobile/android/app/src/main/kotlin/uniffi/phantom_protocol/
```

See `app/src/main/kotlin/uniffi/phantom_protocol/PLACE_GENERATED_BINDING_HERE.md`.

## 3. Run a `phantom-server` and bake in its pinned key

The client pins the server's hybrid verifying key (Security Invariant 1) — it
will not establish a session unless the server proves possession of the
matching private key. Generate a persistent server identity and extract its
public half with the admin CLI:

```sh
# Generate a 0600 server signing key.
cargo run --manifest-path cli/Cargo.toml -- keygen --out ./server.key

# Print the verifying-key hex (this is what the client pins).
cargo run --manifest-path cli/Cargo.toml -- pubkey --in ./server.key
```

Run the reference server with that persistent identity:

```sh
cargo run --manifest-path server/Cargo.toml -- \
    --bind 0.0.0.0:4242 --signing-key-file ./server.key
```

Now bake the **public** key into the app as raw bytes at
`app/src/main/res/raw/phantom_server_pk`. If you have the hex from `pubkey`,
convert it to raw bytes:

```sh
# macOS/Linux: hex string -> raw bytes
echo -n "<verifying-key-hex>" | xxd -r -p \
  > examples/mobile/android/app/src/main/res/raw/phantom_server_pk
```

- On the **emulator**, the host machine is reachable at `10.0.2.2`. The default
  `PhantomServerConfig.DEMO_HOST` holds the host only (`10.0.2.2`) and
  `PhantomServerConfig.DEMO_PORT` holds the port (`4242`);
  `res/xml/network_security_config.xml` permits cleartext for that host.
- On a **physical device**, set `DEMO_HOST` to the server's LAN IP (or hostname)
  — host only, no port — and add it to `network_security_config.xml`.

> Never bundle the server's **signing** (private) key — only the verifying
> (public) key. Never fetch the pinned key at runtime.

## 4. Open in Android Studio and run

This sample ships without the Gradle wrapper JAR / `gradlew` scripts. Either:

- open the `examples/mobile/android/` folder in Android Studio (it provisions
  the wrapper and Gradle 8.7 automatically), **or**
- generate the wrapper yourself with a local Gradle 8.7:
  `cd examples/mobile/android && gradle wrapper --gradle-version 8.7`.

Then build and run the `app` configuration on an emulator or device. Tap
**Connect**, type a message and **Send**; tap **Reconnect (0-RTT)** to exercise
the network-change recovery path; **Disconnect** for a graceful close.

## What the buttons do

- **Connect** — starts the foreground `PhantomSessionService`, then calls
  `connectPinnedWithResumption` if a fresh resumption ticket is stored (0-RTT,
  folding a small early-data payload into the ClientHello) or `connectPinned`
  otherwise (full 1-RTT PQC handshake). On success it harvests a new ticket
  into `EncryptedSharedPreferences` and starts the recv loop + state poller. The
  config is remembered so the recovery path can reconnect without it.
- **Send** — UTF-8 `session.send(...)`.
- **Reconnect (0-RTT)** — the genuinely-working mobile recovery pattern: harvest
  + persist a fresh `ResumptionHint`, tear the session down, then re-establish
  via `connectPinnedWithResumption` (0-RTT). A
  `ConnectivityManager.NetworkCallback` in the service triggers this
  automatically on a Wi-Fi <-> cellular handover, and the client's state poller
  triggers it when the session goes `MIGRATING`/`DEAD` (or `recv()` fails).
- **Call migrate() API (no-op over TCP)** — calls `session.migrate("0.0.0.0:0")`
  purely to demonstrate the API. Over the TCP transport exposed by
  `connectPinned` it is a no-op; the client appends a system message saying so.
  Real path migration requires the native UDP transport (not yet on the FFI
  surface).
- **Disconnect** — persists a final resumption ticket, `session.disconnect()`,
  stops the service.

The colored banner reflects `session.connectionState()` (polled lock-free):
amber during the handshake, green when `PQC_READY`/`CONNECTED`, blue while
`MIGRATING`, red on `FAILED`/`DEAD`, grey when `CLOSED`. `MIGRATING`/`DEAD` are
surfaced in the UI and also drive an automatic 0-RTT reconnect.

## Migration vs. reconnect, in one paragraph

Phantom's seamless connection migration (keep the keys + connection id, move to
a new local socket without a re-handshake) is a property of the native **UDP**
transport. The mobile FFI surface (`connectPinned` /
`connectPinnedWithResumption`) runs over **TCP**, where `session.migrate()` is a
default no-op and a socket cannot rebind in place. This sample therefore models
network changes as **reconnect-with-0-RTT**: it keeps a fresh resumption ticket
warm and, on a network change, opens a new session and folds the first request
into the new ClientHello as early-data. Exposing the UDP transport (and thus
real seamless migration) through the FFI surface is future work.

## Module map

| File | Role |
| --- | --- |
| `PhantomClient.kt` | Session lifecycle, recv loop, state poller, 0-RTT + reconnect recovery |
| `ResumptionStore.kt` | `EncryptedSharedPreferences`-backed 0-RTT ticket store (1h TTL) |
| `NetworkChangeMonitor.kt` | `ConnectivityManager` callback → 0-RTT reconnect trigger |
| `PhantomServerConfig.kt` | Host/port + pinned key from `R.raw.phantom_server_pk` |
| `PhantomSessionService.kt` | Foreground service hosting the session (survives Doze) |
| `MainActivity.kt` | Compose chat UI + `ViewModel` |
