# Mobile client deployment

Reference patterns for embedding a Phantom Core client in native iOS (Swift) and Android (Kotlin)
apps via UniFFI bindings.

## iOS (Swift)

**Build setup.** Compile three slices then assemble an XCFramework:

```sh
# Device (arm64), Apple Silicon simulator, Intel simulator
cargo build --release --target aarch64-apple-ios        --manifest-path core/Cargo.toml
cargo build --release --target aarch64-apple-ios-sim    --manifest-path core/Cargo.toml
cargo build --release --target x86_64-apple-ios         --manifest-path core/Cargo.toml

# Merge simulator slices; then build the XCFramework
lipo -create \
    target/aarch64-apple-ios-sim/release/libphantom_core.a \
    target/x86_64-apple-ios/release/libphantom_core.a \
    -output target/universal-sim/libphantom_core.a

xcodebuild -create-xcframework \
    -library target/aarch64-apple-ios/release/libphantom_core.a  -headers tests/bindings/swift/ \
    -library target/universal-sim/libphantom_core.a              -headers tests/bindings/swift/ \
    -output PhantomCore.xcframework
```

Auto-generated Swift sources in `tests/bindings/swift/`: `phantom_core.swift`,
`phantom_coreFFI.h`, `phantom_coreFFI.modulemap`. Regenerate via
`core/src/bin/uniffi-bindgen.rs` (uniffi 0.29 cli) after any surface change.

**SwiftPM integration.**

```swift
// Package.swift
let package = Package(
    name: "MyApp", platforms: [.iOS(.v16)],
    targets: [
        .binaryTarget(name: "PhantomCoreFFI", path: "PhantomCore.xcframework"),
        .target(
            name: "PhantomCore", dependencies: ["PhantomCoreFFI"],
            path: "Sources/PhantomCore",          // place phantom_core.swift here
            swiftSettings: [.unsafeFlags(["-suppress-warnings"])]
        ),
        .target(name: "MyApp", dependencies: ["PhantomCore"]),
    ]
)
```

**Using `PhantomSession` from Swift.** The UniFFI surface exposes
`connectPinned(host:port:pinnedKey:)` (landed in commit `bfbf808`) which
internally opens a `TcpSessionTransport`, pins via `HybridVerifyingKey::
from_bytes`, and delegates to `PhantomSession::connect_with_transport`
(Security Invariant 1 enforced unconditionally). Use it directly:

```swift
import PhantomCore

// Pinned key baked into the bundle — NEVER fetched at runtime.
let keyData = try! Data(contentsOf: Bundle.main.url(
    forResource: "phantom_server_pk", withExtension: "bin")!)

// Shim exposes: connectPinned(host:port:pinnedKey:) -> PhantomSession
let session = try await PhantomCore.connectPinned(
    host: "phantom.example.com", port: 4242,
    pinnedKey: keyData   // from PhantomListener::verifying_key_bytes()
)
try await session.send(data: "hello".data(using: .utf8)!)
let reply = try await session.recv()
await session.disconnect()
```

**App Transport Security note.** iOS ATS blocks non-TLS connections by default.
Add an explicit ATS hostname exception in `Info.plist`, or front the Phantom server
with a WebSocket endpoint carrying a valid PKI cert — the outer TLS satisfies ATS;
Phantom's `HybridVerifyingKey` provides the post-quantum auth layer.

**Background mode.** iOS suspends connections when the app backgrounds. Register
for Background App Refresh (`BGAppRefreshTask`); on `sceneDidEnterBackground`
persist `session.resumptionHint()` — a `ResumptionHint` with `sessionId` /
`resumptionSecret` — to Keychain (`SecItemAdd`); on foreground reload pass it
to `connectPinnedWithResumption` (0-RTT skips PQC keygen). Discard hints older
than 1 hour (server default).

## Android (Kotlin)

**Build setup.** Compile for each ABI and stage under `jniLibs/`:

```sh
export ANDROID_NDK_HOME=$HOME/Library/Android/sdk/ndk/26.1.10909125
export CC_aarch64_linux_android=\
  $ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android35-clang
# Set CC_armv7_linux_androideabi and CC_x86_64_linux_android similarly.

cargo build --release --target aarch64-linux-android   --manifest-path core/Cargo.toml
cargo build --release --target armv7-linux-androideabi --manifest-path core/Cargo.toml
cargo build --release --target x86_64-linux-android    --manifest-path core/Cargo.toml

mkdir -p app/src/main/jniLibs/{arm64-v8a,armeabi-v7a,x86_64}
cp target/aarch64-linux-android/release/libphantom_core.so   app/src/main/jniLibs/arm64-v8a/
cp target/armv7-linux-androideabi/release/libphantom_core.so app/src/main/jniLibs/armeabi-v7a/
cp target/x86_64-linux-android/release/libphantom_core.so    app/src/main/jniLibs/x86_64/
```

Auto-generated Kotlin source: `tests/bindings/kotlin/uniffi/phantom_core/phantom_core.kt`.
Copy to `src/main/kotlin/uniffi/phantom_core/`; regenerate via `uniffi-bindgen.rs`.

**Gradle integration.**

```groovy
// app/build.gradle
android {
    sourceSets.main {
        jniLibs.srcDirs = ['src/main/jniLibs']   // picks up libphantom_core.so
        java.srcDirs   += ['src/main/kotlin']
    }
}
dependencies {
    implementation("net.java.dev.jna:jna:5.14.0@aar")  // UniFFI Kotlin bindings runtime
}
```

**Using `PhantomSession` from Kotlin.** `connectPinned` is on the UniFFI
surface as of `bfbf808` — call it directly:

```kotlin
import uniffi.phantom_core.*

val pinnedKeyBytes = resources.openRawResource(R.raw.phantom_server_pk).use { it.readBytes() }

// Shim: connectPinned(host, port, pinnedKey) — wraps connect_with_transport
val session = PhantomCoreKt.connectPinned(
    host = "phantom.example.com", port = 4242u,
    pinnedKey = pinnedKeyBytes   // from PhantomListener::verifying_key_bytes()
)
session.send("hello".encodeToByteArray())
val reply = session.recv()
session.disconnect()
```

**Network Security Config.** Add `res/xml/network_security_config.xml`; reference
via `android:networkSecurityConfig` in the manifest:

```xml
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="false" />
    <domain-config>
        <domain includeSubdomains="false">phantom.example.com</domain>
        <trust-anchors><certificates src="system" /></trust-anchors>
    </domain-config>
</network-security-config>
```

**Foreground service.** Android Doze kills background connections. Host the Phantom
session in a `ForegroundService` (declare `FOREGROUND_SERVICE` and
`FOREGROUND_SERVICE_DATA_SYNC` permissions):

```kotlin
class PhantomSessionService : Service() {
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startForeground(NOTIF_ID, buildNotification())   // prevents Doze termination
        lifecycleScope.launch { runPhantomSession() }
        return START_STICKY
    }
}
```

**Battery optimization.** Foreground services alone do not survive Android's
"Battery optimization" without user consent. Request exemption at runtime and
prompt during onboarding:

```kotlin
val pm = getSystemService(POWER_SERVICE) as PowerManager
if (!pm.isIgnoringBatteryOptimizations(packageName))
    startActivity(Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS)
        .apply { data = Uri.parse("package:$packageName") })
// Without this, sessions may be killed overnight even with a foreground service.
```

## Cross-platform patterns

**Server key pinning.** Bake `PhantomListener::verifying_key_bytes()` output into
the app — iOS: `Bundle.main.url(forResource:withExtension:)`; Android:
`R.raw.phantom_server_pk`. **Never** fetch the key at runtime — that voids the
trust model. Rotating the signing key requires an app update.

**Resumption ticket storage.** Persist the `ResumptionHint` (`sessionId`,
`resumptionSecret`) from `session.resumptionHint()` to secure storage:

- iOS: Keychain (`SecItemAdd`/`SecItemCopyMatching`),
  `kSecAttrAccessible = kSecAttrAccessibleAfterFirstUnlock`.
- Android: `EncryptedSharedPreferences` with `MasterKey` from
  `androidx.security.crypto` (AES-256-GCM in Android Keystore).

TTL: **1 hour** (server `SessionCache` default). Check saved timestamp before
reuse; expired hints fall back to 1-RTT automatically.

**Connection migration (Wi-Fi ↔ LTE) — not yet supported in 1.0.** Live
interface migration is future work: the path-validation primitives exist only on
the internal `transport::Session`, not on `PhantomSession` or the UniFFI surface,
and the data pump holds a single fixed transport with no rebind seam. On a
network change, **reconnect** — register for `NWPathMonitor` (iOS) /
`ConnectivityManager.NetworkCallback` (Android), then open a fresh session.
Minimise the cost with **0-RTT resumption**: harvest a `ResumptionHint` after the
first connect and reconnect via `connect_pinned_with_resumption`, which folds the
first request into the new `ClientHello`.

## Performance considerations

**PQC keygen.** A full handshake runs ML-KEM-768 + ML-DSA-65. Expect **~30–100 ms**
on modern phone CPUs (TBD — measure with Instruments / Android Profiler on target
devices). 0-RTT resumption skips keygen entirely.

**Memory.** ~64 KiB per session (matches `perf-tuning.md` server numbers).

**Binary size.** arm64 slice roughly **4–6 MiB** stripped (TBD — verify with
`size` / APK Analyzer). Set `opt-level = "z"`, `lto = true`,
`codegen-units = 1`, `strip = "symbols"` in `[profile.release]`.

## Security caveats

**Pinned-connect shim (LANDED).** Commit `bfbf808` adds
`#[uniffi::export] pub async fn connect_pinned(host, port, pinned_key)
-> Result<Arc<PhantomSession>, CoreError>` to `core/src/api/session.rs`.
Internally: parses `pinned_key: Vec<u8>` into a `HybridVerifyingKey`,
opens a `TcpSessionTransport` via `tokio::net::TcpStream::connect`, and
delegates to `PhantomSession::connect_with_transport` — Security
Invariant 1 (server pinning) is enforced unconditionally. Available
in all four binding languages (Swift, Kotlin, Python, C). The
placeholder `connect(addr)` is still on the surface as the unpinned
back-compat path — do NOT use it in production.

**Resumption secret access.** Keychain / EncryptedSharedPreferences secrets are
accessible to apps sharing the same team ID (iOS) or user ID (Android). Assess
your threat model; clear tickets on detected compromise.

**Reproducible builds.** Recommended for supply-chain hygiene. SLSA-3 provenance
(Phase 7.4) covers Rust artifacts — integrate with your mobile CI/CD pipeline.

**Signing key is server-side only.** The bytes baked into the app are the *public*
`HybridVerifyingKey`. Never bundle a `HybridSigningKey` (private).

## See also

- `docs/operations/wasm.md` — browser client guide (companion to this one)
- `docs/operations/kubernetes.md` — server-side cluster deployment
- `docs/operations/perf-tuning.md` — server-side build flags and throughput numbers
- `tests/bindings/swift/` — auto-generated Swift sources
- `tests/bindings/kotlin/uniffi/phantom_core/phantom_core.kt` — auto-generated Kotlin source
