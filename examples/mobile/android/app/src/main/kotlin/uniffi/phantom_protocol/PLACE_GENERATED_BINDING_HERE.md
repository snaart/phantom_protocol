# Generated UniFFI Kotlin binding goes here

This directory must contain the auto-generated UniFFI Kotlin binding before the
app will compile. It is intentionally **not** checked in here, because it is a
generated artifact that must match the exact `phantom_protocol` build you ship
the native `.so` from.

Copy the generated file into this directory (keep the package path
`uniffi/phantom_protocol/`):

```sh
# From the repository root, after regenerating the binding:
cp tests/bindings/kotlin/uniffi/phantom_protocol/phantom_protocol.kt \
   examples/mobile/android/app/src/main/kotlin/uniffi/phantom_protocol/
```

Regenerate it from the Rust source with the bindgen entry point
(`core/src/bin/uniffi-bindgen.rs`); the repo's `tests/generate_kotlin.sh` script
does this for you. The resulting file declares:

- `package uniffi.phantom_protocol`
- top-level `suspend fun connectPinned(...)` / `connectPinnedWithResumption(...)`
- `interface PhantomSessionInterface` + `class PhantomSession`
- `data class ResumptionHint`
- `enum class ConnectionState`
- `sealed class CoreException`

Do **not** hand-edit the generated file. The Gradle module's
`sourceSets.main.java.srcDirs += "src/main/kotlin"` picks it up automatically
once it is present here.
