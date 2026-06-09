# Phantom Protocol — binding packaging

This directory ships **starting-point packaging configs** for distributing
the four FFI bindings:

| Language | Artifact | Files |
|---|---|---|
| Python | per-platform wheel | `pyproject.toml`, `MANIFEST.in` |
| Swift  | SwiftPM + XCFramework | `swift/Package.swift`, `swift/build-xcframework.sh` |
| Kotlin | Android Library (AAR) | `kotlin/build.gradle.kts`, `kotlin/settings.gradle.kts`, `kotlin/build-jnilibs.sh` |
| C      | release tarball + pkg-config | `c/phantom_protocol.pc.in`, `c/package.sh` |

**Publishing is intentionally manual.** None of the steps below are
automated in CI — releasing a binding is a deliberate human action.
SLSA-3 build-provenance attestation is wired up for the Rust crate
(`.github/workflows/release.yml`); per-binding publish workflows are a
follow-up beyond the scope of these configs.

---

## Python — PyPI wheel

The wheel bundles `phantom_protocol.py`; the native library is platform-specific
and must be staged next to the module before the build.

```sh
cd tests/bindings
cargo build --release --manifest-path ../../core/Cargo.toml
./generate_python.sh
cp ../../target/release/libphantom_protocol.{dylib,so} . 2>/dev/null || true
python -m build --wheel        # produces dist/phantom_protocol-0.3.0-*.whl
twine upload dist/*.whl        # manual — needs PyPI credentials
```

The wheel produced by `python -m build` includes `phantom_protocol.py` but does
**not** automatically bundle the native library — `MANIFEST.in` covers the
sdist, not the wheel. For a real PyPI release across OS/arch combinations
wrap this config with **`cibuildwheel`** or **`maturin`**; each tool
builds and bundles per-platform wheels in a matrix.

---

## Swift — SwiftPM + XCFramework

```sh
cd tests/bindings/swift
rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios
./build-xcframework.sh         # produces PhantomProtocol.xcframework
# Then commit a tag and host the XCFramework on a GitHub Release;
# update Package.swift's `.binaryTarget(url:checksum:)` to point at it.
```

A *published* SwiftPM package needs a binary target hosted at a stable
URL with a SHA-256 checksum; the in-tree `Package.swift` declares a
`path:`-based binary target suitable for local consumption. For a tagged
release, switch the binary target to the `(url, checksum)` form and
upload `PhantomProtocol.xcframework.zip` to the GitHub Release.

---

## Kotlin — Android library (AAR)

```sh
cd tests/bindings/kotlin
export ANDROID_NDK_HOME=$HOME/Library/Android/sdk/ndk/<version>
# Plus CC_aarch64_linux_android, CC_armv7_linux_androideabi,
# CC_x86_64_linux_android — see docs/operations/mobile.md.
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
./build-jnilibs.sh             # cross-compiles + stages jniLibs/{arm64-v8a,armeabi-v7a,x86_64}
../generate_kotlin.sh          # regenerates uniffi/phantom_protocol/phantom_protocol.kt
gradle :assembleRelease        # produces build/outputs/aar/phantom_protocol-release.aar
gradle :publishToMavenLocal    # or :publish to push to your Maven repo
```

The Android NDK setup is the load-bearing prerequisite — the Gradle
module itself is mechanical. The mobile guide (`docs/operations/mobile.md`)
has the proven NDK toolchain incantations.

---

## C — release tarball

```sh
cd tests/bindings/c
./package.sh                              # default --prefix /usr/local
# or
./package.sh --prefix /opt/phantom_protocol
# Output: phantom_protocol-c-<version>-<os>-<arch>.tar.gz in $PWD
```

Run on every OS / arch you intend to publish for — the tarball bundles
the host's prebuilt `libphantom_protocol.{dylib,so,dll}`. Attach the tarballs
to a GitHub Release.

---

## A note on pre-1.0 versioning

`phantom-protocol` is at version **0.3.0** — every binding artifact carries the
same version. The `core/Cargo.toml` version is the single source of truth;
when it bumps, update each binding's manifest in lock step:

- `tests/bindings/pyproject.toml` (`version = ...`)
- `tests/bindings/c/phantom_protocol.pc.in` (`Version: ...`)
- `tests/bindings/c/package.sh` (`VERSION=...`)
- `tests/bindings/swift/Package.swift` — no version field, but git-tag
  the release at the same SemVer.
- `tests/bindings/kotlin/build.gradle.kts` — add a `version =` if you
  start publishing to a Maven repo.
