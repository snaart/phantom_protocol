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

There are **two** Python packaging configs in the repo:

| Config | Purpose | Bundles native lib? |
|---|---|---|
| `tests/bindings/pyproject.toml` | Pure-Python wheel (setuptools) for dev use / manual staging | No — caller must stage `libphantom_protocol.{so,dylib,dll}` next to the `.py` |
| `python/pyproject.toml` | Platform-specific wheel (**maturin**) for PyPI distribution | Yes — cdylib is compiled and bundled automatically |

### Recommended: maturin wheel (bundles native library)

`python/pyproject.toml` uses [maturin](https://github.com/PyO3/maturin) in
`uniffi` bindings mode. maturin compiles the Rust cdylib, runs `uniffi-bindgen`
to generate the Python glue, and bundles both into a single platform-specific
wheel. The result is installable with a plain `pip install`.

```sh
# Prerequisites
pip install "maturin>=1.6,<2.0"

# Build a wheel for the current platform (from the repo root):
cd python
maturin build --release --manifest-path ../core/Cargo.toml --features bindings --out ../target/wheels

# Install it (no extra steps — cdylib is inside the wheel):
pip install --no-index --find-links ../target/wheels phantom-protocol

# Verify:
python -c "import phantom_protocol; print('ok')"

# Publish to PyPI (manual — needs MATURIN_PYPI_TOKEN):
maturin publish --manifest-path ../core/Cargo.toml
```

For a real multi-platform PyPI release (manylinux, macOS, Windows) wrap
the build with **`cibuildwheel`** targeting the `python/pyproject.toml`. A
CI job (`build-python-wheel` in `.github/workflows/release.yml`, manually
triggered via `workflow_dispatch`) demonstrates the single-platform
smoke-test flow.

### Legacy: setuptools wheel (manual native-lib staging)

The `tests/bindings/pyproject.toml` (setuptools) is kept for local development
and CI drift checking. It does NOT bundle the native library and is NOT suitable
for PyPI distribution without extra staging:

```sh
cd tests/bindings
cargo build --release --manifest-path ../../core/Cargo.toml
./generate_python.sh
cp ../../target/release/libphantom_protocol.{dylib,so} . 2>/dev/null || true
python -m build --wheel        # produces dist/phantom_protocol-0.2.2-*.whl
twine upload dist/*.whl        # manual — needs PyPI credentials
```

Use this flow only for local testing or the `bindings/drift` CI job.

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

`phantom-protocol` is at version **0.2.2** — every binding artifact carries the
same version. The `core/Cargo.toml` version is the single source of truth;
when it bumps, update each binding's manifest in lock step:

- `tests/bindings/pyproject.toml` (`version = ...`)
- `tests/bindings/c/phantom_protocol.pc.in` (`Version: ...`)
- `tests/bindings/c/package.sh` (`VERSION=...`)
- `tests/bindings/swift/Package.swift` — no version field, but git-tag
  the release at the same SemVer.
- `tests/bindings/kotlin/build.gradle.kts` — add a `version =` if you
  start publishing to a Maven repo.
