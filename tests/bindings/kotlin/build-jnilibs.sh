#!/usr/bin/env bash
set -euo pipefail
# Cross-compile libphantom_core.so for the three Android ABIs and stage them
# under jniLibs/ for the Gradle module. Requires the Android NDK plus the
# three Rust targets:
#
#     rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
#
# And the NDK's clang wrappers — set ANDROID_NDK_HOME and the CC_* env vars
# (see docs/operations/mobile.md):
#
#     export ANDROID_NDK_HOME=$HOME/Library/Android/sdk/ndk/<version>
#     export CC_aarch64_linux_android=...
#     export CC_armv7_linux_androideabi=...
#     export CC_x86_64_linux_android=...

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
TARGET="${REPO_ROOT}/target"
JNI_LIBS="${SCRIPT_DIR}/jniLibs"

: "${ANDROID_NDK_HOME:?ANDROID_NDK_HOME is required — install the Android NDK and re-run}"

for triple in aarch64-linux-android armv7-linux-androideabi x86_64-linux-android; do
    echo "==> cargo build --release --target ${triple}"
    cargo build --release --target "${triple}" --manifest-path "${REPO_ROOT}/core/Cargo.toml"
done

mkdir -p "${JNI_LIBS}/arm64-v8a" "${JNI_LIBS}/armeabi-v7a" "${JNI_LIBS}/x86_64"
cp "${TARGET}/aarch64-linux-android/release/libphantom_core.so"   "${JNI_LIBS}/arm64-v8a/"
cp "${TARGET}/armv7-linux-androideabi/release/libphantom_core.so" "${JNI_LIBS}/armeabi-v7a/"
cp "${TARGET}/x86_64-linux-android/release/libphantom_core.so"    "${JNI_LIBS}/x86_64/"

echo "==> jniLibs staged at ${JNI_LIBS}/"
