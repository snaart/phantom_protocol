#!/usr/bin/env bash
set -euo pipefail

# Compile-checks the generated Kotlin binding together with LoopbackTest.kt
# against its JNA + kotlinx-coroutines runtime dependencies. This is a
# compile-only verification — it proves the generated Kotlin is well-formed
# and type-checks against its deps; it does not execute the test.
#
# Requires a JDK (java on PATH) and network access — it downloads a pinned
# kotlinc plus the two runtime jars from GitHub Releases / Maven Central
# and verifies each artifact against a SHA-256 hash before unpacking. A
# mismatch aborts the script, so an MITM that swaps the bytes between the
# CDN and this runner cannot land a tampered compiler / jar.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

KOTLIN_VERSION="2.0.21"
JNA_VERSION="5.14.0"
COROUTINES_VERSION="1.8.1"

# SHA-256 checksums of the artifacts above. Computed once against the
# upstream downloads; regenerate (and commit alongside) when bumping the
# version pins above.
KOTLIN_SHA256="0352c0a45bd22f80f6b26e485cd04da8047baa5de54865281fb9f89a4a7bcf2a"
JNA_SHA256="34ed1e1f27fa896bca50dbc4e99cf3732967cec387a7a0d5e3486c09673fe8c6"
COROUTINES_SHA256="f3d4f5de1c391bbcc20f3b3435ccbac013521e76b6902d7d59635ec15c1f797e"

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

# Pick the available SHA-256 tool (`sha256sum` on Linux, `shasum -a 256`
# on macOS). Both spit "<hex>  <file>" so we read the first field either
# way.
if command -v sha256sum >/dev/null 2>&1; then
    SHA256_CMD="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
    SHA256_CMD="shasum -a 256"
else
    echo "ERROR: neither sha256sum nor shasum found on PATH" >&2
    exit 1
fi

verify_sha256() {
    local file="$1"
    local expected="$2"
    local label="$3"
    local actual
    actual="$(${SHA256_CMD} "${file}" | awk '{print $1}')"
    if [ "${actual}" != "${expected}" ]; then
        echo "ERROR: SHA-256 mismatch for ${label}" >&2
        echo "  expected: ${expected}" >&2
        echo "  actual:   ${actual}" >&2
        exit 1
    fi
}

echo "==> Fetching kotlinc ${KOTLIN_VERSION} + JNA ${JNA_VERSION} + coroutines ${COROUTINES_VERSION}"
curl -fsSL -o "${WORK}/kotlinc.zip" \
    "https://github.com/JetBrains/kotlin/releases/download/v${KOTLIN_VERSION}/kotlin-compiler-${KOTLIN_VERSION}.zip"
verify_sha256 "${WORK}/kotlinc.zip" "${KOTLIN_SHA256}" "kotlinc ${KOTLIN_VERSION}"
unzip -q "${WORK}/kotlinc.zip" -d "${WORK}"

curl -fsSL -o "${WORK}/jna.jar" \
    "https://repo1.maven.org/maven2/net/java/dev/jna/jna/${JNA_VERSION}/jna-${JNA_VERSION}.jar"
verify_sha256 "${WORK}/jna.jar" "${JNA_SHA256}" "JNA ${JNA_VERSION}"

curl -fsSL -o "${WORK}/coroutines.jar" \
    "https://repo1.maven.org/maven2/org/jetbrains/kotlinx/kotlinx-coroutines-core-jvm/${COROUTINES_VERSION}/kotlinx-coroutines-core-jvm-${COROUTINES_VERSION}.jar"
verify_sha256 "${WORK}/coroutines.jar" "${COROUTINES_SHA256}" "coroutines ${COROUTINES_VERSION}"

echo "==> All artifacts verified, compiling the generated binding + LoopbackTest.kt"
"${WORK}/kotlinc/bin/kotlinc" \
    -classpath "${WORK}/jna.jar:${WORK}/coroutines.jar" \
    "${SCRIPT_DIR}/uniffi/phantom_core/phantom_core.kt" \
    "${SCRIPT_DIR}/LoopbackTest.kt" \
    -d "${WORK}/classes"

echo "OK: Kotlin binding compiles against JNA + kotlinx-coroutines"
