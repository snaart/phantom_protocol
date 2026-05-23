#!/usr/bin/env bash
set -euo pipefail

# Compile-checks the generated Kotlin binding together with LoopbackTest.kt
# against its JNA + kotlinx-coroutines runtime dependencies. This is a
# compile-only verification — it proves the generated Kotlin is well-formed
# and type-checks against its deps; it does not execute the test.
#
# Requires a JDK (java on PATH) and network access — it downloads a pinned
# kotlinc plus the two runtime jars from Maven Central.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

KOTLIN_VERSION="2.0.21"
JNA_VERSION="5.14.0"
COROUTINES_VERSION="1.8.1"

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

echo "==> Fetching kotlinc ${KOTLIN_VERSION} + JNA ${JNA_VERSION} + coroutines ${COROUTINES_VERSION}"
curl -fsSL -o "${WORK}/kotlinc.zip" \
    "https://github.com/JetBrains/kotlin/releases/download/v${KOTLIN_VERSION}/kotlin-compiler-${KOTLIN_VERSION}.zip"
unzip -q "${WORK}/kotlinc.zip" -d "${WORK}"

curl -fsSL -o "${WORK}/jna.jar" \
    "https://repo1.maven.org/maven2/net/java/dev/jna/jna/${JNA_VERSION}/jna-${JNA_VERSION}.jar"
curl -fsSL -o "${WORK}/coroutines.jar" \
    "https://repo1.maven.org/maven2/org/jetbrains/kotlinx/kotlinx-coroutines-core-jvm/${COROUTINES_VERSION}/kotlinx-coroutines-core-jvm-${COROUTINES_VERSION}.jar"

echo "==> Compiling the generated binding + LoopbackTest.kt"
"${WORK}/kotlinc/bin/kotlinc" \
    -classpath "${WORK}/jna.jar:${WORK}/coroutines.jar" \
    "${SCRIPT_DIR}/uniffi/phantom_core/phantom_core.kt" \
    "${SCRIPT_DIR}/LoopbackTest.kt" \
    -d "${WORK}/classes"

echo "OK: Kotlin binding compiles against JNA + kotlinx-coroutines"
