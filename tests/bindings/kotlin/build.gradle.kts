// Android library module for the phantom_core Kotlin (UniFFI) binding.
//
// Bundles per-ABI prebuilt `libphantom_core.so` from `jniLibs/` plus the
// UniFFI-generated Kotlin source under `uniffi/phantom_core/`. Refresh
// the native libs via `./build-jnilibs.sh` (NDK cross-compile) and the
// Kotlin source via `../generate_kotlin.sh` after any FFI surface change.

plugins {
    id("com.android.library") version "8.1.4"
    kotlin("android") version "2.0.21"
}

android {
    namespace = "uniffi.phantom_core"
    compileSdk = 34
    defaultConfig {
        minSdk = 24
        ndk { abiFilters += setOf("arm64-v8a", "armeabi-v7a", "x86_64") }
    }
    sourceSets["main"].apply {
        kotlin.srcDirs("uniffi")
        jniLibs.srcDirs("jniLibs")
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
}

dependencies {
    // UniFFI's Kotlin runtime depends on JNA for the JNI plumbing and
    // kotlinx-coroutines for `suspend fun` callable across the boundary.
    implementation("net.java.dev.jna:jna:5.14.0@aar")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")
}
