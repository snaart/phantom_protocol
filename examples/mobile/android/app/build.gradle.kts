plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.example.phantomdemo"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.example.phantomdemo"
        minSdk = 24
        targetSdk = 34
        versionCode = 1
        versionName = "1.0"

        // Only ship the ABIs we cross-compile the .so for (see README).
        ndk {
            abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64")
        }
    }

    sourceSets {
        getByName("main") {
            // Picks up libphantom_protocol.so per-ABI.
            jniLibs.srcDirs("src/main/jniLibs")
            // The generated UniFFI Kotlin binding + our hand-written sources both
            // live under src/main/kotlin.
            java.srcDirs("src/main/kotlin")
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        compose = true
    }

    composeOptions {
        // Compose compiler extension compatible with Kotlin 1.9.24.
        kotlinCompilerExtensionVersion = "1.5.14"
    }

    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
    }
}

dependencies {
    // UniFFI Kotlin bindings runtime. The generated binding talks to the native
    // library through JNA, so this is mandatory.
    implementation("net.java.dev.jna:jna:5.14.0@aar")

    // Coroutines — the whole UniFFI surface is `suspend fun`.
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")

    // Jetpack Compose.
    val composeBom = platform("androidx.compose:compose-bom:2024.06.00")
    implementation(composeBom)
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.activity:activity-compose:1.9.0")
    debugImplementation("androidx.compose.ui:ui-tooling")

    // Lifecycle + ViewModel for Compose.
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.2")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.2")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.2")

    // EncryptedSharedPreferences for the resumption-ticket store.
    implementation("androidx.security:security-crypto:1.1.0-alpha06")

    // Core KTX (Build.VERSION helpers, etc.).
    implementation("androidx.core:core-ktx:1.13.1")
}
