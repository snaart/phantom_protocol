# The UniFFI Kotlin binding loads the native library through JNA reflection.
# Keep the binding package and JNA's structures so R8/ProGuard does not strip
# the JNI-facing classes in a minified release build.
-keep class uniffi.phantom_protocol.** { *; }
-keep class com.sun.jna.** { *; }
-keepclassmembers class * extends com.sun.jna.** { *; }
-dontwarn java.awt.**
