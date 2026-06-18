// swift-tools-version:5.9
// SPDX-License-Identifier: Apache-2.0
import PackageDescription

// Phantom Protocol — iOS sample app, structured as a Swift Package so the demo
// logic in PhantomDemoKit is importable and unit-testable, while the SwiftUI
// entry point lives in PhantomDemoApp.
//
// NOTE: `swift build` / `xcodebuild` will FAIL to resolve this package until
// two artifacts are placed by hand (see README.md):
//
//   1. Frameworks/PhantomProtocol.xcframework  — built from the Rust core via
//      the commands in README.md (cargo build per iOS target + lipo +
//      xcodebuild -create-xcframework). It is intentionally NOT committed.
//
//   2. Sources/PhantomProtocol/phantom_protocol.swift — the UniFFI-generated
//      Swift binding, copied from the repo's tests/bindings/swift/. The
//      directory ships with a placeholder note; the real file is NOT committed
//      here to avoid drift with the generated source of truth.
//
// This mirrors the project's "not built in CI — verify locally with Xcode"
// posture for the mobile samples.

let package = Package(
    name: "PhantomDemoApp",
    platforms: [
        .iOS(.v16),
        .macOS(.v13),
    ],
    products: [
        .library(name: "PhantomDemoKit", targets: ["PhantomDemoKit"]),
        .executable(name: "PhantomDemoApp", targets: ["PhantomDemoApp"]),
    ],
    targets: [
        // The XCFramework wrapping the Rust static library + UniFFI C headers.
        // Build it with the commands in README.md; output path is relative to
        // this manifest.
        .binaryTarget(
            name: "PhantomProtocolFFI",
            path: "Frameworks/PhantomProtocol.xcframework"
        ),

        // The generated Swift binding. Copy phantom_protocol.swift here
        // (see Sources/PhantomProtocol/PLACE_GENERATED_SOURCES_HERE.md).
        // -suppress-warnings keeps the generated source quiet under -Werror-ish
        // build settings, matching docs/operations/mobile.md.
        .target(
            name: "PhantomProtocol",
            dependencies: ["PhantomProtocolFFI"],
            path: "Sources/PhantomProtocol",
            swiftSettings: [.unsafeFlags(["-suppress-warnings"])]
        ),

        // All substantial demo logic: ViewModel, Keychain, path monitor, config.
        .target(
            name: "PhantomDemoKit",
            dependencies: ["PhantomProtocol"],
            path: "Sources/PhantomDemoKit",
            resources: [
                // The bundled pinned server public key. Replace the placeholder
                // with real bytes (see README.md keygen/pubkey step).
                .process("Resources")
            ]
        ),

        // The SwiftUI @main App + ContentView.
        .executableTarget(
            name: "PhantomDemoApp",
            dependencies: ["PhantomDemoKit"],
            path: "Sources/PhantomDemoApp"
        ),

        // Unit tests for the FFI-independent demo logic (hex, placeholder
        // detection, Keychain blob round-trip, interface classification).
        // Transitively needs the XCFramework + generated binding, like the rest
        // of the sample.
        .testTarget(
            name: "PhantomDemoKitTests",
            dependencies: ["PhantomDemoKit"],
            path: "Tests/PhantomDemoKitTests"
        ),
    ]
)
