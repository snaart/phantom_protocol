// swift-tools-version:5.7
// Package.swift — SwiftPM manifest for the phantom_core UniFFI binding.
//
// Consumes a `PhantomCore.xcframework` built by build-xcframework.sh.
// The XCFramework holds the per-iOS-target static `libphantom_core.a`
// slices; this package wires it together with the generated Swift
// source (`phantom_core.swift`). `phantom_coreFFI.h` and
// `phantom_coreFFI.modulemap` are embedded inside the XCFramework by
// `xcodebuild -create-xcframework -headers ...`, so SwiftPM consumers
// do not see them as loose files.
//
// Building the XCFramework:
//     ./build-xcframework.sh
//
// Using in an app:
//     dependencies: [ .package(path: "path/to/tests/bindings/swift") ],
//     dependencies in target:
//         [ .product(name: "PhantomCore", package: "swift") ]

import PackageDescription

let package = Package(
    name: "PhantomCore",
    platforms: [.iOS(.v16), .macOS(.v13)],
    products: [
        .library(name: "PhantomCore", targets: ["PhantomCore"]),
    ],
    targets: [
        .binaryTarget(name: "PhantomCoreFFI", path: "PhantomCore.xcframework"),
        .target(
            name: "PhantomCore",
            dependencies: ["PhantomCoreFFI"],
            path: ".",
            exclude: [
                "LoopbackTest.swift",
                "build-xcframework.sh",
                "run_swift_test.sh",
                "PhantomCore.xcframework",
                "phantom_coreFFI.h",
                "phantom_coreFFI.modulemap",
            ],
            sources: ["phantom_core.swift"]
        ),
    ]
)
