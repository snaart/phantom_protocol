// swift-tools-version:5.7
// Package.swift — SwiftPM manifest for the phantom_protocol UniFFI binding.
//
// Consumes a `PhantomProtocol.xcframework` built by build-xcframework.sh.
// The XCFramework holds the per-iOS-target static `libphantom_protocol.a`
// slices; this package wires it together with the generated Swift
// source (`phantom_protocol.swift`). `phantom_protocolFFI.h` and
// `phantom_protocolFFI.modulemap` are embedded inside the XCFramework by
// `xcodebuild -create-xcframework -headers ...`, so SwiftPM consumers
// do not see them as loose files.
//
// Building the XCFramework:
//     ./build-xcframework.sh
//
// Using in an app:
//     dependencies: [ .package(path: "path/to/tests/bindings/swift") ],
//     dependencies in target:
//         [ .product(name: "PhantomProtocol", package: "swift") ]

import PackageDescription

let package = Package(
    name: "PhantomProtocol",
    platforms: [.iOS(.v16), .macOS(.v13)],
    products: [
        .library(name: "PhantomProtocol", targets: ["PhantomProtocol"]),
    ],
    targets: [
        .binaryTarget(name: "PhantomProtocolFFI", path: "PhantomProtocol.xcframework"),
        .target(
            name: "PhantomProtocol",
            dependencies: ["PhantomProtocolFFI"],
            path: ".",
            exclude: [
                "LoopbackTest.swift",
                "build-xcframework.sh",
                "run_swift_test.sh",
                "PhantomProtocol.xcframework",
                "phantom_protocolFFI.h",
                "phantom_protocolFFI.modulemap",
            ],
            sources: ["phantom_protocol.swift"]
        ),
    ]
)
