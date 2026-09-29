// swift-tools-version:5.7
// Package.swift — SwiftPM manifest for the phantom_protocol UniFFI binding.
//
// Consumes a `PhantomProtocol.xcframework` built by build-xcframework.sh. The
// XCFramework holds the static `libphantom_protocol.a` slices for the three
// platforms declared below — iOS device, iOS simulator and macOS — together
// with `phantom_protocolFFI.h` and a `module.modulemap` that names the
// `phantom_protocolFFI` module the generated Swift imports. The header and the
// modulemap are staged into the framework by the build script, so SwiftPM
// consumers never see them as loose files.
//
// `platforms:` and the slice list in build-xcframework.sh are one decision in
// two places: a platform declared here without a slice in the framework
// resolves fine and then fails to link, so change them together.
//
// Building the XCFramework:
//     ./build-xcframework.sh
//
// Checking that the binding compiles against it (macOS host):
//     swift build
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
