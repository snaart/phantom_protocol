# Place the built XCFramework here

`Package.swift` declares:

```swift
.binaryTarget(name: "PhantomProtocolFFI", path: "Frameworks/PhantomProtocol.xcframework")
```

So the build expects:

```
Frameworks/PhantomProtocol.xcframework
```

This artifact is **not committed** — it is several megabytes of compiled Rust
static library per architecture, and it must track the current Rust source.
Build it locally (macOS + Xcode + the iOS Rust targets) per the top-level
`README.md`. Until it exists, `swift build` / Xcode resolution will fail with a
"missing binary target" error — that is expected for this sample, which is
verified locally rather than in CI.

The repository ships a ready-made build script that produces exactly this
artifact (device arm64 + a lipo'd simulator slice, with the UniFFI C headers
bundled):

```sh
# from the repository root
./tests/bindings/swift/build-xcframework.sh
# -> tests/bindings/swift/PhantomProtocol.xcframework

# then move/copy it next to this note:
cp -R tests/bindings/swift/PhantomProtocol.xcframework \
      examples/mobile/ios/Frameworks/PhantomProtocol.xcframework
```
