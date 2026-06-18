# Place the generated UniFFI Swift binding here

This directory is the `PhantomProtocol` SwiftPM target. It must contain the
**auto-generated** Swift binding before the package will compile:

```
Sources/PhantomProtocol/
  phantom_protocol.swift      <-- copy this in (NOT committed here)
```

## Where the file comes from

The binding is generated from the Rust core by the UniFFI bindgen
(`core/src/bin/uniffi-bindgen.rs`, uniffi 0.29). The repository keeps a
freshly-generated copy under:

```
tests/bindings/swift/phantom_protocol.swift
```

Copy it into this directory:

```sh
# from the repository root
cp tests/bindings/swift/phantom_protocol.swift \
   examples/mobile/ios/Sources/PhantomProtocol/phantom_protocol.swift
```

Regenerate the binding after any change to the Rust public surface:

```sh
./tests/generate_swift.sh
```

## Why it is not committed in this sample

The generated binding is a build artifact whose single source of truth lives in
`tests/bindings/swift/`. Committing a second copy here would drift the moment the
Rust surface changes. The sample therefore ships only this note plus a `.gitkeep`;
you copy the current binding in as part of the local build (see the top-level
`README.md`).

The C headers (`phantom_protocolFFI.h`, `phantom_protocolFFI.modulemap`) live
inside `Frameworks/PhantomProtocol.xcframework` — they are bundled into the
XCFramework's `-headers` directory by `tests/bindings/swift/build-xcframework.sh`,
so they do not need to be copied here.
