//! # Phantom Protocol SDK
//!
//! Post-quantum secure L4/L6 universal transport framework.
//!
//! Provides:
//! - Hybrid key exchange (X25519 + ML-KEM-768; X-Wing-style combiner). Under
//!   `--features fips` the classical half swaps to ECDH-P-256.
//! - Hybrid signatures (Ed25519 + ML-DSA-65) — both halves must verify.
//! - PhantomUDP, a native reliable transport over raw UDP (the production
//!   transport), plus byte-pipe `SessionTransport` impls for TCP, browser
//!   WebSocket, WASI, embedded UART/USB, and an off-by-default TLS-mimicry leg.
//! - Seamless single-path connection migration (not multipath aggregation —
//!   that was deliberately rejected) with liveness detection and keep-alive PINGs.
//! - Stream multiplexing (reliable + unreliable).
//!
//! The core transmits only `Vec<u8>` / `Bytes`.
//! Serialization (JSON, Protobuf, etc.) is the user's responsibility.

// Security-friendly lints. Now `deny` (was `warn` until the codebase drove the
// remaining unannotated sites to zero). Every surviving panic-shaped call in
// production code carries an inline `// PANIC-SAFETY:` comment and a narrow
// `#[allow(clippy::unwrap_used)]` / `#[allow(clippy::expect_used)]` at the
// statement scope; the canonical inventory lives in `docs/security/panic-sites.md`.
// Tests opt in to `expect_used` for readable failure diagnostics.
//
// `clippy::indexing_slicing` is deliberately omitted at this stage — it fires
// on every constant-bounded array index and would generate too much noise.
// A bounds-check audit is tracked as a separate follow-up.
//
// On docs.rs — which sets `--cfg docsrs` on nightly via the
// `[package.metadata.docs.rs]` table — auto-generate "Available on crate
// feature X" badges for every `#[cfg(feature = …)]`-gated item. `doc_auto_cfg`
// was merged into `doc_cfg` in Rust 1.92, which now carries the auto-cfg
// behaviour. The attribute is inert on every normal (stable) build: `docsrs` is
// never set there, so the unstable `doc_cfg` feature is never requested.
#![cfg_attr(docsrs, feature(doc_cfg))]
// Pull the repository README into the crate-level rustdoc so docs.rs shows the
// full README rather than a thin stub. All code fences in the README use
// ```rust,no_run```, ```bash```, or ```text``` so they are not executed as
// doctests (they require a live peer and cannot run standalone).
//
// The path stays inside `core/` because it has to: a `cargo package` archive
// contains only what sits under the manifest directory, and there `src/lib.rs`
// is one level below the archive root rather than two below the repository
// root. `core/README.md` is a byte-identical copy of the repository-root
// `README.md`, kept in step by `scripts/sync_readme.sh` and by the
// `packaged_readme` tests further down this file.
#![doc = include_str!("../README.md")]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unreachable,
    clippy::todo,
    clippy::unimplemented,
    clippy::missing_safety_doc
)]
// Tests use `expect()` / `unwrap()` / `panic!()` freely so failures surface as
// readable diagnostics rather than swallowed `Result`s. The `deny` above only
// governs the production code path; this `cfg_attr(test, allow(...))` flips
// the same lints back to permissive for `cargo test` builds.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented,
        clippy::missing_safety_doc,
        // Same rationale: tests call `.unwrap()` on `Result` / `Option`
        // routinely; the disallowed-methods list in `.clippy.toml` is
        // for production code, not the test harness.
        clippy::disallowed_methods
    )
)]
// Deny `unsafe` by default at the crate root. The two modules that genuinely
// require `unsafe` (wasm-bindgen-generated JS-boundary glue in
// `transport::legs::websocket`, wasm32-only; `unsafe impl Send/Sync for
// WasiLeg` over WIT-bindgen `Resource<T>` socket handles in
// `transport::legs::wasi`, WASI-only) opt back in with a module-level
// `#![allow(unsafe_code)]` and per-block `// SAFETY:` comments. Both are
// cross-language-boundary glue; no native build compiles any `unsafe` at all.
// Audit note: any future PR touching `unsafe` outside those two modules will
// fail this lint and must justify itself explicitly.
#![deny(unsafe_code)]
// Phase 3.6: when neither `std` nor any std-implying feature is on, drop std
// from the crate root so a bare-metal `--no-default-features --features
// embedded,no-std` build links only `core` + `alloc`. The std build (the
// default) is unchanged.
#![cfg_attr(not(feature = "std"), no_std)]

// Phase 5.5 / A8 — the FIPS 140-3 primitive swap (X25519 → ECDH-P-256,
// ring → aws-lc-rs, blake3 → HKDF-SHA256, drop ChaCha20-Poly1305,
// CTR_DRBG RNG, POST hook) is **shipped**. `--features fips` now
// builds and serves a FIPS-substrate Phantom Protocol. The scaffold
// `compile_error!` from commit `d4d121b` is gone; the only
// remaining build-time gate enforces mutual exclusion with `no-std`,
// since `aws-lc-rs` requires libc + dlopen / OpenSSL ABI and cannot
// run on bare-metal.
#[cfg(all(feature = "fips", feature = "no-std"))]
compile_error!(
    "Cargo features `fips` and `no-std` are mutually exclusive — \
     `aws-lc-rs` (the FIPS-validated substrate) needs libc / dlopen \
     and does not build for bare-metal targets. Build either with \
     `--features fips` (FIPS posture, requires std) or with \
     `--features embedded,no-std` (no_std posture, default crypto)."
);

// The `wasi-leg` Cargo feature lives at the WASI target (the
// `wasi` crate's WIT bindings are only available there). Enabling it
// on `wasm32-unknown-unknown` (the browser target with WebSocketLeg /
// WasmRuntime) is a misconfiguration; fail the build loudly with a
// pointer at the recipe.
#[cfg(all(feature = "wasi-leg", target_arch = "wasm32", not(target_os = "wasi")))]
compile_error!(
    "The `wasi-leg` Cargo feature is only supported on WASI targets \
     (wasm32-wasi, wasm32-wasip1, wasm32-wasip2). For \
     wasm32-unknown-unknown (browser) builds use the default feature \
     set, which exposes the `WebSocketLeg` + `WasmRuntime` surface \
     instead."
);

#[cfg(not(feature = "std"))]
extern crate alloc;

// `errors` and the `transport::session_transport` / `transport::legs::embedded`
// subtree are no_std-clean and compile under both feature configurations.
mod errors;

// ── std-only top-level modules ─────────────────────────────────────────
// The bare-metal subset (Phase 3.6) compiles only `errors` and the embedded
// transport subset. Everything below is gated behind `std`: it either uses
// `tokio`, `parking_lot`, `dashmap`, raw sockets, `std::time::Instant`,
// `std::sync::*`, or a std-bound dep (e.g. `ml-kem`, the classical-crypto
// `ring` / `x25519-dalek`) that is itself only compiled when `std` is on.

#[cfg(feature = "std")]
pub mod config;
#[cfg(feature = "std")]
pub mod observability;
#[cfg(feature = "std")]
pub mod security;
#[cfg(feature = "std")]
pub mod validation;

// Crypto module (hybrid KEM, hybrid sign) — std-only: pulls `ed25519-dalek`,
// `ml-kem`, `ml-dsa` unconditionally, plus `ring` + `x25519-dalek` via the
// default-on `classical-crypto` feature. Under `--features fips` the classical
// substrate swaps to `aws-lc-rs` (`ring` / `x25519-dalek` dropped entirely).
#[cfg(feature = "std")]
pub mod crypto;

// Transport module (Phantom Protocol transport). The module itself has a
// no_std-clean subset (`session_transport`, `legs::embedded`). The rest of the
// sub-modules opt into `std` from within `transport/mod.rs`.
pub mod transport;

// Async runtime abstraction (Phase 3.1). `TokioRuntime` is the default
// implementation; `WasmRuntime` (browser), `EmbeddedRuntime` (host-thread
// scaffold), and `WasiRuntime` (WASI Preview 2) are the shipped alternate
// backends, injected via the `_with_runtime` API variants.
#[cfg(feature = "std")]
pub mod runtime;

// Public API facade — std-only: every entry point (`PhantomSession`,
// `PhantomListener`, `TcpSessionTransport`) depends on `tokio`.
#[cfg(feature = "std")]
pub mod api;

// Test harness for network simulation
#[cfg(all(test, feature = "std"))]
pub mod test_harness;

// Public exports
#[cfg(feature = "std")]
pub use config::PhantomConfig;
pub use errors::CoreError;

// Re-export the one-shot connect helpers at the crate root so callers can write
// `phantom_protocol::connect_pinned_udp(...)` without qualifying the module path.
// Native-only: the free functions live behind `cfg(not(target_arch = "wasm32"))`.
#[cfg(all(feature = "std", not(target_arch = "wasm32")))]
pub use api::session::{
    connect_pinned, connect_pinned_udp, connect_pinned_udp_with_config,
    connect_pinned_udp_with_resumption, connect_pinned_with_config, connect_pinned_with_resumption,
};

// UniFFI scaffolding. Gated on the `bindings` feature so the WASI
// guest build (which sets `--features wasi-leg` without `bindings`)
// skips it — UniFFI's exported-symbol metadata is incompatible with
// `wasm-component-ld`, the wasm32-wasip2 linker. Default builds keep
// `bindings` active, so the native FFI consumers (Swift / Kotlin /
// Python / C bindings) see the historical surface unchanged.
#[cfg(feature = "bindings")]
uniffi::setup_scaffolding!();

/// Keeps the crate's landing page reachable from inside the published archive.
///
/// A `cargo package` tarball contains only what sits under the manifest directory,
/// and inside it `src/lib.rs` is one level below the archive root where in the
/// repository it is two levels below the repository root. A relative path that
/// leaves `core/` therefore resolves to different files in the two layouts — in the
/// archive it addresses the parent of the extracted directory, which is whatever the
/// build host happened to have there. That is not a path that can be made correct on
/// both sides: the only paths that survive packaging are the ones that stay inside
/// the package, so the landing page has to exist there as a file.
///
/// It does, as `core/README.md`, kept byte-identical to the repository-root
/// `README.md`. Duplication rather than a symlink, because a checkout without
/// symlink support turns the link into a twelve-byte file whose entire contents are
/// the text `../README.md`; `include_str!` compiles that happily and both crates.io
/// and the docs.rs front page then ship the string, with every exit code zero. A
/// duplicate cannot fail that way — it can only drift, and drift is what the two
/// tests below and `scripts/sync_readme.sh` exist to make impossible.
#[cfg(test)]
mod packaged_readme {
    /// The repository-root README: the page GitHub renders, and the one the
    /// `#![doc]` attribute at the top of this file inlines into the crate docs.
    const LANDING_PAGE: &str = include_str!("../../README.md");

    /// The copy that travels inside the archive. `core/Cargo.toml`'s
    /// `readme = "README.md"` resolves relative to the manifest directory, so this
    /// is the file crates.io renders — and the only README a tarball carries.
    const PACKAGED: &str = include_str!("../README.md");

    /// This file's own source, so the attribute's argument can be read as text.
    /// Nothing else can see it: `include_str!` leaves no trace of its argument in
    /// the expansion, so a path that escapes the package is invisible to the
    /// compiler on this side of packaging and only surfaces minutes into the cold
    /// verification build of an extracted crate.
    const SOURCE: &str = include_str!("lib.rs");

    /// The literal opening of the crate-level doc attribute. Written with an escaped
    /// quote, so this constant's own text does not match the pattern it carries and
    /// the search below cannot find itself.
    const DOC_INCLUDE: &str = "#![doc = include_str!(\"";

    /// The path named by the crate-level doc attribute.
    fn crate_doc_include_path(source: &str) -> Option<&str> {
        let rest = source.split_once(DOC_INCLUDE)?.1;
        rest.split_once('"').map(|(path, _)| path)
    }

    /// Where `path`, read from `core/src/`, lands inside the package — as components
    /// below `core/` — or `None` if the walk ever rises above `core/`.
    ///
    /// The verdict is about the traversal, not the destination. `core/` is the
    /// archive root, so there is nothing above it to descend from: a path that
    /// leaves and comes back names a file that exists in a repository checkout and
    /// does not exist in an extracted crate, and `cargo package` fails on it with
    /// `couldn't read src/../../core/README.md`. Judging where the path lands
    /// cannot tell that apart from a path that never left, because both land on the
    /// same file here. So the stack below starts at `["src"]` — rooted at `core`,
    /// not at the repository — and popping it empty is fatal on the spot, however
    /// the rest of the path continues.
    fn resolve_from_core_src(path: &str) -> Option<Vec<&str>> {
        let mut below_core = vec!["src"];
        for part in path.split('/') {
            match part {
                "" | "." => {}
                ".." => {
                    below_core.pop()?;
                }
                name => below_core.push(name),
            }
        }
        Some(below_core)
    }

    /// The two copies must agree byte for byte, or the page crates.io renders is not
    /// the page this repository maintains. The failure is stated in sizes rather than
    /// as a diff: the way this goes wrong is that one file is edited and the other is
    /// forgotten, and the sizes say which one at a glance.
    #[test]
    fn packaged_readme_is_the_landing_page() {
        assert_eq!(
            PACKAGED,
            LANDING_PAGE,
            "core/README.md ({} bytes) has drifted from README.md ({} bytes); \
             run scripts/sync_readme.sh",
            PACKAGED.len(),
            LANDING_PAGE.len()
        );
    }

    /// The attribute's argument must stay inside `core/` for the whole of its walk.
    /// Checking the text rather than the resolved contents is deliberate: in this
    /// working copy `../README.md`, `../../README.md` and `../../core/README.md` all
    /// compile, and the first and third even inline the same bytes, so no assertion
    /// about the inlined string can tell them apart. Only the shape of the path can.
    #[test]
    fn crate_doc_include_stays_inside_the_package() {
        assert_eq!(
            SOURCE.matches(DOC_INCLUDE).count(),
            1,
            "expected exactly one crate-level `#![doc = include_str!(\"…\")]`; \
             a second one would be unchecked here"
        );

        let path = crate_doc_include_path(SOURCE)
            .expect("lib.rs carries a crate-level `#![doc = include_str!(\"…\")]`");

        let landed = resolve_from_core_src(path);
        assert!(
            landed.is_some(),
            "`#![doc = include_str!(\"{path}\")]` walks above core/, so the file it \
             names is absent from the crate archive and `cargo package` cannot \
             compile the lib — even if the path descends back into core/ afterwards, \
             because in the archive core/ is the root"
        );
    }

    /// The resolver is what decides the verdict above, so a resolver that answered
    /// "inside the package" for everything would leave that test green forever.
    ///
    /// The cases that matter are the ones that leave `core/` and come back.
    /// `../../core/README.md` is what a contributor writes when thinking from the
    /// repository root, and it addresses the right file *here* — so a resolver that
    /// judges the destination accepts it, and `cargo package` then fails on
    /// `couldn't read src/../../core/README.md`, which is the exact failure this
    /// whole mechanism exists to prevent. The verdict has to be about the walk.
    #[test]
    fn resolver_rejects_every_path_that_leaves_core() {
        // Escapes and returns. Lands on a file that exists in this checkout and
        // is absent from the archive, because in the archive there is nothing
        // above the package root to descend from.
        assert_eq!(resolve_from_core_src("../../core/README.md"), None);
        assert_eq!(resolve_from_core_src("../../core/src/../README.md"), None);
        assert_eq!(
            resolve_from_core_src("../../core/src/api/../../README.md"),
            None
        );

        // Escapes, and never returns.
        assert_eq!(resolve_from_core_src("../../README.md"), None);
        assert_eq!(resolve_from_core_src("../../../README.md"), None);

        // Inside, and where the crate-level attribute actually points.
        assert_eq!(
            resolve_from_core_src("../README.md"),
            Some(vec!["README.md"])
        );
        assert_eq!(
            resolve_from_core_src("./api/mod.rs"),
            Some(vec!["src", "api", "mod.rs"])
        );
        // Dips to the package root and descends again without ever rising above it.
        // A resolver that merely refused any `..` would reject this, and it is
        // correct: the walk touches `core/` but never rises past it.
        assert_eq!(
            resolve_from_core_src("api/../../README.md"),
            Some(vec!["README.md"])
        );
    }
}

/// Keeps the version bytes stated in prose tied to the constants they describe.
///
/// Three documents outside the code name `WIRE_VERSION` and `PROTOCOL_VERSION` as
/// values rather than as names, and prose does not move when a constant does. No
/// other test notices: the wire vectors pin bytes, not sentences. The last bump
/// left two of these three documents naming a wire the code had stopped speaking.
///
/// # Why the check reads markers and not sentences
///
/// The obvious gate — find the constant's name, read the number near it, compare —
/// cannot work, because whether a number is a claim about today is a fact about the
/// sentence, not about the number. All three of these are true and two of them name
/// a version the code does not speak:
///
/// - "the `WIRE_VERSION` 6 → 7 bump landed in 0.3"
/// - "captured under `WIRE_VERSION = 2`, whereas the shipped format is 7"
/// - "the shipped format is 7 (`WIRE_VERSION`)"
///
/// A parser guessing at those gets some wrong in each direction, and the two
/// directions are not equally priced. A missed drift is caught by the next person
/// who reads the document. A false alarm fails `--lib`, which is a required
/// branch-protection context, and the only way past it is to rewrite a sentence
/// that was already correct — so the gate would be teaching contributors that the
/// prose serves the parser. That trade is bad enough that this gate does not read
/// prose at all.
///
/// Instead a claim is marked where it is made. Immediately before the digits, and
/// nowhere else, the author writes an HTML comment naming the constant:
///
/// ```text
/// The current on-wire format is **WIRE_VERSION=<!--pinned:WIRE_VERSION-->7**.
/// ```
///
/// Markdown renders the comment as nothing, so the sentence reads unchanged on
/// GitHub, on docs.rs (this README is inlined by the `#![doc]` above), and in a
/// terminal. The gate checks exactly the marked digits and is blind to every other
/// number in the file — which is what makes the three sentences above sayable, in
/// any wording, forever. Marking a claim is therefore a decision the author makes,
/// not one a parser makes for them.
///
/// The cost of that choice — what a marker-only gate cannot see — is stated
/// plainly on `marked_claims_state_the_pinned_versions` below.
#[cfg(test)]
mod pinned_version_claims {
    use crate::transport::{handshake::PROTOCOL_VERSION, types::WIRE_VERSION};

    /// The marker's two halves. `pinned:` names what the marker asserts — that the
    /// digits which follow are a constant the code pins, not free prose.
    const OPEN: &str = "<!--pinned:";
    const CLOSE: &str = "-->";

    /// A document that states pinned version bytes in prose.
    ///
    /// `text` is inlined at compile time, so renaming or deleting a listed document
    /// is a build failure rather than a check that quietly stops running. These
    /// paths reach outside `core/`, where nothing survives packaging — the archive
    /// carries only what sits under the manifest directory, and its `README.md` is
    /// the `core/README.md` copy rather than the file addressed here. That costs
    /// nothing, because `cargo package` verifies by building the crate and a build
    /// never compiles a `cfg(test)` module. Production code cannot borrow the same
    /// licence: see `packaged_readme` above, which is why the `#![doc]` attribute at
    /// the top of this file reads its README from inside `core/`.
    struct VersionedDoc {
        path: &'static str,
        text: &'static str,
        /// Constants this document must keep at least one marked claim for, so that
        /// deleting the sentence is not a way to pass. It is a field rather than a
        /// path compared against a literal, because the next document added here
        /// would otherwise inherit whatever the literal happened to exempt.
        must_claim: &'static [&'static str],
    }

    const DOCS: &[VersionedDoc] = &[
        VersionedDoc {
            path: "README.md",
            text: include_str!("../../README.md"),
            must_claim: &["WIRE_VERSION", "PROTOCOL_VERSION"],
        },
        VersionedDoc {
            path: "BENCHMARKS.md",
            text: include_str!("../../BENCHMARKS.md"),
            must_claim: &["WIRE_VERSION"],
        },
        VersionedDoc {
            path: "docs/operations/deployment.md",
            text: include_str!("../../docs/operations/deployment.md"),
            must_claim: &["WIRE_VERSION", "PROTOCOL_VERSION"],
        },
    ];

    /// The value the code pins for a constant a marker may name, or `None` for a
    /// name this gate does not know. An unknown name is reported rather than
    /// ignored: a typo in the marker would otherwise disable the claim silently,
    /// which is the failure the gate exists to prevent, one level up.
    fn pinned(name: &str) -> Option<u8> {
        match name {
            "WIRE_VERSION" => Some(WIRE_VERSION),
            "PROTOCOL_VERSION" => Some(PROTOCOL_VERSION),
            _ => None,
        }
    }

    /// One marker found in a document: the constant it names, the digit run written
    /// immediately after it (empty when the author left none), and where to look.
    struct Marked<'a> {
        name: &'a str,
        digits: &'a str,
        line: usize,
    }

    /// Every marker in `text`, in source order.
    ///
    /// Deliberately total and unconditional: it never decides that some occurrence
    /// does not count. Everything it reports is checked, and everything it does not
    /// report was never written as a claim.
    fn marked<'a>(text: &'a str) -> Vec<Marked<'a>> {
        let mut found = Vec::new();
        let mut cursor = 0usize;
        while let Some(rel) = text[cursor..].find(OPEN) {
            let at = cursor + rel;
            let body = &text[at + OPEN.len()..];
            cursor = at + OPEN.len();
            // A marker is one line by construction; letting the terminator be found
            // across a line break would let an unterminated marker swallow the rest
            // of the document and name a "constant" spanning half a paragraph.
            let Some(end) = body.find(CLOSE) else {
                continue;
            };
            if body[..end].contains('\n') {
                continue;
            }
            let after = &body[end + CLOSE.len()..];
            let digits = after
                .find(|c: char| !c.is_ascii_digit())
                .map_or(after, |stop| &after[..stop]);
            found.push(Marked {
                name: &body[..end],
                digits,
                line: text[..at].bytes().filter(|b| *b == b'\n').count() + 1,
            });
            cursor = at + OPEN.len() + end;
        }
        found
    }

    /// The whole physical line containing 1-based `line`, untrimmed, so a report can
    /// quote the sentence back instead of only pointing at it — and so the leading
    /// whitespace stays readable to the placement rule below.
    fn line_text(text: &str, line: usize) -> &str {
        text.lines().nth(line.saturating_sub(1)).unwrap_or("")
    }

    /// Everything wrong with one document, as sentences an author can act on.
    ///
    /// Collected rather than asserted one at a time: a version bump invalidates
    /// every marked claim at once, and a gate that stops at the first one turns a
    /// single edit into a series of rebuilds.
    fn problems(doc: &VersionedDoc, into: &mut Vec<String>) {
        let mut claimed: Vec<&str> = Vec::new();
        for mark in marked(doc.text) {
            let at = format!("{}:{}", doc.path, mark.line);
            let raw = line_text(doc.text, mark.line);
            let quoted = raw.trim();
            // A line whose first non-blank characters are `<!--` opens a CommonMark
            // HTML block, and the block swallows the rest of that line as raw HTML:
            // the paragraph is cut in two and the inline markup on the line stops
            // rendering. The marker is invisible only while it stays inside a line,
            // so where it sits is part of the convention rather than a matter of
            // taste, and the wrapping that puts it at a line start is the kind of
            // edit nobody looks at twice.
            if raw.trim_start().starts_with(OPEN) {
                into.push(format!(
                    "{at}: the marker starts its line, which opens a CommonMark HTML \
                     block and breaks the paragraph where it renders. Move it after \
                     at least one word — rewrap the line if need be.\n    {quoted}"
                ));
                continue;
            }
            let Some(expected) = pinned(mark.name) else {
                into.push(format!(
                    "{at}: marker names `{}`, which is not a constant this gate \
                     knows. It checks WIRE_VERSION and PROTOCOL_VERSION; add the \
                     constant to `pinned()` or fix the spelling.\n    {quoted}",
                    mark.name
                ));
                continue;
            };
            claimed.push(mark.name);
            if mark.digits.is_empty() {
                into.push(format!(
                    "{at}: the `{}` marker is not followed by digits. It must sit \
                     immediately before the number it certifies, with nothing in \
                     between — not even a backtick, since a marker inside a code \
                     span would render as literal text.\n    {quoted}",
                    mark.name
                ));
                continue;
            }
            if mark.digits.parse::<u16>() != Ok(u16::from(expected)) {
                into.push(format!(
                    "{at}: states {} = {}, but the code pins {expected}. Correct the \
                     number here, or — if this sentence is about a past version — \
                     drop the marker, which is what tells this gate the number is \
                     not a claim about today.\n    {quoted}",
                    mark.name, mark.digits
                ));
            }
        }
        for required in doc.must_claim {
            if !claimed.contains(required) {
                into.push(format!(
                    "{}: no marked claim for {required} is left. Restore it as \
                     `{OPEN}{required}{CLOSE}<value>` next to the sentence that \
                     states the version, so deleting the sentence cannot be the way \
                     this check passes.",
                    doc.path
                ));
            }
        }
    }

    /// Every marked claim in every listed document states the pinned value, and
    /// every document still carries the claims it is supposed to make.
    ///
    /// What this does **not** cover, stated so nobody mistakes a green run for
    /// more: a version stated in prose with no marker beside it is invisible here,
    /// and so is a version stated in a document not listed in `DOCS`. Both are
    /// deliberate — they are the price of never failing on a sentence that is true
    /// — and both are bounded by the coverage rule above, which keeps each listed
    /// document making at least one claim the gate does watch. So a bump can still
    /// leave an unmarked sentence stale; it cannot leave the document untouched.
    #[test]
    fn marked_claims_state_the_pinned_versions() {
        let mut found = Vec::new();
        for doc in DOCS {
            problems(doc, &mut found);
        }
        assert!(
            found.is_empty(),
            "the documented version bytes no longer match the code:\n\n{}\n",
            found.join("\n")
        );
    }

    /// The scanner decides what the gate can see, so its blind spots and its teeth
    /// are pinned here rather than left to be rediscovered. An accident in `marked`
    /// disarms the test above without failing anything.
    #[test]
    fn the_scanner_reads_marked_digits_and_nothing_else() {
        // True sentences that name a number the code does not pin. Each one broke a
        // sentence-reading version of this gate; none of them is visible to this one.
        for invisible in [
            "the `WIRE_VERSION` 6 → 7 bump landed in 0.3",
            "captured under `WIRE_VERSION = 2`, whereas the shipped format is 7",
            "the shipped format is 7 (`WIRE_VERSION`)",
            "`WIRE_VERSION` was 6 before the anti-fingerprint pass",
        ] {
            assert!(
                marked(invisible).is_empty(),
                "unmarked prose must not be read as a claim: {invisible:?}"
            );
        }

        // Wording is the author's business; the marker is the whole interface. Each
        // of these is one claim of 7, however the sentence around it is phrased.
        for phrasing in [
            "`WIRE_VERSION` is <!--pinned:WIRE_VERSION-->7",
            "`WIRE_VERSION` is now <!--pinned:WIRE_VERSION-->7, bumped from 6",
            "**WIRE_VERSION=<!--pinned:WIRE_VERSION-->7**",
            "| wire | `WIRE_VERSION` = <!--pinned:WIRE_VERSION-->7 — pinned |",
        ] {
            let marks = marked(phrasing);
            assert_eq!(marks.len(), 1, "one claim expected in {phrasing:?}");
            assert_eq!(marks[0].name, "WIRE_VERSION");
            assert_eq!(marks[0].digits, "7", "read from {phrasing:?}");
        }

        // Two claims on one line, as the deployment table writes them, with the
        // second marker's digits read from after the second marker and not the first.
        let table = "| `WIRE_VERSION` = <!--pinned:WIRE_VERSION-->7, \
                     `PROTOCOL_VERSION` = <!--pinned:PROTOCOL_VERSION-->4 |";
        let marks = marked(table);
        assert_eq!(marks.len(), 2);
        assert_eq!((marks[0].name, marks[0].digits), ("WIRE_VERSION", "7"));
        assert_eq!((marks[1].name, marks[1].digits), ("PROTOCOL_VERSION", "4"));

        // Line numbers are what makes a failure actionable in a file that says
        // WIRE_VERSION eight times.
        let multiline = "one\ntwo\nthree <!--pinned:WIRE_VERSION-->7\n";
        assert_eq!(marked(multiline)[0].line, 3);
        assert_eq!(line_text(multiline, 3), "three <!--pinned:WIRE_VERSION-->7");
    }

    /// The three ways a marked document can be wrong, checked against synthetic
    /// text so the evidence survives without having to break a real document.
    #[test]
    fn a_marked_claim_that_drifts_is_reported_with_its_location() {
        let stale = VersionedDoc {
            path: "STALE.md",
            text: "the wire is WIRE_VERSION=<!--pinned:WIRE_VERSION-->6 today",
            must_claim: &["WIRE_VERSION"],
        };
        let mut found = Vec::new();
        problems(&stale, &mut found);
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].starts_with("STALE.md:1: states WIRE_VERSION = 6, but"));
        assert!(
            found[0].contains(&format!("the code pins {WIRE_VERSION}")),
            "{}",
            found[0]
        );

        // Deleting the sentence must not be the way to pass.
        let silent = VersionedDoc {
            path: "SILENT.md",
            text: "no version is stated here at all",
            must_claim: &["PROTOCOL_VERSION"],
        };
        found.clear();
        problems(&silent, &mut found);
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].contains("no marked claim for PROTOCOL_VERSION"));

        // A marker whose digits ended up inside a code span certifies nothing, a
        // misspelled constant would silently certify nothing either, and a marker
        // rewrapped to the start of its line breaks the rendering it is supposed to
        // stay invisible in.
        let misplaced = VersionedDoc {
            path: "MISPLACED.md",
            text: "`WIRE_VERSION` is <!--pinned:WIRE_VERSION-->`7`\n\
                   `WIRE_VERSION` is <!--pinned:WIRE_VESRION-->7\n\
                   the wire is\n  <!--pinned:WIRE_VERSION-->7 today",
            must_claim: &[],
        };
        found.clear();
        problems(&misplaced, &mut found);
        assert_eq!(found.len(), 3, "{found:?}");
        assert!(found[0].contains("is not followed by digits"));
        assert!(found[1].contains("not a constant this gate knows"));
        assert!(found[2].contains("starts its line"), "{}", found[2]);
    }
}
