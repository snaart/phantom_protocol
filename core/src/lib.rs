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
// The Rust fences carry no `# ` hidden lines, and must not gain any. rustdoc
// strips them, but this same file is what crates.io renders as CommonMark,
// which has no such convention and prints them; the `packaged_readme` tests
// below hold the two renderers to the same text.
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

// `--no-default-features` with nothing named enters the bare-metal branch above,
// because that branch is selected by the *absence* of `std` rather than by any
// affirmative choice. On a host target the build then fails inside `core` with
// "no global memory allocator found", "`#[panic_handler]` function required" and
// "unwinding panics are not supported without std" — three errors that name
// nothing this crate's consumer can act on, and that a consumer reasonably reads
// as the library being broken rather than as a feature set that was never
// selected. The `no-std` feature is the affirmative marker for that branch, so
// its absence alongside `std`'s is the misconfiguration.
#[cfg(all(not(feature = "std"), not(feature = "no-std")))]
compile_error!(
    "No Phantom Protocol feature set was selected: `--no-default-features` \
     switched off `std` and nothing turned it, or the bare-metal subset, back \
     on. Name one. A host build: `--features std,classical-crypto` (add \
     `bindings` for the UniFFI surface and `compression-zstd` for the zstd \
     algorithm menu), or drop `--no-default-features` and take the default set. \
     A FIPS host build: `--features fips,bindings`. Bare metal: \
     `--features embedded,no-std`."
);

// A `std` build needs one of the two crypto substrates. `classical-crypto` gives
// it `ring` + `x25519-dalek`; `fips` gives it `aws-lc-rs` with ECDH-P-256 in
// place of X25519. Neither is implied by `std` — deliberately, so the `fips`
// build (which implies `std`) can drop the classical crates entirely — with the
// result that `--no-default-features --features std` alone compiles a crate whose
// AEAD and classical KEM have no implementation, and fails with five errors
// inside `crypto/` whose first line is `unresolved module or unlinked crate
// `ring``. That reads as a missing dependency rather than as the one-word feature
// it is.
#[cfg(all(
    feature = "std",
    not(feature = "classical-crypto"),
    not(feature = "fips")
))]
compile_error!(
    "A `std` build of Phantom Protocol needs a crypto substrate, and `std` \
     implies neither (so that the FIPS build can drop the classical crates). \
     Add `classical-crypto` for the default substrate (X25519 + ML-KEM-768, \
     `ring` AEAD) or `fips` for the FIPS-140-3 one (ECDH-P-256 + ML-KEM-768, \
     `aws-lc-rs` AEAD, ChaCha20-Poly1305 refused). The two do not interoperate \
     on the wire — their handshakes advertise different `PROTOCOL_VARIANT` \
     tags — so this is a deployment-wide choice, not a build detail."
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

// The types a caller has to name to use the crate-root entry points, re-exported
// beside them.
//
// `CoreError` and `PhantomConfig` were here and the rest were not, which made the
// import a reader writes from the signature of a crate-root function fail:
// `connect_pinned_udp` hands back an `Arc<PhantomSession>`, the session answers
// with a `ConnectionState`, opens a `PhantomStream` and produces a
// `ResumptionHint` that the resuming entry point takes back — and every one of
// those lived only at `phantom_protocol::api::…`, so `use
// phantom_protocol::ConnectionState;` did not compile while
// `use phantom_protocol::CoreError;` did. Nothing is moved: these are additions,
// and the `api::` paths keep working.
#[cfg(feature = "std")]
pub use api::{
    ConnectionState, PaddingPolicy, PhantomSession, PhantomStream, ResumptionHint,
    TrafficShapingConfig,
};
/// The flat metrics record [`PhantomSession::metrics_snapshot`] returns.
#[cfg(feature = "std")]
pub use observability::MetricsSnapshotFfi;

// The server-side surface and the one-shot connect helpers. Native-only: the
// listeners and the free functions all live behind
// `cfg(not(target_arch = "wasm32"))`, so a browser-wasm build sees neither here
// nor under `api::`.
#[cfg(all(feature = "std", not(target_arch = "wasm32")))]
pub use api::session::{
    connect_pinned, connect_pinned_udp, connect_pinned_udp_with_config,
    connect_pinned_udp_with_resumption, connect_pinned_with_config, connect_pinned_with_resumption,
};
#[cfg(all(feature = "std", not(target_arch = "wasm32")))]
pub use api::{AcceptOutcome, PhantomListener, PhantomUdpListener};

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
///
/// The license text is in the same position for a different reason. The manifest's
/// `license = "Apache-2.0"` names the license by its SPDX identifier and carries no
/// text, so an archive built from `core/` alone ships none — while Apache-2.0 §4(a)
/// requires every redistribution to give its recipients a copy. `core/LICENSE` is a
/// byte copy of the repository-root `LICENSE`, mirrored by the same script and held
/// to it by `packaged_license_is_the_repository_license`.
#[cfg(test)]
mod packaged_readme {
    /// The repository-root README: the page GitHub renders, and the one the
    /// `#![doc]` attribute at the top of this file inlines into the crate docs.
    const LANDING_PAGE: &str = include_str!("../../README.md");

    /// The copy that travels inside the archive. `core/Cargo.toml`'s
    /// `readme = "README.md"` resolves relative to the manifest directory, so this
    /// is the file crates.io renders — and the only README a tarball carries.
    const PACKAGED: &str = include_str!("../README.md");

    /// The repository-root license text, the one GitHub shows and the source of
    /// truth for the copy below.
    const REPOSITORY_LICENSE: &str = include_str!("../../LICENSE");

    /// The license text inside the archive, and the only one a `.crate` carries.
    /// Named directly, so deleting the copy is a build failure of this module
    /// rather than a test that quietly compares nothing.
    const PACKAGED_LICENSE: &str = include_str!("../LICENSE");

    /// This file's own source, so the attribute's argument can be read as text.
    /// Nothing else can see it: `include_str!` leaves no trace of its argument in
    /// the expansion, so a path that escapes the package is invisible to the
    /// compiler on this side of packaging and only surfaces minutes into the cold
    /// verification build of an extracted crate.
    const SOURCE: &str = include_str!("lib.rs");

    /// The crate manifest, which is inside the package and so readable from here.
    /// Read as text for one key: nothing else in this file, in the sync script, or
    /// in the archive assertion is derived from it, and the whole arrangement is
    /// built on what it says.
    const MANIFEST: &str = include_str!("../Cargo.toml");

    /// The file name every other part of this arrangement assumes: the copy under
    /// the manifest directory, the target of `scripts/sync_readme.sh`, and the
    /// archive entry the packaging job compares against the landing page.
    const PACKAGED_FILE_NAME: &str = "README.md";

    /// The literal opening of the crate-level doc attribute. Written with an escaped
    /// quote, so this constant's own text does not match the pattern it carries and
    /// the search below cannot find itself.
    const DOC_INCLUDE: &str = "#![doc = include_str!(\"";

    /// The path named by the crate-level doc attribute.
    fn crate_doc_include_path(source: &str) -> Option<&str> {
        let rest = source.split_once(DOC_INCLUDE)?.1;
        rest.split_once('"').map(|(path, _)| path)
    }

    /// Whether `path` is anchored at a filesystem root rather than at the file that
    /// names it.
    ///
    /// Three spellings, because the argument is only text and the machine that wrote
    /// it is not necessarily the machine that reads it: a leading `/`, a Windows
    /// drive letter, and a UNC share. A backslash anywhere is treated as a root
    /// anchor too — it is a separator this resolver does not model, and refusing a
    /// path it cannot walk is the only answer it can give honestly.
    fn is_root_anchored(path: &str) -> bool {
        let drive_letter = path
            .split('/')
            .next()
            .is_some_and(|first| first.len() == 2 && first.ends_with(':'));
        path.starts_with('/') || path.contains('\\') || drive_letter
    }

    /// Where `path`, read from a file whose directory is `start` components below
    /// `core/`, lands inside the package — or `None` if it does not stay inside
    /// `core/` for the whole of its walk.
    ///
    /// The verdict is about the traversal, not the destination. `core/` is the
    /// archive root, so there is nothing above it to descend from: a path that
    /// leaves and comes back names a file that exists in a repository checkout and
    /// does not exist in an extracted crate, and `cargo package` fails on it with
    /// `couldn't read src/../../core/README.md`. Judging where the path lands
    /// cannot tell that apart from a path that never left, because both land on the
    /// same file here. So the stack below starts at the naming file's own directory
    /// — rooted at `core`, not at the repository — and popping it empty is fatal on
    /// the spot, however the rest of the path continues.
    ///
    /// An absolute path is rejected before the walk begins, and it has to be,
    /// because counting `..` cannot see it: it never rises above anything. Left to
    /// the loop, its leading empty component would be skipped by the same arm that
    /// tolerates `./` and a doubled slash, and `/Users/someone/README.md` would
    /// resolve to `src/Users/someone/README.md` — a location inside the package, and
    /// a verdict of "fine". Nothing downstream disagrees either: `cargo package`
    /// verifies by building the extracted crate on the host that wrote the path,
    /// where the path still resolves, so the archive is built, published, and
    /// unbuildable everywhere else.
    fn resolve_below_core<'a>(start: &[&'a str], path: &'a str) -> Option<Vec<&'a str>> {
        if is_root_anchored(path) {
            return None;
        }
        let mut below_core = start.to_vec();
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

    /// The same verdict for the common case: a path written in a file that sits
    /// directly in `core/src/`.
    fn resolve_from_core_src(path: &str) -> Option<Vec<&str>> {
        resolve_below_core(&["src"], path)
    }

    /// The two macros that name a file from inside a source file, and so the two
    /// that can name one the archive does not carry. Written without their opening
    /// parenthesis on purpose: this constant is itself text in this file, and the
    /// scan below would otherwise find itself.
    const INCLUDE_MACROS: &[&str] = &["include_str!", "include_bytes!"];

    /// One occurrence of an inclusion macro, as found in a source file.
    struct IncludeSite<'a> {
        /// Which of `INCLUDE_MACROS` was written.
        macro_name: &'a str,
        /// The path literal, or `None` when the argument is not a plain string
        /// literal — a raw string, a nested macro, anything this scan declines to
        /// interpret rather than guess at.
        argument: Option<&'a str>,
        line: usize,
    }

    /// Every inclusion-macro occurrence in `source` that carries an argument.
    ///
    /// Two occurrences are deliberately not reported. One is a bare mention with no
    /// parenthesis after it, which is prose about the macro rather than a use of it.
    /// The other is an occurrence whose argument opens with a backslash, which can
    /// only happen when the whole thing sits inside a Rust string literal — this
    /// file quotes the crate-level attribute in several assertion messages, and
    /// those are text, not includes.
    ///
    /// Everything else is reported, including arguments the scan cannot read. An
    /// unreadable argument is a finding rather than a skip: silently passing over
    /// the one spelling nobody anticipated is how the narrow version of this check
    /// came to cover a single site.
    fn include_sites(source: &str) -> Vec<IncludeSite<'_>> {
        let mut sites = Vec::new();
        for name in INCLUDE_MACROS {
            let mut cursor = 0usize;
            while let Some(rel) = source[cursor..].find(name) {
                let at = cursor + rel;
                cursor = at + name.len();
                // `my_include_str!` is somebody else's macro.
                if source[..at]
                    .chars()
                    .next_back()
                    .is_some_and(|c| c.is_alphanumeric() || c == '_')
                {
                    continue;
                }
                let Some(inside) = source[cursor..].trim_start().strip_prefix('(') else {
                    continue;
                };
                let inside = inside.trim_start();
                if inside.starts_with('\\') {
                    continue;
                }
                sites.push(IncludeSite {
                    macro_name: name,
                    argument: inside
                        .strip_prefix('"')
                        .and_then(|rest| rest.split_once('"'))
                        .map(|(literal, _)| literal),
                    line: source[..at].bytes().filter(|b| *b == b'\n').count() + 1,
                });
            }
        }
        sites.sort_by_key(|site| site.line);
        sites
    }

    /// Every `.rs` file under `dir`, recursively, in a stable order.
    fn rust_sources_under(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
        let mut found = Vec::new();
        let mut pending = vec![dir.to_path_buf()];
        while let Some(next) = pending.pop() {
            let entries = std::fs::read_dir(&next)
                .unwrap_or_else(|why| panic!("cannot read {}: {why}", next.display()));
            for entry in entries {
                let path = entry.expect("a readable directory entry").path();
                if path.is_dir() {
                    pending.push(path);
                } else if path.extension().is_some_and(|extension| extension == "rs") {
                    found.push(path);
                }
            }
        }
        found.sort();
        found
    }

    /// `file`'s location relative to `root`, spelled with forward slashes whatever
    /// the host separator is, so the listing below reads the same everywhere.
    fn relative_slash_path(root: &std::path::Path, file: &std::path::Path) -> String {
        file.strip_prefix(root)
            .expect("every scanned file sits under the manifest directory")
            .components()
            .map(|component| component.as_os_str().to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join("/")
    }

    /// The inclusion arguments allowed to name a file outside `core/`, as
    /// (source file below `core/`, argument as written).
    ///
    /// Each of these sits in a `#[cfg(test)]` module, which `cargo package`'s
    /// verification build never compiles, so the file it names does not have to
    /// exist in the archive. The scan cannot establish that for itself: it reads
    /// text, and telling a `cfg(test)` module from production code by text alone
    /// means parsing `cfg` attributes and module nesting, which would be a second
    /// mechanism able to fail quietly. So every site is checked and the exceptions
    /// are written here by hand. Adding a line is a deliberate act; a production
    /// include slipping past because nobody looked is not available.
    const ESCAPES_OUTSIDE_THE_PACKAGE: &[(&str, &str)] = &[
        ("src/lib.rs", "../../README.md"),
        ("src/lib.rs", "../../LICENSE"),
        ("src/lib.rs", "../../BENCHMARKS.md"),
        ("src/lib.rs", "../../docs/operations/deployment.md"),
    ];

    /// The `readme` value from the manifest's `[package]` table, as written.
    ///
    /// A hand-rolled scan rather than a TOML parser: one key is wanted, out of one
    /// table, from a file this crate already carries, and a dependency added to read
    /// it would be a dependency of the published crate.
    ///
    /// Section tracking is what makes it a scan of `[package]` and not of the whole
    /// file — `[package.metadata.docs.rs]` is a different table, and a `readme` key
    /// under some future table is not the one crates.io reads.
    fn package_readme_key(manifest: &str) -> Option<&str> {
        let mut in_package = false;
        for line in manifest.lines() {
            let line = line.trim();
            if let Some(header) = line.strip_prefix('[') {
                in_package = header.starts_with("package]");
                continue;
            }
            if !in_package {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            if key.trim() != "readme" {
                continue;
            }
            return value
                .trim_start()
                .strip_prefix('"')
                .and_then(|quoted| quoted.split_once('"'))
                .map(|(name, _)| name);
        }
        None
    }

    /// Languages this repository's Markdown fences are written in, plus the common
    /// ones a future page is likely to reach for. Nothing else about a fence is
    /// consulted; this list alone decides what the hidden-line scan skips.
    ///
    /// Kept sorted so an addition is a one-line diff in an obvious place.
    const NON_RUST_FENCE_LANGUAGES: &[&str] = &[
        "asm",
        "bash",
        "c",
        "c++",
        "cmake",
        "console",
        "cpp",
        "cs",
        "csharp",
        "css",
        "diff",
        "dockerfile",
        "go",
        "gradle",
        "groovy",
        "hcl",
        "html",
        "http",
        "ini",
        "java",
        "javascript",
        "js",
        "json",
        "kotlin",
        "kt",
        "lua",
        "makefile",
        "markdown",
        "md",
        "mermaid",
        "nix",
        "none",
        "objc",
        "patch",
        "perl",
        "php",
        "plain",
        "powershell",
        "protobuf",
        "ps1",
        "py",
        "python",
        "rb",
        "ruby",
        "scala",
        "sh",
        "shell",
        "sql",
        "swift",
        "text",
        "toml",
        "ts",
        "typescript",
        "wat",
        "wit",
        "xml",
        "yaml",
        "yml",
        "zsh",
    ];

    /// Whether a fence carrying this info string is compiled as Rust by rustdoc.
    ///
    /// The rule is inverted from the way an info string reads. rustdoc does not
    /// look for the word `rust`: it starts from "this is Rust" and only a token it
    /// recognises as another language talks it out of that. Every token it does not
    /// recognise is an attribute — `no_run`, `ignore`, `should_panic`,
    /// `compile_fail`, `edition2021`, `test_harness` and anything added after this
    /// sentence was written — and a fence carrying one is Rust that rustdoc
    /// compiles, hidden lines and all.
    ///
    /// Reading it the other way round, as "Rust unless the first token is `rust` or
    /// absent", loses every one of those spellings, and the loss is silent: the scan
    /// below skips the fence, the gate stays green, and the `# ` lines land on
    /// crates.io. So the verdict is taken from a list of languages rather than from
    /// a list of Rust-isms, and an unlisted token is Rust. That errs towards
    /// scanning a fence that did not need it, whose worst outcome is a failing
    /// assertion naming the language to add here.
    fn fence_is_rust(info: &str) -> bool {
        // Both separators, because rustdoc accepts either and the language is
        // whichever token comes first under both readings.
        let language = info
            .split([',', ' ', '\t'])
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        !NON_RUST_FENCE_LANGUAGES.contains(&language.as_str())
    }

    /// Whether `line`, inside a Rust fence, is a rustdoc hidden-line marker: a `#`
    /// alone or followed by a space. `#[attr]`, `#![attr]` and the `##` escape are
    /// code, and a fence is the only place any of this applies.
    fn is_rustdoc_hidden_line(line: &str) -> bool {
        match line.trim_start().strip_prefix('#') {
            None => false,
            Some(rest) => rest.is_empty() || rest.starts_with(' '),
        }
    }

    /// The 1-based lines of `markdown` that rustdoc would hide from a Rust fence.
    ///
    /// Fence-aware because it has to be: the quickstart is shell, and `# Generate a
    /// persistent server identity` is a comment there, not a marker.
    fn rustdoc_hidden_lines(markdown: &str) -> Vec<usize> {
        let mut hidden = Vec::new();
        let mut open_fence_is_rust: Option<bool> = None;
        for (index, line) in markdown.lines().enumerate() {
            if let Some(info) = line.trim_start().strip_prefix("```") {
                open_fence_is_rust = match open_fence_is_rust {
                    Some(_) => None,
                    None => Some(fence_is_rust(info)),
                };
                continue;
            }
            if open_fence_is_rust == Some(true) && is_rustdoc_hidden_line(line) {
                hidden.push(index + 1);
            }
        }
        hidden
    }

    /// The byte offset at which the two pages first differ, or `None` when they
    /// agree. One page being a prefix of the other counts as differing where the
    /// shorter one ends.
    fn first_difference(landing: &str, packaged: &str) -> Option<usize> {
        landing
            .as_bytes()
            .iter()
            .zip(packaged.as_bytes())
            .position(|(a, b)| a != b)
            .or_else(|| {
                (landing.len() != packaged.len()).then(|| landing.len().min(packaged.len()))
            })
    }

    /// Up to eighty bytes of `page` around `at`, escaped onto a single line.
    ///
    /// Bytes rather than characters, and lossy rather than sliced, because the
    /// window can land mid-codepoint — this README is full of box-drawing and
    /// em-dashes — and a panic inside the reporter would replace the diagnosis
    /// with a byte-boundary error. Escaping keeps the excerpt to one line, which
    /// is what makes two of them readable side by side.
    fn excerpt(page: &str, at: usize) -> String {
        const RADIUS: usize = 40;
        let bytes = page.as_bytes();
        let from = at.saturating_sub(RADIUS);
        let to = at.saturating_add(RADIUS).min(bytes.len());
        String::from_utf8_lossy(&bytes[from..to])
            .escape_debug()
            .to_string()
    }

    /// What a contributor sees when the two copies have drifted apart.
    ///
    /// Sizes alone cannot describe the common case: an edit that substitutes text
    /// of the same length leaves them identical, and the message then names two
    /// equal numbers and nothing else. The offset says where to look and the two
    /// excerpts say what changed, in a few hundred bytes rather than in both
    /// pages — this runs in `cargo test --lib`, whose log is read.
    fn drift_report(landing: &str, packaged: &str) -> String {
        let Some(at) = first_difference(landing, packaged) else {
            return String::from("README.md and core/README.md agree");
        };
        format!(
            "core/README.md has drifted from README.md at byte {at} (README.md {} \
             bytes, core/README.md {} bytes); run scripts/sync_readme.sh\n  \
             README.md      …{}…\n  core/README.md …{}…",
            landing.len(),
            packaged.len(),
            excerpt(landing, at),
            excerpt(packaged, at),
        )
    }

    /// The drift assertion, as a function, so a test can drive it with two pages
    /// that differ and read the message a contributor would actually see.
    fn assert_landing_pages_agree(landing: &str, packaged: &str) {
        assert!(landing == packaged, "{}", drift_report(landing, packaged));
    }

    /// The message the assertion above produces when the two pages differ.
    fn drift_message(landing: &str, packaged: &str) -> String {
        let unwound = std::panic::catch_unwind(|| assert_landing_pages_agree(landing, packaged));
        let payload = unwound.expect_err("two differing pages must fail the drift assertion");
        payload
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| payload.downcast_ref::<&str>().map(|s| (*s).to_string()))
            .expect("the drift assertion panics with a string payload")
    }

    /// The two copies must agree byte for byte, or the page crates.io renders is not
    /// the page this repository maintains.
    #[test]
    fn packaged_readme_is_the_landing_page() {
        assert_landing_pages_agree(LANDING_PAGE, PACKAGED);
    }

    /// The license text the archive carries must be the repository's, byte for
    /// byte. A copy that drifted would put a license into every downloaded crate
    /// that is not the one the project grants, and nothing downstream reads it
    /// closely enough to notice.
    #[test]
    fn packaged_license_is_the_repository_license() {
        if let Some(at) = first_difference(REPOSITORY_LICENSE, PACKAGED_LICENSE) {
            panic!(
                "core/LICENSE has drifted from LICENSE at byte {at} (LICENSE {} bytes, \
                 core/LICENSE {} bytes); run scripts/sync_readme.sh\n  \
                 LICENSE      …{}…\n  core/LICENSE …{}…",
                REPOSITORY_LICENSE.len(),
                PACKAGED_LICENSE.len(),
                excerpt(REPOSITORY_LICENSE, at),
                excerpt(PACKAGED_LICENSE, at),
            );
        }
        assert!(
            PACKAGED_LICENSE.contains("Apache License") && PACKAGED_LICENSE.contains("Version 2.0"),
            "core/LICENSE agrees with LICENSE but is not the Apache-2.0 text that \
             core/Cargo.toml's `license = \"Apache-2.0\"` declares"
        );
    }

    /// A failing gate has to say what went wrong, and this one runs inside
    /// `cargo test --lib` — a required context whose log a contributor reads.
    ///
    /// The two things it must not do are both things it did: print the whole of
    /// both pages, and describe the difference only as two sizes. Sizes say
    /// nothing at all about an edit that replaces one byte with another, which is
    /// most of them; the pair below is deliberately equal-length for that reason.
    #[test]
    fn drift_is_reported_by_location_and_not_by_reprinting_both_pages() {
        let landing = format!("{}phantom{}", "a".repeat(19_000), "b".repeat(19_000));
        let packaged = format!("{}phantoM{}", "a".repeat(19_000), "b".repeat(19_000));
        let message = drift_message(&landing, &packaged);

        assert!(
            message.len() < 1024,
            "the drift message is {} bytes for two {}-byte pages; it is reprinting \
             them rather than locating the difference",
            message.len(),
            landing.len()
        );
        assert!(
            message.contains("19006"),
            "the drift message does not give the byte offset of the first \
             difference: {message}"
        );
        assert!(
            message.contains("phantom") && message.contains("phantoM"),
            "the drift message does not quote both sides around the difference, so \
             two equal-length pages are indistinguishable in it: {message}"
        );
        assert!(
            message.contains("scripts/sync_readme.sh"),
            "the drift message does not say how to repair the tree: {message}"
        );
    }

    /// This page has two renderers and only one of them knows rustdoc's
    /// conventions.
    ///
    /// rustdoc hides a fenced line that begins `# `, so an example can carry its
    /// `#[tokio::main]` and its `fn main` without showing them, and docs.rs is
    /// clean. crates.io renders the same file as CommonMark, which has no such
    /// convention: it prints the `# ` lines as written, and a reader sees a
    /// headline example interrupted by stray hashes and apparently having no
    /// `main`, which fails to compile on the first line if pasted. The 5 KiB stub
    /// this page replaced had no such problem, so a marker here is a regression on
    /// exactly the surface the landing page was enlarged to fix.
    ///
    /// The rule that keeps both renderers honest is to write the lines out.
    #[test]
    fn readme_rust_examples_carry_no_rustdoc_hidden_lines() {
        let hidden = rustdoc_hidden_lines(LANDING_PAGE);
        assert!(
            hidden.is_empty(),
            "README.md {hidden:?} (1-based) are rustdoc hidden-line markers inside a \
             Rust fence. rustdoc strips them and docs.rs stays clean, but crates.io \
             renders this file as CommonMark and prints them verbatim. Drop the \
             `# ` prefixes and let the lines show. If the fence is not Rust at all, \
             its language is missing from NON_RUST_FENCE_LANGUAGES above — an \
             unlisted info string is read as Rust on purpose, because the reverse \
             mistake is silent."
        );
    }

    /// The scanner decides the verdict above, and the two ways it could be wrong
    /// pull in opposite directions: blind to fences it would call the quickstart's
    /// `# Generate a persistent server identity` a marker, and blind to markers it
    /// would pass anything. Both directions are covered here.
    #[test]
    fn hidden_line_scanner_reads_rust_fences_only() {
        // Shell comments, prose headings, attributes and the `##` escape are not
        // markers.
        assert!(rustdoc_hidden_lines("```bash\n# Generate a key\ncargo run\n```\n").is_empty());
        assert!(rustdoc_hidden_lines("# Heading\n\nprose\n").is_empty());
        assert!(rustdoc_hidden_lines("```rust\n#[derive(Debug)]\nstruct S;\n```\n").is_empty());
        assert!(rustdoc_hidden_lines("```rust\n#![allow(dead_code)]\n```\n").is_empty());
        assert!(rustdoc_hidden_lines("```rust\n##[cfg(test)]\n```\n").is_empty());

        // Markers, in each of the forms rustdoc recognises and each fence spelling
        // this README uses.
        assert_eq!(
            rustdoc_hidden_lines("```rust,no_run\n# fn main() {}\n```\n"),
            vec![2]
        );
        assert_eq!(
            rustdoc_hidden_lines("```rust\n#\nlet x = 1;\n```\n"),
            vec![2]
        );
        // An unlabelled fence is Rust to rustdoc.
        assert_eq!(rustdoc_hidden_lines("```\n# hidden\n```\n"), vec![2]);
        // Fences close: a marker-shaped line after one is prose again.
        assert_eq!(
            rustdoc_hidden_lines("```rust\n# hidden\n```\n\n# Heading\n"),
            vec![2]
        );

        // A bare attribute is the spelling that matters most, because it is the
        // one an author reaches for. Every token here is a rustdoc attribute, not
        // a language, so every one of these fences is compiled as Rust and every
        // marker inside it is stripped on docs.rs and printed on crates.io.
        for info in [
            "no_run",
            "ignore",
            "should_panic",
            "compile_fail",
            "edition2021",
            "test_harness",
            "no_run,rust",
            "ignore,should_panic",
        ] {
            assert_eq!(
                rustdoc_hidden_lines(&format!("```{info}\n# fn main() {{}}\n```\n")),
                vec![2],
                "a ```{info} fence is Rust with an attribute, and its hidden lines \
                 reach crates.io verbatim"
            );
        }

        // Genuine other languages, which is the whole of what the fence check is
        // allowed to skip.
        for info in ["bash", "toml", "text", "console", "yaml", "TOML"] {
            assert!(
                rustdoc_hidden_lines(&format!("```{info}\n# a comment\ncmd\n```\n")).is_empty(),
                "```{info} is not Rust, so a `# ` line in it is that language's own \
                 syntax and not a rustdoc marker"
            );
        }
    }

    /// Everything else here protects the *file* `core/README.md`, and nothing else
    /// here reads the manifest key that decides which file crates.io renders.
    ///
    /// `core/README.md` reaches the archive because it is an ordinary tracked file
    /// under the manifest directory, not because `readme` names it — so repointing
    /// `readme` at a stub leaves the sync script green, the drift test green,
    /// `cargo package` green, and the archive comparison green, while the page on
    /// crates.io becomes the stub. Every gate agreeing is not the same as every
    /// gate being right, and this is the one that reads the key itself.
    #[test]
    fn manifest_readme_key_names_the_packaged_copy() {
        let named = package_readme_key(MANIFEST)
            .expect("core/Cargo.toml's [package] table carries a `readme` key");

        assert_eq!(
            named, PACKAGED_FILE_NAME,
            "core/Cargo.toml says readme = \"{named}\", but every other part of this \
             arrangement — scripts/sync_readme.sh, the drift test above, and the \
             archive comparison in CI's package job — maintains \
             core/{PACKAGED_FILE_NAME}. crates.io would render {named}, which \
             nothing checks"
        );
    }

    /// The scanner decides the verdict above, so one that answered `README.md` for
    /// any input would leave that test green through exactly the repointing it
    /// exists to catch. The `[package.metadata.docs.rs]` case is the one that makes
    /// section tracking load-bearing rather than decorative.
    #[test]
    fn readme_key_scanner_reads_the_package_table_only() {
        assert_eq!(
            package_readme_key("[package]\nreadme = \"README.md\"\n"),
            Some("README.md")
        );
        assert_eq!(
            package_readme_key("[package]\nname = \"x\"\nreadme = \"CRATE_README.md\"\n"),
            Some("CRATE_README.md")
        );
        // A `readme` key belonging to another table is not the one crates.io reads.
        assert_eq!(
            package_readme_key(
                "[package]\nname = \"x\"\n\n[package.metadata.docs.rs]\nreadme = \"other.md\"\n"
            ),
            None
        );
        assert_eq!(
            package_readme_key("[features]\nreadme = \"other.md\"\n"),
            None
        );
        // Absent entirely — cargo then falls back to an untracked default, which is
        // not the arrangement the rest of this module maintains.
        assert_eq!(package_readme_key("[package]\nname = \"x\"\n"), None);
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
            "`#![doc = include_str!(\"{path}\")]` does not stay inside core/, so the \
             file it names is absent from the crate archive. Either it walks above \
             core/ — which is fatal even if it descends back in afterwards, because \
             in the archive core/ is the root and `cargo package` fails on it — or \
             it is anchored at a filesystem root, which is worse: that one builds \
             here, packages here, publishes, and is unbuildable everywhere else"
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

    /// An absolute path is the one escape no later gate can catch.
    ///
    /// It never rises above `core/` — it never walks at all — so a resolver that
    /// only counts `..` sees nothing wrong and answers with a plausible-looking
    /// location inside the package. Downstream is no better: `cargo package`
    /// verifies by building the extracted crate on the host that wrote the path,
    /// where the path still resolves, so the archive is produced and published with
    /// one machine's directory layout compiled into `src/lib.rs`. The first failure
    /// is on a consumer's machine and on docs.rs, and by then the version is
    /// immutable.
    #[test]
    fn resolver_rejects_absolute_paths() {
        assert_eq!(resolve_from_core_src("/README.md"), None);
        assert_eq!(
            resolve_from_core_src("/Users/someone/phantom_core_rust/README.md"),
            None
        );
        assert_eq!(resolve_from_core_src("/tmp/README.md"), None);
        // A root-anchored path that walks back down into a directory named like the
        // package is the shape most likely to look right in review.
        assert_eq!(
            resolve_from_core_src("/home/ci/checkout/core/README.md"),
            None
        );
        // Windows spellings, since a path written on one is still text here.
        assert_eq!(resolve_from_core_src("C:/Users/someone/README.md"), None);
        assert_eq!(resolve_from_core_src("C:\\Users\\someone\\README.md"), None);
        assert_eq!(resolve_from_core_src("\\\\server\\share\\README.md"), None);

        // Relative paths are untouched by the rejection: a leading `./` is still a
        // walk that starts where the file sits.
        assert_eq!(
            resolve_from_core_src("./README.md"),
            Some(vec!["src", "README.md"])
        );
        assert_eq!(
            resolve_from_core_src("../README.md"),
            Some(vec!["README.md"])
        );
    }

    /// The check above reads one attribute in one file, and that is not where the
    /// next escape will be.
    ///
    /// A `#[doc = …]` attribute on a module pulling in the protocol specification
    /// is the obvious next thing somebody writes, and a plain include of a fixture
    /// or a table is the next after that. Neither is the crate-level attribute, so
    /// neither was looked at, and `cargo test --lib` — the required
    /// branch-protection context — would have stayed green through both. Only the
    /// packaging job would have failed, and it is not required, so the failure lands
    /// on whoever next runs a release rather than on whoever wrote the line.
    ///
    /// So the whole of `core/src` is walked, cfg-gated modules included: a
    /// `wasm32`-only or `fips`-only file's include still ships in the archive and
    /// still has to resolve there, and the fact that this host does not compile it
    /// says nothing about the host that will.
    #[test]
    fn no_include_reaches_outside_the_package() {
        let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut problems: Vec<String> = Vec::new();
        let mut exercised: Vec<(String, String)> = Vec::new();

        for file in rust_sources_under(&manifest_dir.join("src")) {
            let shown = relative_slash_path(manifest_dir, &file);
            let source = std::fs::read_to_string(&file)
                .unwrap_or_else(|why| panic!("cannot read {shown}: {why}"));

            // The naming file's own directory is where its relative argument starts
            // walking, so a file three levels down gets three levels of slack.
            let mut directory: Vec<&str> = shown.split('/').collect();
            directory.pop();

            for site in include_sites(&source) {
                let at = format!("{shown}:{}", site.line);
                let Some(argument) = site.argument else {
                    problems.push(format!(
                        "{at}: `{}` is given an argument this check cannot read as a \
                         plain string literal, so where it points is unknown. Write \
                         the path as an ordinary literal, or add the spelling to \
                         `include_sites`.",
                        site.macro_name
                    ));
                    continue;
                };
                if resolve_below_core(&directory, argument).is_some() {
                    continue;
                }
                if ESCAPES_OUTSIDE_THE_PACKAGE.contains(&(shown.as_str(), argument)) {
                    exercised.push((shown.clone(), argument.to_owned()));
                    continue;
                }
                problems.push(format!(
                    "{at}: `{}` names `{argument}`, which does not stay inside core/. \
                     A cargo package archive carries only what sits under the manifest \
                     directory, so the file is absent from it and the crate cannot be \
                     built by anyone who downloads it or by docs.rs. Copy the file \
                     under core/ and point at the copy — that is what core/README.md \
                     is. If this line is inside a #[cfg(test)] module, which the \
                     packaging build never compiles, add it to \
                     ESCAPES_OUTSIDE_THE_PACKAGE.",
                    site.macro_name
                ));
            }
        }

        // A listed exception that no longer matches anything is an allowance nobody
        // asked for, sitting ready for the next path that happens to be spelled the
        // same way.
        for (file, argument) in ESCAPES_OUTSIDE_THE_PACKAGE {
            if !exercised
                .iter()
                .any(|(seen_file, seen_argument)| seen_file == file && seen_argument == argument)
            {
                problems.push(format!(
                    "{file}: the listed exception for `{argument}` matches nothing in \
                     the tree any more. Delete the entry rather than leaving it to \
                     pre-approve some later include."
                ));
            }
        }

        assert!(
            problems.is_empty(),
            "an inclusion in core/src names a file the published archive will not \
             carry:\n\n{}\n",
            problems.join("\n")
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
/// - "captured under `WIRE_VERSION = 2`, whereas the shipped format is 8"
/// - "the shipped format is 8 (`WIRE_VERSION`)"
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
/// The current on-wire format is **WIRE_VERSION=<!--pinned:WIRE_VERSION-->8**.
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

/// The dependency features a consumer of this crate inherits, and which of them may
/// not be taken away without a major release.
///
/// Cargo unifies features across the whole dependency graph, so what this crate asks
/// of a shared dependency is added to what a consumer asked of the same dependency,
/// and the consumer's own code compiles against the union. A consumer that writes
/// `tokio = { version = "1", features = ["rt-multi-thread", "macros"] }` and then
/// calls `tokio::signal::ctrl_c()` compiles only because this crate enables `signal`;
/// remove it and their build breaks on `cargo update`, which the `= "0.3"`
/// requirement the README recommends invites.
///
/// 0.3.1 removed four such tokio features and moved `time` out of `std`, and both
/// were reproduced twice against unchanged consumer source: a program that built
/// against 0.3.0 gave five compile errors, none of which named this crate or a
/// feature. They were restored, and this module is why they stay restored: nothing
/// else in the repository can see the break. `cargo-semver-checks` compares this
/// crate's public API and not its dependencies' feature selections; the cross-target
/// matrix, the integration suites and the trial consumer all name enough features of
/// their own to paper over the loss; and a consumer is the only party who finds out.
///
/// So the gate is deliberately a text assertion about the manifest rather than a test
/// that uses the features. A test using them would compile whenever any
/// **dev**-dependency happened to enable them — and dev-dependencies are not part of
/// what a consumer inherits, so such a test would be green for the exact change it
/// is supposed to catch.
#[cfg(test)]
mod inherited_dependency_features {
    /// This crate's manifest, read as text. It sits inside the package, so this
    /// resolves both here and in an extracted `cargo package` archive.
    const MANIFEST: &str = include_str!("../Cargo.toml");

    /// The `tokio` features a consumer has been inheriting from the native
    /// dependency block since long before 0.3.0, with what each one provides.
    ///
    /// The first two are what this library itself calls. The other four are not used
    /// anywhere in `core/src`, and that is exactly why they are easy to delete and
    /// why they are listed here: their only remaining job is to keep compiling
    /// somebody else's code.
    const INHERITED_TOKIO_FEATURES: &[(&str, &str)] = &[
        ("net", "this library's own TCP/UDP sockets"),
        ("rt-multi-thread", "this library's own spawned tasks"),
        ("signal", "a consumer's `tokio::signal::ctrl_c()`"),
        ("process", "a consumer's `tokio::process::Command`"),
        ("fs", "a consumer's `tokio::fs`"),
        ("io-std", "a consumer's `tokio::io::stdin` / `stdout`"),
    ];

    /// The native dependency block's `tokio` entry, as text.
    ///
    /// Taken from the target table rather than from the whole file, so the
    /// cross-target `tokio` entry near the top — which names `time`, a tokio feature
    /// with nothing to do with the `time` crate below — cannot satisfy an assertion
    /// about the native one.
    fn native_tokio_entry() -> &'static str {
        let table = "[target.'cfg(not(target_arch = \"wasm32\"))'.dependencies]";
        let after = MANIFEST
            .split_once(table)
            .unwrap_or_else(|| panic!("the manifest has no {table} table"))
            .1;
        let entry = after
            .split_once("\ntokio = ")
            .unwrap_or_else(|| panic!("the {table} table declares no tokio"))
            .1;
        // To the end of the inline table, which spans several lines.
        let end = entry
            .find(" }")
            .unwrap_or_else(|| panic!("tokio's entry in {table} does not close"));
        &entry[..=end]
    }

    /// Every feature above is still named in the native `tokio` entry.
    #[test]
    fn the_native_tokio_entry_still_names_every_inherited_feature() {
        let entry = native_tokio_entry();
        for (feature, who_needs_it) in INHERITED_TOKIO_FEATURES {
            assert!(
                entry.contains(&format!("\"{feature}\"")),
                "core/Cargo.toml no longer enables tokio's `{feature}` for native \
                 targets, which is what provides {who_needs_it}. Cargo unifies features \
                 across the graph, so taking it away breaks the build of every consumer \
                 that relied on inheriting it and named fewer features itself — a \
                 breaking change, and one no other gate here can see. It may go in a \
                 major release, with a note a consumer reads before upgrading, and not \
                 before. The entry reads: {entry}"
            );
        }
    }

    /// `std` still enables `time`, so a consumer that declares the crate with
    /// `default-features = false` keeps inheriting `time/std` from us.
    ///
    /// `time` is read nowhere outside the `mimicry` leg, so by this crate's own needs
    /// the line is dead — which is how it came to be deleted. What it carries is
    /// `time`'s **default features**, and `time/std` is where `OffsetDateTime::now_utc`
    /// lives: a consumer with `time = { version = "0.3", default-features = false }`
    /// lost that method and was told `no function or associated item named 'now_utc'`.
    #[test]
    fn the_std_feature_still_carries_the_time_crate() {
        let std_block = MANIFEST
            .split_once("\nstd = [")
            .expect("the manifest declares a `std` feature")
            .1
            .split_once("\n]")
            .expect("the `std` feature list closes")
            .0;
        assert!(
            std_block.contains("\"dep:time\""),
            "core/Cargo.toml's `std` feature no longer enables `dep:time`. Nothing in \
             this crate reads `time` outside the `mimicry` leg, so this looks like dead \
             weight — but it is what hands a consumer `time`'s default features, and \
             dropping it took `OffsetDateTime::now_utc` away from consumer code that \
             declared `time` with `default-features = false`. It may go in a major \
             release and not before. The `std` list reads: {std_block}"
        );
    }

    /// The manifest says, beside both of them, that they are compatibility entries and
    /// when they may go.
    ///
    /// Without this the next reader finds two feature selections the crate does not
    /// use, deletes them as cleanup, and the two assertions above become a puzzle
    /// rather than an explanation — which is how the first deletion happened.
    #[test]
    fn both_compatibility_entries_carry_the_note_that_says_why() {
        let note = "KEPT ON THE 0.3.x LINE FOR COMPATIBILITY";
        assert_eq!(
            MANIFEST.matches(note).count(),
            2,
            "core/Cargo.toml should carry the `{note}` note exactly twice — once beside \
             `dep:time` in the `std` feature and once beside the native `tokio` entry — \
             so a reader who finds either selection unused learns why it is there \
             before deleting it."
        );
    }
}

/// The paths a caller writes from the signature of a crate-root entry point.
///
/// The crate root exported [`CoreError`] and [`PhantomConfig`] and none of the rest,
/// which made the obvious import fail: `connect_pinned_udp` hands back an
/// `Arc<PhantomSession>`, that session answers with a `ConnectionState`, opens a
/// `PhantomStream`, takes a `TrafficShapingConfig` with a `PaddingPolicy` inside it
/// and produces a `ResumptionHint` the resuming entry point takes back — and every
/// one of those could only be named through `phantom_protocol::api::…`, or, for
/// `PaddingPolicy`, through `phantom_protocol::transport::shaping`, a module a caller
/// of an `api` method has no reason to have opened. So
/// `use phantom_protocol::ConnectionState;` did not compile beside a
/// `use phantom_protocol::CoreError;` that did.
///
/// Naming each type is the whole test. A path that does not resolve is a compile
/// error, so a re-export deleted here cannot report itself as a passing run — which
/// is the one thing a test asserting a value could not give: there is no value to
/// read, only a name, and an absent name stops the build.
#[cfg(test)]
mod crate_root_paths {
    use std::sync::Arc;

    #[test]
    fn every_type_a_caller_must_name_resolves_at_the_crate_root() {
        let _: Option<Arc<crate::PhantomSession>> = None;
        let _: Option<Arc<crate::PhantomStream>> = None;
        let _: Option<Arc<crate::ResumptionHint>> = None;
        let _: Option<crate::ConnectionState> = None;
        let _: Option<crate::CoreError> = None;
        let _: Option<crate::PhantomConfig> = None;
        let _: Option<crate::TrafficShapingConfig> = None;
        let _: Option<crate::PaddingPolicy> = None;
        let _: Option<crate::MetricsSnapshotFfi> = None;
    }

    /// The server side, which is native-only in both places — so a browser-wasm build
    /// finds these neither at the crate root nor under `api::`, and this assertion is
    /// gated exactly as the re-exports are.
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn the_server_types_resolve_at_the_crate_root_on_native_targets() {
        let _: Option<Arc<crate::PhantomListener>> = None;
        let _: Option<Arc<crate::PhantomUdpListener>> = None;
        let _: Option<Arc<crate::AcceptOutcome>> = None;
    }

    /// The re-export is the type itself and not a second declaration that happens to
    /// share a name, so a value produced through one path is usable through the other.
    #[test]
    fn the_crate_root_name_and_the_module_name_are_one_type() {
        let through_the_module: crate::api::ConnectionState =
            crate::api::ConnectionState::Connected;
        let through_the_root: crate::ConnectionState = through_the_module;
        assert_eq!(
            through_the_root,
            crate::api::session::ConnectionState::Connected
        );
    }
}
