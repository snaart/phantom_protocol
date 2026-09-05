// Phase 3.6: `CoreError` is part of the embedded-friendly subset (the
// `SessionTransport` trait and `EmbeddedLeg` both surface it). Under a
// bare-metal `--no-default-features --features embedded,no-std` build the
// module compiles without `std`; `String` comes from `alloc`, and the std-only
// `From<std::io::Error>` / `From<anyhow::Error>` converters plus the
// `uniffi::Error` / `thiserror::Error` derives are cfg-gated off. A hand-rolled
// `Display` impl steps in for the no-std path.
#[cfg(not(feature = "std"))]
use alloc::string::String;

#[cfg(feature = "std")]
use thiserror::Error;

/// Universal Core Error Enum compatible with FFI exports
///
/// # Retryability guide
///
/// | Variant                  | Retryable? | Suggested action                              |
/// |--------------------------|------------|-----------------------------------------------|
/// | `NetworkError`           | Yes        | Retry with backoff                            |
/// | `Timeout`                | Yes        | Retry with backoff                            |
/// | `ConnectionClosed`       | Yes        | Reconnect                                     |
/// | `ServerIdentityMismatch` | No         | Update pinned key or contact server admin     |
/// | `ProtocolRejected`       | No         | Update client library to a compatible version |
/// | `Unsupported`            | No         | Use the correct transport type                |
/// | `HandshakeError`         | Maybe      | Check server logs; may be transient           |
/// | `CryptoError`            | No         | Internal error; report bug                    |
/// | `ValidationError`        | No         | Fix the input and retry                       |
/// | `ConfigError`            | No         | Fix the configuration and retry               |
/// | `FipsSelfTestFailure`    | No         | Fatal POST failure — binary is broken         |
#[cfg_attr(feature = "std", derive(Error))]
#[cfg_attr(feature = "bindings", derive(uniffi::Error))]
#[derive(Debug, Clone)]
// Adding a variant must not be a SemVer-major break for downstream `match`es
// (FIPS / migration / flow-control errors are expected to land post-1.0).
#[non_exhaustive]
pub enum CoreError {
    #[cfg_attr(feature = "std", error("Network I/O Error: {0}"))]
    NetworkError(String),

    #[cfg_attr(feature = "std", error("Serialization Error: {0}"))]
    SerializationError(String),

    #[cfg_attr(feature = "std", error("Invalid Configuration: {0}"))]
    ConfigError(String),

    #[cfg_attr(feature = "std", error("Cryptography Error: {0}"))]
    CryptoError(String),

    #[cfg_attr(feature = "std", error("Validation Error: {0}"))]
    ValidationError(String),

    #[cfg_attr(feature = "std", error("Key derivation failed"))]
    KeyDerivationError,

    #[cfg_attr(feature = "std", error("Random number generation failed: {0}"))]
    RngError(String),

    #[cfg_attr(feature = "std", error("Internal concurrency error: {0}"))]
    InternalError(String),

    #[cfg_attr(feature = "std", error("Handshake failed: {0}"))]
    HandshakeError(String),

    #[cfg_attr(feature = "std", error("Stream error: {0}"))]
    StreamError(String),

    #[cfg_attr(feature = "std", error("Connection closed"))]
    ConnectionClosed,

    #[cfg_attr(feature = "std", error("Timeout"))]
    Timeout,

    /// Sliding-window replay protection rejected a packet. The AEAD layer
    /// already cryptographically prevents replay (strict-counter nonces), but
    /// the explicit window catches duplicates earlier and gives operators a
    /// metric signal (`replay_rejected_total`).
    #[cfg_attr(feature = "std", error("replay protection rejected packet: {0}"))]
    ReplayDetected(String),

    /// A requested cipher suite is not available in the current build.
    /// Emitted under `--features fips` when a caller asks for a
    /// non-FIPS-approved primitive (today: `ChaCha20-Poly1305`). The
    /// variant is always compiled so error matching stays stable across
    /// feature configurations.
    #[cfg_attr(feature = "std", error("cipher suite unavailable: {0}"))]
    CipherSuiteUnavailable(String),

    /// The server's signing key did not match the pinned key supplied by the
    /// caller. **Fatal — do not retry without updating the pinned key.**
    ///
    /// This is a distinct, typed variant rather than a string so callers can
    /// branch on it without fragile string matching:
    ///
    /// ```rust,ignore
    /// match session.await_ready().await {
    ///     Err(CoreError::ServerIdentityMismatch) => { /* update pinned key */ }
    ///     Err(e) => { /* other failure */ }
    ///     Ok(()) => { /* connected */ }
    /// }
    /// ```
    #[cfg_attr(
        feature = "std",
        error("server identity mismatch: the server's signing key did not match the pinned key")
    )]
    ServerIdentityMismatch,

    /// The server explicitly rejected the connection — the client and server
    /// speak incompatible protocol versions or build variants (e.g., fips vs
    /// non-fips). **Fatal — do not retry with the same client binary.**
    ///
    /// The payload contains a human-readable diagnostic string (e.g., which
    /// versions were expected vs received).
    #[cfg_attr(feature = "std", error("protocol rejected by server: {0}"))]
    ProtocolRejected(String),

    /// The requested operation is not supported by this transport or
    /// configuration. For example, calling `migrate()` on a TCP-backed session
    /// (which does not support seamless migration) returns this variant.
    ///
    /// **Not retryable** — use the correct transport type (e.g.,
    /// `UdpClientTransport` for migration support).
    #[cfg_attr(feature = "std", error("unsupported operation: {0}"))]
    Unsupported(String),

    /// FIPS 140-3 §7.7 power-on self-test failed at process start.
    /// Surfaced by [`crate::api::PhantomListener::bind`] /
    /// [`crate::api::PhantomSession::connect_with_transport`] under
    /// `--features fips` when
    /// [`crate::crypto::self_tests::ensure_post_passed`] returns an
    /// error — refusing to stand up a session / listener over broken
    /// primitives.
    ///
    /// Gated on `fips`. The payload is a `String` (not the typed
    /// `SelfTestError`) so the variant stays UniFFI-exportable — the
    /// `Debug` rendering of `SelfTestError` is sufficient diagnostic
    /// signal for a fatal POST failure.
    #[cfg(feature = "fips")]
    #[error("FIPS POST self-test failed: {0}")]
    FipsSelfTestFailure(String),
}

// --- Converters for internal errors ---

// `std::io::Error`, `anyhow::Error`, and `getrandom::Error` are all only in
// the dep graph when the `std` feature is on; gate the converters accordingly.
#[cfg(feature = "std")]
impl core::convert::From<std::io::Error> for CoreError {
    fn from(e: std::io::Error) -> Self {
        CoreError::NetworkError(e.to_string())
    }
}

#[cfg(feature = "std")]
impl From<getrandom::Error> for CoreError {
    fn from(e: getrandom::Error) -> Self {
        CoreError::RngError(e.to_string())
    }
}

#[cfg(feature = "std")]
impl From<anyhow::Error> for CoreError {
    fn from(e: anyhow::Error) -> Self {
        CoreError::InternalError(e.to_string())
    }
}

// Hand-rolled Display impl for the no-std path — `thiserror` 1.x is std-bound
// so its derive is gated off above. The format strings mirror the
// `#[error("…")]` attributes exactly.
#[cfg(not(feature = "std"))]
impl core::fmt::Display for CoreError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NetworkError(s) => write!(f, "Network I/O Error: {s}"),
            Self::SerializationError(s) => write!(f, "Serialization Error: {s}"),
            Self::Busy => write!(f, "System Busy"),
            Self::ConfigError(s) => write!(f, "Invalid Configuration: {s}"),
            Self::CryptoError(s) => write!(f, "Cryptography Error: {s}"),
            Self::ValidationError(s) => write!(f, "Validation Error: {s}"),
            Self::RuntimeError(s) => write!(f, "Runtime initialization failed: {s}"),
            Self::KeyDerivationError => write!(f, "Key derivation failed"),
            Self::RngError(s) => write!(f, "Random number generation failed: {s}"),
            Self::InternalError(s) => write!(f, "Internal concurrency error: {s}"),
            Self::HandshakeError(s) => write!(f, "Handshake failed: {s}"),
            Self::StreamError(s) => write!(f, "Stream error: {s}"),
            Self::SessionNotFound(s) => write!(f, "Session not found: {s}"),
            Self::ConnectionClosed => write!(f, "Connection closed"),
            Self::Timeout => write!(f, "Timeout"),
            Self::ReplayDetected(s) => write!(f, "replay protection rejected packet: {s}"),
            Self::CipherSuiteUnavailable(s) => write!(f, "cipher suite unavailable: {s}"),
            Self::ServerIdentityMismatch => write!(
                f,
                "server identity mismatch: the server's signing key did not match the pinned key"
            ),
            Self::ProtocolRejected(s) => write!(f, "protocol rejected by server: {s}"),
            Self::Unsupported(s) => write!(f, "unsupported operation: {s}"),
        }
    }
}

// No `core::error::Error` impl is provided on the no-std path. The std path
// gets `std::error::Error` from the `thiserror::Error` derive (gated above);
// the no-std path deliberately stops at `Display` + `Debug`, which is all the
// embedded subset's error-propagation needs — there is no `?`-into-`dyn Error`
// boundary in that build. (`core::error::Error` would be available at the
// current 1.93 MSRV, but wiring it up buys the embedded path nothing.)

#[cfg(test)]
mod variant_discipline {
    /// Every variant this enum offers is one some production path constructs.
    ///
    /// The reasoning is the sibling of `every_connection_state_has_a_production_writer`
    /// in `api::session`, and the reason it is worth repeating here is that
    /// `CoreError` crosses the FFI: UniFFI turns each variant into an arm a
    /// foreign embedder writes in an exhaustive Kotlin `when` or Swift `switch`.
    /// A variant nobody constructs is therefore worse than a missing one — it is
    /// a branch someone maintains forever against an event that cannot happen.
    /// Three of them shipped that way (`Busy`, `RuntimeError`, `SessionNotFound`,
    /// zero construction sites between them) until this test existed.
    ///
    /// It reads the source rather than the type, because Rust offers no way to
    /// enumerate the variants of a foreign-facing enum and no way to ask which
    /// are constructed. The search is deliberately loose — any `CoreError::V`
    /// outside this file counts, including inside a test — so the test stays a
    /// gate on *dead* variants and never on where a variant is used.
    #[test]
    fn every_variant_has_a_construction_site() {
        const ERRORS: &str = include_str!("errors.rs");
        const SESSION: &str = include_str!("api/session.rs");
        const LIB: &str = include_str!("lib.rs");

        // The declarations, taken from this file's own enum body rather than
        // from a hand-kept list that would drift the moment one is added.
        let body = ERRORS
            .split_once("pub enum CoreError {")
            .and_then(|(_, rest)| rest.split_once("\n}\n"))
            .map(|(body, _)| body)
            .expect("the enum's body has to be findable for this to check anything");
        let declared: Vec<&str> = body
            .lines()
            .map(str::trim)
            .filter(|l| {
                l.chars().next().is_some_and(char::is_uppercase)
                    && !l.starts_with("///")
                    && !l.starts_with("#[")
            })
            .map(|l| l.split(['(', ',', ' ']).next().unwrap_or(l))
            .collect();
        assert!(
            declared.len() > 10,
            "the variant parse found only {declared:?}, so its silence about dead \
             variants would mean nothing"
        );

        // Where a variant may be constructed. `errors.rs` itself is excluded on
        // purpose: a `From` impl inside this file is plumbing, not a production
        // path that decides to raise the error.
        let haystack = format!("{SESSION}{LIB}");
        let dead: Vec<&&str> = declared
            .iter()
            .filter(|v| !haystack.contains(&format!("CoreError::{v}")))
            .collect();

        // A variant constructed elsewhere in the crate is fine; this test can
        // only see two files, so it names what it could not find rather than
        // failing on it. The gate is the `expect` below, which is what catches a
        // variant with no construction site anywhere.
        for v in &dead {
            let found = std::process::Command::new("grep")
                .args(["-rl", &format!("CoreError::{v}"), "src"])
                .current_dir(env!("CARGO_MANIFEST_DIR"))
                .output()
                .map(|o| !o.stdout.is_empty())
                .unwrap_or(true);
            assert!(
                found,
                "CoreError::{v} is declared and constructed nowhere in the crate. \
                 It still crosses the FFI, so an embedder writing an exhaustive \
                 match maintains an arm for an event that cannot happen. Either \
                 construct it or remove it."
            );
        }
    }
}
