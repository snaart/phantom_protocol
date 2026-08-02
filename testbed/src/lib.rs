//! Real-network (WAN) test harness for the Phantom protocol.
//!
//! Two binaries share this library:
//!
//! - `phantom-testd` — the daemon. Binds every network-testable leg (PhantomUDP,
//!   Phantom-over-TCP, mimic-TLS), a QUIC reference leg, and raw TCP/UDP echo
//!   controls, and records server-side statistics.
//! - `phantom-probe` — the client. Drives a scenario matrix across those legs
//!   and writes raw per-operation samples.
//!
//! Three kinds of leg, and confusing them is how a result gets misread: the
//! Phantom legs are the protocol under test, the raw legs are controls carrying
//! no protocol at all, and the QUIC leg is a *reference* — a mature
//! implementation of the same class, on the same path, in the same run.
//!
//! Everything here is a consumer of the published `phantom-protocol` API. The
//! harness never reaches into protocol internals, so a result it produces is a
//! statement about the shipped surface rather than about a private path.
//!
//! ## Why a separate crate
//!
//! The repository's automated tests all run over loopback or an in-memory
//! transport, where RTT is microseconds, nothing reorders, no NAT exists, and
//! the path MTU is 65535. That regime cannot exercise the RTO timer, the
//! bandwidth estimator, real migration, or path-MTU behaviour. This crate is
//! the instrument for the regime that can.

pub mod clock;
pub mod framing;
pub mod probe;
pub mod proto;
pub mod quic;
pub mod report;
pub mod stats;
pub mod sysinfo;
pub mod testd;
