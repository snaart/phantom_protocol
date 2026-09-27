// SPDX-License-Identifier: Apache-2.0
//! The interop peer built against this tree.
//!
//! The behaviour is in `scripts/interop/peer.rs`, included verbatim by this crate and by
//! `peer-030`, so the only difference between the two binaries is which version of
//! `phantom-protocol` their manifests name. That the same source compiles against both is
//! itself part of what the job proves: a patch that breaks a consumer's build is the defect
//! this release was told to avoid.

/// Which side of the pairing this binary is, for the log.
const PEER_CORE_VERSION: &str = "this tree";

include!("../../peer.rs");
