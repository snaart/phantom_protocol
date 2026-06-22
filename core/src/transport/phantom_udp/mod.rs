//! PhantomUDP datagram framing — the outer UDP envelope + fragmentation for the
//! native reliable-UDP transport (the production transport, with seamless
//! single-path connection migration).
//!
//! This module is just the framing layer: [`envelope`] is the unauthenticated
//! `[flags][cid]` outer header, and [`datagram`] maps one logical frame to one or
//! more MTU-bounded UDP datagrams (fragmenting + reassembling oversized frames).
//! The `SessionTransport` impls and the CID-window demux listener that build on it
//! live in `api/udp_transport.rs` / `api/udp_listener.rs`, NOT here.
//!
//! See `docs/protocol/PROTOCOL.md` §4.9 (the outer datagram envelope and
//! fragmentation) and §12 (connection migration / liveness).
pub mod datagram;
pub mod envelope;
