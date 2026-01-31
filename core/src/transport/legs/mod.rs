//! Transport Legs Module
//! 
//! Pluggable physical transports (KCP, TCP, FakeTLS)

pub mod kcp;
pub mod tcp;
pub mod faketls;

use async_trait::async_trait;
use bytes::Bytes;
use std::io;
use std::net::SocketAddr;

/// Transport leg trait - abstraction over different physical transports
#[async_trait]
pub trait TransportLeg: Send + Sync {
    /// Send data to the remote peer
    async fn send(&self, data: Bytes) -> io::Result<()>;
    
    /// Receive data from the remote peer
    async fn recv(&self) -> io::Result<Bytes>;
    
    /// Check if this leg is currently available
    fn is_available(&self) -> bool;
    
    /// Get the current RTT estimate in milliseconds
    fn rtt_ms(&self) -> u32;
    
    /// Get packet loss percentage (0-100)
    fn loss_percent(&self) -> u8;
    
    /// Get the remote address
    fn remote_addr(&self) -> Option<SocketAddr>;
    
    /// Gracefully close the transport
    async fn close(&self) -> io::Result<()>;
}

/// Leg type identifier for scheduler decisions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LegType {
    /// KCP over UDP - fast, reliable, primary transport
    Kcp,
    /// Raw TCP - reliable fallback
    Tcp,
    /// FakeTLS over TCP - obfuscated for DPI bypass
    FakeTls,
}

impl LegType {
    /// Whether this leg type provides reliability at transport level
    pub fn is_reliable(&self) -> bool {
        matches!(self, LegType::Kcp | LegType::Tcp | LegType::FakeTls)
    }
    
    /// Whether this leg type uses encryption/obfuscation
    pub fn is_obfuscated(&self) -> bool {
        matches!(self, LegType::FakeTls)
    }
}
