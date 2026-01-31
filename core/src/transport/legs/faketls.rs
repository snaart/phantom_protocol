//! FakeTLS Transport Leg
//!
//! Obfuscated transport that mimics TLS 1.3 traffic for DPI bypass.
//! Wraps actual payload in fake TLS records.

use crate::transport::legs::TransportLeg;

use async_trait::async_trait;
use bytes::{Bytes, BytesMut, Buf, BufMut};
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, AtomicU8, AtomicBool, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use rand::Rng;
use rand::seq::SliceRandom;
use x25519_dalek::{StaticSecret, PublicKey as X25519PublicKey};

/// TLS record types
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
enum TlsContentType {
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
}

/// FakeTLS configuration
#[derive(Debug, Clone)]
pub struct FakeTlsConfig {
    /// Server Name Indication (SNI) to use in ClientHello
    pub sni: String,
    /// TLS version to advertise
    pub version: u16,
}

impl Default for FakeTlsConfig {
    fn default() -> Self {
        Self {
            sni: "www.google.com".to_string(),
            version: 0x0303, // TLS 1.2 (for compatibility)
        }
    }
}

/// FakeTLS transport leg
pub struct FakeTlsLeg {
    /// Configuration
    config: FakeTlsConfig,
    /// Underlying TCP stream
    stream: Mutex<Option<TcpStream>>,
    /// Remote address
    remote_addr: Option<SocketAddr>,
    /// Current RTT estimate (ms)
    rtt_ms: AtomicU32,
    /// Whether leg is available
    available: AtomicBool,
    /// Whether handshake is complete
    handshake_done: AtomicBool,
    /// Read buffer
    read_buf: Mutex<BytesMut>,
}

impl FakeTlsLeg {
    /// Create a new FakeTLS leg with default config
    pub fn new() -> Self {
        Self::with_config(FakeTlsConfig::default())
    }

    /// Create with custom config
    pub fn with_config(config: FakeTlsConfig) -> Self {
        Self {
            config,
            stream: Mutex::new(None),
            remote_addr: None,
            rtt_ms: AtomicU32::new(150),
            available: AtomicBool::new(false),
            handshake_done: AtomicBool::new(false),
            read_buf: Mutex::new(BytesMut::with_capacity(16384)),
        }
    }

    /// Connect and perform fake TLS handshake
    pub async fn connect(addr: SocketAddr, config: FakeTlsConfig) -> io::Result<Self> {
        let start = std::time::Instant::now();
        let stream = TcpStream::connect(addr).await?;
        let rtt = start.elapsed().as_millis() as u32;
        
        stream.set_nodelay(true)?;
        
        let leg = Self {
            config,
            stream: Mutex::new(Some(stream)),
            remote_addr: Some(addr),
            rtt_ms: AtomicU32::new(rtt),
            available: AtomicBool::new(true),
            handshake_done: AtomicBool::new(false),
            read_buf: Mutex::new(BytesMut::with_capacity(16384)),
        };
        
        // Perform fake handshake
        leg.do_fake_handshake().await?;
        
        log::info!("FakeTLS connected to {} (SNI: {})", addr, leg.config.sni);
        Ok(leg)
    }

    /// Perform fake TLS handshake
    async fn do_fake_handshake(&self) -> io::Result<()> {
        let mut stream_guard = self.stream.lock().await;
        let stream = stream_guard.as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "Not connected"))?;
        
        // Send fake ClientHello
        let client_hello = self.build_fake_client_hello();
        stream.write_all(&client_hello).await?;
        
        // Read fake ServerHello (we just consume whatever the server sends)
        // In a real implementation, the server would also send fake TLS records
        let mut buf = [0u8; 4096];
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            stream.read(&mut buf),
        ).await;
        
        self.handshake_done.store(true, Ordering::Relaxed);
        Ok(())
    }

    /// Build a fake TLS ClientHello that looks legitimate and randomized (JA3)
    fn build_fake_client_hello(&self) -> Vec<u8> {
        let mut record = Vec::with_capacity(512);
        let mut rng = rand::thread_rng();
        
        // TLS record header
        record.push(TlsContentType::Handshake as u8);
        record.extend_from_slice(&self.config.version.to_be_bytes());
        
        // Placeholder for length (will fill in later)
        let length_pos = record.len();
        record.extend_from_slice(&[0u8; 2]);
        
        // Handshake header
        record.push(0x01); // ClientHello
        // Placeholder for handshake length
        let hs_length_pos = record.len();
        record.extend_from_slice(&[0u8; 3]);
        
        // Client version (Legacy TLS 1.2)
        record.extend_from_slice(&0x0303u16.to_be_bytes()); 
        
        // Random (32 bytes)
        let mut random = [0u8; 32];
        getrandom::getrandom(&mut random).unwrap_or_default();
        record.extend_from_slice(&random);
        
        // Session ID (32 bytes)
        record.push(32);
        let mut session_id = [0u8; 32];
        getrandom::getrandom(&mut session_id).unwrap_or_default();
        record.extend_from_slice(&session_id);
        
        // Cipher suites (Randomized order and selection)
        // Grease ciphers: 0x0a0a, 0x1a1a, etc.
        let grease = (rng.gen::<u8>() & 0xf0) as u16 + 0x0a0a; 
        
        let mut suites = vec![
            0x1301, // TLS_AES_128_GCM_SHA256
            0x1302, // TLS_AES_256_GCM_SHA384
            0x1303, // TLS_CHACHA20_POLY1305_SHA256
            0xc02b, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            0xc02c, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
            0xc02f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            0xc030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
            0xcca9, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
            0xcca8, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
        ];
        
        // Shuffle and take random subset (at least 3)
        use rand::seq::SliceRandom;
        use rand::Rng; // Add this import if not present, but better to use fully qualified or assume scope
        
        suites.shuffle(&mut rng);
        let num_suites = rng.gen_range(3..=suites.len());
        suites.truncate(num_suites);
        
        // Insert GREASE at random position
        suites.insert(rng.gen_range(0..=suites.len()), grease);
        
        record.extend_from_slice(&((suites.len() * 2) as u16).to_be_bytes());
        for s in suites {
            record.extend_from_slice(&s.to_be_bytes());
        }
        
        // Compression methods (Unused in TLS 1.3 but required for legacy)
        record.push(1);
        record.push(0); // null compression
        
        // Extensions
        let extensions_start = record.len();
        record.extend_from_slice(&[0u8; 2]); // Extensions length placeholder
        
        // Generate and shuffle extensions
        let mut exts = Vec::new();
        
        // SNI (0)
        exts.push((0u16, self.make_sni_extension_body()));
        
        // Supported Groups (10) - X25519, P-256, P-384 + GREASE
        exts.push((10u16, self.make_supported_groups_body(&mut rng)));

        // EC Point Formats (11)
        exts.push((11u16, vec![1, 0])); // Len 1, Uncompressed (0)

        // Signature Algorithms (13)
        exts.push((13u16, self.make_signature_algorithms_body()));
        
        // Key Share (51)
        exts.push((51u16, self.make_key_share_body(&mut rng)));

        // Supported Versions (43) - TLS 1.3, TLS 1.2 + GREASE
        exts.push((43u16, self.make_supported_versions_body(&mut rng)));
        
        // Padding (21) - to avoid fingerprinting by length
        // We pad ClientHello to be between 512 and 1024 bytes usually if needed, 
        // but here just random small padding to vary size.
        // Actually, Chrome pads to 517+ bytes sometimes. 
        // Let's add random padding extension.
        exts.push((21u16, vec![0u8; rng.gen_range(1..100)]));

        // Shuffle extensions (except SNI which usually comes first, and some others? No, TLS 1.3 allows any order, but SNI usually first)
        // We'll keep SNI first if present, shuffle rest
        if !exts.is_empty() {
            let sni = exts.remove(0); // Assuming we pushed SNI first
            exts.shuffle(&mut rng);
            exts.insert(0, sni);
        }

        for (etype, body) in exts {
            record.extend_from_slice(&etype.to_be_bytes());
            record.extend_from_slice(&(body.len() as u16).to_be_bytes());
            record.extend_from_slice(&body);
        }
        
        // Fill in extensions length
        let extensions_len = (record.len() - extensions_start - 2) as u16;
        record[extensions_start..extensions_start + 2]
            .copy_from_slice(&extensions_len.to_be_bytes());
        
        // Fill in handshake length
        let hs_len = (record.len() - hs_length_pos - 3) as u32;
        record[hs_length_pos] = ((hs_len >> 16) & 0xFF) as u8;
        record[hs_length_pos + 1] = ((hs_len >> 8) & 0xFF) as u8;
        record[hs_length_pos + 2] = (hs_len & 0xFF) as u8;
        
        // Fill in record length
        let record_len = (record.len() - 5) as u16;
        record[length_pos..length_pos + 2].copy_from_slice(&record_len.to_be_bytes());
        
        record
    }

    fn make_sni_extension_body(&self) -> Vec<u8> {
        let mut body = Vec::new();
        let sni_bytes = self.config.sni.as_bytes();
        body.extend_from_slice(&((3 + sni_bytes.len()) as u16).to_be_bytes()); // Server name list length
        body.push(0); // Name type: host_name
        body.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
        body.extend_from_slice(sni_bytes);
        body
    }

    fn make_supported_groups_body(&self, rng: &mut impl rand::Rng) -> Vec<u8> {
        let mut body = Vec::new();
        let grease = (rng.gen::<u8>() & 0xf0) as u16 + 0x0a0a;
        let groups = [
            grease,
            0x001d, // X25519
            0x0017, // secp256r1
        ];
        let len = (groups.len() * 2) as u16;
        body.extend_from_slice(&len.to_be_bytes());
        for g in groups {
            body.extend_from_slice(&g.to_be_bytes());
        }
        body
    }
    
    fn make_signature_algorithms_body(&self) -> Vec<u8> {
         let mut body = Vec::new();
         let algos: [u16; 8] = [
             0x0403, // ecdsa_secp256r1_sha256
             0x0804, // rsa_pss_rsae_sha256
             0x0401, // rsa_pkcs1_sha256
             0x0503, // ecdsa_secp384r1_sha384
             0x0805, // rsa_pss_rsae_sha384
             0x0501, // rsa_pkcs1_sha384
             0x0806, // rsa_pss_rsae_sha512
             0x0601, // rsa_pkcs1_sha512
         ];
         let len = (algos.len() * 2) as u16;
         body.extend_from_slice(&len.to_be_bytes());
         for a in algos {
             body.extend_from_slice(&a.to_be_bytes());
         }
         body
    }
    
    fn make_key_share_body(&self, rng: &mut (impl rand::Rng + rand::CryptoRng)) -> Vec<u8> {
        let mut body = Vec::new();
        let grease = (rng.gen::<u8>() & 0xf0) as u16 + 0x0a0a;
        
        // Real X25519 key share
        let secret = StaticSecret::random_from_rng(rng);
        let public = X25519PublicKey::from(&secret);
        let x25519_share = public.as_bytes();
        
        let client_shares_len = 4 + (2 + 32); // Grease (4) + X25519 (2+32)
        body.extend_from_slice(&(client_shares_len as u16).to_be_bytes());
        
        // GREASE share
        body.extend_from_slice(&grease.to_be_bytes());
        body.extend_from_slice(&1u16.to_be_bytes()); // Len 1
        body.push(0);
        
        // X25519 share
        body.extend_from_slice(&0x001du16.to_be_bytes());
        body.extend_from_slice(&(x25519_share.len() as u16).to_be_bytes());
        body.extend_from_slice(x25519_share);
        
        body
    }

    fn make_supported_versions_body(&self, rng: &mut impl rand::Rng) -> Vec<u8> {
        let mut body = Vec::new();
        let grease = (rng.gen::<u8>() & 0xf0) as u16 + 0x0a0a;
        let versions = [
            grease,
            0x0304, // TLS 1.3
            0x0303, // TLS 1.2
        ];
        let len = (versions.len() * 2) as u16;
        body.push((len & 0xFF) as u8); // Supported versions length is 1 byte in this extension body
        for v in versions {
            body.extend_from_slice(&v.to_be_bytes());
        }
        body
    }

    /// Wrap data as TLS Application Data record
    fn wrap_as_tls_record(&self, data: &[u8]) -> Vec<u8> {
        let mut record = Vec::with_capacity(5 + data.len());
        
        // TLS record header
        record.push(TlsContentType::ApplicationData as u8);
        record.extend_from_slice(&self.config.version.to_be_bytes());
        record.extend_from_slice(&(data.len() as u16).to_be_bytes());
        record.extend_from_slice(data);
        
        record
    }

    /// Unwrap TLS Application Data record
    fn unwrap_tls_record<'a>(&self, record: &'a [u8]) -> io::Result<&'a [u8]> {
        if record.len() < 5 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Record too short"));
        }
        
        // Skip record header (5 bytes)
        Ok(&record[5..])
    }
}

impl Default for FakeTlsLeg {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl TransportLeg for FakeTlsLeg {
    async fn send(&self, data: Bytes) -> io::Result<()> {
        if !self.is_available() {
            return Err(io::Error::new(io::ErrorKind::NotConnected, "FakeTLS not connected"));
        }

        let record = self.wrap_as_tls_record(&data);
        
        let mut stream_guard = self.stream.lock().await;
        let stream = stream_guard.as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "Not connected"))?;
        
        stream.write_all(&record).await?;
        stream.flush().await
    }

    async fn recv(&self) -> io::Result<Bytes> {
        if !self.is_available() {
            return Err(io::Error::new(io::ErrorKind::NotConnected, "FakeTLS not connected"));
        }

        let mut stream_guard = self.stream.lock().await;
        let stream = stream_guard.as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "Not connected"))?;
        
        let mut read_buf = self.read_buf.lock().await;
        
        // Read TLS record header (5 bytes)
        while read_buf.len() < 5 {
            let mut temp = [0u8; 4096];
            let n = stream.read(&mut temp).await?;
            if n == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Connection closed"));
            }
            read_buf.extend_from_slice(&temp[..n]);
        }
        
        // Parse record length
        let record_len = u16::from_be_bytes([read_buf[3], read_buf[4]]) as usize;
        
        // Read full record
        while read_buf.len() < 5 + record_len {
            let mut temp = [0u8; 4096];
            let n = stream.read(&mut temp).await?;
            if n == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Connection closed"));
            }
            read_buf.extend_from_slice(&temp[..n]);
        }
        
        // Extract record
        let record = read_buf.split_to(5 + record_len);
        
        // Unwrap and return payload
        Ok(Bytes::copy_from_slice(&record[5..]))
    }

    fn is_available(&self) -> bool {
        self.available.load(Ordering::Relaxed) && self.handshake_done.load(Ordering::Relaxed)
    }

    fn rtt_ms(&self) -> u32 {
        self.rtt_ms.load(Ordering::Relaxed)
    }

    fn loss_percent(&self) -> u8 {
        0 // Based on TCP
    }

    fn remote_addr(&self) -> Option<SocketAddr> {
        self.remote_addr
    }

    async fn close(&self) -> io::Result<()> {
        self.available.store(false, Ordering::Relaxed);
        
        if let Some(stream) = self.stream.lock().await.take() {
            drop(stream);
        }
        
        log::info!("FakeTLS closed");
        Ok(())
    }
}

impl std::fmt::Debug for FakeTlsLeg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FakeTlsLeg")
            .field("sni", &self.config.sni)
            .field("remote", &self.remote_addr)
            .field("rtt_ms", &self.rtt_ms.load(Ordering::Relaxed))
            .field("available", &self.is_available())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_faketls_leg_creation() {
        let leg = FakeTlsLeg::new();
        assert!(!leg.is_available());
        assert_eq!(leg.config.sni, "www.google.com");
    }

    #[test]
    fn test_fake_client_hello() {
        let leg = FakeTlsLeg::new();
        let hello = leg.build_fake_client_hello();
        
        // Should start with TLS handshake record
        assert_eq!(hello[0], TlsContentType::Handshake as u8);
        assert!(hello.len() > 100); // Should be substantial
    }

    #[test]
    fn test_wrap_tls_record() {
        let leg = FakeTlsLeg::new();
        let data = b"test payload";
        let record = leg.wrap_as_tls_record(data);
        
        assert_eq!(record[0], TlsContentType::ApplicationData as u8);
        assert_eq!(record.len(), 5 + data.len());
    }

    #[test]
    fn test_ja3_randomization() {
        let leg = FakeTlsLeg::new();
        let hello1_ = leg.build_fake_client_hello();
        let hello2 = leg.build_fake_client_hello();
        
        // They should be different due to random session ID, random, and shuffling
        assert_ne!(hello1_, hello2);
        
        // Check standard parts presence
        // TLS 1.2 Version (0x0303) at offset 9
        assert_eq!(hello1_[9], 0x03);
        assert_eq!(hello1_[10], 0x03);
    }

    #[test]
    fn test_client_hello_structure() {
        let leg = FakeTlsLeg::new();
        let hello = leg.build_fake_client_hello();
        
        // Parse with strict TLS parser
        use tls_parser::{parse_tls_plaintext, TlsMessage, TlsMessageHandshake};
        
        let (_, msg) = parse_tls_plaintext(&hello).expect("Should parse as valid TLS record");
        
        // Ensure it's a Handshake -> ClientHello
        if let TlsMessage::Handshake(TlsMessageHandshake::ClientHello(ch)) = &msg.msg[0] {
            // Verify structure
            assert_eq!(ch.version, tls_parser::TlsVersion::Tls12); // Legacy version
            assert!(ch.session_id.is_some());
            assert!(ch.ciphers.len() >= 3);
            
            // Check for KeyShare extension (for X25519)
            if let Some(ext_bytes) = ch.ext {
                let (_, extensions) = tls_parser::parse_tls_extensions(ext_bytes).expect("Should parse extensions");
                let has_keyshare = extensions.iter().any(|ext| {
                    match ext {
                        tls_parser::TlsExtension::KeyShare(_) => true,
                        _ => false,
                    }
                });
                assert!(has_keyshare, "ClientHello must contain KeyShare extension");
            } else {
                panic!("ClientHello must contain extensions");
            }
            
        } else {
            panic!("Expected Handshake(ClientHello), got {:?}", msg);
        }
    }
}
