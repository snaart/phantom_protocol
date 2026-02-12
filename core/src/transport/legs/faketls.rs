//! FakeTLS Transport Leg
//!
//! Obfuscated transport that mimics TLS 1.3 traffic for DPI bypass.
//! Wraps actual payload in fake TLS records.

use crate::transport::legs::TransportLeg;

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicBool, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use rand::rngs::OsRng;
use x25519_dalek::{StaticSecret, PublicKey as X25519PublicKey};
use ring::aead::{self, LessSafeKey, UnboundKey, Nonce};

/// TLS record types
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
enum TlsContentType {
    #[allow(dead_code)]
    ChangeCipherSpec = 20,
    #[allow(dead_code)]
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

/// State machine for FakeTLS Handshake
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FakeTlsState {
    /// Initial state (0)
    Init = 0,
    /// Client: Sent ClientHello, waiting for ServerHello (1)
    /// Server: Received ClientHello, waiting to send ServerHello (1)
    ClientHelloDone = 1,
    /// Handshake completed, ready for Application Data (2)
    ServerHelloDone = 2,
    /// Ready for Phantom packets wrapped in ApplicationData (3)
    ApplicationData = 3,
}

/// FakeTLS transport leg
///
/// AEAD note: This is an *outer* DPI-obfuscation layer. Real confidentiality
/// and authentication come from the inner Phantom session (see
/// `crate::transport::session::Session`). The outer AEAD key is derived
/// deterministically from a public seed (SNI + version) so both peers reach
/// the same key without a Diffie-Hellman exchange; nonce uniqueness per record
/// is provided by an atomic counter (mirrors `AesSession::make_nonce`).
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
    /// Current connection state
    state: parking_lot::RwLock<FakeTlsState>,
    /// Read buffer
    read_buf: Mutex<BytesMut>,
    /// AES-256-GCM key used for sealing outbound records.
    send_key: LessSafeKey,
    /// AES-256-GCM key used for opening inbound records.
    recv_key: LessSafeKey,
    /// 4-byte nonce prefix; remaining 8 bytes are a per-direction counter.
    nonce_prefix: [u8; 4],
    /// Monotonically increasing counter for outbound records.
    send_counter: AtomicU64,
    /// Monotonically increasing counter for inbound records (TCP is in-order).
    recv_counter: AtomicU64,
    /// Is this leg acting as a server?
    #[allow(dead_code)]
    is_server: bool,
}

/// Derive the outer AEAD key material for both peers from a publicly-known seed.
///
/// Because the seed is public this layer provides no real confidentiality — it
/// exists solely to produce pseudo-random ciphertext that defeats DPI
/// fingerprinting. The inner Phantom session provides actual auth/conf.
fn derive_outer_keys(
    sni: &str,
    version: u16,
    is_server: bool,
) -> io::Result<(LessSafeKey, LessSafeKey, [u8; 4])> {
    let mut seed = Vec::with_capacity(64);
    seed.extend_from_slice(b"phantom-faketls-outer-v1");
    seed.extend_from_slice(&version.to_be_bytes());
    seed.extend_from_slice(sni.as_bytes());

    let key_c2s = blake3::derive_key("phantom-faketls-c2s-v1", &seed);
    let key_s2c = blake3::derive_key("phantom-faketls-s2c-v1", &seed);
    let pfx = blake3::derive_key("phantom-faketls-pfx-v1", &seed);

    let mut nonce_prefix = [0u8; 4];
    nonce_prefix.copy_from_slice(&pfx[..4]);

    let (send_bytes, recv_bytes) = if is_server {
        (key_s2c, key_c2s)
    } else {
        (key_c2s, key_s2c)
    };
    // `UnboundKey::new(&AES_256_GCM, key)` only fails if the slice length is
    // wrong — `blake3::derive_key` always emits exactly 32 bytes and
    // `AES_256_GCM.key_len()` is 32, so this is structurally infallible.
    // Surface it as a typed error anyway so the function stays total.
    let send_unbound = UnboundKey::new(&aead::AES_256_GCM, &send_bytes)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("AES key init (send): {}", e)))?;
    let recv_unbound = UnboundKey::new(&aead::AES_256_GCM, &recv_bytes)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("AES key init (recv): {}", e)))?;
    Ok((
        LessSafeKey::new(send_unbound),
        LessSafeKey::new(recv_unbound),
        nonce_prefix,
    ))
}

impl FakeTlsLeg {
    /// Create a new FakeTLS leg with default config. Returns an error only
    /// in the structurally-impossible case that AES-256-GCM key initialization
    /// fails (preserved as a `Result` to keep the API panic-free).
    pub fn new() -> io::Result<Self> {
        Self::with_config(FakeTlsConfig::default())
    }

    /// Create with custom config (client role; not yet connected). See
    /// [`FakeTlsLeg::new`] for the error contract.
    pub fn with_config(config: FakeTlsConfig) -> io::Result<Self> {
        let (send_key, recv_key, nonce_prefix) =
            derive_outer_keys(&config.sni, config.version, false)?;

        Ok(Self {
            config,
            stream: Mutex::new(None),
            remote_addr: None,
            rtt_ms: AtomicU32::new(150),
            available: AtomicBool::new(false),
            state: parking_lot::RwLock::new(FakeTlsState::Init),
            read_buf: Mutex::new(BytesMut::with_capacity(16384)),
            send_key,
            recv_key,
            nonce_prefix,
            send_counter: AtomicU64::new(0),
            recv_counter: AtomicU64::new(0),
            is_server: false,
        })
    }

    /// Connect as Client and perform fake TLS handshake
    pub async fn connect(addr: SocketAddr, config: FakeTlsConfig) -> io::Result<Self> {
        let start = std::time::Instant::now();
        let stream = TcpStream::connect(addr).await?;
        let rtt = start.elapsed().as_millis() as u32;

        stream.set_nodelay(true)?;

        let (send_key, recv_key, nonce_prefix) =
            derive_outer_keys(&config.sni, config.version, false)?;

        let leg = Self {
            config,
            stream: Mutex::new(Some(stream)),
            remote_addr: Some(addr),
            rtt_ms: AtomicU32::new(rtt),
            available: AtomicBool::new(true),
            state: parking_lot::RwLock::new(FakeTlsState::Init),
            read_buf: Mutex::new(BytesMut::with_capacity(16384)),
            send_key,
            recv_key,
            nonce_prefix,
            send_counter: AtomicU64::new(0),
            recv_counter: AtomicU64::new(0),
            is_server: false,
        };

        leg.do_client_handshake().await?;

        Ok(leg)
    }

    /// Accept connection as Server and perform fake TLS handshake
    pub async fn accept(stream: TcpStream, config: FakeTlsConfig) -> io::Result<Self> {
        stream.set_nodelay(true)?;
        let remote_addr = stream.peer_addr().ok();

        let (send_key, recv_key, nonce_prefix) =
            derive_outer_keys(&config.sni, config.version, true)?;

        let leg = Self {
            config,
            stream: Mutex::new(Some(stream)),
            remote_addr,
            rtt_ms: AtomicU32::new(150),
            available: AtomicBool::new(true),
            state: parking_lot::RwLock::new(FakeTlsState::Init),
            read_buf: Mutex::new(BytesMut::with_capacity(16384)),
            send_key,
            recv_key,
            nonce_prefix,
            send_counter: AtomicU64::new(0),
            recv_counter: AtomicU64::new(0),
            is_server: true,
        };

        leg.do_server_handshake().await?;

        Ok(leg)
    }

    /// Construct nonce: 4-byte prefix || 8-byte big-endian counter.
    #[inline]
    fn make_nonce(&self, counter: u64) -> Nonce {
        let mut n = [0u8; 12];
        n[..4].copy_from_slice(&self.nonce_prefix);
        n[4..12].copy_from_slice(&counter.to_be_bytes());
        Nonce::assume_unique_for_key(n)
    }

    /// Perform client-side fake handshake
    async fn do_client_handshake(&self) -> io::Result<()> {
        let mut stream_guard = self.stream.lock().await;
        let stream = stream_guard.as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "Not connected"))?;
        
        // State 0 -> 1: Send ClientHello
        let client_hello = self.build_fake_client_hello();
        stream.write_all(&client_hello).await?;
        *self.state.write() = FakeTlsState::ClientHelloDone;
        
        // State 1 -> 2: Read ServerHello
        let mut buf = [0u8; 4096];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            stream.read(&mut buf),
        ).await.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "ServerHello timeout"))??;

        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::ConnectionAborted, "Connection closed by server"));
        }
        
        // We received dummy ServerHello
        *self.state.write() = FakeTlsState::ServerHelloDone;
        
        // State 2 -> 3: Application Data (Ready)
        *self.state.write() = FakeTlsState::ApplicationData;
        Ok(())
    }

    /// Perform server-side fake handshake
    async fn do_server_handshake(&self) -> io::Result<()> {
        let mut stream_guard = self.stream.lock().await;
        let stream = stream_guard.as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "Not connected"))?;
        
        // State 0 -> 1: Read ClientHello
        let mut buf = [0u8; 4096];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            stream.read(&mut buf),
        ).await.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "ClientHello timeout"))??;
        
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::ConnectionAborted, "Connection closed by client"));
        }
        
        *self.state.write() = FakeTlsState::ClientHelloDone;
        
        // State 1 -> 2: Send ServerHello
        let server_hello = self.build_fake_server_hello();
        stream.write_all(&server_hello).await?;
        *self.state.write() = FakeTlsState::ServerHelloDone;
        
        // State 2 -> 3: Application Data (Ready)
        *self.state.write() = FakeTlsState::ApplicationData;
        Ok(())
    }

    /// Build a fake TLS ServerHello
    fn build_fake_server_hello(&self) -> Vec<u8> {
        let mut record = Vec::with_capacity(128);
        record.push(TlsContentType::Handshake as u8);
        record.extend_from_slice(&self.config.version.to_be_bytes()); // e.g. TLS 1.2
        
        let mut hs = Vec::new();
        hs.push(0x02); // ServerHello
        // length placeholder
        hs.extend_from_slice(&[0, 0, 0]);
        // Server version
        hs.extend_from_slice(&0x0303u16.to_be_bytes());
        
        // Server Random
        let mut random = [0u8; 32];
        if getrandom::getrandom(&mut random).is_err() {
            use rand::RngCore;
            rand::thread_rng().fill_bytes(&mut random);
        }
        hs.extend_from_slice(&random);
        
        // Session ID length (0)
        hs.push(0);
        
        // Cipher suite TLS_AES_256_GCM_SHA384
        hs.extend_from_slice(&0x1302u16.to_be_bytes());
        // Compression method null
        hs.push(0);
        
        // Extensions
        hs.extend_from_slice(&[0, 8]); // Extensions len: 8
        // Key share (Server)
        hs.extend_from_slice(&51u16.to_be_bytes());
        hs.extend_from_slice(&4u16.to_be_bytes()); // len 4
        hs.extend_from_slice(&0x001du16.to_be_bytes()); // X25519
        hs.extend_from_slice(&0u16.to_be_bytes()); // dummy payload
        
        let hs_len = (hs.len() - 4) as u32;
        hs[1] = ((hs_len >> 16) & 0xFF) as u8;
        hs[2] = ((hs_len >> 8) & 0xFF) as u8;
        hs[3] = (hs_len & 0xFF) as u8;
        
        record.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        record.extend_from_slice(&hs);
        
        record
    }

    /// Build a fake TLS ClientHello that looks legitimate and randomized (JA3)
    fn build_fake_client_hello(&self) -> Vec<u8> {
        let mut record = Vec::with_capacity(512);
        let mut rng = OsRng;
        
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
        if getrandom::getrandom(&mut random).is_err() {
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut random);
        }
        record.extend_from_slice(&random);
        
        // Session ID (32 bytes)
        record.push(32);
        let mut session_id = [0u8; 32];
        if getrandom::getrandom(&mut session_id).is_err() {
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut session_id);
        }
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

        // Shuffle extensions (except SNI which usually comes first)
        if !exts.is_empty() {
            let sni = exts.remove(0); // Assuming we pushed SNI first
            exts.shuffle(&mut rng);
            exts.insert(0, sni);
        }

        // Padding (21) - MUST be at the end for JA3 fingerprinting evasion
        // Add random size padding to randomize the ClientHello length
        exts.push((21u16, vec![0u8; rng.gen_range(50..200)]));

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

    /// Wrap data as TLS Application Data record using ring AEAD.
    ///
    /// Each call increments `send_counter` so the (key, nonce) pair is unique
    /// per record — the previous implementation reused `[0u8; 12]` and was
    /// vulnerable to the Forbidden Attack on AES-GCM.
    fn wrap_as_tls_record(&self, data: &[u8]) -> Vec<u8> {
        // TLS 1.3 framing: inner plaintext + TLS1.3 AppData type (0x17)
        let mut inner_plaintext = Vec::with_capacity(data.len() + 1);
        inner_plaintext.extend_from_slice(data);
        inner_plaintext.push(TlsContentType::ApplicationData as u8); // inner content type

        // Encrypt with ring using a counter-based nonce.
        let mut in_out = inner_plaintext;
        let counter = self.send_counter.fetch_add(1, Ordering::Relaxed);
        let nonce = self.make_nonce(counter);

        let aad = aead::Aad::empty();
        self.send_key
            .seal_in_place_append_tag(nonce, aad, &mut in_out)
            .unwrap();

        let mut record = Vec::with_capacity(5 + in_out.len());

        // Outer TLS record header (Legacy Application Data)
        record.push(TlsContentType::ApplicationData as u8);
        record.extend_from_slice(&self.config.version.to_be_bytes());
        record.extend_from_slice(&(in_out.len() as u16).to_be_bytes());
        record.extend_from_slice(&in_out);

        record
    }

    /// Unwrap TLS Application Data record.
    ///
    /// Each call increments `recv_counter` in lockstep with the peer's
    /// `send_counter` (TCP guarantees in-order delivery). If a record is
    /// corrupted or the counters drift, decryption fails and the leg should
    /// be closed.
    fn unwrap_tls_record<'a>(&self, record: &'a mut [u8]) -> io::Result<&'a [u8]> {
        if record.len() < 5 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Record too short"));
        }

        let payload = &mut record[5..];

        let counter = self.recv_counter.fetch_add(1, Ordering::Relaxed);
        let nonce = self.make_nonce(counter);
        let aad = aead::Aad::empty();

        let decrypted = self
            .recv_key
            .open_in_place(nonce, aad, payload)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "AEAD decryption failed"))?;

        // Remove inner content type (last byte)
        if decrypted.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Empty inner plaintext"));
        }

        let inner_len = decrypted.len() - 1;
        Ok(&decrypted[..inner_len])
    }
}

impl Default for FakeTlsLeg {
    /// `Default` panics on key-init failure — see [`FakeTlsLeg::new`] for the
    /// structurally-impossible error contract. Prefer the explicit
    /// `FakeTlsLeg::new()` in code that cares about the error.
    fn default() -> Self {
        #[allow(clippy::expect_used)]
        Self::new().expect("FakeTlsLeg::default: AES key init invariant violated")
    }
}

#[async_trait]
impl TransportLeg for FakeTlsLeg {
    async fn send(&self, data: Bytes) -> io::Result<()> {
        if !self.is_available() {
            return Err(io::Error::new(io::ErrorKind::NotConnected, "FakeTLS not connected"));
        }

        if *self.state.read() != FakeTlsState::ApplicationData {
            return Err(io::Error::new(io::ErrorKind::Other, "Handshake not finished"));
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

        if *self.state.read() != FakeTlsState::ApplicationData {
            return Err(io::Error::new(io::ErrorKind::Other, "Handshake not finished"));
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
        let mut record = read_buf.split_to(5 + record_len);
        
        // Unwrap and decrypt payload
        // We have to copy it to a new Bytes because unwrap_tls_record mutates in place
        // and returns a reference. Or we can just use `unwrap_tls_record(&mut record)`.
        let payload_len = self.unwrap_tls_record(&mut record)?.len();
        
        // The decrypted payload is at `&record[5..5+payload_len]`
        let mut out = BytesMut::with_capacity(payload_len);
        out.extend_from_slice(&record[5..5+payload_len]);
        
        Ok(out.freeze())
    }

    fn is_available(&self) -> bool {
        self.available.load(Ordering::Relaxed) && *self.state.read() == FakeTlsState::ApplicationData
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
        let leg = FakeTlsLeg::new().expect("FakeTlsLeg::new");
        assert!(!leg.is_available());
        assert_eq!(leg.config.sni, "www.google.com");
    }

    #[test]
    fn test_fake_client_hello() {
        let leg = FakeTlsLeg::new().expect("FakeTlsLeg::new");
        let hello = leg.build_fake_client_hello();
        
        // Should start with TLS handshake record
        assert_eq!(hello[0], TlsContentType::Handshake as u8);
        assert!(hello.len() > 100); // Should be substantial
    }

    #[test]
    fn test_wrap_tls_record() {
        let leg = FakeTlsLeg::new().expect("FakeTlsLeg::new");
        let data = b"test payload";
        let record = leg.wrap_as_tls_record(data);
        
        assert_eq!(record[0], TlsContentType::ApplicationData as u8);
        // data len + 1 for inner content type + 16 for auth tag
        assert_eq!(record.len(), 5 + data.len() + 1 + 16);
    }

    #[test]
    fn test_ja3_randomization() {
        let leg = FakeTlsLeg::new().expect("FakeTlsLeg::new");
        let hello1_ = leg.build_fake_client_hello();
        let hello2 = leg.build_fake_client_hello();
        
        // They should be different due to random session ID, random, and shuffling
        assert_ne!(hello1_, hello2);
        
        // Check standard parts presence
        // TLS 1.2 Version (0x0303) at offset 9
        assert_eq!(hello1_[9], 0x03);
        assert_eq!(hello1_[10], 0x03);
    }

    /// Round-trip test: a client-side leg encrypts, a server-side leg decrypts.
    /// Proves that derived-key + counter-nonce works end-to-end.
    #[test]
    fn test_wrap_unwrap_roundtrip_across_peers() {
        // Build a "client" leg.
        let client = FakeTlsLeg::with_config(FakeTlsConfig::default()).expect("FakeTlsLeg::with_config");

        // Build a "server" leg from scratch: same config but is_server = true.
        // We construct it directly since `accept` requires a real TcpStream.
        let cfg = FakeTlsConfig::default();
        let (send_key, recv_key, nonce_prefix) =
            derive_outer_keys(&cfg.sni, cfg.version, true).expect("derive_outer_keys");
        let server = FakeTlsLeg {
            config: cfg,
            stream: Mutex::new(None),
            remote_addr: None,
            rtt_ms: AtomicU32::new(0),
            available: AtomicBool::new(false),
            state: parking_lot::RwLock::new(FakeTlsState::ApplicationData),
            read_buf: Mutex::new(BytesMut::new()),
            send_key,
            recv_key,
            nonce_prefix,
            send_counter: AtomicU64::new(0),
            recv_counter: AtomicU64::new(0),
            is_server: true,
        };

        let plaintexts: &[&[u8]] = &[
            b"first record",
            b"second record",
            b"third record (a bit longer to vary length)",
        ];
        for pt in plaintexts {
            let mut record = client.wrap_as_tls_record(pt);
            let recovered_len = server.unwrap_tls_record(&mut record).unwrap().len();
            assert_eq!(&record[5..5 + recovered_len], *pt);
        }
    }

    /// Encrypting identical plaintexts twice must produce different ciphertexts
    /// because the per-record counter advances.
    #[test]
    fn test_nonce_advances_per_record() {
        let leg = FakeTlsLeg::with_config(FakeTlsConfig::default()).expect("FakeTlsLeg::with_config");
        let r1 = leg.wrap_as_tls_record(b"identical");
        let r2 = leg.wrap_as_tls_record(b"identical");
        assert_ne!(r1, r2, "counter must advance — identical plaintext must not produce identical ciphertext");
    }

    #[test]
    fn test_client_hello_structure() {
        let leg = FakeTlsLeg::new().expect("FakeTlsLeg::new");
        let hello = leg.build_fake_client_hello();

        // Verify TLS record header
        assert_eq!(hello[0], TlsContentType::Handshake as u8, "First byte should be Handshake (22)");

        // TLS record version (bytes 1-2)
        let record_version = u16::from_be_bytes([hello[1], hello[2]]);
        assert_eq!(record_version, 0x0303, "Record version should be TLS 1.2 (0x0303)");

        // Record length (bytes 3-4)
        let record_len = u16::from_be_bytes([hello[3], hello[4]]) as usize;
        assert_eq!(hello.len(), 5 + record_len, "Record length should match payload");

        // Handshake type (byte 5) should be ClientHello (0x01)
        assert_eq!(hello[5], 0x01, "Handshake type should be ClientHello");

        // Client version at bytes 9-10 (legacy TLS 1.2)
        assert_eq!(hello[9], 0x03, "Legacy version major");
        assert_eq!(hello[10], 0x03, "Legacy version minor");

        // Random (32 bytes starting at byte 11) should not be all zeros
        let random = &hello[11..43];
        assert!(!random.iter().all(|&b| b == 0), "Random should not be all zeros");

        // Session ID length at byte 43 should be 32
        assert_eq!(hello[43], 32, "Session ID length should be 32");
    }
}
