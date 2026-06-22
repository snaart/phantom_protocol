//! Zero-Copy TCP Framing Pipeline
//!
//! Problem: the old approach did `data.clone()` + `encrypt_in_place()` +
//! `write(len)` + `write(data)` = 2 syscalls + 1 clone per message. TLS 1.3
//! (rustls) does the equivalent in a single internal write.
//!
//! Solution: prepend a 4-byte length header, encrypt the payload in place into the
//! same buffer, then issue a single `write_all()` — one syscall, no clone. Multiple
//! chunks / frames are coalesced into one buffer before the write.
//!
//! NOTE: this is a helper for the native TCP path; the production `SessionTransport`
//! over TCP is `TcpSessionTransport` (in `api/tcp_transport.rs`), which carries the
//! same 4-byte big-endian length prefix. PhantomUDP does its own framing elsewhere.

use crate::crypto::adaptive_crypto::{CryptoSession, AEAD_OVERHEAD};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Frame header size: 4 bytes for payload length (u32 BE)
pub const FRAME_HEADER_SIZE: usize = 4;

/// Maximum frame payload size (before encryption)
pub const MAX_FRAME_PAYLOAD: usize = 64 * 1024; // 64 KB

/// Zero-copy frame writer — encrypts and writes in a single syscall
pub struct FrameWriter;

impl Default for FrameWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameWriter {
    /// Create a new frame writer
    pub fn new() -> Self {
        Self
    }

    /// Threshold size (bytes) above which we use tokio::task::spawn_blocking for encryption
    pub const SPAWN_BLOCKING_THRESHOLD: usize = 256 * 1024; // 256 KB

    /// Write a single message as one or more frames: [len:4][encrypted_payload + tag:16]
    ///
    /// If data exceeds MAX_FRAME_PAYLOAD, it is split into multiple frames.
    /// If total data exceeds SPAWN_BLOCKING_THRESHOLD, encryption is offloaded to spawn_blocking.
    #[inline]
    pub async fn write_frame(
        &self,
        stream: &mut TcpStream,
        session: &CryptoSession,
        data: &[u8],
    ) -> Result<usize, FrameError> {
        if data.is_empty() {
            return Ok(0);
        }

        let total_len = data.len();
        let num_chunks = total_len.div_ceil(MAX_FRAME_PAYLOAD);

        // Calculate total buffer size needed for all chunks
        let total_cap = num_chunks * (FRAME_HEADER_SIZE + AEAD_OVERHEAD) + total_len;
        let mut batch_buf = Vec::with_capacity(total_cap);

        if total_len > Self::SPAWN_BLOCKING_THRESHOLD {
            // Offload encryption to blocking thread pool
            let session = session.clone();
            let data = data.to_vec();

            batch_buf = tokio::task::spawn_blocking(move || {
                let mut buf = Vec::with_capacity(total_cap);
                for chunk in data.chunks(MAX_FRAME_PAYLOAD) {
                    let frame_start = buf.len();
                    let ct_len = chunk.len() + AEAD_OVERHEAD;
                    let len_bytes = (ct_len as u32).to_be_bytes();
                    // Length placeholder
                    buf.extend_from_slice(&len_bytes);
                    // Payload
                    buf.extend_from_slice(chunk);
                    // Encrypt in-place at offset
                    session
                        .encrypt_in_place_offset(
                            &len_bytes,
                            &mut buf,
                            frame_start + FRAME_HEADER_SIZE,
                        )
                        .map_err(|_| FrameError::EncryptFailed)?;
                }
                Ok::<Vec<u8>, FrameError>(buf)
            })
            .await
            .map_err(|_| FrameError::EncryptFailed)??;
        } else {
            // Synchronous encryption (on current Tokio worker)
            for chunk in data.chunks(MAX_FRAME_PAYLOAD) {
                let frame_start = batch_buf.len();
                let ct_len = chunk.len() + AEAD_OVERHEAD;
                let len_bytes = (ct_len as u32).to_be_bytes();
                // Length placeholder
                batch_buf.extend_from_slice(&len_bytes);
                // Payload
                batch_buf.extend_from_slice(chunk);
                // Encrypt in-place at offset
                session
                    .encrypt_in_place_offset(
                        &len_bytes,
                        &mut batch_buf,
                        frame_start + FRAME_HEADER_SIZE,
                    )
                    .map_err(|_| FrameError::EncryptFailed)?;
            }
        }

        // Single syscall write for all chunks
        stream.write_all(&batch_buf).await.map_err(FrameError::Io)?;

        Ok(total_len)
    }

    /// Write multiple frames in a batch (TCP write coalescing).
    /// Accumulates all frames into a single buffer → one write_all().
    #[inline]
    pub async fn write_frames_batch(
        &self,
        stream: &mut TcpStream,
        session: &CryptoSession,
        payloads: &[&[u8]],
    ) -> Result<usize, FrameError> {
        if payloads.is_empty() {
            return Ok(0);
        }

        // Calculate total buffer size needed
        let total_size: usize = payloads
            .iter()
            .map(|p| FRAME_HEADER_SIZE + p.len() + AEAD_OVERHEAD)
            .sum();

        let mut batch_buf = Vec::with_capacity(total_size);
        let mut total_payload = 0usize;

        for payload in payloads {
            let frame_start = batch_buf.len();
            let ct_len = payload.len() + AEAD_OVERHEAD;
            let len_bytes = (ct_len as u32).to_be_bytes();

            // Length placeholder
            batch_buf.extend_from_slice(&len_bytes);
            // Payload
            batch_buf.extend_from_slice(payload);

            // Encrypt in-place at offset
            let encrypt_start = frame_start + FRAME_HEADER_SIZE;
            session
                .encrypt_in_place_offset(&len_bytes, &mut batch_buf, encrypt_start)
                .map_err(|_| FrameError::EncryptFailed)?;

            total_payload += payload.len();
        }

        // Single write for all frames
        stream.write_all(&batch_buf).await.map_err(FrameError::Io)?;

        Ok(total_payload)
    }
}

/// Zero-copy frame reader — reads and decrypts from TCP stream
pub struct FrameReader {
    /// Internal read buffer
    header_buf: [u8; FRAME_HEADER_SIZE],
}

impl Default for FrameReader {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameReader {
    pub fn new() -> Self {
        Self {
            header_buf: [0u8; FRAME_HEADER_SIZE],
        }
    }

    /// Read a single frame: reads `[len:4]`, then reads `[encrypted_payload]`, decrypts in-place.
    /// Returns decrypted plaintext as `Vec<u8>`.
    #[inline]
    pub async fn read_frame(
        &mut self,
        stream: &mut TcpStream,
        session: &CryptoSession,
    ) -> Result<Vec<u8>, FrameError> {
        // Read length header
        stream
            .read_exact(&mut self.header_buf)
            .await
            .map_err(FrameError::Io)?;

        let ct_len = u32::from_be_bytes(self.header_buf) as usize;

        if ct_len > MAX_FRAME_PAYLOAD + AEAD_OVERHEAD {
            return Err(FrameError::FrameTooLarge(ct_len));
        }

        // Read ciphertext
        let mut ct = vec![0u8; ct_len];
        stream.read_exact(&mut ct).await.map_err(FrameError::Io)?;

        // Decrypt in-place
        // Offload to spawn_blocking if frame is large
        if ct_len > FrameWriter::SPAWN_BLOCKING_THRESHOLD {
            let session = session.clone();
            let header_buf = self.header_buf; // Copy for closure
            ct = tokio::task::spawn_blocking(move || {
                let pt = session
                    .decrypt_in_place(&header_buf, &mut ct)
                    .map_err(|_| FrameError::DecryptFailed)?;
                let pt_len = pt.len();
                ct.truncate(pt_len);
                Ok::<Vec<u8>, FrameError>(ct)
            })
            .await
            .map_err(|_| FrameError::DecryptFailed)??;
        } else {
            let pt = session
                .decrypt_in_place(&self.header_buf, &mut ct)
                .map_err(|_| FrameError::DecryptFailed)?;
            let pt_len = pt.len();
            ct.truncate(pt_len);
        }

        Ok(ct)
    }
}

/// Frame errors
#[derive(Debug)]
pub enum FrameError {
    Io(std::io::Error),
    EncryptFailed,
    DecryptFailed,
    FrameTooLarge(usize),
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "Frame I/O error: {}", e),
            Self::EncryptFailed => write!(f, "Frame encryption failed"),
            Self::DecryptFailed => write!(f, "Frame decryption / auth failed"),
            Self::FrameTooLarge(n) => write!(f, "Frame too large: {} bytes", n),
        }
    }
}

impl std::error::Error for FrameError {}

impl From<std::io::Error> for FrameError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

// NOTE: an earlier, never-wired "adaptive padding" scaffold (PaddingProfile /
// adaptive_pad_size / apply_adaptive_padding / write_frame_padded) lived here. It
// was dead code — only its own tests exercised it. Anti-fingerprint size padding
// now ships, wired into the real data plane, as PADÉ bucketing in
// `crate::transport::shaping` (WIRE v6, direction #4). The scaffold was removed.

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn frame_round_trip() {
        let secret = [0xABu8; 32];
        let cs = Arc::new(CryptoSession::from_shared_secret(&secret).unwrap());
        let ss = Arc::new(CryptoSession::from_shared_secret_peer(&secret).unwrap());

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let ss2 = ss.clone();
        let handle = tokio::spawn(async move {
            let (mut tcp, _) = listener.accept().await.unwrap();
            let mut reader = FrameReader::new();
            let data = reader.read_frame(&mut tcp, &ss2).await.unwrap();
            assert_eq!(&data, b"Hello, zero-copy framing!");
        });

        let mut tcp = TcpStream::connect(addr).await.unwrap();
        let writer = FrameWriter::new();
        writer
            .write_frame(&mut tcp, &cs, b"Hello, zero-copy framing!")
            .await
            .unwrap();

        handle.await.unwrap();
    }

    #[tokio::test]
    async fn large_message_round_trip() {
        let secret = [0x12u8; 32];
        let cs = Arc::new(CryptoSession::from_shared_secret(&secret).unwrap());
        let ss = Arc::new(CryptoSession::from_shared_secret_peer(&secret).unwrap());

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let original_data = vec![0x42u8; 1024 * 1024]; // 1MB
        let data_clone = original_data.clone();

        let ss2 = ss.clone();
        let handle = tokio::spawn(async move {
            let (mut tcp, _) = listener.accept().await.unwrap();
            let mut reader = FrameReader::new();
            let mut received_data = Vec::new();

            let num_chunks = (data_clone.len() + MAX_FRAME_PAYLOAD - 1) / MAX_FRAME_PAYLOAD;
            for _ in 0..num_chunks {
                let chunk = reader.read_frame(&mut tcp, &ss2).await.unwrap();
                received_data.extend_from_slice(&chunk);
            }
            assert_eq!(received_data, data_clone);
        });

        let mut tcp = TcpStream::connect(addr).await.unwrap();
        let writer = FrameWriter::new();
        writer
            .write_frame(&mut tcp, &cs, &original_data)
            .await
            .unwrap();

        handle.await.unwrap();
    }

    #[tokio::test]
    async fn frame_batch_round_trip() {
        let secret = [0xCDu8; 32];
        let cs = Arc::new(CryptoSession::from_shared_secret(&secret).unwrap());
        let ss = Arc::new(CryptoSession::from_shared_secret_peer(&secret).unwrap());

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let ss2 = ss.clone();
        let handle = tokio::spawn(async move {
            let (mut tcp, _) = listener.accept().await.unwrap();
            let mut reader = FrameReader::new();
            let d1 = reader.read_frame(&mut tcp, &ss2).await.unwrap();
            let d2 = reader.read_frame(&mut tcp, &ss2).await.unwrap();
            let d3 = reader.read_frame(&mut tcp, &ss2).await.unwrap();
            assert_eq!(&d1, b"Frame 1");
            assert_eq!(&d2, b"Frame 2");
            assert_eq!(&d3, b"Frame 3");
        });

        let mut tcp = TcpStream::connect(addr).await.unwrap();
        let writer = FrameWriter::new();
        let payloads: Vec<&[u8]> = vec![b"Frame 1", b"Frame 2", b"Frame 3"];
        writer
            .write_frames_batch(&mut tcp, &cs, &payloads)
            .await
            .unwrap();

        handle.await.unwrap();
    }
}
