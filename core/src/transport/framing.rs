//! Zero-Copy TCP Framing Pipeline
//!
//! Проблема: старый подход делал `data.clone()` + `encrypt_in_place()` + `write(len)` + `write(data)` = 2 syscalls + 1 clone.
//! TLS 1.3 (rustls) делает всё за 1 внутренний write.
//!
//! Решение: prepend 4-byte length header → encrypt payload in-place → single write_all().

use crate::crypto::adaptive_crypto::{CryptoSession, AEAD_OVERHEAD};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Frame header size: 4 bytes for payload length (u32 BE)
pub const FRAME_HEADER_SIZE: usize = 4;

/// Maximum frame payload size (before encryption)
pub const MAX_FRAME_PAYLOAD: usize = 64 * 1024; // 64 KB

/// Zero-copy frame writer — encrypts and writes in a single syscall
pub struct FrameWriter;

impl FrameWriter {
    /// Create a new frame writer
    pub fn new() -> Self {
        Self
    }

    /// Write a single encrypted frame: [len:4][encrypted_payload + tag:16]
    ///
    /// Zero-copy pipeline:
    /// 1. Get buffer from pool (no alloc)
    /// 2. Copy data into buf[4..] (one memcpy)
    /// 3. Encrypt in-place at offset 4 (zero-copy)
    /// 4. Write length header into buf[0..4]
    /// 5. Single write_all() — one syscall
    #[inline]
    pub async fn write_frame(
        &self,
        stream: &mut TcpStream,
        session: &CryptoSession,
        data: &[u8],
    ) -> Result<usize, FrameError> {
        let total_cap = FRAME_HEADER_SIZE + data.len() + AEAD_OVERHEAD;
        let mut buf = Vec::with_capacity(total_cap);

        // Reserve space for length header
        buf.extend_from_slice(&[0u8; FRAME_HEADER_SIZE]);
        // Copy payload
        buf.extend_from_slice(data);

        // Encrypt in-place starting at offset 4
        let ct_len = session
            .encrypt_in_place_offset(&mut buf, FRAME_HEADER_SIZE)
            .map_err(|_| FrameError::EncryptFailed)?;

        // Write length header
        let len_bytes = (ct_len as u32).to_be_bytes();
        buf[..FRAME_HEADER_SIZE].copy_from_slice(&len_bytes);

        let total = FRAME_HEADER_SIZE + ct_len;

        // Single syscall write
        stream
            .write_all(&buf[..total])
            .await
            .map_err(|e| FrameError::Io(e))?;

        Ok(data.len())
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

            // Length placeholder
            batch_buf.extend_from_slice(&[0u8; FRAME_HEADER_SIZE]);
            // Payload
            batch_buf.extend_from_slice(payload);

            // Encrypt in-place at offset
            let encrypt_start = frame_start + FRAME_HEADER_SIZE;
            let ct_len = session
                .encrypt_in_place_offset(&mut batch_buf, encrypt_start)
                .map_err(|_| FrameError::EncryptFailed)?;

            // Write length
            let len_bytes = (ct_len as u32).to_be_bytes();
            batch_buf[frame_start..frame_start + FRAME_HEADER_SIZE]
                .copy_from_slice(&len_bytes);

            total_payload += payload.len();
        }

        // Single write for all frames
        stream
            .write_all(&batch_buf)
            .await
            .map_err(|e| FrameError::Io(e))?;

        Ok(total_payload)
    }
}

/// Zero-copy frame reader — reads and decrypts from TCP stream
pub struct FrameReader {
    /// Internal read buffer
    header_buf: [u8; FRAME_HEADER_SIZE],
}

impl FrameReader {
    pub fn new() -> Self {
        Self {
            header_buf: [0u8; FRAME_HEADER_SIZE],
        }
    }

    /// Read a single frame: reads [len:4], then reads [encrypted_payload], decrypts in-place.
    /// Returns decrypted plaintext as Vec<u8>.
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
            .map_err(|e| FrameError::Io(e))?;

        let ct_len = u32::from_be_bytes(self.header_buf) as usize;

        if ct_len > MAX_FRAME_PAYLOAD + AEAD_OVERHEAD {
            return Err(FrameError::FrameTooLarge(ct_len));
        }

        // Read ciphertext
        let mut ct = vec![0u8; ct_len];
        stream
            .read_exact(&mut ct)
            .await
            .map_err(|e| FrameError::Io(e))?;

        // Decrypt in-place
        let pt = session
            .decrypt_in_place(&mut ct)
            .map_err(|_| FrameError::DecryptFailed)?;

        let pt_len = pt.len();
        ct.truncate(pt_len);
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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;
    use crate::crypto::adaptive_crypto::CipherSuite;
    use std::sync::Arc;

    #[tokio::test]
    async fn frame_round_trip() {
        let secret = [0xABu8; 32];
        let cs = Arc::new(CryptoSession::with_suite(&secret, CipherSuite::Aes256Gcm));
        let ss = Arc::new(CryptoSession::with_suite_peer(&secret, CipherSuite::Aes256Gcm));

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
    async fn frame_batch_round_trip() {
        let secret = [0xCDu8; 32];
        let cs = Arc::new(CryptoSession::with_suite(&secret, CipherSuite::ChaCha20Poly1305));
        let ss = Arc::new(CryptoSession::with_suite_peer(&secret, CipherSuite::ChaCha20Poly1305));

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

