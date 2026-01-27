use bytes::{Bytes, BytesMut, BufMut, Buf};
use anyhow::{Result, ensure};
use rand::Rng;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub struct Framer;

const PADDING_BLOCK_SIZE: usize = 256;

impl Framer {
    /// Encapsulates payload into a frame: [Length: u32][GroupId: 16B][Epoch: u8][PaddingLen: u8][AuthLen: u8][AuthToken][Payload][PaddingBytes]
    pub fn frame(group_id: &[u8; 16], epoch: u64, payload: &[u8], auth_token: &[u8]) -> Bytes {
        let payload_len = payload.len();
        let auth_len = auth_token.len();
        
        // Header sizes:
        // Length: 4
        // GroupId: 16
        // Epoch: 8
        // PaddingLen: 1
        // AuthLen: 1
        // Total Header Fixed: 26 bytes (excluding Length prefix)
        
        let body_content_len = 26 + auth_len + payload_len; 
        let target_size = ((body_content_len + PADDING_BLOCK_SIZE - 1) / PADDING_BLOCK_SIZE) * PADDING_BLOCK_SIZE;
        let padding_bytes_needed = target_size - body_content_len;
        let padding_len = padding_bytes_needed as u8;
        
        // Total len includes the 4 bytes length prefix technically? No, usually length prefix describes body.
        // Assuming current logic: total_frame_len is written as u32.
        
        let total_frame_len = 4 + body_content_len + (padding_len as usize);
        
        let mut buf = BytesMut::with_capacity(total_frame_len);
        buf.put_u32(total_frame_len as u32);
        buf.put_slice(group_id);
        buf.put_u64(epoch);
        buf.put_u8(padding_len);
        buf.put_u8(auth_len as u8); // New field
        buf.put_slice(auth_token);  // New field
        buf.put_slice(payload);
        
        let mut rng = rand::thread_rng();
        let mut padding_buf = vec![0u8; padding_len as usize];
        rng.fill(&mut padding_buf[..]);
        buf.put_slice(&padding_buf);
        
        buf.freeze()
    }

    /// Reads a frame from a stream.
    /// Returns (GroupId, Epoch, Payload, AuthToken)
    pub async fn read_frame<S>(stream: &mut S) -> Result<([u8; 16], u64, Bytes, Bytes)> 
    where S: AsyncRead + Unpin 
    {
        let len_buf_future = stream.read_u32();
        let length = match tokio::time::timeout(tokio::time::Duration::from_secs(5), len_buf_future).await {
            Ok(res) => res? as usize,
            Err(_) => {
                // Determine if stream is just empty (EOF) or timed out mid-connection
                // For MVP, just bail.
                anyhow::bail!("Header Read timeout")
            }
        };
        
        ensure!(length >= 30, "Frame too short"); // 4 + 16 + 8 + 1 + 1 = 30 min
        ensure!(length < 2 * 1024 * 1024, "Frame too large"); 

        // Incremental allocation to prevent OOM attacks
        // Start small, grow as we read.
        let mut buffer = Vec::new();
        let body_len = length.saturating_sub(4);
        let mut take_stream = stream.take(body_len as u64);
        
        // Anti-Slow-Loris: Enforce timeout on the ENTIRE body read
        let read_future = async {
            // Use read_to_end which adapts to the Take limit. 
            // NOTE: Ensure we trust read_to_end not to pre-allocate full capacity if huge.
            // But since we capped length at 2MB, it's safe.
            // If User insists on manual chunking:
            let mut chunk = vec![0u8; std::cmp::min(length, 4096)];
            let mut total_read = 0;
            while total_read < body_len {
                let to_read = std::cmp::min(body_len - total_read, chunk.len());
                let n = take_stream.read(&mut chunk[0..to_read]).await?;
                if n == 0 {
                    anyhow::bail!("Unexpected EOF");
                }
                buffer.extend_from_slice(&chunk[0..n]);
                total_read += n;
            }
            Ok::<(), anyhow::Error>(())
        };

        match tokio::time::timeout(tokio::time::Duration::from_secs(60), read_future).await { // Phase 5: audit fix recommended higher timeout for large files? No, header said 5s.
             // Let's keep 10s or 60s. Task 57 check.
            Ok(res) => res?,
            Err(_) => anyhow::bail!("Read timeout"),
        };
        
        let mut buf = Bytes::from(buffer);
        
        let mut group_id = [0u8; 16];
        buf.copy_to_slice(&mut group_id);
        let epoch = buf.get_u64();
        let padding_len = buf.get_u8() as usize;
        let auth_len = buf.get_u8() as usize; // New field
        
        ensure!(buf.remaining() >= padding_len + auth_len, "Invalid frame length");
        
        let auth_token = buf.slice(0..auth_len);
        buf.advance(auth_len);
        
        let payload_len = buf.remaining() - padding_len;
        let payload = buf.slice(0..payload_len);
        
        Ok((group_id, epoch, payload, auth_token))
    }

    pub async fn write_frame<S>(stream: &mut S, group_id: &[u8], epoch: u64, payload: &[u8], auth_token: &[u8]) -> Result<()>
    where S: AsyncWrite + Unpin
    {
        // Ensure group_id is 16 bytes
        let gid: &[u8; 16] = group_id.try_into().map_err(|_| anyhow::anyhow!("Invalid GroupId len"))?;
        let bytes = Self::frame(gid, epoch, payload, auth_token);
        stream.write_all(&bytes).await?;
        stream.flush().await?;
        Ok(())
    }
}
