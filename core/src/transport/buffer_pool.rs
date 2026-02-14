//! Pre-allocated Buffer Pool
//!
//! Eliminates per-packet memory allocations for maximum throughput.

use std::sync::atomic::{AtomicUsize, Ordering};
use parking_lot::Mutex;

/// A pool of pre-allocated buffers for zero-allocation I/O
pub struct BufferPool {
    /// Pool of available buffers
    buffers: Mutex<Vec<Vec<u8>>>,
    /// Buffer size
    buffer_size: usize,
    /// Max pool size
    max_buffers: usize,
    /// Stats: total allocations
    allocations: AtomicUsize,
    /// Stats: pool hits
    hits: AtomicUsize,
}

impl BufferPool {
    /// Create a new buffer pool
    pub fn new(buffer_size: usize, initial_count: usize, max_buffers: usize) -> Self {
        let mut buffers = Vec::with_capacity(max_buffers);
        for _ in 0..initial_count {
            buffers.push(vec![0u8; buffer_size]);
        }
        
        Self {
            buffers: Mutex::new(buffers),
            buffer_size,
            max_buffers,
            allocations: AtomicUsize::new(initial_count),
            hits: AtomicUsize::new(0),
        }
    }
    
    /// Acquire a buffer from the pool
    #[inline]
    pub fn acquire(&self) -> PooledBuffer {
        let mut pool = self.buffers.lock();
        
        let buffer = if let Some(mut buf) = pool.pop() {
            self.hits.fetch_add(1, Ordering::Relaxed);
            buf.clear();
            buf
        } else {
            self.allocations.fetch_add(1, Ordering::Relaxed);
            Vec::with_capacity(self.buffer_size)
        };
        
        PooledBuffer {
            buffer,
            pool: self,
        }
    }
    
    /// Return a buffer to the pool
    #[inline]
    fn return_buffer(&self, mut buffer: Vec<u8>) {
        let mut pool = self.buffers.lock();
        if pool.len() < self.max_buffers {
            buffer.clear();
            pool.push(buffer);
        }
        // If pool is full, buffer is dropped
    }
    
    /// Get pool statistics
    pub fn stats(&self) -> PoolStats {
        PoolStats {
            allocations: self.allocations.load(Ordering::Relaxed),
            hits: self.hits.load(Ordering::Relaxed),
            pool_size: self.buffers.lock().len(),
        }
    }
}

/// A buffer borrowed from the pool
pub struct PooledBuffer<'a> {
    buffer: Vec<u8>,
    pool: &'a BufferPool,
}

impl<'a> PooledBuffer<'a> {
    /// Get mutable reference to inner buffer
    #[inline]
    pub fn as_mut(&mut self) -> &mut Vec<u8> {
        &mut self.buffer
    }
    
    /// Get reference to inner buffer
    #[inline]
    pub fn as_ref(&self) -> &[u8] {
        &self.buffer
    }
    
    /// Get the buffer length
    #[inline]
    pub fn len(&self) -> usize {
        self.buffer.len()
    }
    
    /// Check if buffer is empty
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }
}

impl<'a> std::ops::Deref for PooledBuffer<'a> {
    type Target = Vec<u8>;
    
    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.buffer
    }
}

impl<'a> std::ops::DerefMut for PooledBuffer<'a> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.buffer
    }
}

impl<'a> Drop for PooledBuffer<'a> {
    fn drop(&mut self) {
        let buffer = std::mem::take(&mut self.buffer);
        self.pool.return_buffer(buffer);
    }
}

/// Pool statistics
#[derive(Debug, Clone, Copy)]
pub struct PoolStats {
    pub allocations: usize,
    pub hits: usize,
    pub pool_size: usize,
}

impl PoolStats {
    /// Hit rate (0.0 - 1.0)
    pub fn hit_rate(&self) -> f64 {
        if self.allocations + self.hits == 0 {
            0.0
        } else {
            self.hits as f64 / (self.allocations + self.hits) as f64
        }
    }
}

/// Global buffer pool for common use
static GLOBAL_POOL: std::sync::OnceLock<BufferPool> = std::sync::OnceLock::new();

/// Get the global buffer pool
pub fn global_pool() -> &'static BufferPool {
    GLOBAL_POOL.get_or_init(|| {
        // 64 KB buffers, 16 initial, max 256
        BufferPool::new(64 * 1024, 16, 256)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_buffer_pool() {
        let pool = BufferPool::new(1024, 4, 16);
        
        // Acquire buffers
        let mut buf1 = pool.acquire();
        buf1.extend_from_slice(b"hello");
        assert_eq!(buf1.len(), 5);
        
        let buf2 = pool.acquire();
        assert_eq!(buf2.len(), 0);
        
        // Return buffers
        drop(buf1);
        drop(buf2);
        
        // Pool should have 2 buffers now
        let stats = pool.stats();
        assert_eq!(stats.pool_size, 2);
    }
    
    #[test]
    fn test_buffer_pool_reuse() {
        let pool = BufferPool::new(1024, 0, 16);
        
        // First acquire allocates
        {
            let _buf = pool.acquire();
        }
        
        // Second acquire should hit
        {
            let _buf = pool.acquire();
        }
        
        let stats = pool.stats();
        assert_eq!(stats.allocations, 1);
        assert_eq!(stats.hits, 1);
    }
}
