//! Pre-allocated Buffer Pool
//!
//! Eliminates per-packet memory allocations for maximum throughput.

use crossbeam_queue::ArrayQueue;
use std::cell::RefCell;
use std::sync::atomic::{AtomicUsize, Ordering};

const BATCH_SIZE: usize = 32;
const MAX_LOCAL_BUFFERS: usize = 64;

/// A pool of pre-allocated buffers for zero-allocation I/O
pub struct BufferPool {
    /// Global pool of available buffers
    buffers: ArrayQueue<Vec<u8>>,
    /// Buffer size
    buffer_size: usize,
    /// Max pool size
    #[allow(dead_code)]
    max_buffers: usize,
    /// Stats: total allocations
    allocations: AtomicUsize,
    /// Stats: pool hits
    hits: AtomicUsize,
}

thread_local! {
    static LOCAL_POOL: RefCell<Vec<Vec<u8>>> = RefCell::new(Vec::with_capacity(MAX_LOCAL_BUFFERS));
}

impl BufferPool {
    /// Create a new buffer pool
    pub fn new(buffer_size: usize, initial_count: usize, max_buffers: usize) -> Self {
        let buffers = ArrayQueue::new(max_buffers);
        let count = std::cmp::min(initial_count, max_buffers);
        for _ in 0..count {
            let _ = buffers.push(vec![0u8; buffer_size]);
        }

        Self {
            buffers,
            buffer_size,
            max_buffers,
            allocations: AtomicUsize::new(count),
            hits: AtomicUsize::new(0),
        }
    }

    /// Acquire a buffer from the pool
    #[inline]
    pub fn acquire(&self) -> PooledBuffer<'_> {
        let mut buffer: Option<Vec<u8>> = LOCAL_POOL.with(|local| {
            let mut local_pool = local.borrow_mut();
            if let Some(mut buf) = local_pool.pop() {
                buf.clear();
                return Some(buf);
            }
            None
        });

        if buffer.is_none() {
            // Refill local pool from global pool
            LOCAL_POOL.with(|local| {
                let mut local_pool = local.borrow_mut();
                for _ in 0..BATCH_SIZE {
                    if let Some(mut buf) = self.buffers.pop() {
                        buf.clear();
                        local_pool.push(buf);
                    } else {
                        break;
                    }
                }
            });

            buffer = LOCAL_POOL.with(|local| {
                let mut local_pool = local.borrow_mut();
                local_pool.pop()
            });
        }

        let buffer = if let Some(buf) = buffer {
            self.hits.fetch_add(1, Ordering::Relaxed);
            buf
        } else {
            self.allocations.fetch_add(1, Ordering::Relaxed);
            Vec::with_capacity(self.buffer_size)
        };

        PooledBuffer { buffer, pool: self }
    }

    /// Return a buffer to the pool
    #[inline]
    fn return_buffer(&self, mut buffer: Vec<u8>) {
        buffer.clear();
        LOCAL_POOL.with(|local| {
            let mut local_pool = local.borrow_mut();
            if local_pool.len() < MAX_LOCAL_BUFFERS {
                local_pool.push(buffer);
            } else {
                // If local pool is full, flush half back to global pool
                let half = MAX_LOCAL_BUFFERS / 2;
                for _ in 0..half {
                    if let Some(buf) = local_pool.pop() {
                        let _ = self.buffers.push(buf);
                    }
                }

                local_pool.push(buffer);
            }
        });
    }

    /// Get pool statistics
    pub fn stats(&self) -> PoolStats {
        PoolStats {
            allocations: self.allocations.load(Ordering::Relaxed),
            hits: self.hits.load(Ordering::Relaxed),
            pool_size: self.buffers.len(),
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
        // Only return if it has some capacity (not completely empty shell)
        if buffer.capacity() > 0 {
            self.pool.return_buffer(buffer);
        }
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
        // 64 KB buffers, 1024 initial, 65536 max
        BufferPool::new(64 * 1024, 1024, 65536)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_buffer_pool() {
        let pool = BufferPool::new(1024, 4, 16);

        let mut buf1 = pool.acquire();
        buf1.extend_from_slice(b"hello");
        assert_eq!(buf1.len(), 5);

        let buf2 = pool.acquire();
        assert_eq!(buf2.len(), 0);

        drop(buf1);
        drop(buf2);

        // After returning, buffers are pushed to local pool.
        // It preloaded 4 buffers initially, we used 2 and returned 2. So it has 4.
        LOCAL_POOL.with(|local| {
            assert_eq!(local.borrow().len(), 4);
        });
    }

    #[test]
    fn test_thread_local_flushing() {
        let pool = std::sync::Arc::new(BufferPool::new(1024, 0, 100));

        let p_clone = pool.clone();
        thread::spawn(move || {
            let mut bufs = Vec::new();
            // Allocate 70 buffers to exceed MAX_LOCAL_BUFFERS (64)
            for _ in 0..70 {
                bufs.push(p_clone.acquire());
            }

            // Drop all
            drop(bufs);

            // Local pool should have 64 buffers (or less if flushed), global should have some
            let mut count = 0;
            LOCAL_POOL.with(|local| {
                count = local.borrow().len();
            });
            assert!(count <= MAX_LOCAL_BUFFERS);
        })
        .join()
        .unwrap();

        // global pool should have received the flushed buffers
        assert!(pool.buffers.len() > 0);
    }
}
