use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use parking_lot::Mutex;
use phantom_protocol::transport::buffer_pool::BufferPool;
use std::sync::Arc;
use std::thread;

/// Legacy pool for comparison
pub struct LegacyBufferPool {
    buffers: Mutex<Vec<Vec<u8>>>,
    buffer_size: usize,
    max_buffers: usize,
}

impl LegacyBufferPool {
    pub fn new(buffer_size: usize, initial_count: usize, max_buffers: usize) -> Self {
        let mut buffers = Vec::with_capacity(max_buffers);
        for _ in 0..initial_count {
            buffers.push(vec![0u8; buffer_size]);
        }
        Self {
            buffers: Mutex::new(buffers),
            buffer_size,
            max_buffers,
        }
    }

    pub fn acquire(&self) -> Vec<u8> {
        let mut pool = self.buffers.lock();
        if let Some(mut buf) = pool.pop() {
            buf.clear();
            buf
        } else {
            Vec::with_capacity(self.buffer_size)
        }
    }

    pub fn return_buffer(&self, mut buffer: Vec<u8>) {
        let mut pool = self.buffers.lock();
        if pool.len() < self.max_buffers {
            buffer.clear();
            pool.push(buffer);
        }
    }
}

fn bench_pool(c: &mut Criterion) {
    let mut group = c.benchmark_group("Buffer Pool Concurrent Threads");
    let pool_size = 65536;
    let buffer_size = 1024;
    let allocations_per_thread = 50_000;

    for thread_count in [1, 2, 8, 16, 32].iter() {
        group.throughput(Throughput::Elements(
            (*thread_count * allocations_per_thread) as u64,
        ));

        group.bench_with_input(
            BenchmarkId::new("Legacy_Mutex", thread_count),
            thread_count,
            |b, &threads| {
                b.iter_custom(|iters| {
                    let mut total_time = std::time::Duration::new(0, 0);
                    for _ in 0..iters {
                        let pool =
                            Arc::new(LegacyBufferPool::new(buffer_size, pool_size, pool_size));
                        let start = std::time::Instant::now();

                        let mut handles = vec![];
                        for _ in 0..threads {
                            let pool_clone = pool.clone();
                            handles.push(thread::spawn(move || {
                                for _ in 0..allocations_per_thread {
                                    let buf = pool_clone.acquire();
                                    pool_clone.return_buffer(buf);
                                }
                            }));
                        }

                        for h in handles {
                            h.join().unwrap();
                        }
                        total_time += start.elapsed();
                    }
                    total_time
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("LockFree_ThreadLocal", thread_count),
            thread_count,
            |b, &threads| {
                b.iter_custom(|iters| {
                    let mut total_time = std::time::Duration::new(0, 0);
                    for _ in 0..iters {
                        let pool = Arc::new(BufferPool::new(buffer_size, pool_size, pool_size));
                        let start = std::time::Instant::now();

                        let mut handles = vec![];
                        for _ in 0..threads {
                            let pool_clone = pool.clone();
                            handles.push(thread::spawn(move || {
                                for _ in 0..allocations_per_thread {
                                    let buf = pool_clone.acquire();
                                    drop(buf); // dropped back to pool via Drop trait
                                }
                            }));
                        }

                        for h in handles {
                            h.join().unwrap();
                        }
                        total_time += start.elapsed();
                    }
                    total_time
                });
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_pool);
criterion_main!(benches);
