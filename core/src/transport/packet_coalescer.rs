//! Packet Coalescer — UDP Datagram Batching
//!
//! Объединяет множество мелких пакетов в крупные UDP-датаграммы.
//! Вместо N мелких пакетов (N syscalls) отправляем 1 большой (1 syscall).
//!
//! Формат: [count: u16][len1: u16][payload1][len2: u16][payload2]...
//!
//! Шифрование одного крупного блока задействует HW AES на полной скорости.

use std::time::{Duration, Instant};

/// Максимальный размер UDP-датаграммы (без фрагментации)
pub const MAX_UDP_PAYLOAD: usize = 65507;
/// Размер заголовка coalesced-пакета (2 байта count)
const HEADER_SIZE: usize = 2;
/// Размер заголовка каждого sub-пакета (2 байта length)
const SUB_HEADER_SIZE: usize = 2;

/// Настройки coalescer
#[derive(Debug, Clone)]
pub struct CoalescerConfig {
    /// Максимальный размер итоговой датаграммы
    pub max_datagram_size: usize,
    /// Максимальное время ожидания перед flush (µs)
    pub flush_timeout_us: u64,
    /// Максимальное количество sub-пакетов в одной датаграмме
    pub max_packets: u16,
}

impl Default for CoalescerConfig {
    fn default() -> Self {
        Self {
            max_datagram_size: MAX_UDP_PAYLOAD,
            flush_timeout_us: 500, // 0.5ms — агрессивный flush
            max_packets: 256,
        }
    }
}

/// Батчер отправки: собирает пакеты, отдаёт готовые датаграммы
pub struct PacketCoalescer {
    config: CoalescerConfig,
    /// Буфер для накопления
    buf: Vec<u8>,
    /// Количество пакетов в текущем буфере
    count: u16,
    /// Время первого добавленного пакета в текущем batch
    batch_start: Option<Instant>,
}

impl PacketCoalescer {
    pub fn new(config: CoalescerConfig) -> Self {
        let cap = config.max_datagram_size;
        let mut buf = Vec::with_capacity(cap);
        // Резервируем место для заголовка count
        buf.extend_from_slice(&[0u8; HEADER_SIZE]);
        Self {
            config,
            buf,
            count: 0,
            batch_start: None,
        }
    }

    /// Добавить пакет в batch. Возвращает `Some(datagram)` если batch полон.
    #[inline]
    pub fn push(&mut self, data: &[u8]) -> Option<Vec<u8>> {
        let needed = SUB_HEADER_SIZE + data.len();

        // Если пакет не влезает — flush текущий batch, начать новый
        if self.buf.len() + needed > self.config.max_datagram_size
            || self.count >= self.config.max_packets
        {
            let flushed = self.flush();
            self.push_inner(data);
            return flushed;
        }

        self.push_inner(data);
        None
    }

    #[inline]
    fn push_inner(&mut self, data: &[u8]) {
        let len = data.len() as u16;
        self.buf.extend_from_slice(&len.to_be_bytes());
        self.buf.extend_from_slice(data);
        self.count += 1;
        if self.batch_start.is_none() {
            self.batch_start = Some(Instant::now());
        }
    }

    /// Проверить, нужно ли flush по таймауту
    #[inline]
    pub fn should_flush(&self) -> bool {
        if self.count == 0 {
            return false;
        }
        match self.batch_start {
            Some(start) => {
                start.elapsed() >= Duration::from_micros(self.config.flush_timeout_us)
            }
            None => false,
        }
    }

    /// Flush: вернуть готовую датаграмму, сбросить буфер
    pub fn flush(&mut self) -> Option<Vec<u8>> {
        if self.count == 0 {
            return None;
        }

        // Записать count в заголовок
        let count_bytes = self.count.to_be_bytes();
        self.buf[0] = count_bytes[0];
        self.buf[1] = count_bytes[1];

        // Забрать буфер, поставить новый
        let mut out = Vec::with_capacity(self.config.max_datagram_size);
        out.extend_from_slice(&[0u8; HEADER_SIZE]); // placeholder для нового batch
        std::mem::swap(&mut self.buf, &mut out);

        self.count = 0;
        self.batch_start = None;
        Some(out)
    }

    /// Количество пакетов в текущем batch
    #[inline]
    pub fn pending_count(&self) -> u16 {
        self.count
    }

    /// Текущий размер буфера
    #[inline]
    pub fn pending_bytes(&self) -> usize {
        self.buf.len() - HEADER_SIZE
    }
}

/// Разборщик coalesced датаграммы.
/// Принимает датаграмму, итерирует по sub-пакетам.
pub struct Decoalescer<'a> {
    data: &'a [u8],
    offset: usize,
    remaining: u16,
}

impl<'a> Decoalescer<'a> {
    /// Создать из полученной датаграммы
    pub fn new(datagram: &'a [u8]) -> Option<Self> {
        if datagram.len() < HEADER_SIZE {
            return None;
        }
        let count = u16::from_be_bytes([datagram[0], datagram[1]]);
        Some(Self {
            data: datagram,
            offset: HEADER_SIZE,
            remaining: count,
        })
    }

    /// Количество sub-пакетов
    #[inline]
    pub fn count(&self) -> u16 {
        self.remaining
    }
}

impl<'a> Iterator for Decoalescer<'a> {
    type Item = &'a [u8];

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        if self.offset + SUB_HEADER_SIZE > self.data.len() {
            return None;
        }

        let len = u16::from_be_bytes([
            self.data[self.offset],
            self.data[self.offset + 1],
        ]) as usize;
        self.offset += SUB_HEADER_SIZE;

        if self.offset + len > self.data.len() {
            return None;
        }

        let packet = &self.data[self.offset..self.offset + len];
        self.offset += len;
        self.remaining -= 1;
        Some(packet)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_single() {
        let mut c = PacketCoalescer::new(CoalescerConfig::default());
        c.push(b"hello");
        let datagram = c.flush().unwrap();
        let mut dec = Decoalescer::new(&datagram).unwrap();
        assert_eq!(dec.next(), Some(b"hello".as_slice()));
        assert_eq!(dec.next(), None);
    }

    #[test]
    fn round_trip_multiple() {
        let mut c = PacketCoalescer::new(CoalescerConfig::default());
        c.push(b"aaa");
        c.push(b"bbbbb");
        c.push(b"cc");
        let datagram = c.flush().unwrap();
        let mut dec = Decoalescer::new(&datagram).unwrap();
        assert_eq!(dec.next(), Some(b"aaa".as_slice()));
        assert_eq!(dec.next(), Some(b"bbbbb".as_slice()));
        assert_eq!(dec.next(), Some(b"cc".as_slice()));
        assert_eq!(dec.next(), None);
    }

    #[test]
    fn auto_flush_on_full() {
        let config = CoalescerConfig {
            max_datagram_size: 20, // Very small — forces early flush
            ..Default::default()
        };
        let mut c = PacketCoalescer::new(config);
        // First fits: header(2) + sub(2+5) = 9
        assert!(c.push(b"AAAAA").is_none());
        // Second fits: 9 + (2+5) = 16
        assert!(c.push(b"BBBBB").is_none());
        // Third overflows: 16 + (2+5) = 23 > 20 → flush
        let flushed = c.push(b"CCCCC");
        assert!(flushed.is_some());

        // Flushed should have A+B
        let d = flushed.unwrap();
        let mut dec = Decoalescer::new(&d).unwrap();
        assert_eq!(dec.next(), Some(b"AAAAA".as_slice()));
        assert_eq!(dec.next(), Some(b"BBBBB".as_slice()));

        // C should be in the new pending batch
        let d2 = c.flush().unwrap();
        let mut dec2 = Decoalescer::new(&d2).unwrap();
        assert_eq!(dec2.next(), Some(b"CCCCC".as_slice()));
    }

    #[test]
    fn throughput_bench() {
        use std::time::Instant;

        let config = CoalescerConfig {
            max_datagram_size: 65507,
            max_packets: 256,
            ..Default::default()
        };
        let mut c = PacketCoalescer::new(config);
        let packet = vec![0xABu8; 1024]; // 1KB packets
        let total_packets = 100_000;
        let mut datagrams = 0usize;
        let mut total_bytes = 0usize;

        let start = Instant::now();
        for _ in 0..total_packets {
            if let Some(d) = c.push(&packet) {
                datagrams += 1;
                total_bytes += d.len();
            }
        }
        if let Some(d) = c.flush() {
            datagrams += 1;
            total_bytes += d.len();
        }
        let elapsed = start.elapsed();

        let mib_s = (total_packets * 1024) as f64 / 1_048_576.0 / elapsed.as_secs_f64();
        eprintln!(
            "Coalescer: {} packets → {} datagrams ({:.0} MiB/s, {:.3}ms)",
            total_packets, datagrams, mib_s, elapsed.as_secs_f64() * 1000.0,
        );
        // Should be >10 GiB/s (pure memory)
        assert!(mib_s > 1000.0, "Coalescer too slow: {:.0} MiB/s", mib_s);
    }
}
