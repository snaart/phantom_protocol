use super::super::pipeline::Layer;
use async_trait::async_trait;
use bytes::{Buf, BufMut, BytesMut};
use anyhow::{Result, ensure};
use rand::Rng;

/// Слой, отвечающий за длину пакета и метаданные (GroupID, Epoch).
pub struct MlsFramingLayer {
    pub group_id: [u8; 16],
    pub epoch: u64,
    pub auth_token: Vec<u8>,
}

const PADDING_BLOCK_SIZE: usize = 256;

#[async_trait]
impl Layer for MlsFramingLayer {
    async fn on_inbound(&self, buffer: &mut BytesMut) -> Result<Option<BytesMut>> {
        // 1. Проверяем заголовок (min 4 байта длины)
        if buffer.len() < 4 {
            return Ok(None);
        }

        // Читаем длину без продвижения курсора (peek)
        let mut len_bytes = [0u8; 4];
        len_bytes.copy_from_slice(&buffer[0..4]);
        let length = u32::from_be_bytes(len_bytes) as usize;

        ensure!(length < 10 * 1024 * 1024, "Frame too large"); // 10MB limit

        // 2. Проверяем, пришел ли весь пакет
        // Длина поля длины (4) + Тело (length)
        if buffer.len() < 4 + length {
            return Ok(None); // Ждем еще байт
        }

        // 3. Данные есть. Разбираем.
        buffer.advance(4); // Съедаем длину
        let mut frame = buffer.split_to(length);

        // Парсинг заголовка
        ensure!(frame.len() >= 26, "Frame too short header");

        let _recv_group_id = frame.copy_to_bytes(16); // Можно сверять с self.group_id
        let _recv_epoch = frame.get_u64();
        let padding_len = frame.get_u8() as usize;
        let auth_len = frame.get_u8() as usize;

        if frame.remaining() < auth_len + padding_len {
            anyhow::bail!("Frame malformed");
        }

        // Пропускаем auth (или проверяем)
        frame.advance(auth_len);

        // Отрезаем payload
        let payload_len = frame.remaining() - padding_len;
        let payload = frame.split_to(payload_len); // Zero-copy slice

        // Оставшееся - padding, игнорируем (автоматически дропнется)

        Ok(Some(payload)) // Передаем чистые данные дальше (в crypto слой или приложение)
    }

    async fn on_outbound(&self, data: &[u8], buffer: &mut BytesMut) -> Result<()> {
        // Логика упаковки
        let payload_len = data.len();
        let auth_len = self.auth_token.len();

        // Fixed header: 16 (GID) + 8 (Epoch) + 1 (PadLen) + 1 (AuthLen) = 26
        let body_content_len = 26 + auth_len + payload_len;

        // Padding Logic (Obfuscation)
        let target_size = ((body_content_len + PADDING_BLOCK_SIZE - 1) / PADDING_BLOCK_SIZE) * PADDING_BLOCK_SIZE;
        let padding_bytes_needed = target_size - body_content_len;

        let total_len = body_content_len + padding_bytes_needed;

        // Записываем в выходной буфер
        buffer.reserve(4 + total_len);
        buffer.put_u32(total_len as u32);
        buffer.put_slice(&self.group_id);
        buffer.put_u64(self.epoch);
        buffer.put_u8(padding_bytes_needed as u8);
        buffer.put_u8(auth_len as u8);
        buffer.put_slice(&self.auth_token);
        buffer.put_slice(data);

        // Random Padding
        let mut rng = rand::thread_rng();
        let mut pad = vec![0u8; padding_bytes_needed];
        rng.fill(&mut pad[..]);
        buffer.put_slice(&pad);

        Ok(())
    }
}