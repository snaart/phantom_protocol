use anyhow::Result;
use async_trait::async_trait;
use bytes::BytesMut;

/// Слой обработки данных.
/// Inbound: Сеть -> Приложение (Декапсуляция, Расшифровка)
/// Outbound: Приложение -> Сеть (Инкапсуляция, Шифрование)
#[async_trait]
pub trait Layer: Send + Sync {
    /// Обрабатывает входящие байты.
    /// Возвращает Ok(Some(data)) если пакет готов к передаче следующему слою.
    /// Возвращает Ok(None) если нужно больше данных (накопление буфера).
    async fn on_inbound(&self, buffer: &mut BytesMut) -> Result<Option<BytesMut>>;

    /// Обрабатывает исходящие данные.
    /// Записывает результат в buffer.
    async fn on_outbound(&self, data: &[u8], buffer: &mut BytesMut) -> Result<()>;
}
