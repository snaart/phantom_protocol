use std::net::SocketAddr;
use tokio::io::{AsyncRead, AsyncWrite};

/// Универсальный транспорт.
/// Это может быть TCP, QUIC Stream, WebSocket, Serial Port или Bluetooth.
pub trait Transport: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static {
    fn remote_addr(&self) -> Option<SocketAddr> {
        None
    }
}

// Псевдоним для удобства использования в Box
pub type BoxedTransport = Box<dyn Transport>;

// --- Реализации для стандартных типов ---

// 1. TCP Stream
impl Transport for tokio::net::TcpStream {
    fn remote_addr(&self) -> Option<SocketAddr> {
        self.peer_addr().ok()
    }
}

// 2. TLS Client Stream
impl<T: Transport> Transport for tokio_rustls::client::TlsStream<T> {
    // remote_addr можно прокинуть, если T умеет, но для TLS это скрыто
}

// 3. TLS Server Stream
impl<T: Transport> Transport for tokio_rustls::server::TlsStream<T> {}

// --- Заготовка для UDP (QUIC) ---
// В будущем сюда добавится реализация для quinn::SendStream + RecvStream
/*
pub struct QuicTransport { ... }
impl Transport for QuicTransport { ... }
*/
