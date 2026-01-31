use tokio::sync::{mpsc, broadcast};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use bytes::BytesMut;
use anyhow::Result;
use super::transport::BoxedTransport;
use super::pipeline::Layer;

/// Команды управления движком
pub enum EngineCommand {
    Send(Vec<u8>),
    Disconnect,
}

pub struct NetworkEngine {
    transport: BoxedTransport,
    pipeline: Vec<Box<dyn Layer>>,

    // Входящие команды от клиента
    cmd_rx: mpsc::Receiver<EngineCommand>,
    // Исходящие события (сообщения) для клиента
    event_tx: broadcast::Sender<Vec<u8>>,

    // Буферы переиспользуются для zero-copy
    in_buffer: BytesMut,
    out_buffer: BytesMut,
}

impl NetworkEngine {
    pub fn new(
        transport: BoxedTransport,
        pipeline: Vec<Box<dyn Layer>>,
        cmd_rx: mpsc::Receiver<EngineCommand>,
        event_tx: broadcast::Sender<Vec<u8>>,
    ) -> Self {
        Self {
            transport,
            pipeline,
            cmd_rx,
            event_tx,
            in_buffer: BytesMut::with_capacity(8192),
            out_buffer: BytesMut::with_capacity(8192),
        }
    }

    pub async fn run(mut self) {
        let mut temp_buf = [0u8; 4096]; // Чтение из сокета

        loop {
            tokio::select! {
                // 1. Чтение из сети
                read_res = self.transport.read(&mut temp_buf) => {
                    match read_res {
                        Ok(0) => break, // EOF
                        Ok(n) => {
                            // Добавляем сырые байты в буфер
                            self.in_buffer.extend_from_slice(&temp_buf[0..n]);

                            // Прогоняем через Pipeline (Inbound)
                            if let Err(e) = self.process_inbound().await {
                                log::error!("Inbound Pipeline Error: {}", e);
                                break;
                            }
                        }
                        Err(e) => {
                            log::error!("Transport Read Error: {}", e);
                            break;
                        }
                    }
                }

                // 2. Команды от приложения
                cmd = self.cmd_rx.recv() => {
                    match cmd {
                        Some(EngineCommand::Send(data)) => {
                             if let Err(e) = self.process_outbound(&data).await {
                                 log::error!("Outbound Pipeline Error: {}", e);
                                 break;
                             }
                        }
                        Some(EngineCommand::Disconnect) => break,
                        None => break, // Все клиенты отключились
                    }
                }
            }
        }
        log::info!("NetworkEngine stopped");
    }

    async fn process_inbound(&mut self) -> Result<()> {
        // Пытаемся извлечь столько пакетов, сколько есть в буфере
        loop {
            // Для упрощения примера: у нас пока 1 слой (Framer).
            // В реальной системе тут цикл по self.pipeline.
            // Но layers мутируют буфер.

            // ВАЖНО: Архитектура pipeline с BytesMut сложнее, для примера хардкодим вызов единственного слоя
            // или предполагаем цепочку.

            // Берем первый слой (Framer)
            if let Some(layer) = self.pipeline.first() {
                match layer.on_inbound(&mut self.in_buffer).await? {
                    Some(payload) => {
                        // Пакет готов!
                        // Если есть Crypto слой, передали бы payload ему.
                        // Сейчас считаем payload готовым сообщением.
                        let _ = self.event_tx.send(payload.to_vec());
                    }
                    None => break, // Мало данных, ждем еще
                }
            } else {
                break;
            }
        }
        Ok(())
    }

    async fn process_outbound(&mut self, data: &[u8]) -> Result<()> {
        self.out_buffer.clear();

        // Прогоняем через слои (в обратном порядке, если их много)
        // Сейчас один слой
        if let Some(layer) = self.pipeline.first() {
            layer.on_outbound(data, &mut self.out_buffer).await?;
        }

        // Пишем в сеть
        self.transport.write_all(&self.out_buffer).await?;
        self.transport.flush().await?;
        Ok(())
    }
}