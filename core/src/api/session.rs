//! Client-First Transport Session
//!
//! `PhantomSession` provides instant connection establishment with
//! automatic send queuing during handshake. This is the transport-level
//! API that sits below MLS and above the raw UDP/TCP transport.

use crate::errors::CoreError;
use crate::crypto::hybrid_sign::HybridVerifyingKey;
use crate::transport::handshake::{HandshakeClient, ServerHello, HelloRetryRequest};
use crate::transport::multiplexer::StreamDemultiplexer;
use crate::transport::session::Session;
use crate::transport::types::{VersionedPacket, SessionId, PacketHeader, PacketFlags, PhantomPacketV1, StreamId as TransportStreamId};
use crate::transport::stream::Stream;
use tokio::sync::{mpsc, Mutex};
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU32, Ordering};
use dashmap::DashMap;
use bytes::Bytes;

// ─── Connection State ───────────────────────────────────────────────────────

/// Connection state for `PhantomSession`.
///
/// The session is usable from the moment it's created — sends are queued
/// until the handshake completes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
#[repr(u8)]
pub enum ConnectionState {
    /// Connection initiated, handshake pending
    Connecting = 0,
    /// Classical (X25519) channel established — data flows
    ClassicalReady = 1,
    /// PQC upgrade in progress
    PqcUpgrading = 2,
    /// Full hybrid PQC protection active
    PqcReady = 3,
    /// Fully connected and operational
    Connected = 4,
    /// Connection failed
    Failed = 5,
    /// Gracefully closed
    Closed = 6,
}

impl ConnectionState {
    fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Connecting,
            1 => Self::ClassicalReady,
            2 => Self::PqcUpgrading,
            3 => Self::PqcReady,
            4 => Self::Connected,
            5 => Self::Failed,
            6 => Self::Closed,
            _ => Self::Failed,
        }
    }

    /// Whether data can flow (classical or better).
    pub fn is_data_ready(&self) -> bool {
        matches!(
            self,
            Self::ClassicalReady | Self::PqcUpgrading | Self::PqcReady | Self::Connected
        )
    }
}

// ─── Transport Abstraction ──────────────────────────────────────────────────

/// Async transport trait for PhantomSession.
///
/// Abstractions over UDP, TCP, FakeTLS, etc.
/// Used by the background handshake task for I/O.
#[async_trait::async_trait]
pub trait SessionTransport: Send + Sync + 'static {
    /// Send raw bytes to the peer.
    async fn send_bytes(&self, data: &[u8]) -> Result<(), CoreError>;
    /// Receive raw bytes from the peer. Returns None on EOF/close.
    async fn recv_bytes(&self) -> Result<Vec<u8>, CoreError>;
}

// ─── Session ────────────────────────────────────────────────────────────────

/// Client-first session — instant `connect()`, non-blocking `send()`.
///
/// # Design
///
/// ```text
///   let session = PhantomSession::connect("server:443");  // instant!
///   session.send(data).await;   // queued until handshake completes
///   session.send(data2).await;  // also queued
///   // ... handshake completes in background ...
///   // queued data auto-flushed, new sends go directly
/// ```
///
/// The session progresses through states:
/// `Connecting → ClassicalReady → PqcUpgrading → PqcReady → Connected`
#[derive(uniffi::Object)]
pub struct PhantomSession {
    /// Session identifier
    id: String,
    /// Target server address
    peer_addr: String,
    /// Connection state (atomic for lock-free reads)
    state: Arc<AtomicU8>,
    /// Queued messages before connection is ready
    send_queue: Arc<Mutex<Vec<Vec<u8>>>>,
    /// Channel to send commands to the background handshake task
    cmd_tx: mpsc::Sender<SessionCommand>,
    /// Command receiver — taken by the background task when spawned
    #[allow(dead_code)]
    cmd_rx: Mutex<Option<mpsc::Receiver<SessionCommand>>>,
    /// Received messages channel
    recv_rx: Mutex<mpsc::Receiver<Vec<u8>>>,
    /// Multiplexes incoming packets to independent streams
    demux: Arc<StreamDemultiplexer>,
    /// Active outgoing streams (ARQ management)
    streams: Arc<DashMap<u32, Arc<Stream>>>,
}

/// Commands for the background session task
pub enum SessionCommand {
    /// Queue data for sending
    Send(Vec<u8>),
    /// Send data on a specific stream reliably
    SendStreamReliable { stream_id: u32, data: bytes::Bytes },
    /// Send data on a specific stream unreliably
    SendStreamUnreliable { stream_id: u32, data: bytes::Bytes },
    /// Close a specific stream
    CloseStream { stream_id: u32 },
    /// Close the session
    Close,
}

impl PhantomSession {
    /// Create a new session and start the background handshake task.
    ///
    /// Requires `expected_server_key` for MITM resistance — the client will
    /// abort the handshake unless the server presents this exact verifying key.
    /// Callers obtain this key out-of-band (e.g. from `PhantomListener::verifying_key_bytes`).
    ///
    /// The handshake runs in the background:
    /// 1. Exchange hybrid PQC `ClientHello`/`ServerHello`.
    /// 2. Verify server identity against `expected_server_key`.
    /// 3. Derive AEAD keys; flush queued sends as encrypted packets.
    ///
    /// All network I/O goes through the provided `SessionTransport`.
    pub fn connect_with_transport<T: SessionTransport>(
        peer_addr: &str,
        transport: T,
        expected_server_key: HybridVerifyingKey,
    ) -> Self {
        let (cmd_tx, cmd_rx) = mpsc::channel(256);
        let (recv_tx, recv_rx) = mpsc::channel(256);

        let state = Arc::new(AtomicU8::new(ConnectionState::Connecting as u8));
        let send_queue = Arc::new(Mutex::new(Vec::new()));
        let peer = peer_addr.to_string();
        let (demux, _ctrl_rx) = StreamDemultiplexer::new(256);
        let demux = Arc::new(demux);

        let streams = Arc::new(DashMap::new());

        let session = Self {
            id: format!("phantom-{}", rand::random::<u32>()),
            peer_addr: peer.clone(),
            state: state.clone(),
            send_queue: send_queue.clone(),
            cmd_tx: cmd_tx.clone(),
            cmd_rx: Mutex::new(None), // taken by background task
            recv_rx: Mutex::new(recv_rx),
            demux: demux.clone(),
            streams: streams.clone(),
        };

        // Spawn the background handshake + data pump task
        tokio::spawn(Self::background_task(
            state, send_queue, cmd_tx, cmd_rx, recv_tx, transport, peer,
            demux, streams, expected_server_key,
        ));

        session
    }

    /// Install a server-side `Session` (already derived by `HandshakeServer::process_client_hello`)
    /// and spawn the data pump. Used by `PhantomListener::accept` after driving the server handshake.
    pub(crate) fn from_accepted_server_session<T: SessionTransport>(
        peer_addr: String,
        transport: T,
        server_session: Arc<Session>,
    ) -> Arc<Self> {
        let (cmd_tx, cmd_rx) = mpsc::channel(256);
        let (recv_tx, recv_rx) = mpsc::channel(256);

        let state = Arc::new(AtomicU8::new(ConnectionState::Connected as u8));
        let send_queue = Arc::new(Mutex::new(Vec::new()));
        let (demux, _ctrl_rx) = StreamDemultiplexer::new(256);
        let demux = Arc::new(demux);
        let streams = Arc::new(DashMap::new());

        let session = Arc::new(Self {
            id: format!("phantom-{}", rand::random::<u32>()),
            peer_addr: peer_addr.clone(),
            state: state.clone(),
            send_queue: send_queue.clone(),
            cmd_tx,
            cmd_rx: Mutex::new(None),
            recv_rx: Mutex::new(recv_rx),
            demux: demux.clone(),
            streams: streams.clone(),
        });

        let session_id = *server_session.id();
        let next_app_seq = Arc::new(AtomicU32::new(1));
        tokio::spawn(run_data_pump(
            server_session, session_id, Arc::new(transport),
            state, send_queue, cmd_rx, recv_tx, demux, streams, next_app_seq,
        ));

        session
    }

    /// Background task: performs handshake, then pumps data.
    async fn background_task<T: SessionTransport>(
        state: Arc<AtomicU8>,
        send_queue: Arc<Mutex<Vec<Vec<u8>>>>,
        _cmd_tx: mpsc::Sender<SessionCommand>,
        cmd_rx: mpsc::Receiver<SessionCommand>,
        recv_tx: mpsc::Sender<Vec<u8>>,
        transport: T,
        peer: String,
        demux: Arc<StreamDemultiplexer>,
        streams: Arc<DashMap<u32, Arc<Stream>>>,
        expected_server_key: HybridVerifyingKey,
    ) {
        log::info!("PhantomSession: starting handshake with {}", peer);

        // ── Stage 1 & 2: Hybrid Handshake ──
        let handshake = HandshakeClient::new();
        let mut hello = handshake.create_client_hello();

        let server_hello = loop {
            // Send our hello (Full Hybrid ClientHello)
            let hello_bytes = borsh::to_vec(&hello).unwrap();
            if let Err(e) = transport.send_bytes(&hello_bytes).await {
                log::error!("PhantomSession: failed to send hello: {}", e);
                state.store(ConnectionState::Failed as u8, Ordering::Relaxed);
                return;
            }

            // Receive peer's response
            let resp_bytes = match transport.recv_bytes().await {
                Ok(bytes) => bytes,
                Err(e) => {
                    log::error!("PhantomSession: failed to receive server response: {}", e);
                    state.store(ConnectionState::Failed as u8, Ordering::Relaxed);
                    return;
                }
            };

            // Try to deserialize ServerHello
            if let Ok(sh) = borsh::from_slice::<ServerHello>(&resp_bytes) {
                break sh;
            } else if let Ok(retry) = borsh::from_slice::<HelloRetryRequest>(&resp_bytes) {
                log::info!("PhantomSession: Received HelloRetryRequest, retrying...");
                hello.cookie = retry.cookie;
                if let Some(challenge) = retry.challenge {
                    log::info!("PhantomSession: Solving PoW challenge...");
                    hello.pow_solution = Some(challenge.solve());
                }
                continue;
            } else {
                log::error!("PhantomSession: invalid ServerHello or Retry received");
                state.store(ConnectionState::Failed as u8, Ordering::Relaxed);
                return;
            }
        };

        let crypto_session = match handshake.process_server_hello(
            &hello,
            &server_hello,
            Some(&expected_server_key),
        ) {
            Ok(s) => Arc::new(s),
            Err(e) => {
                log::error!("PhantomSession: handshake failed: {:?}", e);
                state.store(ConnectionState::Failed as u8, Ordering::Relaxed);
                return;
            }
        };
        log::info!("PhantomSession: Handshake complete — hybrid channel ready");

        let session_id = *crypto_session.id();
        state.store(ConnectionState::Connected as u8, Ordering::Relaxed);
        log::info!("PhantomSession: fully connected to {} (stage: {:?})", peer, handshake.stage());

        let next_app_seq = Arc::new(AtomicU32::new(1));
        run_data_pump(
            crypto_session,
            session_id,
            Arc::new(transport),
            state,
            send_queue,
            cmd_rx,
            recv_tx,
            demux,
            streams,
            next_app_seq,
        )
        .await;
    }
}

/// Shared client/server data pump.
///
/// After the handshake completes (client side) or after the server `Session` is
/// derived (server side), this loop:
///   - drains the queued early-data buffer,
///   - listens for incoming packets and decrypts them,
///   - encrypts outgoing application/stream packets,
///   - sends ACKs for reliable packets.
async fn run_data_pump<T: SessionTransport>(
    crypto_session: Arc<Session>,
    session_id: SessionId,
    transport: Arc<T>,
    state: Arc<AtomicU8>,
    send_queue: Arc<Mutex<Vec<Vec<u8>>>>,
    mut cmd_rx: mpsc::Receiver<SessionCommand>,
    recv_tx: mpsc::Sender<Vec<u8>>,
    demux: Arc<StreamDemultiplexer>,
    streams: Arc<DashMap<u32, Arc<Stream>>>,
    next_app_seq: Arc<AtomicU32>,
) {
    // ── Flush queued early-data sends as encrypted packets ──
    {
        let mut queue = send_queue.lock().await;
        let count = queue.len();
        for msg in queue.drain(..) {
            if !send_app_data(
                &transport,
                &crypto_session,
                session_id,
                1, // raw-app stream_id
                next_app_seq.fetch_add(1, Ordering::Relaxed),
                &msg,
                PacketFlags::RELIABLE,
            )
            .await
            {
                log::error!("PhantomSession: failed to flush queued message");
            }
        }
        if count > 0 {
            log::info!("PhantomSession: flushed {} queued messages", count);
        }
    }

    // ── Receive task: deserialize, decrypt, route to streams / recv_tx ──
    let transport_recv = transport.clone();
    let transport_send_ack = transport.clone();
    let crypto_recv = crypto_session.clone();
    let demux_recv = demux.clone();
    let streams_recv = streams.clone();
    let recv_tx_for_task = recv_tx.clone();
    let mut recv_handle = tokio::spawn(async move {
        loop {
            let data = match transport_recv.recv_bytes().await {
                Ok(b) => b,
                Err(_) => break,
            };

            let versioned = match alkahest::deserialize::<VersionedPacket, VersionedPacket>(&data) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let packet = match versioned.into_v1() {
                Some(p) => p,
                None => continue,
            };
            let stream_id: u32 = packet.header.stream_id.into();

            if packet.header.flags.is_ack() {
                if let Some(stream) = streams_recv.get(&stream_id) {
                    stream.ack(packet.header.sequence).await;
                }
                demux_recv.route_ack_async(stream_id, packet.header.sequence).await;
                if packet.header.flags.is_fin() {
                    demux_recv.route_close_async(stream_id).await;
                }
                continue;
            }

            // Non-ACK data packet: decrypt the payload if marked encrypted.
            let plaintext: Vec<u8> = if packet.header.flags.contains(PacketFlags::ENCRYPTED) {
                match crypto_recv.decrypt_packet(&packet.header, &packet.payload) {
                    Ok(pt) => pt,
                    Err(e) => {
                        log::warn!("PhantomSession: decrypt failed (dropping packet): {}", e);
                        continue;
                    }
                }
            } else if !packet.payload.is_empty() {
                // Reject unencrypted application data post-handshake to defeat
                // a stripped-flag downgrade attempt.
                log::warn!("PhantomSession: dropping unencrypted post-handshake data packet");
                continue;
            } else {
                Vec::new()
            };

            // Send ACK for reliable packets.
            if packet.header.flags.is_reliable() {
                let ack_header = PacketHeader::new(
                    session_id,
                    stream_id as TransportStreamId,
                    packet.header.sequence,
                    PacketFlags::new(PacketFlags::ACK),
                );
                let ack_packet = PhantomPacketV1::new(ack_header, Vec::new()).into_versioned();
                let mut buf = Vec::new();
                let (size, _) = alkahest::serialize_to_vec::<VersionedPacket, _>(&ack_packet, &mut buf);
                let _ = transport_send_ack.send_bytes(&buf[..size]).await;
            }

            if !plaintext.is_empty() {
                demux_recv
                    .route_data_async(stream_id, Bytes::from(plaintext.clone()))
                    .await;
                if recv_tx_for_task.send(plaintext).await.is_err() {
                    break;
                }
            }

            if packet.header.flags.is_fin() {
                demux_recv.route_close_async(stream_id).await;
            }
        }
    });

    drop(recv_tx); // drop the parent clone so the channel closes when recv_handle exits

    // MTU for transport packets
    const TRANSPORT_MTU: usize = 1300;
    let mut poll_interval = tokio::time::interval(std::time::Duration::from_millis(10));

    loop {
        tokio::select! {
            _ = poll_interval.tick() => {
                for entry in streams.iter() {
                    let stream_id = *entry.key();
                    let stream = entry.value();
                    while let Some((seq, payload, is_reliable)) = stream.poll_send().await {
                        let base = if is_reliable { PacketFlags::RELIABLE } else { PacketFlags::UNRELIABLE };
                        if !send_app_data(
                            &transport,
                            &crypto_session,
                            session_id,
                            stream_id as TransportStreamId,
                            seq,
                            &payload,
                            base,
                        ).await {
                            log::error!("PhantomSession: stream poll send failed");
                            break;
                        }
                    }
                }
            }
            cmd_opt = cmd_rx.recv() => {
                match cmd_opt {
                    Some(SessionCommand::Send(data)) => {
                        let seq = next_app_seq.fetch_add(1, Ordering::Relaxed);
                        if !send_app_data(
                            &transport,
                            &crypto_session,
                            session_id,
                            1,
                            seq,
                            &data,
                            PacketFlags::RELIABLE,
                        ).await {
                            log::error!("PhantomSession: SessionCommand::Send failed");
                            break;
                        }
                    }
                    Some(SessionCommand::SendStreamReliable { stream_id, data }) => {
                        if let Some(stream) = streams.get(&stream_id) {
                            for chunk in data.chunks(TRANSPORT_MTU) {
                                stream.send_reliable(Bytes::copy_from_slice(chunk)).await;
                            }
                        }
                    }
                    Some(SessionCommand::SendStreamUnreliable { stream_id, data }) => {
                        if let Some(stream) = streams.get(&stream_id) {
                            for chunk in data.chunks(TRANSPORT_MTU) {
                                stream.send_unreliable(Bytes::copy_from_slice(chunk)).await;
                            }
                        }
                    }
                    Some(SessionCommand::CloseStream { stream_id }) => {
                        if let Some(stream) = streams.get(&stream_id) {
                            stream.finish().await;
                            let seq = next_app_seq.fetch_add(1, Ordering::Relaxed);
                            let _ = send_app_data(
                                &transport,
                                &crypto_session,
                                session_id,
                                stream_id as TransportStreamId,
                                seq,
                                &[],
                                PacketFlags::FIN,
                            ).await;
                        }
                        streams.remove(&stream_id);
                        demux.close_stream(stream_id);
                    }
                    Some(SessionCommand::Close) => {
                        log::info!("PhantomSession: closing");
                        break;
                    }
                    None => {
                        log::info!("PhantomSession: command channel dropped");
                        break;
                    }
                }
            }
            _ = &mut recv_handle => {
                log::error!("PhantomSession: receive task ended unexpectedly (transport closed)");
                break;
            }
        }
    }

    recv_handle.abort();
    state.store(ConnectionState::Closed as u8, Ordering::Relaxed);
}

/// Encrypt `payload` and emit a single `PhantomPacketV1` over the transport.
/// Returns `false` on a transport or crypto error so the caller can react.
async fn send_app_data<T: SessionTransport>(
    transport: &Arc<T>,
    crypto_session: &Arc<Session>,
    session_id: SessionId,
    stream_id: TransportStreamId,
    sequence: u32,
    payload: &[u8],
    base_flags: u8,
) -> bool {
    let mut flags = PacketFlags::new(base_flags);
    flags.set(PacketFlags::ENCRYPTED);
    let header = PacketHeader::new(session_id, stream_id, sequence, flags);
    let ciphertext = match crypto_session.encrypt_packet(&header, payload) {
        Ok(c) => c,
        Err(e) => {
            log::error!("PhantomSession: encrypt_packet failed: {}", e);
            return false;
        }
    };
    let packet = PhantomPacketV1::new(header, ciphertext).into_versioned();
    let mut buf = Vec::new();
    let (size, _) = alkahest::serialize_to_vec::<VersionedPacket, _>(&packet, &mut buf);
    if let Err(e) = transport.send_bytes(&buf[..size]).await {
        log::error!("PhantomSession: transport send failed: {}", e);
        return false;
    }
    true
}

#[uniffi::export]
impl PhantomSession {
    /// Create a new session — returns instantly.
    ///
    /// Handshake is not started until a transport is provided.
    /// Use `connect_with_transport()` for full integration.
    #[uniffi::constructor]
    pub fn connect(peer_addr: String) -> Arc<Self> {
        let (cmd_tx, cmd_rx) = mpsc::channel(256);
        let (_recv_tx, recv_rx) = mpsc::channel(256);

        let (demux, _ctrl_rx) = StreamDemultiplexer::new(256);
        let streams = Arc::new(DashMap::new());
        Arc::new(Self {
            id: format!("phantom-{}", rand::random::<u32>()),
            peer_addr,
            state: Arc::new(AtomicU8::new(ConnectionState::Connecting as u8)),
            send_queue: Arc::new(Mutex::new(Vec::new())),
            cmd_tx,
            cmd_rx: Mutex::new(Some(cmd_rx)),
            recv_rx: Mutex::new(recv_rx),
            demux: Arc::new(demux),
            streams,
        })
    }

    /// Open a new multiplexed stream
    pub fn open_stream(&self) -> Arc<crate::api::stream::PhantomStream> {
        let handle = self.demux.open_stream(1024);
        let stream_id = handle.stream_id;
        
        let transport_stream = Arc::new(Stream::new(stream_id as TransportStreamId));
        self.streams.insert(stream_id, transport_stream);
        
        Arc::new(crate::api::stream::PhantomStream::new(handle, self.cmd_tx.clone()))
    }

    /// Send data through the session.
    ///
    /// - If the session is connected: sends immediately
    /// - If still handshaking: queues the data for auto-flush later
    pub async fn send(&self, data: Vec<u8>) -> Result<(), CoreError> {
        let state = self.connection_state();

        if state.is_data_ready() {
            // Channel is up — send directly
            self.cmd_tx
                .send(SessionCommand::Send(data))
                .await
                .map_err(|_| CoreError::NetworkError("Session closed".into()))?;
        } else if state == ConnectionState::Connecting {
            // Still handshaking — queue
            self.send_queue.lock().await.push(data);
        } else {
            return Err(CoreError::NetworkError(format!(
                "Cannot send in state {:?}",
                state
            )));
        }

        Ok(())
    }

    /// Receive data from the session.
    pub async fn recv(&self) -> Result<Vec<u8>, CoreError> {
        let mut rx = self.recv_rx.lock().await;
        rx.recv()
            .await
            .ok_or_else(|| CoreError::NetworkError("Session closed".into()))
    }

    /// Get the current connection state (lock-free).
    pub fn connection_state(&self) -> ConnectionState {
        ConnectionState::from_u8(self.state.load(Ordering::Relaxed))
    }

    /// Transition to a new connection state.
    pub fn set_state(&self, new_state: ConnectionState) {
        self.state.store(new_state as u8, Ordering::Relaxed);
    }

    /// Whether the session is ready for data transmission.
    pub fn is_data_ready(&self) -> bool {
        self.connection_state().is_data_ready()
    }

    /// Whether the session has full PQC protection.
    pub fn is_pqc_ready(&self) -> bool {
        matches!(
            self.connection_state(),
            ConnectionState::PqcReady | ConnectionState::Connected
        )
    }

    /// Flush all queued messages (called when handshake completes).
    pub async fn flush_queue(&self) -> Result<u32, CoreError> {
        let mut queue = self.send_queue.lock().await;
        let count = queue.len() as u32;
        for msg in queue.drain(..) {
            self.cmd_tx
                .send(SessionCommand::Send(msg))
                .await
                .map_err(|_| CoreError::NetworkError("Session closed during flush".into()))?;
        }
        Ok(count)
    }

    /// Number of messages queued (waiting for handshake).
    pub async fn queued_count(&self) -> u32 {
        self.send_queue.lock().await.len() as u32
    }

    /// Session identifier.
    pub fn id(&self) -> String {
        self.id.clone()
    }

    /// Target peer address.
    pub fn peer_addr(&self) -> String {
        self.peer_addr.clone()
    }

    /// Close the session.
    pub async fn close(&self) -> Result<(), CoreError> {
        self.set_state(ConnectionState::Closed);
        let _ = self.cmd_tx.send(SessionCommand::Close).await;
        Ok(())
    }
}

impl PhantomSession {
    /// Get the stream demultiplexer (internal use, not exposed to UniFFI)
    pub fn demux(&self) -> Arc<StreamDemultiplexer> {
        self.demux.clone()
    }
}

impl std::fmt::Debug for PhantomSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PhantomSession")
            .field("id", &self.id)
            .field("peer", &self.peer_addr)
            .field("state", &self.connection_state())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use crate::transport::handshake::{HandshakeServer, HandshakeResponse, ClientHello};
    use super::*;

    // ── Mock transport for testing ──

    /// In-memory transport using channels (simulates a loopback pipe).
    struct ChannelTransport {
        tx: mpsc::Sender<Vec<u8>>,
        rx: Mutex<mpsc::Receiver<Vec<u8>>>,
    }

    impl ChannelTransport {
        /// Create a pair of connected transports (client ↔ server).
        fn pair() -> (Self, Self) {
            let (a_tx, b_rx) = mpsc::channel(64);
            let (b_tx, a_rx) = mpsc::channel(64);
            (
                Self { tx: a_tx, rx: Mutex::new(a_rx) },
                Self { tx: b_tx, rx: Mutex::new(b_rx) },
            )
        }
    }

    #[async_trait::async_trait]
    impl SessionTransport for ChannelTransport {
        async fn send_bytes(&self, data: &[u8]) -> Result<(), CoreError> {
            self.tx
                .send(data.to_vec())
                .await
                .map_err(|_| CoreError::NetworkError("channel closed".into()))
        }

        async fn recv_bytes(&self) -> Result<Vec<u8>, CoreError> {
            let mut rx = self.rx.lock().await;
            rx.recv()
                .await
                .ok_or_else(|| CoreError::NetworkError("channel closed".into()))
        }
    }

    // ── Tests ──

    #[tokio::test]
    async fn test_phantom_session_instant_connect() {
        let session = PhantomSession::connect("example.com:443".to_string());

        // Should be in Connecting state immediately
        assert_eq!(session.connection_state(), ConnectionState::Connecting);
        assert!(!session.is_data_ready());
        assert_eq!(session.peer_addr(), "example.com:443");
    }

    #[tokio::test]
    async fn test_phantom_session_send_queue() {
        let session = PhantomSession::connect("example.com:443".to_string());

        // Send while still connecting — should queue
        session.send(vec![1, 2, 3]).await.unwrap();
        session.send(vec![4, 5, 6]).await.unwrap();
        assert_eq!(session.queued_count().await, 2);

        // Simulate handshake completion
        session.set_state(ConnectionState::ClassicalReady);
        assert!(session.is_data_ready());

        // Flush queue
        let flushed = session.flush_queue().await.unwrap();
        assert_eq!(flushed, 2);
        assert_eq!(session.queued_count().await, 0);
    }

    #[tokio::test]
    async fn test_phantom_session_state_progression() {
        let session = PhantomSession::connect("example.com:443".to_string());

        assert_eq!(session.connection_state(), ConnectionState::Connecting);
        assert!(!session.is_data_ready());

        session.set_state(ConnectionState::ClassicalReady);
        assert!(session.is_data_ready());
        assert!(!session.is_pqc_ready());

        session.set_state(ConnectionState::PqcUpgrading);
        assert!(session.is_data_ready());
        assert!(!session.is_pqc_ready());

        session.set_state(ConnectionState::PqcReady);
        assert!(session.is_data_ready());
        assert!(session.is_pqc_ready());

        session.set_state(ConnectionState::Connected);
        assert!(session.is_data_ready());
        assert!(session.is_pqc_ready());
    }

    #[tokio::test]
    async fn test_phantom_session_close() {
        let session = PhantomSession::connect("example.com:443".to_string());
        session.close().await.unwrap();
        assert_eq!(session.connection_state(), ConnectionState::Closed);
        assert!(!session.is_data_ready());
    }

    /// Helper: decrypt an incoming encrypted PhantomPacketV1 frame on the test server side.
    fn decrypt_incoming(
        server_session: &crate::transport::session::Session,
        bytes: &[u8],
    ) -> Vec<u8> {
        let versioned = alkahest::deserialize::<VersionedPacket, VersionedPacket>(bytes)
            .expect("deserialize VersionedPacket");
        let pkt = versioned.into_v1().expect("v1");
        assert!(
            pkt.header.flags.contains(PacketFlags::ENCRYPTED),
            "expected ENCRYPTED flag on application data"
        );
        server_session
            .decrypt_packet(&pkt.header, &pkt.payload)
            .expect("decrypt application data")
    }

    /// Helper: build an encrypted reply frame to send from the test server side.
    fn encrypt_outgoing(
        server_session: &crate::transport::session::Session,
        session_id: SessionId,
        stream_id: TransportStreamId,
        sequence: u32,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut flags = PacketFlags::new(PacketFlags::RELIABLE);
        flags.set(PacketFlags::ENCRYPTED);
        let header = PacketHeader::new(session_id, stream_id, sequence, flags);
        let ct = server_session
            .encrypt_packet(&header, payload)
            .expect("encrypt reply");
        let packet = PhantomPacketV1::new(header, ct).into_versioned();
        let mut buf = Vec::new();
        let (size, _) = alkahest::serialize_to_vec::<VersionedPacket, _>(&packet, &mut buf);
        buf[..size].to_vec()
    }

    /// Integration test: Client handshake via ChannelTransport with a
    /// simulated server responder.
    #[tokio::test]
    async fn test_phantom_session_handshake_via_transport() {
        let (client_transport, server_transport) = ChannelTransport::pair();
        let server_hs = HandshakeServer::new().unwrap();
        let server_pinned_key = server_hs.verifying_key().clone();

        // Start client session — spawns background handshake (with pinning)
        let session = PhantomSession::connect_with_transport(
            "test-server:9000",
            client_transport,
            server_pinned_key,
        );

        // Queue a message before handshake completes
        session.send(b"early-data".to_vec()).await.unwrap();

        // Simulate server responder
        let server_handle = tokio::spawn(async move {
            let client_ip = "127.0.0.1".parse().unwrap();

            // 1. Receive client hello
            let client_hello_bytes = server_transport.recv_bytes().await.unwrap();
            let client_hello = borsh::from_slice::<ClientHello>(&client_hello_bytes).unwrap();

            // 2. Process — may retry with cookie/PoW.
            let server_session = loop {
                let response = server_hs.process_client_hello(&client_hello, 0, client_ip);
                match response {
                    HandshakeResponse::Retry(retry) => {
                        let retry_bytes = borsh::to_vec(&retry).unwrap();
                        server_transport.send_bytes(&retry_bytes).await.unwrap();
                        // Receive retried client hello
                        let next_bytes = server_transport.recv_bytes().await.unwrap();
                        let next_hello = borsh::from_slice::<ClientHello>(&next_bytes).unwrap();
                        let resp2 = server_hs.process_client_hello(&next_hello, 0, client_ip);
                        match resp2 {
                            HandshakeResponse::Success(server_hello, session) => {
                                let server_hello_bytes = borsh::to_vec(&server_hello).unwrap();
                                server_transport.send_bytes(&server_hello_bytes).await.unwrap();
                                break session;
                            }
                            _ => panic!("Expected success after retry"),
                        }
                    }
                    HandshakeResponse::Success(server_hello, session) => {
                        let server_hello_bytes = borsh::to_vec(&server_hello).unwrap();
                        server_transport.send_bytes(&server_hello_bytes).await.unwrap();
                        break session;
                    }
                    HandshakeResponse::Fail(e) => panic!("handshake failed: {:?}", e),
                }
            };

            let session_id = *server_session.id();

            // 3. Receive the flushed early data — must be ENCRYPTED.
            let early_frame = server_transport.recv_bytes().await.unwrap();
            assert!(
                !early_frame.windows(b"early-data".len()).any(|w| w == b"early-data"),
                "encrypted frame must not contain plaintext early-data"
            );
            let early_plain = decrypt_incoming(&server_session, &early_frame);
            assert_eq!(early_plain, b"early-data");

            // 4. Receive a post-handshake message — must be ENCRYPTED.
            let post_frame = server_transport.recv_bytes().await.unwrap();
            let post_plain = decrypt_incoming(&server_session, &post_frame);
            assert_eq!(post_plain, b"after-handshake");

            // 5. Send encrypted reply back.
            let reply = encrypt_outgoing(&server_session, session_id, 1, 1, b"server-reply");
            server_transport.send_bytes(&reply).await.unwrap();
        });

        // Wait for handshake to progress
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        // Should be connected now
        assert_eq!(session.connection_state(), ConnectionState::Connected);

        // Send after handshake
        session.send(b"after-handshake".to_vec()).await.unwrap();

        // Receive server reply — now returns DECRYPTED plaintext payload.
        let reply = session.recv().await.unwrap();
        assert_eq!(reply, b"server-reply");

        server_handle.await.unwrap();
        session.close().await.unwrap();
    }
}
