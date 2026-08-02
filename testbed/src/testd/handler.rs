//! Per-session testbed protocol handler.
//!
//! Full duplex by construction: a reader task drains `session.recv()` while a
//! writer task owns every `session.send()`. Both hold the same `Arc<PhantomSession>`,
//! which is safe because the session multiplexes through the data pump's
//! channels rather than a lock.
//!
//! The split is not incidental — a single-task handler would block its receive
//! loop for the entire duration of a `SOURCE` download, so the `bidir` scenario
//! would silently degrade into two sequential half-duplex transfers and report
//! a number that looks like a full-duplex result but is not one.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use phantom_protocol::api::session::PhantomSession;
use phantom_protocol::CoreError;
use tokio::io::AsyncWriteExt;
use tokio::sync::{mpsc, Mutex};

use crate::framing::{encode_framed, Framed};
use crate::proto::{checksum, Msg, PayloadGen};
use crate::report::{
    unix_nanos, MarkRecord, PerLegCounters, ProcInfo, ServerStats, SessionRecord, WindowSample,
};
use crate::testd::collector::CollectorHandle;

/// Depth of the handler's outbound queue.
const OUT_QUEUE: usize = 256;

/// Hard ceiling on a single uploaded result file (64 MiB). A deep-profile
/// bundle is a few MiB; this bounds a misbehaving or malicious client.
const MAX_UPLOAD_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Default)]
pub struct Counters {
    pub frames_recv: AtomicU64,
    pub frames_sent: AtomicU64,
    pub bytes_recv: AtomicU64,
    pub bytes_sent: AtomicU64,
    pub echo_frames: AtomicU64,
    pub sink_frames: AtomicU64,
    pub source_frames: AtomicU64,
    pub streams_accepted: AtomicU64,
    /// Logical messages that arrived split across more than one transport read.
    pub split_messages: AtomicU64,
}

pub struct SessionCtx {
    pub uid: u64,
    pub listener: String,
    pub peer: String,
    pub early_data_bytes: usize,
    pub upload_root: PathBuf,
    pub counters: Counters,
    pub marks: Mutex<Vec<MarkRecord>>,
}

enum OutCmd {
    Frame(Vec<u8>),
    Source {
        total_bytes: u64,
        frame_size: u32,
        pace_kbps: u32,
    },
}

/// Drive one accepted session to completion, then emit its `SessionRecord`.
pub async fn run(session: Arc<PhantomSession>, ctx: Arc<SessionCtx>, collector: CollectorHandle) {
    let t_open = unix_nanos();
    let started = Instant::now();
    collector.event(
        &ctx.listener,
        "session_open",
        Some(ctx.peer.clone()),
        Some(ctx.uid),
        format!("early_data_bytes={}", ctx.early_data_bytes),
    );

    let (tx_out, rx_out) = mpsc::channel::<OutCmd>(OUT_QUEUE);

    let writer = tokio::spawn(writer_loop(session.clone(), ctx.clone(), rx_out));
    let window_sampler = tokio::spawn(window_loop(session.clone(), ctx.clone(), collector.clone()));
    let streams = tokio::spawn(stream_loop(session.clone(), ctx.clone(), collector.clone()));

    let framed = Framed::new(session.clone());
    let close_reason = reader_loop(&framed, ctx.clone(), tx_out, collector.clone()).await;

    // Dropping the outbound sender ends the writer; the stream acceptor exits
    // when the session tears down.
    writer.abort();
    streams.abort();
    window_sampler.abort();
    let _ = session.disconnect().await;

    let t_close = unix_nanos();
    let c = &ctx.counters;
    let marks = ctx.marks.lock().await.clone();
    collector.session(SessionRecord {
        session_uid: ctx.uid,
        listener: ctx.listener.clone(),
        peer: ctx.peer.clone(),
        t_open_unix_ns: t_open,
        t_close_unix_ns: t_close,
        duration_ns: started.elapsed().as_nanos() as u64,
        early_data_bytes: ctx.early_data_bytes,
        had_early_data: ctx.early_data_bytes > 0,
        frames_recv: c.frames_recv.load(Ordering::Relaxed),
        frames_sent: c.frames_sent.load(Ordering::Relaxed),
        bytes_recv: c.bytes_recv.load(Ordering::Relaxed),
        bytes_sent: c.bytes_sent.load(Ordering::Relaxed),
        echo_frames: c.echo_frames.load(Ordering::Relaxed),
        sink_frames: c.sink_frames.load(Ordering::Relaxed),
        source_frames: c.source_frames.load(Ordering::Relaxed),
        streams_accepted: c.streams_accepted.load(Ordering::Relaxed),
        split_messages: c.split_messages.load(Ordering::Relaxed),
        marks,
        close_reason: close_reason.clone(),
    });
    collector.event(
        &ctx.listener,
        "session_close",
        Some(ctx.peer.clone()),
        Some(ctx.uid),
        close_reason,
    );
}

// ── Receive side ────────────────────────────────────────────────────────────

#[derive(Default)]
struct SinkState {
    active: bool,
    frames: u64,
    bytes: u64,
    first_ns: u64,
    last_ns: u64,
}

struct UploadState {
    file: tokio::fs::File,
    path: PathBuf,
    written: u64,
    declared: u64,
    hasher_input: Vec<u8>,
}

async fn reader_loop(
    framed: &Framed,
    ctx: Arc<SessionCtx>,
    tx_out: mpsc::Sender<OutCmd>,
    collector: CollectorHandle,
) -> String {
    let session = framed.session().clone();
    let mut sink = SinkState::default();
    let mut upload: Option<UploadState> = None;

    loop {
        let (msg, arrival) = match framed.recv().await {
            Ok(v) => v,
            Err(CoreError::ConnectionClosed) => return "peer_closed".to_string(),
            // A framing desync means the byte stream no longer parses. There is
            // no honest way to resynchronise, so record it and end the session
            // rather than emit garbage records for the rest of its life.
            Err(e @ CoreError::ProtocolRejected(_)) => {
                collector.event(
                    &ctx.listener,
                    "framing_error",
                    Some(ctx.peer.clone()),
                    Some(ctx.uid),
                    format!("{e:?}"),
                );
                return format!("framing_error:{e:?}");
            }
            Err(e) => {
                collector.event(
                    &ctx.listener,
                    "recv_error",
                    Some(ctx.peer.clone()),
                    Some(ctx.uid),
                    format!("{e:?}"),
                );
                return format!("recv_error:{e:?}");
            }
        };

        ctx.counters.frames_recv.fetch_add(1, Ordering::Relaxed);
        ctx.counters
            .bytes_recv
            .fetch_add(arrival.message_len as u64, Ordering::Relaxed);
        // A logical message that needed more than one transport read was split
        // by the session. Recorded once per occurrence so the server-side data
        // shows the same behaviour the client measures.
        if arrival.chunks > 1 {
            ctx.counters.split_messages.fetch_add(1, Ordering::Relaxed);
        }

        match msg {
            Msg::Echo {
                seq,
                client_send_ns,
                payload,
            } => {
                let server_recv_ns = unix_nanos();
                ctx.counters.echo_frames.fetch_add(1, Ordering::Relaxed);
                let reply = Msg::EchoReply {
                    seq,
                    client_send_ns,
                    server_recv_ns,
                    server_send_ns: unix_nanos(),
                    payload,
                };
                if tx_out
                    .send(OutCmd::Frame(encode_framed(&reply)))
                    .await
                    .is_err()
                {
                    return "writer_gone".to_string();
                }
            }

            Msg::Sink { payload, .. } => {
                let now = unix_nanos();
                if !sink.active {
                    sink = SinkState {
                        active: true,
                        first_ns: now,
                        ..Default::default()
                    };
                }
                sink.frames += 1;
                sink.bytes += payload.len() as u64;
                sink.last_ns = now;
                ctx.counters.sink_frames.fetch_add(1, Ordering::Relaxed);
            }

            Msg::SinkEnd { .. } => {
                let report = Msg::SinkReport {
                    frames: sink.frames,
                    bytes: sink.bytes,
                    first_recv_ns: sink.first_ns,
                    last_recv_ns: sink.last_ns,
                };
                sink.active = false;
                if tx_out
                    .send(OutCmd::Frame(encode_framed(&report)))
                    .await
                    .is_err()
                {
                    return "writer_gone".to_string();
                }
            }

            Msg::SourceReq {
                total_bytes,
                frame_size,
                pace_kbps,
            } => {
                if tx_out
                    .send(OutCmd::Source {
                        total_bytes,
                        frame_size,
                        pace_kbps,
                    })
                    .await
                    .is_err()
                {
                    return "writer_gone".to_string();
                }
            }

            Msg::StatsReq => {
                let stats = collect_stats(&session, &ctx.listener).await;
                let json = serde_json::to_vec(&stats).unwrap_or_else(|_| b"{}".to_vec());
                if tx_out
                    .send(OutCmd::Frame(encode_framed(&Msg::Stats { json })))
                    .await
                    .is_err()
                {
                    return "writer_gone".to_string();
                }
            }

            Msg::Mark { label } => {
                let rec = MarkRecord {
                    t_unix_ns: unix_nanos(),
                    label: label.clone(),
                };
                ctx.marks.lock().await.push(rec);
                collector.event(
                    &ctx.listener,
                    "mark",
                    Some(ctx.peer.clone()),
                    Some(ctx.uid),
                    label,
                );
            }

            Msg::UploadBegin { name, total_len } => {
                if let Some(prev) = upload.take() {
                    let _ = tx_out
                        .send(OutCmd::Frame(encode_framed(&Msg::UploadAck {
                            written: prev.written,
                            ok: false,
                        })))
                        .await;
                    // An unterminated previous upload: keep what arrived, note
                    // the truncation rather than discarding it.
                    collector.event(
                        &ctx.listener,
                        "upload_abandoned",
                        Some(ctx.peer.clone()),
                        Some(ctx.uid),
                        format!("{} at {} bytes", prev.path.display(), prev.written),
                    );
                }
                if total_len > MAX_UPLOAD_BYTES {
                    collector.event(
                        &ctx.listener,
                        "upload_rejected",
                        Some(ctx.peer.clone()),
                        Some(ctx.uid),
                        format!("{name}: declared {total_len} over cap"),
                    );
                    let _ = tx_out
                        .send(OutCmd::Frame(encode_framed(&Msg::UploadAck {
                            written: 0,
                            ok: false,
                        })))
                        .await;
                    continue;
                }
                match open_upload(&ctx.upload_root, &name, total_len).await {
                    Ok(st) => {
                        collector.event(
                            &ctx.listener,
                            "upload_begin",
                            Some(ctx.peer.clone()),
                            Some(ctx.uid),
                            format!("{} ({total_len} bytes)", st.path.display()),
                        );
                        upload = Some(st);
                    }
                    Err(e) => collector.event(
                        &ctx.listener,
                        "upload_error",
                        Some(ctx.peer.clone()),
                        Some(ctx.uid),
                        format!("{name}: {e}"),
                    ),
                }
            }

            Msg::UploadChunk { data } => {
                if let Some(st) = upload.as_mut() {
                    if st.written + data.len() as u64 > MAX_UPLOAD_BYTES {
                        collector.event(
                            &ctx.listener,
                            "upload_error",
                            Some(ctx.peer.clone()),
                            Some(ctx.uid),
                            "exceeded upload cap mid-stream".to_string(),
                        );
                        upload = None;
                        continue;
                    }
                    if let Err(e) = st.file.write_all(&data).await {
                        collector.event(
                            &ctx.listener,
                            "upload_error",
                            Some(ctx.peer.clone()),
                            Some(ctx.uid),
                            format!("write: {e}"),
                        );
                        upload = None;
                        continue;
                    }
                    st.written += data.len() as u64;
                    st.hasher_input.extend_from_slice(&data);
                }
            }

            Msg::UploadEnd {
                checksum: declared_sum,
            } => {
                if let Some(mut st) = upload.take() {
                    let _ = st.file.flush().await;
                    let actual = checksum(&st.hasher_input);
                    let ok = actual == declared_sum && st.written == st.declared;
                    // Acknowledge before anything else: the client cannot know a
                    // file arrived from its own send() returning, and it will
                    // close the session as soon as it thinks the bundle is done.
                    let _ = tx_out
                        .send(OutCmd::Frame(encode_framed(&Msg::UploadAck {
                            written: st.written,
                            ok,
                        })))
                        .await;
                    collector.event(
                        &ctx.listener,
                        if ok { "upload_ok" } else { "upload_mismatch" },
                        Some(ctx.peer.clone()),
                        Some(ctx.uid),
                        format!(
                            "{} bytes={} declared={} checksum_ok={}",
                            st.path.display(),
                            st.written,
                            st.declared,
                            actual == declared_sum
                        ),
                    );
                }
            }

            Msg::Bye => return "bye".to_string(),

            // Server-originated verbs; a client sending one is a desync worth
            // recording but not worth tearing the session down for.
            other => collector.event(
                &ctx.listener,
                "unexpected_verb",
                Some(ctx.peer.clone()),
                Some(ctx.uid),
                other.verb_name().to_string(),
            ),
        }
    }
}

/// Resolve an uploaded file name to a path inside `root`.
///
/// The name is client-supplied, so it is treated as untrusted: absolute paths,
/// `..` traversal, and empty components are all rejected. The testbed is not a
/// security boundary, but a harness that can be talked into writing outside its
/// own directory is a liability regardless of intent.
async fn open_upload(
    root: &Path,
    name: &str,
    declared: u64,
) -> Result<UploadState, std::io::Error> {
    let mut safe = PathBuf::new();
    for comp in name.split('/') {
        if comp.is_empty() || comp == "." || comp == ".." {
            continue;
        }
        // Strip anything that is not a plain file-name character.
        let cleaned: String = comp
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
            .take(128)
            .collect();
        if cleaned.is_empty() {
            continue;
        }
        safe.push(cleaned);
    }
    if safe.as_os_str().is_empty() {
        safe.push("unnamed.bin");
    }
    let path = root.join(safe);
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let file = tokio::fs::File::create(&path).await?;
    Ok(UploadState {
        file,
        path,
        written: 0,
        declared,
        hasher_input: Vec::new(),
    })
}

/// Snapshot the owning listener's observability plus process resources.
///
/// `session.observability()` on an accepted session returns the **listener's**
/// aggregate, which is what makes per-leg totals available for the UDP listener
/// at all — it exposes no accessor of its own.
async fn collect_stats(session: &Arc<PhantomSession>, listener: &str) -> ServerStats {
    let snap = session.observability().snapshot();

    let mut per_leg = Vec::with_capacity(4);
    for i in 0..snap.per_leg_packets.len() {
        let (leg, ps, pr) = snap.per_leg_packets[i];
        let (_, bs, br) = snap.per_leg_bytes[i];
        per_leg.push(PerLegCounters {
            leg: format!("{leg:?}").to_lowercase(),
            packets_sent: ps,
            packets_recv: pr,
            bytes_sent: bs,
            bytes_recv: br,
        });
    }

    let sender_window = session.bandwidth_snapshot().await.map(|bw| WindowSample {
        leg: crate::report::Leg::Udp,
        phase: format!("server:{listener}"),
        t_unix_ns: unix_nanos(),
        elapsed_ms: 0,
        cwnd_bytes: bw.cwnd_bytes,
        inflight_bytes: bw.inflight_bytes,
        bottleneck_bw_bps: bw.bottleneck_bw_bps,
        pacing_rate_bps: bw.pacing_rate_bps,
        min_rtt_us: bw.min_rtt.as_micros() as u64,
        delivered_bytes: bw.delivered_bytes,
        state: bw.state.as_str().to_string(),
        app_limited: bw.app_limited,
    });

    ServerStats {
        listener: listener.to_string(),
        t_unix_ns: unix_nanos(),
        metrics: snap.to_ffi().into(),
        per_leg,
        process: proc_info_or_default(),
        sender_window,
    }
}

fn proc_info_or_default() -> ProcInfo {
    crate::sysinfo::proc_info()
}

// ── Send side ───────────────────────────────────────────────────────────────

async fn writer_loop(
    session: Arc<PhantomSession>,
    ctx: Arc<SessionCtx>,
    mut rx: mpsc::Receiver<OutCmd>,
) {
    while let Some(cmd) = rx.recv().await {
        match cmd {
            OutCmd::Frame(bytes) => {
                let n = bytes.len() as u64;
                if session.send(bytes).await.is_err() {
                    return;
                }
                ctx.counters.frames_sent.fetch_add(1, Ordering::Relaxed);
                ctx.counters.bytes_sent.fetch_add(n, Ordering::Relaxed);
            }
            OutCmd::Source {
                total_bytes,
                frame_size,
                pace_kbps,
            } => {
                if source_stream(&session, &ctx, total_bytes, frame_size, pace_kbps)
                    .await
                    .is_err()
                {
                    return;
                }
            }
        }
    }
}

async fn source_stream(
    session: &Arc<PhantomSession>,
    ctx: &Arc<SessionCtx>,
    total_bytes: u64,
    frame_size: u32,
    pace_kbps: u32,
) -> Result<(), CoreError> {
    // Clamp to a sane frame: below the app-frame cap, and at least large enough
    // to carry the header fields.
    let frame_size = frame_size.clamp(64, 256 * 1024) as usize;
    let payload_len = frame_size.saturating_sub(17); // verb + seq + stamp
    let mut gen = PayloadGen::new(0xC0FFEE ^ total_bytes);
    let filler = gen.fill(payload_len);

    let mut sent_bytes = 0u64;
    let mut seq = 0u64;

    // Pacing interval per frame, if a rate was requested. `pace_kbps == 0`
    // means "as fast as backpressure allows" — the interesting case, since it
    // is the session's own pacer and congestion control being measured.
    let per_frame_delay = if pace_kbps > 0 {
        let bits_per_frame = (frame_size as u64) * 8;
        let ns = bits_per_frame.saturating_mul(1_000_000) / (pace_kbps as u64).max(1);
        Some(std::time::Duration::from_nanos(ns))
    } else {
        None
    };

    while sent_bytes < total_bytes {
        let remaining = total_bytes - sent_bytes;
        let this_len = (payload_len as u64).min(remaining) as usize;
        let msg = Msg::SourceData {
            seq,
            server_send_ns: unix_nanos(),
            payload: filler[..this_len].to_vec(),
        };
        let encoded = encode_framed(&msg);
        let n = encoded.len() as u64;
        session.send(encoded).await?;
        ctx.counters.frames_sent.fetch_add(1, Ordering::Relaxed);
        ctx.counters.source_frames.fetch_add(1, Ordering::Relaxed);
        ctx.counters.bytes_sent.fetch_add(n, Ordering::Relaxed);

        sent_bytes += this_len as u64;
        seq += 1;

        if let Some(d) = per_frame_delay {
            tokio::time::sleep(d).await;
        }
    }

    let end = encode_framed(&Msg::SourceEnd {
        frames: seq,
        bytes: sent_bytes,
    });
    let n = end.len() as u64;
    session.send(end).await?;
    ctx.counters.frames_sent.fetch_add(1, Ordering::Relaxed);
    ctx.counters.bytes_sent.fetch_add(n, Ordering::Relaxed);
    Ok(())
}

/// Record this session's congestion-control state for as long as it lives.
///
/// On a download the server is the sender, so this is the window that governs
/// the transfer — and sampling it here rather than answering a client poll
/// keeps the measurement off the path being measured.
async fn window_loop(
    session: Arc<PhantomSession>,
    ctx: Arc<SessionCtx>,
    collector: CollectorHandle,
) {
    // 500 ms: fine enough to watch a window open over a few round trips on a
    // ~200 ms path, coarse enough to be free.
    let mut tick = tokio::time::interval(std::time::Duration::from_millis(500));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let started = Instant::now();
    loop {
        tick.tick().await;
        let Some(bw) = session.bandwidth_snapshot().await else {
            continue;
        };
        collector.window(WindowSample {
            leg: leg_of(&ctx.listener),
            phase: format!("server:session:{}", ctx.uid),
            t_unix_ns: unix_nanos(),
            elapsed_ms: started.elapsed().as_millis() as u64,
            cwnd_bytes: bw.cwnd_bytes,
            inflight_bytes: bw.inflight_bytes,
            bottleneck_bw_bps: bw.bottleneck_bw_bps,
            pacing_rate_bps: bw.pacing_rate_bps,
            min_rtt_us: bw.min_rtt.as_micros() as u64,
            delivered_bytes: bw.delivered_bytes,
            state: bw.state.as_str().to_string(),
            app_limited: bw.app_limited,
        });
    }
}

fn leg_of(listener: &str) -> crate::report::Leg {
    match listener {
        "tcp" => crate::report::Leg::Tcp,
        "mimic" => crate::report::Leg::Mimic,
        _ => crate::report::Leg::Udp,
    }
}

// ── Peer-initiated streams ──────────────────────────────────────────────────

/// Accept peer-opened streams and echo on each.
///
/// Each stream gets its own task so a slow consumer on one stream cannot stall
/// another — which is precisely the head-of-line property the `streams`
/// scenario exists to measure.
async fn stream_loop(
    session: Arc<PhantomSession>,
    ctx: Arc<SessionCtx>,
    collector: CollectorHandle,
) {
    loop {
        let stream = match session.accept_stream().await {
            Ok(s) => s,
            Err(_) => return,
        };
        ctx.counters
            .streams_accepted
            .fetch_add(1, Ordering::Relaxed);
        let sid = stream.stream_id();
        collector.event(
            &ctx.listener,
            "stream_accept",
            Some(ctx.peer.clone()),
            Some(ctx.uid),
            format!("stream_id={sid}"),
        );

        let ctx2 = ctx.clone();
        tokio::spawn(async move {
            loop {
                match stream.recv().await {
                    Ok(Some(data)) => {
                        ctx2.counters.frames_recv.fetch_add(1, Ordering::Relaxed);
                        ctx2.counters
                            .bytes_recv
                            .fetch_add(data.len() as u64, Ordering::Relaxed);
                        // Echo the frame back on the same stream, unchanged, so
                        // the client can time a per-stream round trip.
                        let n = data.len() as u64;
                        if stream.send_reliable(data).await.is_err() {
                            return;
                        }
                        ctx2.counters.frames_sent.fetch_add(1, Ordering::Relaxed);
                        ctx2.counters.bytes_sent.fetch_add(n, Ordering::Relaxed);
                    }
                    // Clean peer FIN — half-close, nothing more is coming.
                    Ok(None) => return,
                    Err(_) => return,
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Per-test root so concurrently-running tests cannot wipe each other's
    /// directory — a shared temp dir made these tests flaky against themselves.
    fn root_for(tag: &str) -> PathBuf {
        let r = std::env::temp_dir().join(format!("tb-up-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&r);
        r
    }

    /// A client-supplied name must never escape the upload root, whatever it
    /// contains.
    #[tokio::test]
    async fn upload_names_cannot_escape_the_root() {
        let root = root_for("escape");
        for hostile in [
            "../../../../etc/passwd",
            "/etc/shadow",
            "..",
            "./../x",
            "a/../../b",
            "",
            "///",
            "....//....//etc/passwd",
        ] {
            let st = open_upload(&root, hostile, 0).await.expect("open");
            let p = st.path.clone();
            drop(st);
            assert!(
                p.starts_with(&root),
                "{hostile:?} escaped the root: {}",
                p.display()
            );
            for comp in p.strip_prefix(&root).expect("under root").components() {
                assert!(
                    !matches!(comp, std::path::Component::ParentDir),
                    "{hostile:?} left a traversal component: {}",
                    p.display()
                );
            }
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn ordinary_names_are_preserved_including_subdirectories() {
        let root = root_for("ordinary");
        let st = open_upload(&root, "samples/udp/rtt_sweep.jsonl", 10)
            .await
            .expect("open");
        assert!(
            st.path.ends_with("samples/udp/rtt_sweep.jsonl"),
            "{:?}",
            st.path
        );
        assert!(st.path.starts_with(&root));
        assert_eq!(st.declared, 10);
        assert_eq!(st.written, 0);
        drop(st);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn empty_name_gets_a_placeholder_rather_than_writing_the_directory() {
        let root = root_for("empty");
        let st = open_upload(&root, "", 0).await.expect("open");
        assert!(st.path.ends_with("unnamed.bin"), "{}", st.path.display());
        assert!(st.path.is_file(), "the placeholder must be a real file");
        drop(st);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn absurdly_long_components_are_truncated() {
        let root = root_for("long");
        let st = open_upload(&root, &"a".repeat(5000), 0)
            .await
            .expect("open");
        let len = st
            .path
            .file_name()
            .and_then(|s| s.to_str())
            .expect("file name")
            .len();
        assert!(len <= 128, "component length {len} not truncated");
        drop(st);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Bytes written must round-trip through the same checksum the client used,
    /// or a truncated upload would be accepted as complete.
    #[tokio::test]
    async fn upload_checksum_matches_the_bytes_written() {
        let root = root_for("sum");
        let mut st = open_upload(&root, "a.bin", 8).await.expect("open");
        let data = PayloadGen::new(3).fill(8);
        st.file.write_all(&data).await.expect("write");
        st.file.flush().await.expect("flush");
        st.written += data.len() as u64;
        st.hasher_input.extend_from_slice(&data);

        assert_eq!(checksum(&st.hasher_input), checksum(&data));
        assert_eq!(st.written, st.declared);

        let mut truncated = st.hasher_input.clone();
        truncated.pop();
        assert_ne!(
            checksum(&truncated),
            checksum(&data),
            "a short upload must not check out"
        );
        drop(st);
        let _ = std::fs::remove_dir_all(&root);
    }
}
