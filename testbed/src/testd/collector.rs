//! Server-side record collection.
//!
//! Every session handler hands its records to one collector task over a bounded
//! channel, so no handler ever performs file I/O. That matters twice over: a
//! slow disk must not show up as protocol latency, and a multi-hour soak must
//! not accumulate write latency inside the sessions being measured.
//!
//! The channel is bounded and offered with `try_send`. If the collector ever
//! falls behind, records are **dropped and counted** rather than back-pressured
//! into the handlers — a data-collection stall must never become a protocol
//! stall, and a visible drop count is a better artifact than a silently skewed
//! measurement.

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;

use crate::report::{
    unix_nanos, EventRecord, JsonlWriter, ServerStats, SessionRecord, WindowSample,
};

/// Per-stream rotation cap: 256 MiB. Three streams, one retained generation
/// each, bounds the worst case at ~1.5 GiB against a 36 GiB volume.
const ROTATE_BYTES: u64 = 256 * 1024 * 1024;

/// Queue depth. Deep enough to absorb a burst of session closes, shallow
/// enough that a wedged writer is noticed in seconds rather than minutes.
const QUEUE_DEPTH: usize = 4096;

pub enum Record {
    Session(Box<SessionRecord>),
    Event(EventRecord),
    Snapshot(Box<ServerStats>),
    Window(Box<WindowSample>),
}

/// How often the writers are flushed regardless of volume.
///
/// A count-only trigger is not durability: during a quiet stretch the last
/// records sit in a `BufWriter` indefinitely, so a box that dies — or an
/// operator who looks at the file — sees a journal missing its most recent
/// entries. That is exactly how a successful upload came to leave no trace in
/// `events.jsonl` while its bytes were already on disk.
const FLUSH_INTERVAL: Duration = Duration::from_secs(2);

#[derive(Clone)]
pub struct CollectorHandle {
    tx: mpsc::Sender<Record>,
    dropped: Arc<AtomicU64>,
}

impl CollectorHandle {
    fn offer(&self, r: Record) {
        if self.tx.try_send(r).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn session(&self, r: SessionRecord) {
        self.offer(Record::Session(Box::new(r)));
    }

    pub fn snapshot(&self, s: ServerStats) {
        self.offer(Record::Snapshot(Box::new(s)));
    }

    /// One observation of a session's own congestion-control state.
    ///
    /// Sampled here rather than requested by the client: during a download the
    /// server is the sender, so this is the window that governs the transfer,
    /// and polling for it over the same session would perturb exactly what is
    /// being measured.
    pub fn window(&self, w: WindowSample) {
        self.offer(Record::Window(Box::new(w)));
    }

    pub fn event(
        &self,
        listener: &str,
        kind: &str,
        peer: Option<String>,
        session_uid: Option<u64>,
        detail: impl Into<String>,
    ) {
        self.offer(Record::Event(EventRecord {
            t_unix_ns: unix_nanos(),
            listener: listener.to_string(),
            kind: kind.to_string(),
            peer,
            session_uid,
            detail: detail.into(),
        }));
    }

    /// Records lost to a full queue. Reported at shutdown so the artifact
    /// states its own completeness instead of implying it.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

/// Spawn the collector task. Returns a cloneable handle plus the join handle.
pub fn spawn(dir: &Path) -> std::io::Result<(CollectorHandle, tokio::task::JoinHandle<()>)> {
    let sessions = JsonlWriter::open(dir.join("sessions.jsonl"), ROTATE_BYTES)?;
    let events = JsonlWriter::open(dir.join("events.jsonl"), ROTATE_BYTES)?;
    let snapshots = JsonlWriter::open(dir.join("snapshots.jsonl"), ROTATE_BYTES)?;
    let windows = JsonlWriter::open(dir.join("windows.jsonl"), ROTATE_BYTES)?;

    let (tx, mut rx) = mpsc::channel::<Record>(QUEUE_DEPTH);
    let dropped = Arc::new(AtomicU64::new(0));

    let handle = tokio::runtime::Handle::current();
    let task = tokio::task::spawn_blocking(move || {
        // Blocking task: the writers are synchronous, and isolating them here
        // keeps every `write(2)` off the async runtime's worker threads.
        let mut since_flush = 0u32;
        loop {
            // A bounded wait rather than a plain recv: the timeout arm is what
            // makes the flush time-bounded during a quiet stretch. An extra
            // sender feeding tick messages would have worked too, but it would
            // also have held the channel open forever and stopped the collector
            // from ever draining on shutdown.
            let next = handle.block_on(tokio::time::timeout(FLUSH_INTERVAL, rx.recv()));
            let rec = match next {
                Ok(Some(rec)) => rec,
                Ok(None) => break,
                Err(_elapsed) => {
                    if since_flush > 0 {
                        since_flush = 0;
                        let _ = sessions.flush();
                        let _ = events.flush();
                        let _ = snapshots.flush();
                        let _ = windows.flush();
                    }
                    continue;
                }
            };
            let res = match &rec {
                Record::Session(r) => sessions.write(r.as_ref()),
                Record::Event(r) => events.write(r),
                Record::Snapshot(r) => snapshots.write(r.as_ref()),
                Record::Window(r) => windows.write(r.as_ref()),
            };
            if let Err(e) = res {
                tracing::error!(error = %e, "collector write failed");
            }
            since_flush += 1;
            if since_flush >= 32 {
                since_flush = 0;
                let _ = sessions.flush();
                let _ = events.flush();
                let _ = snapshots.flush();
                let _ = windows.flush();
            }
        }
        let _ = sessions.flush();
        let _ = events.flush();
        let _ = snapshots.flush();
        let _ = windows.flush();
        tracing::info!("collector drained and flushed");
    });

    Ok((CollectorHandle { tx, dropped }, task))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::MarkRecord;

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("tb-coll-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).expect("mkdir");
        d
    }

    fn sample_session(uid: u64) -> SessionRecord {
        SessionRecord {
            session_uid: uid,
            listener: "udp".into(),
            peer: "1.2.3.4:5".into(),
            t_open_unix_ns: 1,
            t_close_unix_ns: 2,
            duration_ns: 1,
            early_data_bytes: 0,
            had_early_data: false,
            frames_recv: 3,
            frames_sent: 3,
            bytes_recv: 30,
            bytes_sent: 30,
            echo_frames: 3,
            sink_frames: 0,
            source_frames: 0,
            streams_accepted: 0,
            split_messages: 0,
            window_samples: 0,
            window_samples_skipped: 0,
            marks: vec![MarkRecord {
                t_unix_ns: 1,
                label: "x".into(),
            }],
            close_reason: "bye".into(),
            transport_note: None,
        }
    }

    #[tokio::test]
    async fn records_reach_their_own_files() {
        let dir = tmpdir("route");
        let (h, task) = spawn(&dir).expect("spawn");

        h.session(sample_session(1));
        h.event("tcp", "accept", Some("9.9.9.9:1".into()), Some(1), "hello");
        h.snapshot(ServerStats {
            listener: "tcp".into(),
            t_unix_ns: 7,
            build: crate::report::BuildId::current(),
            metrics: crate::report::ClientMetrics {
                packets_sent: 5,
                packets_recv: 6,
                bytes_sent: 7,
                bytes_recv: 8,
                avg_encrypt_ns: 0,
                avg_decrypt_ns: 0,
                encrypt_count: 0,
                decrypt_count: 0,
                rtt_us_path_0: 0,
                active_sessions: 1,
                active_streams: 0,
                handshakes_success: 1,
                handshakes_failure: 0,
                handshake_latency_ns_sum: 0,
                handshake_latency_count: 0,
                replay_rejected_total: 0,
                aead_failure_total: 0,
                unencrypted_dropped_total: 0,
                initial_datagrams_on_committed_route_total: 0,
                initial_flights_on_committed_route_total: 0,
                handshake_flight_repeated_total: 0,
                handshake_flight_evicted_total: 0,
                handshake_flight_refused_total: 0,
                uptime_secs: 1,
            },
            per_leg: vec![],
            process: Default::default(),
            sender_window: None,
        });

        drop(h);
        task.await.expect("collector joins");

        let sessions = std::fs::read_to_string(dir.join("sessions.jsonl")).expect("sessions");
        let events = std::fs::read_to_string(dir.join("events.jsonl")).expect("events");
        let snaps = std::fs::read_to_string(dir.join("snapshots.jsonl")).expect("snapshots");

        assert_eq!(sessions.lines().count(), 1);
        assert_eq!(events.lines().count(), 1);
        assert_eq!(snaps.lines().count(), 1);

        let s: serde_json::Value =
            serde_json::from_str(sessions.lines().next().expect("line")).expect("json");
        assert_eq!(s["session_uid"], 1);
        assert_eq!(s["marks"][0]["label"], "x");

        let e: serde_json::Value =
            serde_json::from_str(events.lines().next().expect("line")).expect("json");
        assert_eq!(e["kind"], "accept");
        assert_eq!(e["peer"], "9.9.9.9:1");

        let sn: serde_json::Value =
            serde_json::from_str(snaps.lines().next().expect("line")).expect("json");
        assert_eq!(sn["metrics"]["packets_recv"], 6);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Every record must survive a clean shutdown, in order.
    #[tokio::test]
    async fn all_records_are_persisted_in_order() {
        let dir = tmpdir("order");
        let (h, task) = spawn(&dir).expect("spawn");
        for i in 0..500u64 {
            h.session(sample_session(i));
        }
        drop(h);
        task.await.expect("join");

        let body = std::fs::read_to_string(dir.join("sessions.jsonl")).expect("read");
        let uids: Vec<u64> = body
            .lines()
            .map(|l| {
                serde_json::from_str::<serde_json::Value>(l).expect("json")["session_uid"]
                    .as_u64()
                    .expect("uid")
            })
            .collect();
        assert_eq!(uids.len(), 500, "no record lost on a clean shutdown");
        assert!(
            uids.windows(2).all(|w| w[0] < w[1]),
            "records preserve submission order"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A record written during a quiet stretch must reach the disk on its own,
    /// without 31 more records arriving to trigger a count-based flush.
    #[tokio::test]
    async fn a_single_record_reaches_disk_without_further_traffic() {
        let dir = tmpdir("flush");
        let (h, _task) = spawn(&dir).expect("spawn");
        h.event("udp", "upload_ok", None, Some(1), "one quiet record");

        // Well past FLUSH_INTERVAL, but far short of the 32-record threshold.
        tokio::time::sleep(Duration::from_millis(2500)).await;

        let body = std::fs::read_to_string(dir.join("events.jsonl")).expect("events");
        assert!(
            body.contains("upload_ok"),
            "a lone record must not sit in the buffer: {body:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Overflow must be counted, never blocking — a stalled collector must not
    /// become a stalled session handler.
    #[tokio::test]
    async fn overflow_is_counted_and_never_blocks() {
        let (tx, _rx) = mpsc::channel::<Record>(1);
        let h = CollectorHandle {
            tx,
            dropped: Arc::new(AtomicU64::new(0)),
        };
        // _rx is alive but never polled, so the queue fills after one record.
        for i in 0..100u64 {
            h.session(sample_session(i));
        }
        assert!(h.dropped() >= 98, "dropped {} of 100", h.dropped());
    }
}
