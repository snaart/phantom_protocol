//! The testbed daemon: every leg, one identity, one collector.

pub mod baseline;
pub mod collector;
pub mod handler;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use anyhow::{Context, Result};
use phantom_protocol::api::listener::PhantomListener;
use phantom_protocol::api::udp_listener::PhantomUdpListener;
use phantom_protocol::crypto::hybrid_sign::HybridSigningKey;
use phantom_protocol::observability::Observability;
use phantom_protocol::PhantomConfig;
use tokio::sync::Semaphore;

use crate::framing::{Framed, MsgLink};
use crate::quic::QuicLink;
use crate::report::{unix_nanos, PerLegCounters, ServerStats};
use crate::testd::collector::CollectorHandle;
use crate::testd::handler::{Counters, SessionCtx};

/// How long shutdown waits for the collector to drain before giving up.
///
/// Shutdown must not be able to block on a session that never ends.
const COLLECTOR_DRAIN_GRACE: Duration = Duration::from_secs(10);

/// How long an accepted QUIC connection may go without opening its stream.
///
/// The probe opens one immediately. A connection that does not is holding a
/// session slot for nothing, and on a 2 GB host those are worth reclaiming.
const QUIC_STREAM_GRACE: Duration = Duration::from_secs(30);

#[derive(Debug, Clone)]
pub struct TestdConfig {
    pub tcp_bind: SocketAddr,
    pub udp_bind: SocketAddr,
    pub mimic_bind: SocketAddr,
    pub quic_bind: SocketAddr,
    pub raw_tcp_bind: SocketAddr,
    pub raw_udp_bind: SocketAddr,
    pub enable_mimic: bool,
    pub enable_quic: bool,
    pub mimic_sni: String,
    pub data_dir: PathBuf,
    pub signing_key_file: PathBuf,
    pub max_sessions: usize,
    pub snapshot_interval: Duration,
    pub keepalive: Duration,
    pub session_timeout: Duration,
}

/// Load the 64-byte signing seed, or mint and persist one at 0600.
///
/// The seed — not an expanded key — is the on-disk form: ML-DSA-65's signing
/// key is fully derivable from its 32-byte seed (FIPS 204 Algorithm 1), so
/// nothing is lost, and it lets the daemon construct one `HybridSigningKey` per
/// listener from the same identity. `HybridSigningKey` is deliberately not
/// `Clone`, so re-deriving from bytes is the supported way to share an identity
/// across listeners.
pub fn load_or_create_seed(path: &Path) -> Result<Vec<u8>> {
    if path.exists() {
        let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
        // Validate before trusting it: a truncated key file should fail here,
        // not at the first handshake.
        HybridSigningKey::from_bytes(&bytes)
            .map_err(|e| anyhow::anyhow!("invalid signing key in {}: {e}", path.display()))?;
        return Ok(bytes);
    }

    let (key, vk) = HybridSigningKey::generate();
    key.pairwise_consistency_check(&vk).map_err(|e| {
        anyhow::anyhow!("freshly generated signing key failed pairwise consistency: {e:?}")
    })?;
    let bytes = key.to_bytes();

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    write_0600(path, &bytes)?;
    Ok(bytes)
}

fn write_0600(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        Ok(())
    }
}

fn key_from_seed(seed: &[u8]) -> Result<HybridSigningKey> {
    HybridSigningKey::from_bytes(seed).map_err(|e| anyhow::anyhow!("signing key from seed: {e}"))
}

/// Where a snapshot's observability comes from, per listener.
///
/// TCP and mimic expose `observability()` directly. `PhantomUdpListener` does
/// not — but every session it accepts shares the listener's `Arc`, so the first
/// accepted session is captured and used for the run's UDP snapshots.
#[derive(Default)]
struct ObsRegistry {
    tcp: StdMutex<Option<Arc<Observability>>>,
    mimic: StdMutex<Option<Arc<Observability>>>,
    udp: StdMutex<Option<Arc<Observability>>>,
}

impl ObsRegistry {
    fn set(&self, listener: &str, obs: Arc<Observability>) {
        let slot = match listener {
            "tcp" => &self.tcp,
            "mimic" => &self.mimic,
            "udp" => &self.udp,
            _ => return,
        };
        let mut g = slot.lock().unwrap_or_else(|e| e.into_inner());
        if g.is_none() {
            *g = Some(obs);
        }
    }

    fn get(&self, listener: &str) -> Option<Arc<Observability>> {
        let slot = match listener {
            "tcp" => &self.tcp,
            "mimic" => &self.mimic,
            "udp" => &self.udp,
            _ => return None,
        };
        slot.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

pub async fn run(cfg: TestdConfig) -> Result<()> {
    std::fs::create_dir_all(&cfg.data_dir)
        .with_context(|| format!("create data dir {}", cfg.data_dir.display()))?;
    let upload_root = cfg.data_dir.join("results").join("client");
    std::fs::create_dir_all(&upload_root)?;

    // Power-on self-test before binding: if a crypto primitive is wedged, the
    // right outcome is refusing to serve, not producing a data set that looks
    // like protocol behaviour.
    phantom_protocol::crypto::self_tests::run_post()
        .map_err(|e| anyhow::anyhow!("power-on self-test failed: {e:?}"))?;
    tracing::info!("power-on self-test passed");

    let seed = load_or_create_seed(&cfg.signing_key_file)?;
    let vk_hex = hex::encode(key_from_seed(&seed)?.verifying_key().to_bytes());
    // Persist the pin alongside the data so a client (or a later analysis) can
    // pick it up without parsing logs.
    std::fs::write(cfg.data_dir.join("pin.hex"), format!("{vk_hex}\n"))?;
    tracing::warn!("server verifying key (pin this on clients): {vk_hex}");

    let (collector, collector_task) = collector::spawn(&cfg.data_dir)?;
    let obs = Arc::new(ObsRegistry::default());
    let uid = Arc::new(AtomicU64::new(1));
    let slots = Arc::new(Semaphore::new(cfg.max_sessions.max(1)));

    // `PhantomConfig` is `#[non_exhaustive]`, so start from the server preset
    // and override the two fields that matter here. The preset's 7200 s
    // `session_timeout` is far too long to observe a session death inside a
    // test run, which is the whole point of the liveness scenario.
    let listener_cfg = {
        let mut c = PhantomConfig::server();
        c.keepalive_interval = cfg.keepalive;
        c.session_timeout = cfg.session_timeout;
        c.session_ticket_lifetime = Duration::from_secs(3600);
        c
    };

    // ── TCP ────────────────────────────────────────────────────────────────
    let tcp = PhantomListener::builder(cfg.tcp_bind.to_string())
        .signing_key(key_from_seed(&seed)?)
        .config(listener_cfg.clone())
        .bind()
        .await
        .context("bind Phantom-over-TCP listener")?;
    obs.set("tcp", tcp.observability());
    tracing::info!(addr = %tcp.local_addr(), "phantom TCP listener bound");

    // ── PhantomUDP ─────────────────────────────────────────────────────────
    let udp = PhantomUdpListener::builder(cfg.udp_bind.to_string())
        .signing_key(key_from_seed(&seed)?)
        .config(listener_cfg.clone())
        .bind()
        .await
        .context("bind PhantomUDP listener")?;
    tracing::info!(addr = %udp.local_addr(), "phantom UDP listener bound");

    // ── mimic-TLS ──────────────────────────────────────────────────────────
    let mimic = if cfg.enable_mimic {
        let l = PhantomListener::builder(cfg.mimic_bind.to_string())
            .signing_key(key_from_seed(&seed)?)
            .config(listener_cfg.clone())
            .mimic_sni(cfg.mimic_sni.clone())
            .bind()
            .await
            .context("bind mimic-TLS listener")?;
        obs.set("mimic", l.observability());
        tracing::info!(addr = %l.local_addr(), sni = %cfg.mimic_sni, "mimic-TLS listener bound");
        Some(l)
    } else {
        None
    };

    // ── QUIC reference ─────────────────────────────────────────────────────
    //
    // Its certificate is persisted next to the signing seed and for the same
    // reason: a restart must not invalidate every probe's pin. The hex form is
    // written out and logged exactly as the Phantom pin is, because an operator
    // needs to copy it to the client the same way.
    let quic = if cfg.enable_quic {
        let id = crate::quic::load_or_create_identity(
            &cfg.data_dir.join("quic-cert.der"),
            &cfg.data_dir.join("quic-key.der"),
        )
        .context("QUIC identity")?;
        let cert_hex = hex::encode(&id.cert_der);
        std::fs::write(cfg.data_dir.join("quic-cert.hex"), format!("{cert_hex}\n"))?;
        let endpoint = quinn::Endpoint::server(
            crate::quic::server_config(&id).context("QUIC server config")?,
            cfg.quic_bind,
        )
        .with_context(|| format!("bind QUIC listener on {}", cfg.quic_bind))?;
        tracing::info!(addr = %cfg.quic_bind, "quic reference listener bound");
        tracing::warn!(
            "quic certificate (pin this on clients, also at <data-dir>/quic-cert.hex): {cert_hex}"
        );
        Some(endpoint)
    } else {
        None
    };

    // ── raw baselines ──────────────────────────────────────────────────────
    let base_stats = Arc::new(baseline::BaselineStats::default());
    {
        let s = base_stats.clone();
        let addr = cfg.raw_tcp_bind.to_string();
        tokio::spawn(async move {
            if let Err(e) = baseline::run_tcp(addr, s).await {
                tracing::error!(error = %e, "raw tcp baseline exited");
            }
        });
    }
    {
        let s = base_stats.clone();
        let addr = cfg.raw_udp_bind.to_string();
        tokio::spawn(async move {
            if let Err(e) = baseline::run_udp(addr, s).await {
                tracing::error!(error = %e, "raw udp baseline exited");
            }
        });
    }

    // ── accept loops ───────────────────────────────────────────────────────
    let mut accepts = Vec::new();
    accepts.push(tokio::spawn(accept_tcp(
        tcp.clone(),
        "tcp",
        collector.clone(),
        obs.clone(),
        uid.clone(),
        slots.clone(),
        upload_root.clone(),
    )));
    if let Some(m) = mimic.clone() {
        accepts.push(tokio::spawn(accept_tcp(
            m,
            "mimic",
            collector.clone(),
            obs.clone(),
            uid.clone(),
            slots.clone(),
            upload_root.clone(),
        )));
    }
    accepts.push(tokio::spawn(accept_udp(
        udp.clone(),
        collector.clone(),
        obs.clone(),
        uid.clone(),
        slots.clone(),
        upload_root.clone(),
    )));
    if let Some(q) = quic.clone() {
        accepts.push(tokio::spawn(accept_quic(
            q,
            collector.clone(),
            uid.clone(),
            slots.clone(),
            upload_root.clone(),
        )));
    }

    // ── periodic snapshots ─────────────────────────────────────────────────
    let snap_task = tokio::spawn(snapshot_loop(
        collector.clone(),
        obs.clone(),
        base_stats.clone(),
        cfg.snapshot_interval,
    ));

    collector.event(
        "daemon",
        "start",
        None,
        None,
        format!(
            "tcp={} udp={} mimic={} quic={} raw_tcp={} raw_udp={} pin={}",
            cfg.tcp_bind,
            cfg.udp_bind,
            if cfg.enable_mimic {
                cfg.mimic_bind.to_string()
            } else {
                "disabled".to_string()
            },
            if cfg.enable_quic {
                cfg.quic_bind.to_string()
            } else {
                "disabled".to_string()
            },
            cfg.raw_tcp_bind,
            cfg.raw_udp_bind,
            vk_hex
        ),
    );
    tracing::info!("phantom-testd ready");

    shutdown_signal().await;
    tracing::info!("shutdown signal received");

    for a in accepts {
        a.abort();
    }
    snap_task.abort();
    tcp.shutdown();
    udp.shutdown();
    if let Some(m) = mimic {
        m.shutdown();
    }
    if let Some(q) = quic {
        // Tell live peers rather than letting them time out: an abrupt exit
        // would show up in a probe's samples as a stall it has no way to
        // attribute to a restart.
        q.close(0u32.into(), b"shutdown");
    }

    // Give in-flight handlers a moment to emit their final session records
    // before the collector's channel closes.
    tokio::time::sleep(Duration::from_secs(3)).await;
    collector.event(
        "daemon",
        "stop",
        None,
        None,
        format!("dropped_records={}", collector.dropped()),
    );
    let dropped = collector.dropped();
    drop(collector);

    // Bounded. Every live session handler holds a `CollectorHandle` clone, and
    // handlers are not tracked — one parked in `session.recv()` on a peer that
    // went away keeps the channel open, so an unbounded await here waits for
    // that peer forever. The daemon then never exits, `systemctl restart` hangs
    // until its stop timeout, and the box sits with a dead listener. That
    // happened.
    //
    // Records already on disk are safe regardless: the collector flushes on a
    // 2-second timer, so abandoning it costs at most that much.
    match tokio::time::timeout(COLLECTOR_DRAIN_GRACE, collector_task).await {
        Ok(_) => tracing::info!("collector drained"),
        Err(_) => tracing::warn!(
            grace_s = COLLECTOR_DRAIN_GRACE.as_secs(),
            "collector did not drain in time — a session handler is still holding it; \
             exiting anyway, at most the last flush interval is unwritten"
        ),
    }
    if dropped > 0 {
        tracing::warn!(dropped, "collector dropped records under load");
    }
    tracing::info!("phantom-testd shut down");
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn accept_tcp(
    listener: Arc<PhantomListener>,
    name: &'static str,
    collector: CollectorHandle,
    obs: Arc<ObsRegistry>,
    uid: Arc<AtomicU64>,
    slots: Arc<Semaphore>,
    upload_root: PathBuf,
) {
    loop {
        let permit = match slots.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => return,
        };
        let accepted = match listener.accept().await {
            Ok(a) => a,
            Err(phantom_protocol::CoreError::ConnectionClosed) => return,
            Err(e) => {
                collector.event(name, "accept_error", None, None, format!("{e:?}"));
                continue;
            }
        };
        let session = accepted.session();
        obs.set(name, session.observability());
        let early = accepted.take_early_data().unwrap_or_default();
        let ctx = Arc::new(SessionCtx {
            uid: uid.fetch_add(1, Ordering::Relaxed),
            listener: name.to_string(),
            peer: accepted.peer_addr_string(),
            early_data_bytes: early.len(),
            upload_root: upload_root.clone(),
            counters: Counters::default(),
            marks: Default::default(),
        });
        let collector2 = collector.clone();
        tokio::spawn(async move {
            let _permit = permit;
            handler::run(Arc::new(Framed::new(session)), ctx, collector2).await;
        });
    }
}

async fn accept_udp(
    listener: Arc<PhantomUdpListener>,
    collector: CollectorHandle,
    obs: Arc<ObsRegistry>,
    uid: Arc<AtomicU64>,
    slots: Arc<Semaphore>,
    upload_root: PathBuf,
) {
    loop {
        let permit = match slots.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => return,
        };
        let accepted = match listener.clone().accept().await {
            Ok(a) => a,
            Err(phantom_protocol::CoreError::ConnectionClosed) => return,
            Err(e) => {
                collector.event("udp", "accept_error", None, None, format!("{e:?}"));
                continue;
            }
        };
        let session = accepted.session();
        // The UDP listener exposes no observability accessor; an accepted
        // session's `Arc` *is* the listener's aggregate, so capturing it here is
        // the only route to per-leg UDP totals.
        obs.set("udp", session.observability());
        let early = accepted.take_early_data().unwrap_or_default();
        let ctx = Arc::new(SessionCtx {
            uid: uid.fetch_add(1, Ordering::Relaxed),
            listener: "udp".to_string(),
            peer: accepted.peer_addr_string(),
            early_data_bytes: early.len(),
            upload_root: upload_root.clone(),
            counters: Counters::default(),
            marks: Default::default(),
        });
        let collector2 = collector.clone();
        tokio::spawn(async move {
            let _permit = permit;
            handler::run(Arc::new(Framed::new(session)), ctx, collector2).await;
        });
    }
}

/// Accept QUIC connections and run the same session handler behind them.
///
/// The handshake is awaited inside the spawned task rather than here, so one
/// slow client cannot hold up the accept loop; the session slot is taken first,
/// exactly as on the other legs, so the daemon's concurrency ceiling means the
/// same thing on all of them.
async fn accept_quic(
    endpoint: quinn::Endpoint,
    collector: CollectorHandle,
    uid: Arc<AtomicU64>,
    slots: Arc<Semaphore>,
    upload_root: PathBuf,
) {
    loop {
        let permit = match slots.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => return,
        };
        let Some(incoming) = endpoint.accept().await else {
            return;
        };
        let collector2 = collector.clone();
        let uid2 = uid.clone();
        let upload_root2 = upload_root.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let peer = incoming.remote_address().to_string();
            let conn = match incoming.await {
                Ok(c) => c,
                Err(e) => {
                    collector2.event("quic", "accept_error", Some(peer), None, format!("{e}"));
                    return;
                }
            };
            // The conversation's single bidirectional stream. It does not exist
            // on the wire until the client writes to it, so this is where an
            // idle connection is dropped instead of holding a slot.
            let (send, recv) = match tokio::time::timeout(QUIC_STREAM_GRACE, conn.accept_bi()).await
            {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => {
                    collector2.event("quic", "stream_error", Some(peer), None, format!("{e}"));
                    return;
                }
                Err(_) => {
                    collector2.event(
                        "quic",
                        "stream_timeout",
                        Some(peer),
                        None,
                        format!("no stream within {}s", QUIC_STREAM_GRACE.as_secs()),
                    );
                    conn.close(0u32.into(), b"no stream");
                    return;
                }
            };
            let ctx = Arc::new(SessionCtx {
                uid: uid2.fetch_add(1, Ordering::Relaxed),
                listener: "quic".to_string(),
                peer,
                // 0-RTT early data is not offered on this leg — see the probe's
                // skipped-scenario notes.
                early_data_bytes: 0,
                upload_root: upload_root2,
                counters: Counters::default(),
                marks: Default::default(),
            });
            let link: Arc<dyn MsgLink> = Arc::new(QuicLink::accepted(conn, send, recv));
            handler::run(link, ctx, collector2).await;
        });
    }
}

async fn snapshot_loop(
    collector: CollectorHandle,
    obs: Arc<ObsRegistry>,
    base: Arc<baseline::BaselineStats>,
    interval: Duration,
) {
    let mut tick = tokio::time::interval(interval);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        for name in ["tcp", "udp", "mimic"] {
            let Some(o) = obs.get(name) else { continue };
            let snap = o.snapshot();
            let mut per_leg = Vec::with_capacity(snap.per_leg_packets.len());
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
            collector.snapshot(ServerStats {
                listener: name.to_string(),
                t_unix_ns: unix_nanos(),
                metrics: snap.to_ffi().into(),
                per_leg,
                process: crate::sysinfo::proc_info(),
                // The periodic sweep is listener-scoped and holds no session,
                // so there is no single sender window to report here. The
                // per-session view comes back through STATS.
                sender_window: None,
            });
        }
        collector.event(
            "baseline",
            "counters",
            None,
            None,
            format!(
                "tcp_conns={} tcp_frames={} tcp_bytes={} udp_datagrams={} udp_bytes={}",
                base.tcp_conns.load(Ordering::Relaxed),
                base.tcp_frames.load(Ordering::Relaxed),
                base.tcp_bytes.load(Ordering::Relaxed),
                base.udp_datagrams.load(Ordering::Relaxed),
                base.udp_bytes.load(Ordering::Relaxed),
            ),
        );
    }
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(_) => return,
        };
        let mut int = match signal(SignalKind::interrupt()) {
            Ok(s) => s,
            Err(_) => return,
        };
        tokio::select! {
            _ = term.recv() => {}
            _ = int.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_round_trips_and_yields_a_stable_identity() {
        let dir = std::env::temp_dir().join(format!("tb-seed-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("signing.key");

        let a = load_or_create_seed(&path).expect("create");
        assert_eq!(a.len(), 64, "on-disk form is the 64-byte seed pair");
        let b = load_or_create_seed(&path).expect("reload");
        assert_eq!(a, b, "reload must not mint a new identity");

        // Three independent keys from one seed must present one verifying key —
        // this is what lets all three legs share a single client pin.
        let vks: Vec<String> = (0..3)
            .map(|_| hex::encode(key_from_seed(&a).expect("key").verifying_key().to_bytes()))
            .collect();
        assert_eq!(vks[0], vks[1]);
        assert_eq!(vks[1], vks[2]);
        assert!(!vks[0].is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn seed_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("tb-perm-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("signing.key");
        load_or_create_seed(&path).expect("create");
        let mode = std::fs::metadata(&path).expect("stat").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "signing key must not be group/world readable");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_corrupt_seed_file_fails_loudly_at_load() {
        let dir = std::env::temp_dir().join(format!("tb-bad-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("signing.key");
        std::fs::write(&path, b"too short").expect("write");
        assert!(
            load_or_create_seed(&path).is_err(),
            "a truncated key must fail at load, not at the first handshake"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn observability_registry_keeps_the_first_writer() {
        let reg = ObsRegistry::default();
        assert!(reg.get("udp").is_none());
        let a = Observability::new(Default::default());
        let b = Observability::new(Default::default());
        reg.set("udp", a.clone());
        reg.set("udp", b);
        let got = reg.get("udp").expect("set");
        assert!(Arc::ptr_eq(&got, &a), "first writer wins");
        assert!(reg.get("nonsense").is_none());
    }
}
