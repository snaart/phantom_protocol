//! Fault-injecting [`SessionTransport`] wrapper for loss-recovery testing.
//!
//! Wraps any inner [`SessionTransport`] and injects faults on the send path. It
//! supports two complementary modes, which compose:
//!
//! ## Deterministic, index-addressed faults
//!
//! - **Drop** — by fixed 0-based send index, or "drop the next N sends from now"
//!   (armed at runtime). A dropped send still returns `Ok(())` to the caller
//!   (the sender believes the bytes left the host); the frame is simply never
//!   handed to the inner transport, exactly as a packet lost in the network.
//! - **Duplicate** — forward a frame to the inner transport twice, so the
//!   receiver's replay window / dedup path is exercised.
//! - **Reorder** — hold the frame at a given index and release it *after* the
//!   next forwarded frame (an adjacent swap), so out-of-order delivery is
//!   exercised. A held frame is flushed by the following send, or explicitly via
//!   [`LossyTransport::flush`]; reorder a non-final frame, or call `flush`.
//! - **Delay** — sleep a fixed duration before forwarding every send, to inject
//!   latency (RTT / RTO timing).
//!
//! ## Seeded stochastic faults (Phase 1.5)
//!
//! Built via [`FaultControl::with_seed`], a stochastic config draws a fresh
//! [SplitMix64] integer per fault class on every send and compares it against a
//! precomputed `u64` threshold (`prob * u64::MAX`). The PRNG state lives in the
//! shared [`FaultState`] and advances deterministically per send, so the **same
//! seed + same config + same send count** always produces the **same** drop /
//! dup / reorder decisions — reproducible loss for CI. The stochastic config is
//! **additive and default-off**: [`FaultControl::new`] and the index
//! constructors inject NO stochastic faults, so all pre-existing deterministic
//! behaviour and tests are unchanged.
//!
//! Per send the draw order is fixed and documented: **loss**, then
//! **duplicate**, then **reorder** — up to three draws per send, one per fault
//! class in that order, short-circuiting on the first class that fires. A
//! stochastic drop consumes exactly one draw and returns immediately; only when
//! no class fires are all three draws consumed. This mirrors the deterministic
//! `classify` precedence.
//!
//! [SplitMix64]: https://prng.di.unimi.it/splitmix64.c
//!
//! Faults compose (a frame can be delayed *and* duplicated, etc.). This is the
//! substrate the reliable-delivery / loss-recovery tests need — without a
//! transport that can drop, dup, reorder, or delay a frame, retransmission and
//! out-of-order handling cannot be exercised at all.
//!
//! Fault state lives behind a cloneable [`FaultControl`] handle so a test can
//! arm faults *after* the transport has been moved into a session's data pump
//! (e.g. drop the first data frame once the handshake has completed).
//!
//! This module is **test-only**: it is compiled under `cfg(all(test,
//! feature = "std"))` and is used exclusively by the crate's own `#[cfg(test)]`
//! tests. It is **not shipped in the production library**.

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;

use crate::errors::CoreError;
use crate::transport::session_transport::SessionTransport;

/// One SplitMix64 step: advance `*state` and return the mixed output.
///
/// The canonical SplitMix64 finalizer (Vigna). Six wrapping ops, no table.
/// Deterministic given the seed: the same start state yields the same stream.
fn splitmix64_next(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Convert a probability in `[0.0, 1.0]` into a SplitMix64 comparison threshold:
/// a draw `< threshold` fires with probability ≈ `prob`. Clamped so out-of-range
/// inputs are saturated rather than producing a garbage threshold.
fn prob_to_threshold(prob: f64) -> u64 {
    let p = prob.clamp(0.0, 1.0);
    // `p == 1.0` must fire on *every* draw; `(1.0 * u64::MAX as f64) as u64`
    // rounds back down to `u64::MAX`, and the strict `<` would then miss the
    // single `draw == u64::MAX` case — so special-case the endpoints.
    if p <= 0.0 {
        0
    } else if p >= 1.0 {
        u64::MAX
    } else {
        (p * (u64::MAX as f64)) as u64
    }
}

/// Precomputed stochastic-fault configuration. Built once in
/// [`FaultControl::with_seed`]; the per-send hot path only draws integers and
/// compares against these thresholds.
struct StochasticConfig {
    loss_threshold: u64,
    dup_threshold: u64,
    reorder_threshold: u64,
}

struct FaultState {
    /// Monotonic count of sends seen so far (0-based index of the next send).
    send_index: AtomicU64,
    /// Number of upcoming sends to drop unconditionally (armed at runtime).
    arm_drop: AtomicU64,
    /// Fixed 0-based send indices to drop (set at construction).
    drop_indices: HashSet<u64>,
    /// Fixed 0-based send indices to forward twice (duplicate).
    dup_indices: HashSet<u64>,
    /// Fixed 0-based send indices to hold and release after the next send
    /// (adjacent reorder).
    reorder_indices: HashSet<u64>,
    /// A frame held back by a reorder, awaiting the next forwarded send.
    pending_reorder: Mutex<Option<Vec<u8>>>,
    /// Per-send forwarding delay in milliseconds (0 = none).
    delay_ms: AtomicU64,
    /// Seeded stochastic config (None = stochastic mode disabled — the default).
    stochastic: Option<StochasticConfig>,
    /// Runtime arm/disarm gate for the stochastic config. `with_seed` arms it
    /// immediately; tests that must keep the handshake loss-free (the client
    /// handshake does NOT retransmit a lost `ClientHello`) disarm it, run the
    /// handshake, then re-arm to inject loss on the data phase only.
    stochastic_armed: AtomicBool,
    /// SplitMix64 PRNG state, advanced deterministically per draw. Behind a
    /// `Mutex` so concurrent sends still produce a well-defined (serialised)
    /// stream; loss tests drive sends sequentially, so contention is nil.
    prng: Mutex<u64>,
}

/// What to do with the current send. Returned by [`FaultControl::classify`],
/// which also advances the send index.
enum SendFault {
    /// Forward to the inner transport unchanged.
    Forward,
    /// Drop (never forward) — simulates network loss.
    Drop,
    /// Forward twice.
    Duplicate,
    /// Hold this frame and release it after the next forwarded send.
    Reorder,
}

/// Lock a `Mutex`, recovering the inner value even if a previous holder
/// panicked. Keeps the production paths free of `expect`/`unwrap` (the crate
/// denies both outside `#[cfg(test)]`); a poisoned lock here is benign — the
/// guarded state is test scaffolding, not a security invariant.
fn lock_recover<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Cloneable handle to a [`LossyTransport`]'s fault state.
///
/// Retain a clone in the test to arm faults after the transport itself has been
/// moved into a session pump.
#[derive(Clone)]
pub struct FaultControl {
    state: Arc<FaultState>,
}

impl FaultControl {
    fn build(
        drop_indices: HashSet<u64>,
        dup_indices: HashSet<u64>,
        reorder_indices: HashSet<u64>,
        delay_ms: u64,
        stochastic: Option<StochasticConfig>,
        seed: u64,
    ) -> Self {
        Self {
            state: Arc::new(FaultState {
                send_index: AtomicU64::new(0),
                arm_drop: AtomicU64::new(0),
                drop_indices,
                dup_indices,
                reorder_indices,
                pending_reorder: Mutex::new(None),
                delay_ms: AtomicU64::new(delay_ms),
                // A stochastic config is armed at construction; a control with
                // no config is trivially disarmed.
                stochastic_armed: AtomicBool::new(stochastic.is_some()),
                stochastic,
                prng: Mutex::new(seed),
            }),
        }
    }

    /// An empty control — injects nothing until armed. No stochastic faults.
    pub fn new() -> Self {
        Self::build(HashSet::new(), HashSet::new(), HashSet::new(), 0, None, 0)
    }

    /// A control that drops the sends at these fixed 0-based indices.
    pub fn with_drop_indices(indices: &[u64]) -> Self {
        Self::build(
            indices.iter().copied().collect(),
            HashSet::new(),
            HashSet::new(),
            0,
            None,
            0,
        )
    }

    /// A control that forwards the sends at these fixed 0-based indices twice.
    pub fn with_dup_indices(indices: &[u64]) -> Self {
        Self::build(
            HashSet::new(),
            indices.iter().copied().collect(),
            HashSet::new(),
            0,
            None,
            0,
        )
    }

    /// A control that reorders (holds-then-releases-after-next) the sends at
    /// these fixed 0-based indices.
    pub fn with_reorder_indices(indices: &[u64]) -> Self {
        Self::build(
            HashSet::new(),
            HashSet::new(),
            indices.iter().copied().collect(),
            0,
            None,
            0,
        )
    }

    /// A control that sleeps `delay` before forwarding every send.
    pub fn with_delay(delay: Duration) -> Self {
        Self::build(
            HashSet::new(),
            HashSet::new(),
            HashSet::new(),
            delay.as_millis() as u64,
            None,
            0,
        )
    }

    /// A **seeded, deterministic stochastic** control (Phase 1.5).
    ///
    /// Every send consults up to three SplitMix64 draws per fault class —
    /// **loss**, then **duplicate**, then **reorder** — short-circuiting on the
    /// first class whose draw falls below its `prob * u64::MAX` threshold (a
    /// drop consumes one draw and returns immediately; only if no class fires are
    /// all three draws consumed). Probabilities are clamped to `[0.0, 1.0]`.
    /// `delay_ms` adds a fixed per-send forwarding delay (0 = none).
    ///
    /// Determinism: two controls built with the same `seed` and the same config,
    /// fed the same number of sends, make identical decisions. No `rand` crate
    /// is involved.
    pub fn with_seed(
        seed: u64,
        loss_prob: f64,
        dup_prob: f64,
        reorder_prob: f64,
        delay_ms: u64,
    ) -> Self {
        let stochastic = StochasticConfig {
            loss_threshold: prob_to_threshold(loss_prob),
            dup_threshold: prob_to_threshold(dup_prob),
            reorder_threshold: prob_to_threshold(reorder_prob),
        };
        Self::build(
            HashSet::new(),
            HashSet::new(),
            HashSet::new(),
            delay_ms,
            Some(stochastic),
            seed,
        )
    }

    /// Drop the next `n` sends from now, regardless of index. Use right after a
    /// handshake completes to target the first data frame(s).
    pub fn arm_drop_next(&self, n: u64) {
        self.state.arm_drop.store(n, Ordering::Relaxed);
    }

    /// Set the per-send forwarding delay (latency injection). `Duration::ZERO`
    /// disables it.
    pub fn set_delay(&self, delay: Duration) {
        self.state
            .delay_ms
            .store(delay.as_millis() as u64, Ordering::Relaxed);
    }

    /// Arm or disarm the seeded stochastic faults at runtime (no effect on a
    /// control built without a stochastic config).
    ///
    /// `with_seed` arms the config immediately. The integration loss-recovery
    /// test disarms it for the handshake — the client handshake sends a single
    /// `ClientHello` and then blocks on the reply with no retransmit, so a lost
    /// hello would wedge it — then re-arms once the session is established so
    /// loss is injected on the data phase only. While disarmed, the PRNG state
    /// is left untouched (no draws), so re-arming resumes the exact same
    /// deterministic stream from where it would have been had loss applied to
    /// only the armed sends.
    pub fn arm_stochastic(&self, armed: bool) {
        self.state.stochastic_armed.store(armed, Ordering::Relaxed);
    }

    /// Draw one SplitMix64 integer, advancing the shared PRNG state by one step.
    fn draw(&self) -> u64 {
        let mut state = lock_recover(&self.state.prng);
        splitmix64_next(&mut state)
    }

    /// Classify the current send, advancing the send index.
    ///
    /// Precedence is identical across both modes: drop, then duplicate, then
    /// reorder, else forward. The deterministic index/armed checks run first
    /// (so an explicit arm still wins); then, if a stochastic config is present,
    /// fresh per-class draws are consulted in the documented loss→dup→reorder
    /// order. The first firing class returns; otherwise we forward.
    fn classify(&self) -> SendFault {
        let index = self.state.send_index.fetch_add(1, Ordering::Relaxed);

        // Deterministic, index-addressed faults take precedence (unchanged).
        if self.state.drop_indices.contains(&index) || self.consume_armed_drop() {
            return SendFault::Drop;
        }
        if self.state.dup_indices.contains(&index) {
            return SendFault::Duplicate;
        }
        if self.state.reorder_indices.contains(&index) {
            return SendFault::Reorder;
        }

        // Seeded stochastic faults (default-off; armed by `with_seed`, gated by
        // `arm_stochastic`). Draw order is fixed: loss → dup → reorder, one
        // fresh draw each. The first that fires wins; a drop short-circuits
        // before dup / reorder are even drawn. While disarmed we draw nothing,
        // so the deterministic stream is preserved across an arm/disarm window.
        if self.state.stochastic_armed.load(Ordering::Relaxed) {
            if let Some(cfg) = self.state.stochastic.as_ref() {
                if cfg.loss_threshold > 0 && self.draw() < cfg.loss_threshold {
                    return SendFault::Drop;
                }
                if cfg.dup_threshold > 0 && self.draw() < cfg.dup_threshold {
                    return SendFault::Duplicate;
                }
                if cfg.reorder_threshold > 0 && self.draw() < cfg.reorder_threshold {
                    return SendFault::Reorder;
                }
            }
        }

        SendFault::Forward
    }

    /// The configured per-send delay, if any.
    fn delay(&self) -> Option<Duration> {
        match self.state.delay_ms.load(Ordering::Relaxed) {
            0 => None,
            ms => Some(Duration::from_millis(ms)),
        }
    }

    /// Take any frame held back by a reorder (to release after the current send).
    fn take_pending_reorder(&self) -> Option<Vec<u8>> {
        lock_recover(&self.state.pending_reorder).take()
    }

    /// Hold a frame for reorder; returns any previously-held frame so the caller
    /// can flush it (a second reorder before the first is released).
    fn hold_for_reorder(&self, data: Vec<u8>) -> Option<Vec<u8>> {
        lock_recover(&self.state.pending_reorder).replace(data)
    }

    fn consume_armed_drop(&self) -> bool {
        loop {
            let pending = self.state.arm_drop.load(Ordering::Relaxed);
            if pending == 0 {
                return false;
            }
            if self
                .state
                .arm_drop
                .compare_exchange_weak(pending, pending - 1, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                return true;
            }
        }
    }
}

impl Default for FaultControl {
    fn default() -> Self {
        Self::new()
    }
}

/// A [`SessionTransport`] that injects faults around an inner transport.
pub struct LossyTransport<T> {
    inner: T,
    control: FaultControl,
}

impl<T> LossyTransport<T> {
    /// Wrap `inner`, sharing the given [`FaultControl`] handle.
    pub fn new(inner: T, control: FaultControl) -> Self {
        Self { inner, control }
    }

    /// Convenience: wrap `inner`, dropping the sends at the given 0-based indices.
    pub fn drop_sends(inner: T, indices: &[u64]) -> Self {
        Self::new(inner, FaultControl::with_drop_indices(indices))
    }

    /// Convenience: wrap `inner`, forwarding the sends at the given 0-based
    /// indices twice (duplication).
    pub fn dup_sends(inner: T, indices: &[u64]) -> Self {
        Self::new(inner, FaultControl::with_dup_indices(indices))
    }

    /// Convenience: wrap `inner`, reordering the sends at the given 0-based
    /// indices (each held and released after the following send).
    pub fn reorder_sends(inner: T, indices: &[u64]) -> Self {
        Self::new(inner, FaultControl::with_reorder_indices(indices))
    }
}

impl<T: SessionTransport> LossyTransport<T> {
    /// Flush any frame currently held back by a reorder (e.g. when the reordered
    /// frame was the last send and has no following frame to release it).
    pub async fn flush(&self) -> Result<(), CoreError> {
        if let Some(held) = self.control.take_pending_reorder() {
            self.inner.send_bytes(&held).await?;
        }
        Ok(())
    }
}

impl<T: SessionTransport> SessionTransport for LossyTransport<T> {
    async fn send_bytes(&self, data: &[u8]) -> Result<(), CoreError> {
        // Latency injection happens before any forwarding decision.
        if let Some(delay) = self.control.delay() {
            tokio::time::sleep(delay).await;
        }
        match self.control.classify() {
            SendFault::Drop => {
                // Simulate loss: tell the sender it succeeded, never forward the
                // bytes. A frame held for reorder is NOT released by a dropped
                // send (the dropped frame isn't "delivered"); it waits for the
                // next forwarded send or an explicit `flush`.
                Ok(())
            }
            SendFault::Reorder => {
                // Hold this frame; release any previously-held frame first so a
                // second reorder before the first is delivered doesn't lose it.
                if let Some(prev) = self.control.hold_for_reorder(data.to_vec()) {
                    self.inner.send_bytes(&prev).await?;
                }
                Ok(())
            }
            SendFault::Duplicate => {
                self.inner.send_bytes(data).await?;
                self.inner.send_bytes(data).await?;
                self.release_pending_reorder().await
            }
            SendFault::Forward => {
                self.inner.send_bytes(data).await?;
                self.release_pending_reorder().await
            }
        }
    }

    async fn recv_bytes(&self) -> Result<Bytes, CoreError> {
        self.inner.recv_bytes().await
    }
}

impl<T: SessionTransport> LossyTransport<T> {
    /// Release a frame held by a reorder *after* the current frame was
    /// forwarded, so the held frame lands later in the stream (the swap).
    async fn release_pending_reorder(&self) -> Result<(), CoreError> {
        if let Some(held) = self.control.take_pending_reorder() {
            self.inner.send_bytes(&held).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Inner transport that records every frame actually forwarded to it.
    struct RecordingTransport {
        forwarded: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    impl SessionTransport for RecordingTransport {
        async fn send_bytes(&self, data: &[u8]) -> Result<(), CoreError> {
            self.forwarded.lock().expect("poisoned").push(data.to_vec());
            Ok(())
        }

        async fn recv_bytes(&self) -> Result<Bytes, CoreError> {
            Err(CoreError::NetworkError("recv unused in this test".into()))
        }
    }

    #[tokio::test]
    async fn lossy_transport_drops_configured_send_indices() {
        let forwarded = Arc::new(Mutex::new(Vec::new()));
        let inner = RecordingTransport {
            forwarded: forwarded.clone(),
        };
        // Drop the 2nd send (0-based index 1).
        let lossy = LossyTransport::drop_sends(inner, &[1]);

        lossy.send_bytes(b"f0").await.expect("send f0");
        lossy.send_bytes(b"f1").await.expect("send f1"); // dropped: never forwarded
        lossy.send_bytes(b"f2").await.expect("send f2");

        let got = forwarded.lock().expect("poisoned");
        assert_eq!(
            &*got,
            &[b"f0".to_vec(), b"f2".to_vec()],
            "frame at index 1 must be dropped, not forwarded to the inner transport"
        );
    }

    #[tokio::test]
    async fn arm_drop_next_drops_exactly_the_next_send() {
        let forwarded = Arc::new(Mutex::new(Vec::new()));
        let inner = RecordingTransport {
            forwarded: forwarded.clone(),
        };
        let control = FaultControl::new();
        let lossy = LossyTransport::new(inner, control.clone());

        control.arm_drop_next(1); // drop the very next send only
        lossy.send_bytes(b"d0").await.expect("send d0"); // dropped
        lossy.send_bytes(b"d1").await.expect("send d1");
        lossy.send_bytes(b"d2").await.expect("send d2");

        let got = forwarded.lock().expect("poisoned");
        assert_eq!(
            &*got,
            &[b"d1".to_vec(), b"d2".to_vec()],
            "an armed drop of 1 must skip exactly the next send, then forward the rest"
        );
    }

    #[tokio::test]
    async fn dup_sends_forwards_configured_indices_twice() {
        let forwarded = Arc::new(Mutex::new(Vec::new()));
        let inner = RecordingTransport {
            forwarded: forwarded.clone(),
        };
        // Duplicate the 2nd send (index 1).
        let lossy = LossyTransport::dup_sends(inner, &[1]);

        lossy.send_bytes(b"u0").await.expect("send u0");
        lossy.send_bytes(b"u1").await.expect("send u1"); // forwarded twice
        lossy.send_bytes(b"u2").await.expect("send u2");

        let got = forwarded.lock().expect("poisoned");
        assert_eq!(
            &*got,
            &[
                b"u0".to_vec(),
                b"u1".to_vec(),
                b"u1".to_vec(),
                b"u2".to_vec()
            ],
            "the duplicated frame must reach the inner transport twice, in place"
        );
    }

    #[tokio::test]
    async fn reorder_sends_swaps_with_the_following_frame() {
        let forwarded = Arc::new(Mutex::new(Vec::new()));
        let inner = RecordingTransport {
            forwarded: forwarded.clone(),
        };
        // Reorder the 2nd send (index 1): it is held and released after index 2.
        let lossy = LossyTransport::reorder_sends(inner, &[1]);

        lossy.send_bytes(b"r0").await.expect("send r0");
        lossy.send_bytes(b"r1").await.expect("send r1"); // held
        lossy.send_bytes(b"r2").await.expect("send r2"); // forwards r2, then r1

        let got = forwarded.lock().expect("poisoned");
        assert_eq!(
            &*got,
            &[b"r0".to_vec(), b"r2".to_vec(), b"r1".to_vec()],
            "the reordered frame must land after the following frame"
        );
    }

    #[tokio::test]
    async fn reorder_of_final_frame_is_released_by_flush() {
        let forwarded = Arc::new(Mutex::new(Vec::new()));
        let inner = RecordingTransport {
            forwarded: forwarded.clone(),
        };
        let lossy = LossyTransport::reorder_sends(inner, &[1]);

        lossy.send_bytes(b"r0").await.expect("send r0");
        lossy.send_bytes(b"r1").await.expect("send r1"); // held, last send

        // Without a following send the held frame is still pending.
        assert_eq!(&*forwarded.lock().expect("poisoned"), &[b"r0".to_vec()]);

        lossy.flush().await.expect("flush the held frame");
        assert_eq!(
            &*forwarded.lock().expect("poisoned"),
            &[b"r0".to_vec(), b"r1".to_vec()],
            "flush must release a reorder held past the final send"
        );
    }

    #[tokio::test]
    async fn delay_holds_each_send_for_at_least_the_configured_duration() {
        let forwarded = Arc::new(Mutex::new(Vec::new()));
        let inner = RecordingTransport {
            forwarded: forwarded.clone(),
        };
        let control = FaultControl::with_delay(Duration::from_millis(25));
        let lossy = LossyTransport::new(inner, control);

        let start = tokio::time::Instant::now();
        lossy.send_bytes(b"slow").await.expect("send slow");
        // `tokio::time::sleep` guarantees at least the requested duration.
        assert!(
            start.elapsed() >= Duration::from_millis(25),
            "delay must hold the send for at least the configured duration"
        );
        assert_eq!(&*forwarded.lock().expect("poisoned"), &[b"slow".to_vec()]);
    }

    // ── Part B: seeded stochastic-mode tool-correctness tests ──

    /// Run `n` sends through a stochastic `LossyTransport` built from the given
    /// seed + loss probability (no dup / reorder), returning the 0-based indices
    /// of the sends that were DROPPED (i.e. never forwarded to the inner).
    async fn dropped_indices_for(seed: u64, loss_prob: f64, n: u64) -> Vec<u64> {
        let forwarded = Arc::new(Mutex::new(Vec::new()));
        let inner = RecordingTransport {
            forwarded: forwarded.clone(),
        };
        let control = FaultControl::with_seed(seed, loss_prob, 0.0, 0.0, 0);
        let lossy = LossyTransport::new(inner, control);

        for i in 0..n {
            // Tag each frame with its index so we can tell which were forwarded.
            let tag = i.to_le_bytes();
            lossy.send_bytes(&tag).await.expect("send");
        }

        let forwarded = forwarded.lock().expect("poisoned");
        let forwarded_set: HashSet<u64> = forwarded
            .iter()
            .map(|f| {
                let mut b = [0u8; 8];
                b.copy_from_slice(&f[..8]);
                u64::from_le_bytes(b)
            })
            .collect();
        (0..n).filter(|i| !forwarded_set.contains(i)).collect()
    }

    /// **B1 — determinism.** Two transports with the same seed + config, fed the
    /// same N sends, drop EXACTLY the same set of send indices.
    #[tokio::test]
    async fn stochastic_loss_is_deterministic_for_a_fixed_seed() {
        const N: u64 = 2_000;
        let a = dropped_indices_for(0xDEAD_BEEF_CAFE_F00D, 0.1, N).await;
        let b = dropped_indices_for(0xDEAD_BEEF_CAFE_F00D, 0.1, N).await;
        assert_eq!(
            a, b,
            "same seed + config + send count must drop the exact same indices"
        );
        // Sanity: at 10% over 2000 sends it must actually drop *something*
        // (otherwise the test would pass vacuously).
        assert!(
            !a.is_empty(),
            "10% loss over 2000 sends must drop at least one frame"
        );

        // A different seed must (with overwhelming probability) differ.
        let c = dropped_indices_for(0x0123_4567_89AB_CDEF, 0.1, N).await;
        assert_ne!(
            a, c,
            "a different seed should produce a different drop pattern"
        );
    }

    /// **B2 — rate sanity.** Over a large N at loss_prob = 0.1, the observed drop
    /// fraction lands within 0.1 ± 0.02. Fixed seed ⇒ deterministic, not flaky.
    #[tokio::test]
    async fn stochastic_loss_rate_matches_the_configured_probability() {
        const N: u64 = 10_000;
        const P: f64 = 0.1;
        let dropped = dropped_indices_for(0x5EED_1234_5678_9ABC, P, N).await;
        let frac = dropped.len() as f64 / N as f64;
        assert!(
            (frac - P).abs() <= 0.02,
            "observed drop fraction {frac:.4} must be within 0.1 ± 0.02 over {N} sends \
             ({} dropped)",
            dropped.len()
        );
    }

    /// **B3 — zero-config regression guard.** `FaultControl::new()` and the index
    /// constructors must NEVER drop a frame stochastically: with no stochastic
    /// config and no index/armed faults, every send is forwarded verbatim.
    #[tokio::test]
    async fn non_stochastic_controls_drop_nothing() {
        async fn forwards_all(control: FaultControl, n: u64) -> bool {
            let forwarded = Arc::new(Mutex::new(Vec::new()));
            let inner = RecordingTransport {
                forwarded: forwarded.clone(),
            };
            let lossy = LossyTransport::new(inner, control);
            for i in 0..n {
                lossy.send_bytes(&i.to_le_bytes()).await.expect("send");
            }
            let count = forwarded.lock().expect("poisoned").len() as u64;
            count == n
        }

        // `new()` — empty control.
        assert!(
            forwards_all(FaultControl::new(), 1_000).await,
            "FaultControl::new() must forward every send (no stochastic drops)"
        );
        // The dup / reorder index constructors don't *drop*, but with no
        // configured indices they must forward everything 1:1 as well.
        assert!(
            forwards_all(FaultControl::with_dup_indices(&[]), 1_000).await,
            "with_dup_indices(&[]) must forward every send 1:1"
        );
        // `with_drop_indices(&[])` configures no indices → no drops.
        assert!(
            forwards_all(FaultControl::with_drop_indices(&[]), 1_000).await,
            "with_drop_indices(&[]) must drop nothing"
        );
    }

    /// SplitMix64 must reproduce the canonical reference stream for a known seed
    /// (the upstream `splitmix64.c` output for seed 0), pinning the PRNG so a
    /// refactor can't silently change the deterministic decision stream.
    #[test]
    fn splitmix64_matches_reference_vector() {
        let mut state = 0u64;
        let got = [
            splitmix64_next(&mut state),
            splitmix64_next(&mut state),
            splitmix64_next(&mut state),
        ];
        // Reference outputs of Vigna's splitmix64.c starting from x = 0.
        assert_eq!(
            got,
            [
                0xE220_A839_7B1D_CDAF,
                0x6E78_9E6A_A1B9_65F4,
                0x06C4_5D18_8009_454F
            ],
            "SplitMix64 must match the canonical reference stream for seed 0"
        );
    }

    /// **B4 — the arm/disarm gate.** While disarmed, a `with_seed` control with
    /// 100% loss drops NOTHING (and draws nothing); once armed, every send is
    /// dropped. This is the seam the integration test uses to keep the handshake
    /// loss-free, then inject loss on the data phase.
    #[tokio::test]
    async fn stochastic_arm_gate_controls_when_loss_applies() {
        let forwarded = Arc::new(Mutex::new(Vec::new()));
        let inner = RecordingTransport {
            forwarded: forwarded.clone(),
        };
        // 100% loss, but start disarmed.
        let control = FaultControl::with_seed(7, 1.0, 0.0, 0.0, 0);
        control.arm_stochastic(false);
        let lossy = LossyTransport::new(inner, control.clone());

        // Disarmed: nothing is dropped despite loss_prob = 1.0.
        for i in 0..5u64 {
            lossy.send_bytes(&i.to_le_bytes()).await.expect("send");
        }
        assert_eq!(
            forwarded.lock().expect("poisoned").len(),
            5,
            "a disarmed stochastic control must forward every send"
        );

        // Arm it: now 100% loss drops everything.
        control.arm_stochastic(true);
        for i in 5..10u64 {
            lossy.send_bytes(&i.to_le_bytes()).await.expect("send");
        }
        assert_eq!(
            forwarded.lock().expect("poisoned").len(),
            5,
            "after arming, a 100%-loss control must drop every further send"
        );
    }

    /// Endpoint thresholds: prob 0.0 never fires, prob 1.0 always fires.
    #[tokio::test]
    async fn stochastic_endpoints_are_all_or_nothing() {
        // 100% loss → every send dropped.
        let all = dropped_indices_for(42, 1.0, 256).await;
        assert_eq!(all.len(), 256, "loss_prob = 1.0 must drop every send");
        // 0% loss → nothing dropped.
        let none = dropped_indices_for(42, 0.0, 256).await;
        assert!(none.is_empty(), "loss_prob = 0.0 must drop nothing");
    }
}
