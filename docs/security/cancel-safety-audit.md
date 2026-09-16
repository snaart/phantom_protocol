# Async cancel-safety audit (Phase 2.13; re-run 2026-06-01; re-checked for 0.3.0)

> **Re-run note (2026-06-01).** The original audit was signed off at Phase 2.13
> and scheduled a re-run "after Phase 4.4." That landed, and the data pump was
> materially rewritten — the loss-recovery rework (route `send()` through a
> per-stream reliable buffer + BBR-paced drain) and the observability wiring (a
> `session_opened` / `session_closed` gauge + `ObservedTransport`). The `run_data_pump` main-loop
> section below is rewritten for the current 5-arm `select!`; the headline
> concern raised for the re-run — a `pace_send` sleep stranding already-dequeued
> data on cancel — was **resolved by the same loss-recovery rework that
> introduced pacing** (see that section). Verdict stands: ✅ cancel-safe, no code change.
>
> **Amended when pacing was connected to the wire.** `pace_send` is gone. The
> pacing wait is now a `sleep_until` *branch* of the main `select!` rather than
> an await inside an arm body, which is stricter than what this document asked
> for: the pump can no longer be parked by the rate limiter at all. The arm
> count went 4 → 5 and the `Paced` outcome is inventoried below. Still no
> cancel-safety code change — the change was made for scheduling reasons and
> happens to close the concern outright.
>
> **Re-checked for the 0.3.0 release.** Every code reference is now keyed on the
> file and the enclosing function instead of a line number — none of the
> previous revision's twenty-two distinct line references still pointed at the
> code it described, and a line number that drifts still resolves, just to
> unrelated code. Each `select!` sketch below was compared with the code and
> redrawn where it had moved: the pump's arm guards (the WIRE v8 draining state,
> the deferred admission queue), the command path's admission through a
> pump-owned queue instead of a parked `send_reliable`, the WIRE v8 close flush,
> the PhantomUDP demux's retire and sweep arms (5 → 7 arms), its reply-flight
> repeat, and the awaits the receive task now takes inside `handle_packet`. No
> cancel-safety code change; one teardown-only residue is recorded under the
> pump.
>
> **Amended when the local close left the command channel.** `disconnect()` and
> `Drop for PhantomSession` used to put `SessionCommand::Close` on the command
> channel, whose arm is disabled while the pump holds a write the send buffer
> refused — and a peer that stops reading can keep one refused indefinitely, so
> the close was never read and a full channel also blocked `disconnect()`. They
> now raise a `watch` signal the pump reads on an ungated arm of its own; the
> arm count went 5 → 6. The new primitive is cancel-safe and its body follows
> the same teardown-only cancellation argument as the others, so the verdict
> stands.

A `select!` arm that fires before its sibling completes effectively
**cancels** the unfinished future. If that future was carrying
state mid-await — half-consumed bytes from a stream, an unposted
ACK, a partially-allocated resource — cancellation can leave the
session in an inconsistent state.

This document inventories every `tokio::select!` and every long-held
`.await` in `phantom_protocol` and confirms whether the pattern is
cancel-safe by tokio's stated guarantees.

**Methodology.** Every `tokio::select!` in `core/src` is matched against
tokio's [cancellation-safety documentation](https://docs.rs/tokio/latest/tokio/macro.select.html#cancellation-safety)
and checked for the "what if the other arm fires first" scenario; every
long-held `.await` on the same paths is checked for what a cancel at that
point would lose. At commit `e5b23d8b`, `grep -rn 'tokio::select!' core/src`
returns 15 invocations: the 11 production sites indexed below, plus four
inside `#[cfg(test)] mod tests` blocks — two in `api/udp_transport.rs` and two
in `api/udp_listener.rs` — which are out of scope.

**Sites are keyed on file and enclosing function, never on a line number.**
Re-checking this file is therefore mechanical: the grep above must return the
index below plus the test-module sites, and a mismatch means a site was added,
moved or removed.

| # | File (under `core/src/`) | Enclosing function | Arms | Section |
| --- | --- | --- | --- | --- |
| 1 | `api/session.rs` | `run_data_pump` (main loop) | 6, three of them guarded | [data pump](#apisessionrsrun_data_pump-main-loop-6-arm) |
| 2 | `api/session.rs` | `PhantomSession::background_task` | 2 (handshake vs deadline) | [client handshake](#apisessionrsphantomsessionbackground_task-handshake-deadline) |
| 3 | `api/listener.rs` | `PhantomListener::accept` | 2, `biased` | [TCP listener](#apilistenerrsphantomlisteneraccept--the-h4-acceptor-task) |
| 4 | `api/listener.rs` | `run_acceptor` | 2, `biased` | [TCP listener](#apilistenerrsphantomlisteneraccept--the-h4-acceptor-task) |
| 5 | `api/listener.rs` | `serve_connection` | 2 (handshake vs deadline) | [TCP listener](#apilistenerrsphantomlisteneraccept--the-h4-acceptor-task) |
| 6 | `api/udp_transport.rs` | `UdpClientTransport::recv_bytes` (handshake phase) | 2, `biased` | [PhantomUDP client](#apiudp_transportrsudpclienttransportrecv_bytes-3-selects) |
| 7 | `api/udp_transport.rs` | `UdpClientTransport::recv_bytes` (migration overlap) | 3 | [PhantomUDP client](#apiudp_transportrsudpclienttransportrecv_bytes-3-selects) |
| 8 | `api/udp_transport.rs` | `UdpClientTransport::recv_bytes` (steady state) | 2, `biased` | [PhantomUDP client](#apiudp_transportrsudpclienttransportrecv_bytes-3-selects) |
| 9 | `api/udp_listener.rs` | `PhantomUdpListener::accept` | 2, `biased` | [PhantomUDP listener](#apiudp_listenerrs--accept-the-demux-loop-and-the-handshake-task) |
| 10 | `api/udp_listener.rs` | `run_udp_demux` | 7, `biased` | [PhantomUDP listener](#apiudp_listenerrs--accept-the-demux-loop-and-the-handshake-task) |
| 11 | `api/udp_listener.rs` | `spawn_handshake_task` (inside the spawned task) | 2 (handshake vs deadline) | [PhantomUDP listener](#apiudp_listenerrs--accept-the-demux-loop-and-the-handshake-task) |

`UdpClientTransport::recv_bytes` is the `SessionTransport` impl's method; the
three sites are the three branches of one `if` / `else if` / `else`, and each
loop iteration enters exactly one of them.

---

## Inventory

### `api/session.rs::run_data_pump` main loop (6-arm)

```rust
// api/session.rs::run_data_pump — main loop
tokio::select! {
    _ = poll_interval.tick() => {
        // Draining (WIRE v8): arm the deadline once, `break` when it passes,
        // otherwise `continue` before sending anything. Not draining:
        // flush_deferred_sends, flush_pending_window_updates,
        // drain_streams_priority_ordered, maybe_send_keepalive, maybe_send_cover,
        // sweep_path_validation_timeouts, apply_liveness (a `Dead` verdict breaks).
    }
    _ = send_notify.notified(), if draining_until.is_none() => {
        // fast wake: flush_deferred_sends, flush_pending_window_updates, drain
    }
    _ = tokio::time::sleep_until(paced_wake),
        if paced_until.is_some() && draining_until.is_none() => {
        // pacing wake: drain
    }
    _ = close_requested.changed() => {
        // never gated: take in the commands queued ahead of the close
        // (try_recv, bounded), finish_and_announce, break
    }
    cmd_opt = cmd_rx.recv(), if deferred.is_empty() => {
        take_command(cmd): Send | SendStreamReliable | SendStreamUnreliable
                         | SetStreamPriority | CloseStream | Migrate
                         | MigrateServer | Close;  None -> finish_and_announce, break
    }
    _ = &mut recv_done_rx => { /* receive task ended -> break */ }
}
```

**Primitive cancel-safety (the six arms):**
- `tokio::time::sleep_until()`: **cancel-safe** — it is a deadline, not an interval, so
  dropping and recreating the future does not lose or extend the wait. Recreated each
  iteration from `paced_until`, which is plain state the drain wrote; a lost poll costs
  at most one extra pass through the loop, and the 10 ms `poll_interval.tick()` drains
  regardless. Disabled entirely unless the last drain stopped for want of pacing credit
  and the session is not draining, so an unpaced session never registers this timer.
- `tokio::time::Interval::tick()`: **cancel-safe** — dropping the future does not
  advance the timer.
- `tokio::sync::Notify::notified()`: created fresh each iteration (not pinned).
  This is safe here because `Session::notify_outbound_ready()` calls `notify_one`,
  whose **stored permit** survives across loop iterations — a notification raised
  while the pump is busy in another arm is observed by the next iteration's fresh
  `notified()`. The rare register-then-drop window can at worst *delay* a wake, and
  the 10 ms `poll_interval.tick()` is an explicit fallback that drains regardless,
  so a missed notification costs ≤ 10 ms of latency, never data.
- `tokio::sync::watch::Receiver::changed()`: **cancel-safe** (tokio documents it so) —
  a dropped future does not mark the new value seen, so a close raised while the pump
  is in another arm is observed on the next iteration. It also resolves, with an
  error, once the sender is gone; the arm treats that as the same request, which is
  what a dropped handle means anyway. Never gated, so no refused write, full channel
  or draining window can keep it from being read. Its body drains the command
  channel with `try_recv`, bounded by the channel's length when the close was seen.
- `tokio::sync::mpsc::Receiver::recv()`: **cancel-safe** — a dropped `recv` does not
  consume a queued message. The `if deferred.is_empty()` guard disables the branch
  while the pump-owned admission queue holds work; a disabled branch is never polled,
  so nothing is taken off the channel while it is off. That guard is the backpressure
  mechanism (a full send buffer stops the pump reading commands, so the caller's
  `send()` blocks on the bounded channel instead of the pump parking), and it also
  means a `Close` is read only once every earlier write has been admitted.
- `tokio::sync::oneshot::Receiver` (`&mut recv_done_rx`): **cancel-safe** — polling
  does not consume the value.

The two `draining_until` guards only disable branches, and the draining path in the
tick arm is synchronous up to its `break` / `continue`, so the WIRE v8 draining state
adds no cancel-safety question of its own.

**The arm *bodies* contain `.await`s — is that a strand risk?** A `select!` arm,
once chosen, runs its body to completion *unless the whole task is cancelled*. The
bodies do await: `flush_deferred_sends`, `flush_pending_window_updates`,
`drain_streams_priority_ordered`, `maybe_send_keepalive` and `maybe_send_cover` in
the tick / notify / paced arms; in the command arm, `flush_deferred_sends`,
`Stream::send_unreliable`, `transport.migrate(..)` / `migrate_server(..)`, and
`finish_and_announce` for `Close` and the channel-closed `None`. So the question is
**whether the pump task can be cancelled mid-body**, and **what is lost if it is**.

1. **The pump is never aborted mid-`await` in normal operation.** Both spawn sites
   detach the handle: the server's `PhantomSession::from_accepted_server_session_with_runtime`
   does `let _detached = runtime.spawn(Box::pin(run_data_pump(..)))`, and the client's
   `PhantomSession::spawn_client` detaches `PhantomSession::background_task` the same
   way, which then awaits `run_data_pump` inline. Dropping a `SpawnHandle` without
   calling `abort` detaches the task (`runtime/mod.rs`). `Drop for PhantomSession`
   only raises the graceful close request and drains the active-streams gauge — it
   never aborts the pump task — and the only production `.abort()` in
   `api/session.rs` is the pump aborting *its own* receive subtask during teardown
   (`recv_handle.abort()`, after the main loop in `run_data_pump`). The pump exits
   exclusively through a loop `break`: the close-request arm (from `disconnect()` or
   `Drop`), a `SessionCommand::Close`, the channel-closed `None` arm, the
   `recv_done_rx` arm, a liveness `Dead` verdict in the tick arm, or the WIRE v8
   draining deadline in the tick arm. The *only* way an arm body is cancelled is the
   **runtime/process being torn down**, where losing in-flight bytes is expected and
   harmless.

2. **Even under that teardown cancel, reliable data is not stranded** — this is what
   resolved the 2026-06-01 re-run's headline concern. The concern was:
   `SessionCommand::Send → send_app_data → pace_send().await` consumes the payload
   from the mpsc channel and then sleeps, so an abort during the sleep silently drops
   a payload the channel had already handed out. **The loss-recovery rework removed
   that path**, and the pacing wiring removed the sleep.

   Today the `Send` and `SendStreamReliable` arms split the payload into
   `MAX_APP_CHUNK` pieces and push them onto the pump-owned `deferred` queue
   synchronously, then call `flush_deferred_sends`. That function admits the head of
   the queue into the stream's reliable send buffer with `Stream::try_send_reliable`
   and pops it only once admitted; a refused chunk stays at the head, and the command
   arm stays disabled until the queue has drained. `try_send_reliable` takes its
   backpressure permit with `Semaphore::try_acquire`, so it never parks on the
   semaphore; its only await is the `send_buffer` lock for one `push_back`. Between
   the channel handing out a payload and the payload sitting in a retained send
   buffer, it is held in a pump-owned queue, not inside a suspended future.

   Transmission happens later, in `drain_streams_priority_ordered` →
   `drain_streams_inner` → `Stream::poll_send` → `send_app_data`, and `poll_send`
   **retains** the segment: it iterates `send_buffer` with `iter_mut`, sets
   `sent_at`, and returns a *clone* — it removes nothing. If `send_app_data` fails,
   the drain hands the segment back with `Stream::mark_unsent`. Only
   `Stream::on_sack()` retires a segment — the SACK-driven retire the pump drives;
   `Stream::ack()` survives but is test-only. So a cancel anywhere in that chain
   leaves the reliable segment in the buffer, and it is re-offered on the next drain
   (after RTO).

   - *Teardown-only residue.* `try_send_reliable` (and its FIN twin `try_queue_fin`)
     assigns the stream offset and forgets the permit *before* awaiting the buffer
     lock. A cancel landing on that await would burn one reliable offset and one
     permit on a stream whose pump is being torn down with the runtime — there is no
     later drain for the gap to stall. Not reachable while the pump runs, because the
     pump is not aborted (point 1).

   `pace_send` itself no longer exists. Pacing is not a wait taken on the send path at
   all: `drain_streams_priority_ordered` asks the pacer whether it may send, and when
   the answer is no it **returns** `DrainStop::Paced(delay)`. The pump turns that into a
   deadline for its own `sleep_until` *branch* (above), so the wait is a cancel-safe
   timer in the `select!` rather than an await inside an arm body. That is a scheduling
   fix as much as a cancel-safety one — a sleep inside the drain parks the whole pump,
   which is how a saturating upload used to starve the download's flow-control credit —
   but it also removes the last place a payload could be sitting mid-await for a pacing
   reason. The one surviving inline pacing wait is in `drain_streams_fully`, which runs
   only from `finish_and_announce` inside the `Close` / `None` arm bodies, after the
   pump has decided to exit and immediately before the `break`; there is no later loop
   iteration left to starve, each wait is capped at `CLOSE_FLUSH_PACING_WAIT_MAX`
   (2 ms), and the flush stops after `DRAIN_MAX_PASSES_ON_CLOSE` passes.

   The remaining inline wait on the send path is `apply_send_jitter`, called from
   `send_app_data`: the opt-in anti-fingerprint timing perturbation (default off, so
   zero-cost unless a session asks for it). It sits in the same place `pace_send` did
   and inherits the same argument: the reliable segment it delays is retained in the
   send buffer, so a teardown cancel re-offers it rather than losing it.
   - *Unreliable* data (`poll_send`'s `unreliable_buffer.pop_front()`) **is** removed
     before `send_app_data`, so a teardown cancel drops it — which is the fire-and-
     forget contract, and only at teardown.
   - The `CloseStream` arm queues a `Deferred::Fin` behind the stream's earlier writes
     and admits it through `flush_deferred_sends` / `Stream::try_queue_fin` as a
     zero-length reliable sentinel, retained and retransmitted like data. Only on
     reliable-offset exhaustion does `flush_deferred_sends` fall back to a bare
     `ENCRYPTED` FIN through `send_app_data`; a teardown cancel there drops a control
     FIN on a stream already being torn down — benign.
   - `finish_and_announce` ends with `announce_close`, which sends the WIRE v8
     `CLOSE` frame `CLOSE_FRAME_COPIES` (3) times. A teardown cancel part-way through
     loses some copies; nothing waits for their acknowledgement anyway, and a peer
     that hears none falls back to its liveness timer, exactly as before WIRE v8.

3. **The `Migrate` / `MigrateServer` arms await `transport.migrate(..)` /
   `transport.migrate_server(..)`** (the two `SessionCommand` arms of the command
   branch in `run_data_pump`). A teardown cancel there abandons a socket rebind on a
   session that is being torn down anyway; the rebind is already best-effort (a
   failed rebind leaves the session on the old socket by design), and the path-id /
   outbound-CID rotation that follows it is synchronous, so a cancel can never leave
   the session half-migrated with a rotated CID on an un-rebound socket. The tick arm
   additionally awaits `flush_deferred_sends` (above), `flush_pending_window_updates`,
   `maybe_send_keepalive` and `maybe_send_cover` — encrypted control frames whose loss
   is equivalent to a network drop; a `WINDOW_UPDATE` carries the cumulative limit
   (WIRE v7), so the next one repairs a lost one.

**Verdict:** ✅ cancel-safe. The pump is non-cancellable in normal operation, and the
admission queue plus the retained reliable buffer mean even teardown cancellation
cannot strand acknowledged-delivery data.

### `api/listener.rs::PhantomListener::accept` + the H4 acceptor task

H4 decoupled the accept path into three `select!`s: `accept()` itself only
drains completed handshakes, a background acceptor task owns the
`TcpListener`, and each handshake runs under its own deadline.

```rust
// api/listener.rs::PhantomListener::accept — H4 decoupled accept
let mut rx = self.accepted_rx.lock().await;
let shutdown_fut = self.shutdown_notify.notified();
tokio::pin!(shutdown_fut);
tokio::select! {
    biased;
    _ = &mut shutdown_fut => Err(CoreError::ConnectionClosed),
    item = rx.recv()      => item.ok_or(CoreError::ConnectionClosed),
}

// api/listener.rs::run_acceptor — background acceptor task (owns the TcpListener)
let (stream, peer) = tokio::select! {
    biased;
    _   = &mut shutdown_fut => break,
    res = listener.accept() => match res { Ok(pair) => pair, Err(_) => continue },
};

// api/listener.rs::serve_connection — per-handshake deadline
// (the PhantomUDP twin is api/udp_listener.rs::spawn_handshake_task)
tokio::select! {
    r = &mut hs_fut => r,
    _ = deadline    => Err(CoreError::Timeout),
}
```

- `mpsc::Receiver::recv()` (the `accept()` arm): **cancel-safe** — a dropped
  `recv` does not consume a queued `AcceptOutcome`.
- `TcpListener::accept()` (the acceptor-task arm): **NOT inherently
  cancel-safe** by the tokio documentation — but the failure mode is "an inbound
  connection was accepted at the OS layer and we drop the `TcpStream` on the
  floor", and the only things that cancel it are the shutdown arm,
  `PhantomListener::shutdown()` and `Drop for PhantomListener`, both of which abort
  the acceptor handle. That's a benign leak: the client sees a closed socket and
  retries. No corruption of listener state. The same holds for the one await after
  the `select!`, the in-flight-handshake permit (`acquire_owned().await` on
  `MAX_INFLIGHT_HANDSHAKES`): an abort there drops the just-accepted socket.
- `Notify::notified()`: **cancel-safe** when pinned. Both sites pin it and
  `&mut` it for the select to permit re-polling — the standard tokio pattern.
- The handshake-deadline `select!` in `serve_connection` is over a pinned
  `drive_server_handshake` future vs a `Runtime::sleep(HANDSHAKE_DEADLINE)`; a
  timeout drops the handshake future before any `Session` is installed or queued,
  so no session state is stranded. A listener in mimicry mode (feature `mimicry`,
  an SNI configured) first runs `MimicTlsLeg::accept` (below) in the same
  per-connection task, under its own deadline.

**Verdict:** ✅ acceptable. A `Notify` fired the same tick as a TCP
accept loses at most one socket; clients reconnect.

### The receive task in `run_data_pump`

```rust
// api/session.rs::run_data_pump — the receive task (`recv_handle`)
loop {
    // backlog cap check (synchronous)
    let data = match transport_recv.recv_bytes().await { Ok(b) => b, Err(_) => break };
    // frame-size gate, parse_protected, WIRE_VERSION gate (all synchronous)
    handle_packet(packet, ..).await;
    // WIRE v8: on a recorded peer close, publish Draining, take the drain
    // deadline once, and `break` when it has passed (all synchronous)
}
drop(deliver_tx);
let _ = recv_done_tx.send(());
```

- No `select!` here. The loop awaits the next transport read and then
  `handle_packet`; when the transport closes, `recv_bytes` returns `Err` and the
  loop breaks cleanly.
- `handle_packet` awaits in two kinds of place: tokio `Mutex` acquisitions on a
  stream's buffers (`Stream::on_sack`, `Stream::accept_in_order`,
  `Stream::received_sack`, `Stream::is_fin_acked`), and best-effort transport sends
  of the replies a packet can call for (the SACK acknowledgement, the keep-alive
  PONG through `send_keepalive`, the path-validation echo through
  `send_path_validation`, and a `PATH_CHALLENGE` to a migration candidate through
  `send_to_candidate`). Each of those stream methods awaits only its lock
  acquisition and then runs synchronously, so a cancel lands before any buffer is
  touched, never halfway through an update; a cancelled send is a lost control
  frame — for a challenge, one that `sweep_path_validation_timeouts` already
  expires when it goes unanswered.
- The only thing that aborts this task is `recv_handle.abort()` at the foot of
  `run_data_pump`, after the main loop has already exited. A cancel at
  `recv_bytes` loses at most one in-flight packet, and a cancel inside
  `handle_packet` loses that packet's processing or the reply it would have
  produced — both equivalent to a network drop, on a session that is ending.
- The observability wiring added per-packet recording inside `handle_packet` (the
  `record_send`/`record_recv`/`record_*_dropped` calls). These are
  synchronous, infallible atomic adds with no `.await`, so an abort cannot
  interrupt a half-finished metric update; a dropped in-flight packet simply
  isn't recorded.

**Verdict:** ✅ cancel-safe. Abort behaviour is a clean equivalent
of "transport closed mid-packet".

### Delivery pipeline (`run_data_pump` — three tasks)

A three-task pipeline replaced the single delivery task: a Router that
fans the reader's `DeliverItem`s into two *unbounded* channels, Task A for the
raw-app stream ids (0 / 1), and Task B for opened streams (id ≥ 2), so a stalled
opened-stream consumer cannot head-of-line-block raw-app delivery. All three are
spawned inside `run_data_pump` with their handles discarded (detached), and each
exits when its input channel closes; nothing aborts them.

```rust
// Router — both downstream channels are UNBOUNDED, so no .await on the send side
while let Some(item) = deliver_router_rx.recv().await { /* id <= 1 -> raw_tx_r, else streams_tx_r */ }

// Task A — raw-app (stream id 0/1)
while let Some((bytes, reliable)) = raw_deliver_rx.recv().await {
    undelivered_a.fetch_sub(delivery_charge(bytes.len()), AcqRel);  // synchronous
    // credit the stream's flow-control window: record_app_consumed +
    // stage_window_update_limit (synchronous)
    recv_tx_deliver.send(bytes).await;
}

// Task B — opened streams (id >= 2)
while let Some(item) = streams_deliver_rx.recv().await {
    undelivered_b.fetch_sub(delivery_charge(bytes.len()), AcqRel);  // synchronous
    // same flow-control credit (synchronous)
    demux_b.route_data_async(stream_id, bytes).await;  // or route_close_async
}
```

- `mpsc::Receiver::recv().await` in all three tasks: **cancel-safe** — a dropped
  `recv` does not consume a queued item; the next poll observes it.
- The Router never awaits a send (both targets are unbounded), so it cannot be
  torn mid-dispatch.
- The backlog and flow-control accounting between the two awaits in Tasks A and B
  is **synchronous**, and `undelivered_bytes` is decremented *before* the blocking
  downstream send, so a cancel can drop an item but can never double-count. The
  `streams.get(..)` guard taken for the flow-control credit is dropped at the end of
  its `if let`, before the downstream `.await` — no DashMap shard lock is held across
  it.
- `recv_tx_deliver.send(bytes).await` / `route_data_async(..).await`:
  **cancel-safe** — a dropped `send` does not lose the item; the value stays
  owned by the future and is re-offered on the next poll (or dropped wholesale
  with the task at teardown). `StreamDemultiplexer::route_data_async` clones the
  per-stream sender out of its `DashMap` before awaiting, for the same reason.

**Verdict:** ✅ cancel-safe. Every await is over a cancel-safe mpsc primitive;
the synchronous bookkeeping between them cannot be torn mid-update.

### `api/session.rs::PhantomSession::background_task` handshake deadline

```rust
// api/session.rs::PhantomSession::background_task — HS-02 client handshake deadline
let handshake_fut = run_client_handshake(&transport, &expected_server_key, resumption_request);
let handshake_timeout = runtime.sleep(CLIENT_HANDSHAKE_DEADLINE);
tokio::pin!(handshake_fut);
tokio::select! {
    r = &mut handshake_fut => r,
    _ = handshake_timeout  => Err(CoreError::Timeout),
}

// api/session.rs::run_client_handshake — no select!; sequential send -> recv
loop {
    let bytes = borsh::to_vec(&hello)?;
    transport.send_bytes(&bytes).await?;
    loop {
        let resp = match transport.recv_bytes().await { .. };
        // ServerHello -> Ok; HelloRetryRequest -> update cookie / PoW and
        // break to re-send; ServerReject or a malformed reply -> Err
    }
}
```

- One `select!` (HS-02): the pinned `run_client_handshake` future raced against a
  10 s `runtime.sleep(CLIENT_HANDSHAKE_DEADLINE)`. Both arms are cancel-safe (a
  pinned future is re-polled; a dropped `sleep` advances nothing), and a deadline
  win drops the handshake future before any `Session` is installed — the client
  stores `CoreError::Timeout` in `terminal_error` and flips to `Failed`.
- Inside the handshake future itself there is no `select!` — sequential
  send → recv. If it is dropped mid-`recv_bytes`, the handshake fails cleanly —
  partial bytes already sent to the peer are harmless (the peer either receives a
  complete `ClientHello` or rejects partial bytes via borsh deserialisation). On
  PhantomUDP, dropping it also drops the `recv_bytes` future's local
  retransmission schedule; nothing re-enters it, because the connect has failed.

**Verdict:** ✅ cancel-safe.

### `transport/legs/mimic_tls/leg.rs::MimicTlsLeg::connect` / `MimicTlsLeg::accept`

The optional anti-DPI mimicry leg's prelude (a TLS-1.3-shaped record
exchange that precedes the real Phantom handshake — anti-fingerprinting
obfuscation only, not confidentiality). Both `MimicTlsLeg::connect` and
`MimicTlsLeg::accept` are straight-line `write_all` / `flush` /
`read_one_record` (which loops on `reader.read(..).await`); no `select!`.
The whole prelude future is wrapped in a single `tokio::time::timeout`
(`PRELUDE_DEADLINE`), which is itself cancel-safe — a dropped `timeout`
future advances no state. On a failed or timed-out prelude, `accept` then drains
the read half through `black_hole` under a second `tokio::time::timeout` sized to
what is left of the same deadline, and writes nothing. Cancel mid-`.await` leaves
the TCP connection in a state where the next attempt resets; the inner Phantom
session has not yet been established, so no session state can be stranded.

**Verdict:** ✅ cancel-safe.

### `transport/stream.rs::Stream::poll_send` (non-blocking)

The fixed-500 ms-timer `poll_send` the original audit described is gone (the loss-recovery
rework replaced it with an RFC 6298 RTO + a BBR congestion window). `poll_send` is now a
**non-blocking** poll: it briefly locks `unreliable_buffer` then `send_buffer`
(`Mutex::lock().await`, released before return), scans for a flagged loss, a
timed-out segment (retransmit) or the next in-window unsent segment, and returns
`Result<OutboundSegment, SendBlocked>` immediately — no inner notifier/timeout
await.

Admission on the pump's path is non-blocking as well: `Stream::try_send_reliable`
and `Stream::try_queue_fin` take a permit with `Semaphore::try_acquire` and report
a full buffer instead of waiting (see the pump section for the one await they do
take). The blocking `Stream::send_reliable` / `Stream::queue_fin` still exist and
wait on `tokio::sync::Semaphore::acquire().await`, which is cancel-safe (a dropped
acquire does not consume a permit; `permit.forget()` runs only after a successful
acquire); inside the crate they are reached only from tests.

**Verdict:** ✅ cancel-safe. No `.await` holds a buffer lock; the only blocking await
(`Semaphore::acquire`) is cancel-safe and off the pump's path.

### `api/udp_transport.rs::UdpClientTransport::recv_bytes` (3 `select!`s)

The production transport's receive path picks one of three `select!`s per loop
iteration, depending on phase. Both sockets are snapshotted as owned `Arc`s at
the top of the loop — **no `ArcSwap` guard is ever held across an `.await`**
(the migration recv-hang class).

```rust
// api/udp_transport.rs::UdpClientTransport::recv_bytes — in-handshake: recv vs RTO retransmit
tokio::select! {
    biased;
    r = active.recv_from(&mut buf)            => { /* got a datagram */ }
    _ = tokio::time::sleep_until(deadline)    => { /* advance the schedule, retransmit last_sent, continue */ }
}

// api/udp_transport.rs::UdpClientTransport::recv_bytes — migration overlap: new socket vs retained old vs migrate wake
tokio::select! {
    r = active.recv_from(&mut buf)            => { /* from_prev = false */ }
    r = prev_sock.recv_from(&mut buf_prev)    => { /* from_prev = true  */ }
    _ = migrate_notified                      => { continue /* re-snapshot sockets */ }
}

// api/udp_transport.rs::UdpClientTransport::recv_bytes — steady state: recv vs migrate wake
tokio::select! {
    biased;
    r = active.recv_from(&mut buf)            => { /* got a datagram */ }
    _ = migrate_notified                      => { continue /* re-snapshot sockets */ }
}
```

- `UdpSocket::recv_from`: **cancel-safe** — a dropped read consumes no datagram.
  The `biased;` ordering on the first and third sites is load-bearing for *RTO /
  wake correctness*, not for cancel-safety (an unbiased select starves the recv
  arm ~50 % of the time when both are ready, causing spurious handshake
  retransmits).
- `tokio::time::sleep_until`: **cancel-safe** — a dropped sleep advances nothing.
  Cancel-safety alone is not enough here, though: the loop re-enters this select
  on every datagram that does not complete a frame, and a timer built from a
  *length* would restart its interval each time, so an off-path source could hold
  the read open for as long as it kept sending. The deadline is an absolute
  instant (`retransmit_at`) computed once and carried across the loop's `continue`
  paths; the schedule (`attempt`, `spent`) is advanced only by an expiry that
  actually elapsed. Nothing an inbound datagram does extends the read.
- The timer arm's body advances that schedule synchronously and then awaits the
  retransmission itself (the `last_sent` lock, one `send_to` per retained
  datagram). A cancel there loses part of one retransmitted flight. The only things
  that drop a `recv_bytes` future are the client handshake deadline in
  `PhantomSession::background_task` (the connect then fails) and the pump's teardown
  abort of its receive task; neither re-enters it.
- `Notify::notified()` (`migrate_notify`): created fresh per iteration and not
  pinned, which is safe here because `UdpClientTransport::migrate_to` calls
  `notify_one`, whose stored permit survives — a migration raised while this task
  is inside another arm is observed by the next iteration's fresh `notified()`.
  That is the whole point of the arm: it exists to force a re-snapshot after
  `migrate_to()`'s two `ArcSwap` stores, so missing it would hang recv on a stale
  socket.
- The winning buffer is recorded as `(n, from_prev, src)` and sliced *after* the
  select, so the losing arm's `&mut buf` borrow is released before any use — a
  cancelled recv leaves both buffers untouched.

**Verdict:** ✅ cancel-safe. A cancelled arm at worst loses one in-flight
datagram, which is indistinguishable from a network drop and is recovered by the
ARQ / handshake-RTO paths.

### `api/udp_listener.rs` — accept, the demux loop and the handshake task

```rust
// api/udp_listener.rs::PhantomUdpListener::accept — same shape as the TCP listener
tokio::select! {
    biased;
    _ = &mut shutdown_fut => Err(CoreError::ConnectionClosed),
    item = rx.recv()      => item.ok_or(CoreError::ConnectionClosed),
}

// api/udp_listener.rs::run_udp_demux — CID-window demux loop (7 arms, biased)
let (n, peer) = tokio::select! {
    biased;
    _ = &mut shutdown_fut                   => break,
    Some((cid, ip)) = reap_rx.recv()        => { /* release per-IP pending, reap dead route */ }
    Some(reg)       = register_rx.recv()    => { /* register a session's CID window; retain its reply flight */ }
    Some(slide)     = slide_rx.recv()       => { /* slide a session's inbound CID window */ }
    Some(owner)     = retire_rx.recv()      => { /* WIRE v8: retire an ended session's routes */ }
    _ = route_sweep.tick()                  => { /* reap dead routes; sweep expired reply flights */ }
    r = listener.socket.recv_from(&mut buf) => { /* route the datagram */ }
};

// api/udp_listener.rs::spawn_handshake_task — per-handshake deadline
// (same shape as api/listener.rs::serve_connection)
tokio::select! {
    r = &mut fut => r,
    _ = deadline => Err(CoreError::Timeout),
}
```

- `mpsc::Receiver::recv()` (the accept queue and all four demux control
  channels), `Interval::tick()` and `UdpSocket::recv_from`: **cancel-safe**;
  `Notify::notified()` is pinned at both shutdown sites. `route_sweep` uses
  `MissedTickBehavior::Delay`, so a demux that fell behind owes one sweep, not a
  burst of them.
- The demux is a single task, so its arms never race each other; the `biased;`
  order drains the reap / register / slide / retire channels and the sweep before
  reading more datagrams, which is a table-growth bound, not a cancel-safety
  property. `retire_rx` is bounded (`RETIRE_QUEUE_DEPTH`) where the other three
  control channels are not, and the `ROUTE_SWEEP_INTERVAL` tick is the reclaim path
  that does not depend on a signal arriving. Every arm body (`RouteTable` mutation,
  `FlightTable::retain` / `FlightTable::sweep`) is **synchronous**, so no route
  table can be observed half-updated.
- This task *is* externally abortable: `PhantomUdpListener::shutdown()` and
  `Drop for PhantomUdpListener` both `abort()` the demux handle in addition to
  firing the `Notify`. The loop body outside the `select!` has two awaits:
  `send_flight_repeat`, which re-sends a retained reply flight after
  `FlightTable::repeat` has decided, synchronously, to answer (PROTOCOL § 6.1),
  and `send_demux_retry`, the stateless `HelloRetryRequest` cookie demand sent
  when `HandshakeServer::udp_admit` returns `Retry`. Neither commits
  per-connection state — an abort there drops a repeat or a cookie demand, and the
  client repeats its `Initial`. Route-table insertion, the per-IP pending count,
  the first-frame `try_send` and the handshake-task spawn that follow them are all
  synchronous (`spawn_handshake_task` is a plain function that calls
  `Runtime::spawn`), so an abort cannot leave a route registered without its
  handshake task (or vice versa).
- Losing one in-flight datagram when the shutdown arm wins is equivalent to a
  network drop; the per-handshake deadline in `spawn_handshake_task` drops the
  handshake future before any `Session` is registered or queued.

**Verdict:** ✅ cancel-safe.

---

## Lock-across-await audit

A lock held across an `.await` blocks other tasks for the duration of
the entire awaited work — performance issue, not correctness — but
the `tokio::sync::Mutex` family is at least re-entrant-safe and
deadlock-free under cancellation (the lock is released on Drop).

Inventory of `&mut`-held locks across `.await`:

| Site | Lock | Holds across await | Risk |
| --- | --- | --- | --- |
| `api/session.rs::drain_streams_inner` (via `drain_streams_priority_ordered`) | DashMap (`streams`) | **no** — snapshotted into a sorted `Vec` before any `.await` (so no shard lock is held across `poll_send`/`send_app_data`) | None (good) |
| `api/session.rs::run_data_pump` (Task A / Task B flow-control credit) | DashMap (`streams`) | **no** — the `get` guard ends with its `if let`, before the downstream send is awaited | None (good) |
| `transport/stream.rs::Stream::poll_send` | tokio Mutex (`unreliable_buffer`, `send_buffer`) | brief — scan + mark `sent_at`, released before `send_app_data` runs | None |
| `transport/stream.rs::Stream::try_send_reliable` / `Stream::try_queue_fin` | tokio Semaphore (`try_acquire`) + tokio Mutex (`send_buffer`) | `try_acquire` never waits; the buffer lock is a single `push_back` | None |
| `transport/stream.rs::Stream::send_reliable` / `Stream::queue_fin` (test callers only) | tokio Semaphore + tokio Mutex (`send_buffer`) | acquire is cancel-safe; the buffer lock is a single `push_back` | None |
| `api/tcp_transport.rs::TcpSessionTransport::send_bytes` | tokio Mutex (write half) | yes — write + flush | Low: serialises sends, the intended semantics |
| `api/tcp_transport.rs::TcpSessionTransport::recv_bytes` | tokio Mutex (read half + accumulator) | yes — length + body read | Low: reads are sequential by construction |
| `api/listener.rs::PhantomListener::accept` | tokio Mutex (`accepted_rx`) | yes — across `rx.recv()` | Low: serialises concurrent `accept()` callers, the intended semantics; `mpsc::Receiver::recv` is cancel-safe and the lock releases on Drop |
| `api/udp_listener.rs::PhantomUdpListener::accept` | tokio Mutex (`accepted_rx`) | yes — across `rx.recv()` | Same shape as the TCP listener |
| `api/udp_transport.rs::UdpClientTransport::recv_bytes` | `ArcSwap` (active / prev socket) | **no** — both sockets are snapshotted as owned `Arc`s before every `select!` | None (good) — holding a guard here was the migration recv-hang class |
| `api/udp_transport.rs::UdpClientTransport::recv_bytes` (handshake timer arm) | tokio Mutex (`last_sent`) | yes — across the retransmit `send_to`s | Low: handshake phase only, one task reads it, and the lock releases on Drop |

No locks discovered that risk deadlock under cancellation. Note the drain path
deliberately snapshots `streams` (a `DashMap`) into a sorted `Vec` *before* awaiting
any send, so no DashMap shard lock is ever held across `send_app_data`'s
`send_bytes` await (or its opt-in `apply_send_jitter` sleep).

---

## Findings

- **Zero cancel-safety bugs identified** (re-confirmed post-Phase-4.4, and again at
  commit `e5b23d8b`). Every `select!` is over cancel-safe primitives; every
  long-held lock is on a tokio Mutex/Semaphore that releases on Drop; no DashMap
  shard lock is held across an await.
- **The 2026-06-01 re-run's headline concern is resolved, not merely tolerated.**
  `pace_send` no longer exists: pacing is a `select!` branch, and between the
  command channel and the retained send buffer a payload sits in a pump-owned queue
  rather than in a suspended future. (And the pump is, in any case, never aborted
  mid-`await` outside runtime teardown.)
- **One teardown-only residue, recorded rather than fixed:**
  `Stream::try_send_reliable` / `Stream::try_queue_fin` commit an offset and a
  permit before their buffer-lock await, so a runtime teardown landing on that
  await burns both on a stream that is going away. Nothing observes the gap.
- The `accept()` race (TCP socket accepted at the OS layer but dropped on shutdown —
  now inside the H4 acceptor task) remains acceptable: clients retry, and the
  listener's shutdown flag prevents subsequent `accept()` calls from blocking. The
  PhantomUDP demux has the same shape one layer down: a datagram lost to the shutdown
  arm is indistinguishable from a network drop.

## Sign-off

- Original audit at the commit that introduced this file; re-run 2026-06-01;
  code references re-derived and every `select!` re-matched for the 0.3.0
  release.
- Method: every `tokio::select!` in `core/src` matched against tokio's documented
  cancellation-safety guarantees, manual review of every `Mutex::lock().await` /
  `Semaphore::acquire().await` site in `core/src/api/` and `core/src/transport/`,
  plus a control-flow trace of the data pump's spawn/abort topology (detached spawn,
  a `Drop for PhantomSession` that only raises the graceful close request, single
  self-`abort` of the receive subtask), covering the receive task and the
  three-task delivery pipeline.
- **Re-run trigger (Phase 4.4 — BBR congestion control, the loss-recovery rework
  and the observability wiring) discharged.** Re-run again if a future change (a) gives the
  pump task an externally-held abort handle, (b) introduces any sleep *before* a
  payload is held in the pump-owned admission queue or a retained (reliable)
  buffer, or (c) adds, moves or removes a `tokio::select!` — the index at the top
  has to name every production site.
