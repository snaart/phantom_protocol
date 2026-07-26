# Async cancel-safety audit (Phase 2.13; re-run 2026-06-01)

> **Re-run note (2026-06-01).** The original audit was signed off at Phase 2.13
> and scheduled a re-run "after Phase 4.4." That landed, and the data pump was
> materially rewritten — the loss-recovery rework (route `send()` through a
> per-stream reliable buffer + BBR-paced drain) and the observability wiring (a
> `session_opened` / `session_closed` gauge + `ObservedTransport`). The `run_data_pump` main-loop
> section below is rewritten for the current 4-arm `select!`; the headline
> concern raised for the re-run — a `pace_send` sleep stranding already-dequeued
> data on cancel — was **resolved by the same loss-recovery rework that
> introduced pacing** (see that section). Verdict stands: ✅ cancel-safe, no code change.

A `select!` arm that fires before its sibling completes effectively
**cancels** the unfinished future. If that future was carrying
state mid-await — half-consumed bytes from a stream, an unposted
ACK, a partially-allocated resource — cancellation can leave the
session in an inconsistent state.

This document inventories every `tokio::select!` and every long-held
`.await` in `phantom_protocol` and confirms whether the pattern is
cancel-safe by tokio's stated guarantees.

Methodology: every `tokio::select!` in `core/src` was matched against
tokio's [cancellation-safety cheatsheet](https://docs.rs/tokio/latest/tokio/macro.select.html#cancellation-safety)
and reviewed for the "what if the other arm fires first"
scenario. `grep -rn 'tokio::select!' core/src` currently returns 13
invocations: the 11 production sites inventoried below, plus two inside
`api/udp_transport.rs`'s `#[cfg(test)] mod tests` (out of scope).

---

## Inventory

### `api/session.rs::run_data_pump` main loop (current, 4-arm)

```rust
tokio::select! {
    _ = poll_interval.tick()       => { drain_streams_priority_ordered(..).await }
    _ = send_notify.notified()     => { drain_streams_priority_ordered(..).await }  // fast-wake
    cmd_opt = cmd_rx.recv()        => { match cmd { Send | SendStream{Reliable,Unreliable}
                                                   | SetStreamPriority | CloseStream
                                                   | Migrate | MigrateServer | Close } }
    _ = &mut recv_done_rx          => { /* recv task ended -> break */ }
}
```

**Primitive cancel-safety (the four arms):**
- `tokio::time::Interval::tick()`: **cancel-safe** — dropping the future does not
  advance the timer.
- `tokio::sync::Notify::notified()`: created fresh each iteration (not pinned).
  This is safe here because `Session::notify_outbound_ready()` calls `notify_one`,
  whose **stored permit** survives across loop iterations — a notification raised
  while the pump is busy in another arm is observed by the next iteration's fresh
  `notified()`. The rare register-then-drop window can at worst *delay* a wake, and
  the 10 ms `poll_interval.tick()` is an explicit fallback that drains regardless,
  so a missed notification costs ≤ 10 ms of latency, never data.
- `tokio::sync::mpsc::Receiver::recv()`: **cancel-safe** — a dropped `recv` does not
  consume a queued message.
- `tokio::sync::oneshot::Receiver` (`&mut recv_done_rx`): **cancel-safe** — polling
  does not consume the value.

**The arm *bodies* contain `.await`s — is that a strand risk?** A `select!` arm,
once chosen, runs its body to completion *unless the whole task is cancelled*. The
bodies do await (`drain_streams...`, `raw_stream.send_reliable`, and — in the
`CloseStream` arm — `send_app_data` for the FIN). So the question is **whether the
pump task can be cancelled mid-body**, and **what is lost if it is**.

1. **The pump is never aborted mid-`await` in normal operation.** Both spawn sites
   detach the handle (`let _detached = runtime.spawn(run_data_pump ...)` on the
   server; the client awaits it inside an equally-detached `background_task`).
   `Drop for PhantomSession` (`api/session.rs:3705`) only best-effort `try_send`s a
   graceful `SessionCommand::Close` — it never aborts the pump task — and the only
   production `.abort()` in the module is the pump aborting *its own* recv subtask
   during teardown (`recv_handle.abort()`, `api/session.rs:1776`). The
   pump exits exclusively through the loop `break` (a graceful `SessionCommand::Close`
   from `disconnect()`, the `None` channel-closed arm, or `recv_done`). The *only* way
   an arm body is cancelled is the **runtime/process being torn down**, where losing
   in-flight bytes is expected and harmless.

2. **Even under that teardown cancel, reliable data is not stranded** — this is what
   resolves the re-run's headline concern. The concern was: `SessionCommand::Send →
   send_app_data → pace_send().await` consumes the payload from the mpsc channel and
   then sleeps, so an abort during the sleep silently drops a payload the channel had
   already handed out. **The loss-recovery rework removed that path.** The `Send` arm now copies the
   payload into the per-stream **reliable send buffer** (`raw_stream.send_reliable`)
   and returns; `pace_send` no longer runs in the command arm at all. The actual paced
   transmission happens later in `drain_streams_priority_ordered → Stream::poll_send →
   send_app_data → pace_send`, and `poll_send` **retains** the segment (it iterates
   `send_buffer` with `iter_mut`, sets `sent_at`, and returns a *clone* — it removes
   nothing; only `Stream::on_sack()` retires a segment — the SACK-driven retire the pump
   drives at `api/session.rs:2746`; `Stream::ack()` survives but is test-only). So a
   cancel during `pace_send` leaves the reliable segment in the buffer; it is re-offered
   on the next drain (after RTO).
   The payload is decoupled from the channel before any sleep — pacing happens on
   buffered, retained data, exactly the "restructure so pacing happens before the value
   leaves the channel" the re-run asked for.
   - *Unreliable* data (`poll_send`'s `unreliable_buffer.pop_front()`) **is** removed
     before `send_app_data`, so a teardown cancel drops it — which is the fire-and-
     forget contract, and only at teardown.
   - The `CloseStream` arm awaits `send_app_data` for a FIN; a teardown cancel there
     drops a control FIN on a stream already being torn down — benign.

3. **The `Migrate` / `MigrateServer` arms await `transport.migrate(..)` /
   `migrate_server(..)`** (`api/session.rs:1669`, `:1707`). A teardown cancel there
   abandons a socket rebind on a session that is being torn down anyway; the rebind is
   already best-effort (a failed rebind leaves the session on the old socket by
   design), and the path-id / outbound-CID rotation that follows it is synchronous, so
   a cancel can never leave the session half-migrated with a rotated CID on an
   un-rebound socket. The tick arm additionally awaits `flush_pending_window_updates`,
   `maybe_send_keepalive` and `maybe_send_cover` — encrypted control frames whose loss
   is equivalent to a network drop.

**Verdict:** ✅ cancel-safe. The pump is non-cancellable in normal operation, and the
reliable-buffer decoupling of the loss-recovery rework means even teardown cancellation cannot strand
acknowledged-delivery data.

### `api/listener.rs::accept` + the H4 acceptor task

H4 decoupled the accept path into three `select!`s: `accept()` itself only
drains completed handshakes, a background acceptor task owns the
`TcpListener`, and each handshake runs under its own deadline.

```rust
// api/listener.rs:371 — PhantomListener::accept (H4 decoupled accept)
let mut rx = self.accepted_rx.lock().await;
let shutdown_fut = self.shutdown_notify.notified();
tokio::pin!(shutdown_fut);
tokio::select! {
    biased;
    _ = &mut shutdown_fut => Err(CoreError::ConnectionClosed),
    item = rx.recv()      => item.ok_or(CoreError::ConnectionClosed),
}

// api/listener.rs:662 — background acceptor task (owns the TcpListener)
tokio::select! {
    biased;
    _   = &mut shutdown_fut => break,
    res = listener.accept() => { /* take new TCP */ }
}

// api/listener.rs:761 — per-handshake deadline (also udp_listener.rs:662)
tokio::select! {
    r = &mut hs_fut => r,
    _ = deadline    => Err(CoreError::Timeout),
}
```

- `mpsc::Receiver::recv()` (the `accept()` arm): **cancel-safe** — a dropped
  `recv` does not consume a queued `AcceptOutcome`.
- `TcpListener::accept()` (now the acceptor-task arm): **NOT inherently
  cancel-safe** by the tokio cookbook — but the failure mode is "an inbound
  connection was accepted at the OS layer and we drop the `TcpStream` on the
  floor", and the only things that cancel it are the shutdown arm and
  `Drop for PhantomListener` (`api/listener.rs:806`), which aborts the acceptor
  handle. That's a benign leak: the client sees a closed socket and retries. No
  corruption of listener state.
- `Notify::notified()`: **cancel-safe** when pinned. Both sites pin it and
  `&mut` it for the select to permit re-polling — the standard tokio pattern.
- The handshake-deadline `select!` is over a pinned `drive_server_handshake`
  future vs a `Runtime::sleep`; a timeout drops the handshake future before
  any `Session` is installed or queued, so no session state is stranded.

**Verdict:** ✅ acceptable. A `Notify` fired the same tick as a TCP
accept loses at most one socket; clients reconnect.

### Inner recv task in `run_data_pump`

```rust
loop {
    let data = match transport_recv.recv_bytes().await { ... };
    // ...PhantomPacket::from_wire, decrypt, route...
}
```

- No `select!` here. The loop awaits the next transport read; when the
  transport closes, `recv_bytes` returns `Err` and the loop breaks
  cleanly. A `recv_handle.abort()` from the outer loop cancels at the
  `.await` point — at worst we lose one in-flight packet, equivalent
  to a network drop.
- The observability wiring added per-packet recording inside `handle_packet` (the
  `record_send`/`record_recv`/`record_*_dropped` calls). These are
  synchronous, infallible atomic adds with no `.await`, so an abort at the
  `recv_bytes().await` point cannot interrupt a half-finished metric update;
  a dropped in-flight packet simply isn't recorded.

**Verdict:** ✅ cancel-safe. Abort behaviour is a clean equivalent
of "transport closed mid-packet".

### Delivery pipeline (`run_data_pump` — three tasks)

A three-task pipeline replaced the single delivery task: a Router that
fans the reader's `DeliverItem`s into two *unbounded* channels, Task A for the
raw-app stream ids (0 / 1), and Task B for opened streams (id ≥ 2), so a stalled
opened-stream consumer cannot head-of-line-block raw-app delivery.

```rust
// Router (api/session.rs:1352) — both downstream channels are UNBOUNDED, so no .await
while let Some(item) = deliver_router_rx.recv().await { /* id<=1 -> raw_tx_r, else streams_tx_r */ }

// Task A (api/session.rs:1279) — raw-app (stream id 0/1)
while let Some(bytes) = raw_deliver_rx.recv().await {
    undelivered_a.fetch_sub(len, AcqRel);   // synchronous
    recv_tx_deliver.send(bytes).await;      // line 1293
}

// Task B (api/session.rs:1307) — opened streams (id >= 2)
while let Some(item) = streams_deliver_rx.recv().await {
    undelivered_b.fetch_sub(len, AcqRel);   // synchronous
    demux_b.route_data_async(stream_id, bytes).await;  // or route_close_async
}
```

- `mpsc::Receiver::recv().await` in all three tasks: **cancel-safe** — a dropped
  `recv` does not consume a queued item; the next poll observes it.
- The Router never awaits a send (both targets are unbounded), so it cannot be
  torn mid-dispatch.
- The flow-control credit accounting between the two awaits in Tasks A and B is
  **synchronous**, and `undelivered_bytes` is decremented *before* the blocking
  downstream send, so a cancel can drop an item but can never double-count.
- `recv_tx_deliver.send(bytes).await` / `route_data_async(..).await`:
  **cancel-safe** — a dropped `send` does not lose the item; the value stays
  owned by the future and is re-offered on the next poll (or dropped wholesale
  with the task at teardown).

**Verdict:** ✅ cancel-safe. Every await is over a cancel-safe mpsc primitive;
the synchronous bookkeeping between them cannot be torn mid-update.

### `api/session.rs::background_task` handshake loop

```rust
let server_hello = loop {
    let hello_bytes = match borsh::to_vec(&hello) { ... };
    if let Err(e) = transport.send_bytes(&hello_bytes).await { ... }
    let resp_bytes = match transport.recv_bytes().await { ... };
    /* parse / retry */
};
```

- One `select!` (HS-02, `api/session.rs:874`): the pinned
  `run_client_handshake` future raced against a 10 s
  `runtime.sleep(CLIENT_HANDSHAKE_DEADLINE)`. Both arms are cancel-safe (a
  pinned future is re-polled; a dropped `sleep` advances nothing), and a
  deadline win drops the handshake future before any `Session` is installed —
  the client stores `CoreError::Timeout` in `terminal_error` and flips to
  `Failed`. Inside the handshake future itself there is no `select!` —
  sequential send → recv. If the calling task is
  cancelled mid-`recv_bytes`, the handshake fails cleanly — partial
  bytes already sent to the peer are harmless (the peer either
  receives a complete `ClientHello` or rejects partial bytes via
  borsh deserialisation).

**Verdict:** ✅ cancel-safe.

### `transport/legs/mimic_tls/leg.rs::connect` / `accept`

The optional anti-DPI mimicry leg's prelude (a TLS-1.3-shaped record
exchange that precedes the real Phantom handshake — anti-fingerprinting
obfuscation only, not confidentiality). Both `MimicTlsLeg::connect` and
`MimicTlsLeg::accept` are straight-line `write_all` / `flush` /
`read_one_record` (which loops on `reader.read(..).await`); no `select!`.
The whole prelude future is wrapped in a single `tokio::time::timeout`
(`PRELUDE_DEADLINE`), which is itself cancel-safe — a dropped `timeout`
future advances no state. Cancel mid-`.await` leaves the TCP connection
in a state where the next attempt resets; the inner Phantom session has
not yet been established, so no session state can be stranded.

**Verdict:** ✅ cancel-safe.

### `transport/stream.rs::poll_send` (current — non-blocking)

The fixed-500 ms-timer `poll_send` the original audit described is gone (the loss-recovery
rework replaced it with an RFC 6298 RTO + a BBR congestion window). `poll_send` is now a
**non-blocking** poll: it briefly locks `unreliable_buffer` then `send_buffer`
(`Mutex::lock().await`, released before return), scans for a timed-out segment
(retransmit) or the next in-window unsent segment, and returns `Option` immediately
— no inner notifier/timeout await. `send_reliable`'s backpressure is a
`tokio::sync::Semaphore::acquire().await`, which is cancel-safe (a dropped acquire
does not consume a permit; `permit.forget()` runs only after a successful acquire).

**Verdict:** ✅ cancel-safe. No `.await` holds a buffer lock; the only blocking await
(`Semaphore::acquire`) is cancel-safe.

### `api/udp_transport.rs::recv_bytes` (PhantomUDP client — 3 `select!`s)

The production transport's receive path picks one of three `select!`s per loop
iteration, depending on phase. Both sockets are snapshotted as owned `Arc`s at
the top of the loop — **no `ArcSwap` guard is ever held across an `.await`**
(the migration recv-hang class).

```rust
// api/udp_transport.rs:289 — in-handshake: recv vs RTO retransmit
tokio::select! {
    biased;
    r = active.recv_from(&mut buf)            => { /* got a datagram */ }
    _ = tokio::time::sleep(HANDSHAKE_RTO)     => { /* retransmit last_sent, continue */ }
}

// api/udp_transport.rs:332 — migration overlap: new socket vs retained old vs migrate wake
tokio::select! {
    r = active.recv_from(&mut buf)            => { /* from_prev = false */ }
    r = prev_sock.recv_from(&mut buf_prev)    => { /* from_prev = true  */ }
    _ = migrate_notified                      => { continue /* re-snapshot sockets */ }
}

// api/udp_transport.rs:361 — steady state: recv vs migrate wake
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
- `tokio::time::sleep`: **cancel-safe** — a dropped sleep advances nothing; the
  RTO budget (`retx`) lives outside the select and is reset on progress.
- `Notify::notified()` (`migrate_notify`): created fresh per iteration and not
  pinned, which is safe here because `migrate_to()` calls `notify_one`, whose
  stored permit survives — a migration raised while this task is inside another
  arm is observed by the next iteration's fresh `notified()`. That is the whole
  point of the arm: it exists to force a re-snapshot after `migrate_to()`'s two
  `ArcSwap` stores, so missing it would hang recv on a stale socket.
- The winning buffer is recorded as `(n, from_prev, src)` and sliced *after* the
  select, so the losing arm's `&mut buf` borrow is released before any use — a
  cancelled recv leaves both buffers untouched.

**Verdict:** ✅ cancel-safe. A cancelled arm at worst loses one in-flight
datagram, which is indistinguishable from a network drop and is recovered by the
ARQ / handshake-RTO paths.

### `api/udp_listener.rs` — `accept` + the demux loop

```rust
// api/udp_listener.rs:270 — PhantomUdpListener::accept (same shape as the TCP listener)
tokio::select! {
    biased;
    _ = &mut shutdown_fut => Err(CoreError::ConnectionClosed),
    item = rx.recv()      => item.ok_or(CoreError::ConnectionClosed),
}

// api/udp_listener.rs:494 — CID-window demux loop (5 arms, biased)
tokio::select! {
    biased;
    _ = &mut shutdown_fut                 => break,
    Some((cid, ip)) = reap_rx.recv()      => { /* release per-IP pending, reap dead route */ }
    Some((cids, tx)) = register_rx.recv() => { /* register a session's CID window */ }
    Some(slide)     = slide_rx.recv()     => { /* slide a session's inbound CID window */ }
    r = listener.socket.recv_from(&mut buf) => { /* route the datagram */ }
}

// api/udp_listener.rs:662 — per-handshake deadline (same shape as api/listener.rs:761)
tokio::select! {
    r = &mut fut => r,
    _ = deadline => Err(CoreError::Timeout),
}
```

- `mpsc::Receiver::recv()` (the accept queue and all three demux control
  channels) and `UdpSocket::recv_from`: **cancel-safe**; `Notify::notified()` is
  pinned at both shutdown sites.
- The demux is a single task, so its arms never race each other; the `biased;`
  order drains the reap / register / slide channels before reading more
  datagrams, which is a table-growth bound, not a cancel-safety property. Every
  arm body (`RouteTable` mutation, `try_send` into a session's inbound channel)
  is **synchronous**, so no route table can be observed half-updated.
- This task *is* externally abortable: `shutdown()` (`api/udp_listener.rs:283`)
  and `Drop for PhantomUdpListener` (`:302`) both `abort()` the demux handle in
  addition to firing the `Notify`. The only `.await` in the loop body outside
  the select is `send_demux_retry` (the
  stateless `HelloRetryRequest` cookie demand, `:560`), which commits no
  per-connection state — an abort there drops a cookie demand and the client
  retransmits its `Initial`. Route-table insertion, the per-IP pending count and
  the handshake-task spawn that follow it are all synchronous, so an abort cannot
  leave a route registered without its handshake task (or vice versa).
- Losing one in-flight datagram when the shutdown arm wins is equivalent to a
  network drop; the per-handshake deadline drops the handshake future before any
  `Session` is registered or queued.

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
| `api/session.rs::drain_streams_priority_ordered` | DashMap (`streams`) | **no** — snapshotted into a `Vec` before any `.await` (so no shard lock is held across `poll_send`/`send_app_data`) | None (good) |
| `transport/stream.rs::poll_send` | tokio Mutex (`unreliable_buffer`, `send_buffer`) | brief — scan + mark `sent_at`, released before `send_app_data` runs | None |
| `transport/stream.rs::send_reliable` | tokio Semaphore + tokio Mutex (`send_buffer`) | acquire is cancel-safe; the buffer lock is a single `push_back` | None |
| `api/tcp_transport.rs::send_bytes` | tokio Mutex (writer) | yes — write + flush | Low: serialises sends, the intended semantics |
| `api/tcp_transport.rs::recv_bytes` | tokio Mutex (reader) | yes — length + body read | Low: reads are sequential by construction |
| `api/listener.rs::accept` | tokio Mutex (`accepted_rx`) | yes — across `rx.recv()` | Low: serialises concurrent `accept()` callers, the intended semantics; `mpsc::Receiver::recv` is cancel-safe and the lock releases on Drop |
| `api/udp_listener.rs::accept` | tokio Mutex (`accepted_rx`) | yes — across `rx.recv()` | Same shape as the TCP listener |
| `api/udp_transport.rs::recv_bytes` | `ArcSwap` (active / prev socket) | **no** — both sockets are snapshotted as owned `Arc`s before every `select!` | None (good) — holding a guard here was the migration recv-hang class |

No locks discovered that risk deadlock under cancellation. Note the drain path
deliberately snapshots `streams` (a `DashMap`) into a sorted `Vec` *before* awaiting
any send, so no DashMap shard lock is ever held across `send_app_data`'s
`pace_send`/`send_bytes` awaits.

---

## Findings

- **Zero cancel-safety bugs identified (re-confirmed post-Phase-4.4).** Every
  `select!` is over cancel-safe primitives; every long-held lock is on a tokio
  Mutex/Semaphore that releases on Drop; no DashMap shard lock is held across an
  await.
- **The re-run's headline concern is resolved, not merely tolerated.** The loss-recovery
  rework's reliable-buffer decoupling means `pace_send` operates on data already copied into
  the per-stream retransmit buffer, so a cancel during pacing cannot strand a
  payload the command channel had handed out. (And the pump is, in any case, never
  aborted mid-`await` outside runtime teardown.)
- The `accept()` race (TCP socket accepted at the OS layer but dropped on shutdown —
  now inside the H4 acceptor task) remains acceptable: clients retry, and the
  listener's shutdown flag prevents subsequent `accept()` calls from blocking. The
  PhantomUDP demux has the same shape one layer down: a datagram lost to the shutdown
  arm is indistinguishable from a network drop.

## Sign-off

- Auditor: _maintainer review; original at the commit that introduced this file,
  re-run 2026-06-01._
- Method: pattern match against `tokio::select!`, manual review of every
  `Mutex::lock().await` / `Semaphore::acquire().await` site in `core/src/api/` and
  `core/src/transport/`, plus a control-flow trace of the data pump's spawn/abort
  topology (detached spawn, a `Drop for PhantomSession` that only enqueues a graceful
  `SessionCommand::Close`, single self-`abort` of the recv subtask), covering the
  inner recv task and the three-task delivery pipeline.
- **Re-run trigger (Phase 4.4 — BBR congestion control, the loss-recovery rework
  and the observability wiring) discharged.** Re-run again if a future change either (a) gives the
  pump task an externally-held abort handle, or (b) calls `pace_send`/any sleep
  *before* a payload is copied into a retained (reliable) buffer.
