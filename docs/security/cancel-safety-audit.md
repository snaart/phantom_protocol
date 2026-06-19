# Async cancel-safety audit (Phase 2.13; re-run 2026-06-01)

> **Re-run note (2026-06-01).** The original audit was signed off at Phase 2.13
> and scheduled a re-run "after Phase 4.4." That landed, and the data pump was
> materially rewritten — B1-A loss recovery (route `send()` through a per-stream
> reliable buffer + BBR-paced drain) and B7 observability (a `session_opened` /
> `session_closed` gauge + `ObservedTransport`). The `run_data_pump` main-loop
> section below is rewritten for the current 4-arm `select!`; the headline
> concern raised for the re-run — a `pace_send` sleep stranding already-dequeued
> data on cancel — was **resolved by the same B1-A refactor that introduced
> pacing** (see that section). Verdict stands: ✅ cancel-safe, no code change.

A `select!` arm that fires before its sibling completes effectively
**cancels** the unfinished future. If that future was carrying
state mid-await — half-consumed bytes from a stream, an unposted
ACK, a partially-allocated resource — cancellation can leave the
session in an inconsistent state.

This document inventories every `tokio::select!` and every long-held
`.await` in `phantom_protocol` and confirms whether the pattern is
cancel-safe by tokio's stated guarantees.

Methodology: I matched every `tokio::select!` in `core/src` against
tokio's [cancellation-safety cheatsheet](https://docs.rs/tokio/latest/tokio/macro.select.html#cancellation-safety)
and tested mentally for the "what if the other arm fires first"
scenario.

---

## Inventory

### `api/session.rs::run_data_pump` main loop (current, 4-arm)

```rust
tokio::select! {
    _ = poll_interval.tick()       => { drain_streams_priority_ordered(..).await }
    _ = send_notify.notified()     => { drain_streams_priority_ordered(..).await }  // fast-wake
    cmd_opt = cmd_rx.recv()        => { match cmd { Send | SendStream* | CloseStream | Close } }
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
   server; the client awaits it inside an equally-detached `background_task`). There
   is **no `Drop for PhantomSession`**, and the only `.abort()` in the module is the
   pump aborting *its own* recv subtask during teardown (`recv_handle.abort()`). The
   pump exits exclusively through the loop `break` (a graceful `SessionCommand::Close`
   from `disconnect()`, the `None` channel-closed arm, or `recv_done`). The *only* way
   an arm body is cancelled is the **runtime/process being torn down**, where losing
   in-flight bytes is expected and harmless.

2. **Even under that teardown cancel, reliable data is not stranded** — this is what
   resolves the re-run's headline concern. The concern was: `SessionCommand::Send →
   send_app_data → pace_send().await` consumes the payload from the mpsc channel and
   then sleeps, so an abort during the sleep silently drops a payload the channel had
   already handed out. **B1-A removed that path.** The `Send` arm now copies the
   payload into the per-stream **reliable send buffer** (`raw_stream.send_reliable`)
   and returns; `pace_send` no longer runs in the command arm at all. The actual paced
   transmission happens later in `drain_streams_priority_ordered → Stream::poll_send →
   send_app_data → pace_send`, and `poll_send` **retains** the segment (it iterates
   `send_buffer` with `iter_mut`, sets `sent_at`, and returns a *clone* — it removes
   nothing; only `Stream::ack()` removes a segment). So a cancel during `pace_send`
   leaves the reliable segment in the buffer; it is re-offered on the next drain (after
   RTO). The payload is decoupled from the channel before any sleep — pacing happens on
   buffered, retained data, exactly the "restructure so pacing happens before the value
   leaves the channel" the re-run asked for.
   - *Unreliable* data (`poll_send`'s `unreliable_buffer.pop_front()`) **is** removed
     before `send_app_data`, so a teardown cancel drops it — which is the fire-and-
     forget contract, and only at teardown.
   - The `CloseStream` arm awaits `send_app_data` for a FIN; a teardown cancel there
     drops a control FIN on a stream already being torn down — benign.

**Verdict:** ✅ cancel-safe. The pump is non-cancellable in normal operation, and the
B1-A reliable-buffer decoupling means even teardown cancellation cannot strand
acknowledged-delivery data.

### `api/listener.rs::accept`

```rust
let shutdown_fut = self.shutdown_notify.notified();
tokio::pin!(shutdown_fut);
let (stream, peer) = tokio::select! {
    result = listener_guard.accept() => { /* take new TCP */ }
    _ = &mut shutdown_fut => { return Err(ConnectionClosed); }
};
```

- `TcpListener::accept()`: **NOT inherently cancel-safe** by the tokio
  cookbook — but the failure mode is "an inbound connection was
  accepted at the OS layer and we drop the `TcpStream` on the floor."
  That's a benign leak: the client sees a closed socket and retries.
  No corruption of listener state.
- `Notify::notified()`: **cancel-safe** when pinned. We pin it and
  `&mut` it for the select to permit re-polling — the standard tokio
  pattern.
- Lock is released via `drop(listener_guard)` after acquiring the
  accepted stream, so no lock leak.

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
- B7 added per-packet observability inside `handle_packet` (the
  `record_send`/`record_recv`/`record_*_dropped` calls). These are
  synchronous, infallible atomic adds with no `.await`, so an abort at the
  `recv_bytes().await` point cannot interrupt a half-finished metric update;
  a dropped in-flight packet simply isn't recorded.

**Verdict:** ✅ cancel-safe. Abort behaviour is a clean equivalent
of "transport closed mid-packet".

### Delivery task (`run_data_pump` spawned at line 777)

```rust
loop {
    let (stream_id, bytes) = match deliver_rx.recv().await { ... };
    // ...demux / per-stream / crypto bookkeeping (synchronous)...
    recv_tx_deliver.send(bytes).await ...;
    // ...window credit...
}
```

This task drains the unbounded `deliver_rx` channel into which the inner recv
task hands decrypted application data, paces delivery at the application's
consumption rate, and credits the per-stream flow-control window.

- `deliver_rx.recv().await` (line 778): **cancel-safe** — a dropped `recv` does
  not consume a queued message; the next poll observes it.
- The demux / per-stream lookup / crypto bookkeeping between the two awaits are
  **synchronous** — no `.await`, so an abort cannot interrupt a half-finished
  update.
- `recv_tx_deliver.send(bytes).await` (line 810): **cancel-safe** — a dropped
  `send` does not lose the item; the value stays owned by the future and is
  re-offered on the next poll (or dropped wholesale with the task at teardown).

**Verdict:** ✅ cancel-safe. Both awaits are over cancel-safe mpsc primitives;
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

- No `select!`. Sequential send → recv. If the calling task is
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

The fixed-500 ms-timer `poll_send` the original audit described is gone (B1-A
replaced it with an RFC 6298 RTO + a BBR congestion window). `poll_send` is now a
**non-blocking** poll: it briefly locks `unreliable_buffer` then `send_buffer`
(`Mutex::lock().await`, released before return), scans for a timed-out segment
(retransmit) or the next in-window unsent segment, and returns `Option` immediately
— no inner notifier/timeout await. `send_reliable`'s backpressure is a
`tokio::sync::Semaphore::acquire().await`, which is cancel-safe (a dropped acquire
does not consume a permit; `permit.forget()` runs only after a successful acquire).

**Verdict:** ✅ cancel-safe. No `.await` holds a buffer lock; the only blocking await
(`Semaphore::acquire`) is cancel-safe.

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
| `api/listener.rs::accept` | tokio Mutex (listener) | held only over `accept()` itself; released before handshake | None (good) |

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
- **The re-run's headline concern is resolved, not merely tolerated.** B1-A's
  reliable-buffer decoupling means `pace_send` operates on data already copied into
  the per-stream retransmit buffer, so a cancel during pacing cannot strand a
  payload the command channel had handed out. (And the pump is, in any case, never
  aborted mid-`await` outside runtime teardown.)
- The `accept()` race (TCP socket accepted at the OS layer but dropped on shutdown)
  remains acceptable: clients retry, and the listener's shutdown flag prevents
  subsequent `accept()` calls from blocking.

## Sign-off

- Auditor: _automated review; original at the commit that introduced this file,
  re-run 2026-06-01._
- Method: pattern match against `tokio::select!`, manual review of every
  `Mutex::lock().await` / `Semaphore::acquire().await` site in `core/src/api/` and
  `core/src/transport/`, plus a control-flow trace of the data pump's spawn/abort
  topology (detached spawn, no `Drop`, single self-`abort` of the recv subtask),
  covering both the inner recv task and the spawned delivery task.
- **Re-run trigger (Phase 4.4 — BBR congestion control + B1-A loss recovery + B7
  observability) discharged.** Re-run again if a future change either (a) gives the
  pump task an externally-held abort handle, or (b) calls `pace_send`/any sleep
  *before* a payload is copied into a retained (reliable) buffer.
