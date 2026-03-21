# Async cancel-safety audit (Phase 2.13)

A `select!` arm that fires before its sibling completes effectively
**cancels** the unfinished future. If that future was carrying
state mid-await — half-consumed bytes from a stream, an unposted
ACK, a partially-allocated resource — cancellation can leave the
session in an inconsistent state.

This document inventories every `tokio::select!` and every long-held
`.await` in `phantom_core` and confirms whether the pattern is
cancel-safe by tokio's stated guarantees.

Methodology: I matched every `tokio::select!` in `core/src` against
tokio's [cancellation-safety cheatsheet](https://docs.rs/tokio/latest/tokio/macro.select.html#cancellation-safety)
and tested mentally for the "what if the other arm fires first"
scenario.

---

## Inventory

### `api/session.rs::run_data_pump` main loop

```rust
tokio::select! {
    _ = poll_interval.tick() => { /* sweep streams, send queued */ }
    cmd_opt = cmd_rx.recv() => { /* application command */ }
    _ = &mut recv_done_rx => { /* recv task ended */ }
}
```

- `tokio::time::Interval::tick()`: **cancel-safe.** From the tokio docs,
  `Interval::tick` is cancel-safe; dropping the future before completion
  is equivalent to never having called it (it does not advance any
  internal timer).
- `tokio::sync::mpsc::Receiver::recv()`: **cancel-safe.** Documented
  guarantee — a dropped `recv` future does not consume a queued message.
- `tokio::sync::oneshot::Receiver` (via `&mut recv_done_rx`):
  **cancel-safe.** Polling a oneshot does not consume the value until
  `.send()` has put one in; dropping the awaiter never loses data.
- Inner work inside `poll_interval.tick()` arm: synchronous after
  `poll_send().await` per-stream. Each `poll_send` is on a per-stream
  `Mutex` held briefly — no inner `select!`, no interleaving with the
  main loop's cancellation.

**Verdict:** ✅ cancel-safe.

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
    // ...alkahest deserialize, decrypt, route...
}
```

- No `select!` here. The loop awaits the next transport read; when the
  transport closes, `recv_bytes` returns `Err` and the loop breaks
  cleanly. A `recv_handle.abort()` from the outer loop cancels at the
  `.await` point — at worst we lose one in-flight packet, equivalent
  to a network drop.

**Verdict:** ✅ cancel-safe. Abort behaviour is a clean equivalent
of "transport closed mid-packet".

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

### `transport/legs/faketls.rs::do_client_handshake` / `do_server_handshake`

Looking at the leg's handshake code (FakeTLS record exchange — pre-
Phantom handshake): straight-line `read_exact` / `write_all`. No
`select!`. Same logic as above — cancel mid-`.await` leaves the TCP
connection in a state where the next handshake attempt will reset.

**Verdict:** ✅ cancel-safe.

### `transport/stream.rs::poll_send` (line 152)

```rust
tokio::time::timeout(Duration::from_millis(500), self.send_notifier.notified())
```

`tokio::time::timeout` is cancel-safe per docs. If the parent task is
cancelled mid-timeout, the inner `notified()` future is dropped — but
because notifications are level-triggered through the `Notify` API,
a subsequent `notified()` call observes the notification.

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
| `api/session.rs::run_data_pump` send_queue drain | tokio Mutex | yes — drain loop | Low: drain is O(queue depth) — was already the design |
| `api/tcp_transport.rs::send_bytes` | tokio Mutex (writer) | yes — write + flush | Low: serialises sends, which is the intended semantics |
| `api/tcp_transport.rs::recv_bytes` | tokio Mutex (reader) | yes — length + body read | Low: reads are sequential by construction |
| `transport/stream.rs::send_reliable` | tokio Mutex (send_buffer) | brief — single push_back | None |
| `api/listener.rs::accept` | tokio Mutex (listener) | held only over `accept()` itself; released before handshake | None (good) |

No locks discovered that risk deadlock under cancellation.

---

## Findings

- **Zero cancel-safety bugs identified.** Every `select!` is over
  cancel-safe primitives; every long-held lock is on a tokio Mutex
  which releases on Drop.
- The `accept()` race (TCP socket accepted at the OS layer but
  dropped on shutdown) is documented as acceptable: clients retry,
  and the listener's `shutting_down` flag prevents subsequent
  `accept()` calls from blocking on the listener Mutex.

## Sign-off

- Auditor: _automated review at the commit that introduces this file_
- Method: pattern match against `tokio::select!`, manual review of
  every `Mutex::lock().await` site in `core/src/api/` and
  `core/src/transport/`.
- Audit will be re-run after Phase 4.4 (BBRv2 congestion control)
  introduces new background tasks.
