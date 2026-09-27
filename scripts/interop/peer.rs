// The interop peer, compiled twice: once against the published `=0.3.0` crate and once
// against this tree.  `peer-030/src/main.rs` and `peer-head/src/main.rs` both `include!` this
// file, so the two binaries differ in exactly one thing -- which version of
// `phantom-protocol` they link -- and nothing about the exchange can be attributed to one of
// them being written differently.
//
// The release notes lead with the claim that a 0.3.1 peer and a 0.3.0 peer interoperate in
// both directions.  Nothing tested it.  `WIRE_VERSION` is 8 in both and a mismatched header
// version is dropped in silence -- no reply, nothing the sender can observe -- so the way
// this claim fails is that a handshake completes, keys agree, and then no byte is ever
// delivered.  A test is the only thing that tells that apart from a slow network.
//
// Usage, driven by `scripts/interop/run_interop_test.sh`:
//
//     peer server --transport udp|tcp --announce FILE    serves one connection
//     peer client --transport udp|tcp --addr A --key HEX
//
// The exchange proves four things in one run: the client's first bytes reach the server, the
// server's reply reaches the client, and each direction survives a payload larger than
// `MAX_APP_CHUNK` (1156 B), which is where the sender splits and the receiver has to
// reassemble.  Every step is bounded, so a peer that agrees keys and then delivers nothing
// fails in seconds instead of hanging a job.
//
// The close is application-acknowledged, and has to be.  `send()` returns once the payload is
// queued and `disconnect()` returns once the close is *requested*: neither waits for the wire,
// and the close frame is never acknowledged or retransmitted.  A peer that sends 4000 bytes
// and then closes and exits therefore delivers a fraction of them -- which is what the first
// draft of this file did, and the truncated read at the other end read exactly like a wire
// incompatibility.  The fix is the one pattern `docs/protocol/PROTOCOL.md` 4.11 leaves for a
// sender who needs delivery: the peer says at the application level that it has everything,
// and the sender closes after that answer.
//
// So every write here except one is followed by a read the other side satisfies, which is what
// keeps the process alive while its pump drains.  The exception is the last message on the
// wire, which no protocol can have acknowledged: the server's echo of `DONE`.  That one is
// covered by `FINAL_FLUSH_GRACE` -- a linger, not an assertion.  The assertion belongs to the
// reader, whose bound is `STEP_TIMEOUT`, ten times as long, so the two do not meet.

use std::sync::Arc;
use std::time::Duration;

use phantom_protocol::api::listener::PhantomListener;
use phantom_protocol::api::udp_listener::PhantomUdpListener;
use phantom_protocol::api::PhantomSession;
use phantom_protocol::{connect_pinned, connect_pinned_udp};

/// Bigger than one `MAX_APP_CHUNK` (1156 B) and not a multiple of it, so the receiver has to
/// reassemble a partial final chunk rather than a run of whole ones.
const BULK_LEN: usize = 4000;

/// Every await in the exchange is bounded by this. A peer that completes the handshake and
/// then delivers nothing -- the shape a silent wire-version mismatch takes -- has to fail,
/// not wait.
const STEP_TIMEOUT: Duration = Duration::from_secs(20);

/// How long the side that speaks last stays alive after its final write.
///
/// The last message on a wire cannot be acknowledged, so the only thing keeping it from being
/// discarded at process exit is that the pump is still running. Four bytes over loopback need
/// microseconds; this is a linger rather than a deadline, and nothing asserts anything about
/// it. What it has to clear is the reader's `STEP_TIMEOUT` by a wide margin -- ten times --
/// because the failure it would otherwise cause surfaces over there, as a read that never
/// completes.
const FINAL_FLUSH_GRACE: Duration = Duration::from_secs(2);

const CLIENT_HELLO: &[u8] = b"interop client hello";
const SERVER_HELLO: &[u8] = b"interop server hello";

/// The client's acknowledgement that it holds every byte the server sent. Short enough that
/// `disconnect()`'s best-effort flush carries it, which `udp_integration.rs` pins separately.
const DONE: &[u8] = b"done";

fn bulk(seed: u8) -> Vec<u8> {
    (0..BULK_LEN).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed)).collect()
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn hex_decode(text: &str) -> Result<Vec<u8>, String> {
    if text.len() % 2 != 0 {
        return Err(format!("hex string has an odd length: {}", text.len()));
    }
    (0..text.len() / 2)
        .map(|i| {
            u8::from_str_radix(&text[i * 2..i * 2 + 2], 16)
                .map_err(|e| format!("bad hex at byte {i}: {e}"))
        })
        .collect()
}

async fn step<F, T>(what: &str, fut: F) -> Result<T, String>
where
    F: std::future::Future<Output = Result<T, phantom_protocol::CoreError>>,
{
    match tokio::time::timeout(STEP_TIMEOUT, fut).await {
        Err(_) => Err(format!("{what}: nothing arrived within {STEP_TIMEOUT:?}")),
        Ok(Err(e)) => Err(format!("{what}: {e:?}")),
        Ok(Ok(v)) => Ok(v),
    }
}

/// `send` splits at `MAX_APP_CHUNK` and preserves no message boundaries, so a reader of a
/// payload larger than one chunk has to accumulate until it holds the expected length.
async fn recv_exactly(session: &Arc<PhantomSession>, want: usize) -> Result<Vec<u8>, String> {
    let mut got = Vec::with_capacity(want);
    while got.len() < want {
        let chunk = step("recv", session.recv()).await?;
        if chunk.is_empty() {
            return Err("recv returned an empty chunk before the payload was complete".into());
        }
        got.extend_from_slice(&chunk);
    }
    if got.len() != want {
        return Err(format!("expected {want} bytes, reassembled {}", got.len()));
    }
    Ok(got)
}

fn expect(what: &str, got: &[u8], want: &[u8]) -> Result<(), String> {
    if got == want {
        println!("  ok   {what}");
        Ok(())
    } else {
        Err(format!("{what}: {} bytes, not the {} expected", got.len(), want.len()))
    }
}

/// Client -> server, server -> client, then the same in bulk. Run from the server's side.
async fn serve_exchange(session: Arc<PhantomSession>) -> Result<(), String> {
    let hello = recv_exactly(&session, CLIENT_HELLO.len()).await?;
    expect("the client's hello arrived", &hello, CLIENT_HELLO)?;
    step("send hello", session.send(SERVER_HELLO.to_vec())).await?;

    let up = recv_exactly(&session, BULK_LEN).await?;
    expect("the client's bulk payload reassembled", &up, &bulk(0x5a))?;
    step("send bulk", session.send(bulk(0xa5))).await?;

    // Wait to be told the payload landed. `disconnect()` does not wait for an
    // acknowledgement and its close frame is neither acknowledged nor retransmitted, so
    // closing here would discard most of what was just sent -- and the client would report
    // a truncated read, which is indistinguishable from a wire incompatibility.
    let done = recv_exactly(&session, DONE.len()).await?;
    expect("the client acknowledged the payload", &done, DONE)?;

    // Echoed back so the client's own acknowledgement is not the last message on the wire --
    // the client has a bounded read waiting for this, which is what keeps its pump running
    // long enough to have sent the `DONE` just read above.
    step("acknowledge", session.send(DONE.to_vec())).await?;
    tokio::time::sleep(FINAL_FLUSH_GRACE).await;
    step("disconnect", session.disconnect()).await?;
    Ok(())
}

/// The other half of `serve_exchange`.
async fn drive_exchange(session: Arc<PhantomSession>) -> Result<(), String> {
    step("send hello", session.send(CLIENT_HELLO.to_vec())).await?;
    let hello = recv_exactly(&session, SERVER_HELLO.len()).await?;
    expect("the server's hello arrived", &hello, SERVER_HELLO)?;

    step("send bulk", session.send(bulk(0x5a))).await?;
    let down = recv_exactly(&session, BULK_LEN).await?;
    expect("the server's bulk payload reassembled", &down, &bulk(0xa5))?;

    // The server closes only once it has this, so it is what proves the whole exchange
    // landed rather than merely having been queued. Reading the echo back is what keeps this
    // process -- and with it the pump that has to transmit the line above -- alive until the
    // server has it.
    step("acknowledge", session.send(DONE.to_vec())).await?;
    let echo = recv_exactly(&session, DONE.len()).await?;
    expect("the server acknowledged in turn", &echo, DONE)?;

    step("disconnect", session.disconnect()).await?;
    Ok(())
}

async fn run_server(transport: &str, announce_to: &str) -> Result<(), String> {
    match transport {
        "udp" => {
            let listener = PhantomUdpListener::bind_udp("127.0.0.1:0".to_string())
                .await
                .map_err(|e| format!("bind_udp: {e:?}"))?;
            announce(announce_to, &listener.local_addr(), &listener.verifying_key_bytes())?;
            let outcome = step("accept", listener.clone().accept()).await?;
            serve_exchange(outcome.session()).await
        }
        "tcp" => {
            let listener = PhantomListener::bind("127.0.0.1:0".to_string())
                .await
                .map_err(|e| format!("bind: {e:?}"))?;
            announce(announce_to, &listener.local_addr(), &listener.verifying_key_bytes())?;
            let outcome = step("accept", listener.accept()).await?;
            serve_exchange(outcome.session()).await
        }
        other => Err(format!("unknown transport {other:?}")),
    }
}

/// The two facts the client side needs -- the bound address and the key to pin -- written to
/// one file and renamed into place.
///
/// A file the orchestrator waits for, rather than two lines it polls a log for: the rename is
/// atomic, so there is no state in which the address is readable and the key is not, and
/// nothing has to guess a port or sleep. The 1984-byte key also stays out of every CI log.
fn announce(path: &str, addr: &str, key: &[u8]) -> Result<(), String> {
    let partial = format!("{path}.partial");
    std::fs::write(&partial, format!("{addr}\n{}\n", hex_encode(key)))
        .map_err(|e| format!("writing {partial}: {e}"))?;
    std::fs::rename(&partial, path).map_err(|e| format!("renaming {partial} to {path}: {e}"))?;
    println!("listening on {addr}");
    Ok(())
}

async fn run_client(transport: &str, addr: &str, key_hex: &str) -> Result<(), String> {
    let key = hex_decode(key_hex)?;
    let (host, port) = addr
        .rsplit_once(':')
        .ok_or_else(|| format!("address {addr:?} carries no port"))?;
    let port: u16 = port.parse().map_err(|e| format!("port in {addr:?}: {e}"))?;

    let session = match transport {
        "udp" => connect_pinned_udp(host.to_string(), port, key).await,
        "tcp" => connect_pinned(host.to_string(), port, key).await,
        other => return Err(format!("unknown transport {other:?}")),
    }
    .map_err(|e| format!("connect: {e:?}"))?;

    // Every `connect_pinned*` returns once the socket is connected; the handshake, and with
    // it the pinned-identity check, runs afterwards. A wire-version disagreement surfaces
    // here or not at all.
    step("await_ready", session.await_ready()).await?;
    println!("  ok   the handshake completed");
    drive_exchange(session).await
}

fn arg(args: &[String], name: &str) -> Option<String> {
    args.windows(2).find(|w| w[0] == name).map(|w| w[1].clone())
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let role = args.first().cloned().unwrap_or_default();
    let transport = arg(&args, "--transport").unwrap_or_else(|| "udp".to_string());

    println!("peer {} {} against phantom-protocol {}", role, transport, PEER_CORE_VERSION);

    let outcome = match role.as_str() {
        "server" => match arg(&args, "--announce") {
            Some(path) => run_server(&transport, &path).await,
            None => Err("server needs --announce <file>".to_string()),
        },
        "client" => {
            let addr = arg(&args, "--addr").unwrap_or_default();
            let key = arg(&args, "--key").unwrap_or_default();
            if addr.is_empty() || key.is_empty() {
                Err("client needs --addr and --key".to_string())
            } else {
                run_client(&transport, &addr, &key).await
            }
        }
        other => Err(format!("first argument must be `server` or `client`, not {other:?}")),
    };

    match outcome {
        Ok(()) => println!("OK: {role} {transport} exchange complete"),
        Err(why) => {
            eprintln!("FAIL: {role} {transport}: {why}");
            std::process::exit(1);
        }
    }
}
