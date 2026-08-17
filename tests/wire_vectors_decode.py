#!/usr/bin/env python3
"""Independent decoder for the Phantom Protocol wire vectors (Phase 6).

A *second implementation* of the wire grammar — deliberately sharing no code
with the Rust crate — that parses the byte-frozen fixtures under
``core/tests/wire_vectors/`` and checks them against the documented format. If
this script and the Rust `wire_vectors.rs` test agree on every byte, the
grammar is genuinely interoperable, not just self-consistent.

What it covers:

  * **borsh handshake messages** (ClientHello / ServerHello / HelloRetryRequest)
    and their crypto sub-structs (HybridKeyPackage / HybridCiphertext /
    HybridVerifyingKey / HybridSignature / PoWChallenge / PoWSolution) —
    *fully* decoded **and** re-encoded; the re-encode must reproduce the fixture
    byte-for-byte (encode/decode parity in a second language), and every field
    is checked against the spec's deterministic filler.

  * **packet header + `PhantomPacket`** — the hand-rolled big-endian codec:
    `version` first, integers network byte order, byte arrays as-is, and the body
    is just `header(15) || payload` (WIRE v6 anti-fingerprint diet: the two
    cleartext `u32` length prefixes are GONE — `payload` is the message remainder —
    and `extensions` are off the wire; the 15-byte header has session_id off-wire).
    Fully decoded **and** re-encoded, same as the borsh structs.

  * **the `WINDOW_UPDATE` plaintext** — an 8-byte big-endian cumulative limit, together
    with the rule a receiver of one must apply. It has no frozen fixture (it is an AEAD
    plaintext, not an outer container), so what is stated here is the codec and the rule,
    in a second language: the encoding against written-out byte strings, and the rule as
    an explicit function fed from the decoder, graded against a written-out transcript.
    The rule has two halves and both are stated — the monotone maximum against the limit
    already held, *and* the local clamp to one `MAX_SEND_WINDOW` past what has been sent,
    which is the half that exists because the number is written by the peer.

Run:``python3 tests/wire_vectors_decode.py`` (stdlib only; exits non-zero on
any mismatch). Regenerate the fixtures from Rust with
``PHANTOM_REGEN_WIRE_VECTORS=1 cargo test --manifest-path core/Cargo.toml``.
"""

from __future__ import annotations

import struct
import sys
from itertools import permutations
from pathlib import Path

VECTORS_DIR = Path(__file__).resolve().parent.parent / "core" / "tests" / "wire_vectors"

# Canonical field lengths for the default (non-fips) build — must match the
# constants in core/tests/wire_vectors.rs.
ML_KEM_PK_LEN = 1184
ML_KEM_CT_LEN = 1088
ML_DSA_PK_LEN = 1952
ML_DSA_SIG_LEN = 3309
CLASSICAL_PK_LEN = 32
PROTOCOL_VARIANT = b"phantom-default-1"
PROTOCOL_VERSION = 4  # bumped 3->4: WINDOW_UPDATE carries a cumulative limit (see below)
WIRE_VERSION = 7  # bumped 6->7 with it, so a peer speaking the older flow control is refused

# WINDOW_UPDATE AEAD plaintext: 8 big-endian bytes, the cumulative total the receiver is
# willing to have sent on that stream, counted from the stream's first byte. It replaced a
# 4-byte relative credit at WIRE_VERSION 7. There is no frozen fixture for it — it is an
# AEAD plaintext rather than an outer container — but a second implementation reading only
# this file has to get the length and the meaning right, so both are stated here and the
# length is asserted against the spec below.
WINDOW_UPDATE_PAYLOAD_LEN = 8

# The three numbers PROTOCOL.md § 4.5 puts on the flow-control ledger. They are not
# encodings, so no fixture can carry them, and a second implementation that guesses them
# wrong stalls or overruns without ever mis-parsing a byte — which is why they are written
# out here under the names the spec uses rather than left as literals in a table.
#
# The limit both ends assume before any WINDOW_UPDATE has been seen. Starting from zero
# instead deadlocks: the first frame is only emitted once the peer's application has
# consumed bytes that, at a zero opening limit, would never have been sent to it.
INITIAL_STREAM_WINDOW = 64 * 1024
# The ceiling on what a receiver may advertise beyond what its application has consumed.
MAX_RECV_WINDOW = 1024 * 1024
# The ceiling on what a sender will honour beyond what it has already sent, whatever
# number arrives. Written out independently of MAX_RECV_WINDOW rather than defined from
# it, so that the two being equal is something this file checks rather than something it
# arranges — see `window_update_limit_rule`.
MAX_SEND_WINDOW = 1024 * 1024


def pat(seed: int, n: int) -> bytes:
    """The deterministic filler used by the Rust vectors: ramp from ``seed``."""
    return bytes((seed + i) & 0xFF for i in range(n))


def arr32(seed: int) -> bytes:
    return pat(seed, 32)


class Failure(Exception):
    pass


def check(cond: bool, msg: str) -> None:
    if not cond:
        raise Failure(msg)


# ─── borsh reader / writer (the subset the wire uses) ───────────────────────


class BorshReader:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def take(self, n: int) -> bytes:
        check(self.pos + n <= len(self.data), f"borsh underrun: need {n} at {self.pos}")
        out = self.data[self.pos : self.pos + n]
        self.pos += n
        return out

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return struct.unpack("<H", self.take(2))[0]

    def u32(self) -> int:
        return struct.unpack("<I", self.take(4))[0]

    def u64(self) -> int:
        return struct.unpack("<Q", self.take(8))[0]

    def fixed(self, n: int) -> bytes:
        return self.take(n)

    def vec_u8(self) -> bytes:
        n = self.u32()
        return self.take(n)

    def option(self, inner):
        tag = self.u8()
        check(tag in (0, 1), f"borsh Option tag must be 0/1, got {tag}")
        return inner() if tag == 1 else None

    def boolean(self) -> bool:
        v = self.u8()
        check(v in (0, 1), f"borsh bool must be 0/1, got {v}")
        return v == 1

    def finish(self) -> None:
        check(self.pos == len(self.data), f"trailing bytes: consumed {self.pos}/{len(self.data)}")


class BorshWriter:
    def __init__(self):
        self.buf = bytearray()

    def u8(self, v: int):
        self.buf.append(v & 0xFF)

    def u16(self, v: int):
        self.buf += struct.pack("<H", v)

    def u32(self, v: int):
        self.buf += struct.pack("<I", v)

    def u64(self, v: int):
        self.buf += struct.pack("<Q", v)

    def fixed(self, b: bytes):
        self.buf += b

    def vec_u8(self, b: bytes):
        self.u32(len(b))
        self.buf += b

    def option(self, value, inner):
        if value is None:
            self.u8(0)
        else:
            self.u8(1)
            inner(value)

    def boolean(self, v: bool):
        self.u8(1 if v else 0)


# ─── borsh struct codecs (decode + encode, mirroring the Rust field order) ──


def dec_key_package(r: BorshReader):
    return {"classical_pk": r.fixed(CLASSICAL_PK_LEN), "ml_kem_pk": r.vec_u8()}


def enc_key_package(w: BorshWriter, v):
    w.fixed(v["classical_pk"])
    w.vec_u8(v["ml_kem_pk"])


def dec_ciphertext(r: BorshReader):
    return {"classical_pk": r.fixed(CLASSICAL_PK_LEN), "ml_kem_ct": r.vec_u8()}


def enc_ciphertext(w: BorshWriter, v):
    w.fixed(v["classical_pk"])
    w.vec_u8(v["ml_kem_ct"])


def dec_verify_key(r: BorshReader):
    return {"ed25519_pk": r.fixed(32), "ml_dsa_pk": r.vec_u8()}


def enc_verify_key(w: BorshWriter, v):
    w.fixed(v["ed25519_pk"])
    w.vec_u8(v["ml_dsa_pk"])


def dec_signature(r: BorshReader):
    return {"ed25519_sig": r.fixed(64), "ml_dsa_sig": r.vec_u8()}


def enc_signature(w: BorshWriter, v):
    w.fixed(v["ed25519_sig"])
    w.vec_u8(v["ml_dsa_sig"])


def dec_pow_challenge(r: BorshReader):
    return {"nonce": r.fixed(32), "difficulty": r.u8()}


def enc_pow_challenge(w: BorshWriter, v):
    w.fixed(v["nonce"])
    w.u8(v["difficulty"])


def dec_pow_solution(r: BorshReader):
    return {"nonce": r.fixed(32), "solution": r.u64()}


def enc_pow_solution(w: BorshWriter, v):
    w.fixed(v["nonce"])
    w.u64(v["solution"])


def dec_client_hello(r: BorshReader):
    return {
        "client_key_package": dec_key_package(r),
        "client_verify_key": dec_verify_key(r),
        "nonce": r.fixed(32),
        "version": r.u8(),
        "cookie": r.option(lambda: r.fixed(32)),
        "pow_solution": r.option(lambda: dec_pow_solution(r)),
        "resume_session_id": r.option(lambda: r.fixed(32)),
        "resumption_binder": r.option(lambda: r.fixed(32)),
        "protocol_variant": r.vec_u8(),
        "early_data": r.option(lambda: r.vec_u8()),
    }


def enc_client_hello(w: BorshWriter, v):
    enc_key_package(w, v["client_key_package"])
    enc_verify_key(w, v["client_verify_key"])
    w.fixed(v["nonce"])
    w.u8(v["version"])
    w.option(v["cookie"], w.fixed)
    w.option(v["pow_solution"], lambda s: enc_pow_solution(w, s))
    w.option(v["resume_session_id"], w.fixed)
    w.option(v["resumption_binder"], w.fixed)
    w.vec_u8(v["protocol_variant"])
    w.option(v["early_data"], w.vec_u8)


def dec_server_hello(r: BorshReader):
    return {
        "server_nonce": r.fixed(32),
        "ciphertext": dec_ciphertext(r),
        "server_verify_key": dec_verify_key(r),
        "signature": dec_signature(r),
        "session_id": r.fixed(32),
        "early_data_accepted": r.boolean(),
    }


def enc_server_hello(w: BorshWriter, v):
    w.fixed(v["server_nonce"])
    enc_ciphertext(w, v["ciphertext"])
    enc_verify_key(w, v["server_verify_key"])
    enc_signature(w, v["signature"])
    w.fixed(v["session_id"])
    w.boolean(v["early_data_accepted"])


def dec_hrr(r: BorshReader):
    return {
        "challenge": r.option(lambda: dec_pow_challenge(r)),
        "cookie": r.option(lambda: r.fixed(32)),
    }


def enc_hrr(w: BorshWriter, v):
    w.option(v["challenge"], lambda c: enc_pow_challenge(w, c))
    w.option(v["cookie"], w.fixed)


# ─── packet codec: hand-rolled, big-endian, version-first ───────────────────
#
# PacketHeader (15 bytes), WIRE_VERSION 6 layout (anti-fingerprint diet — the
# 32-byte inner session_id is OFF-WIRE; on the data-plane wire the WHOLE 15-byte
# header [0:15] is HP-MASKED, version byte INCLUDED, so there is no constant
# cleartext byte; routing is by the outer rotating ConnId):
#   [0]     version       u8   (= WIRE_VERSION)            HP-MASKED (v6)
#   [1:9]   packet_number u64 be                           HP-MASKED
#   [9:11]  flags         u16 be                           HP-MASKED
#   [11:13] stream_id     u16 be                           HP-MASKED
#   [13]    epoch         u8                               HP-MASKED
#   [14]    path_id       u8                               HP-MASKED
# PhantomPacket: header(15) || payload   (WIRE v6: no length prefixes; payload is
# the message remainder; extensions are off the wire).
# NOTE: these fixtures freeze the *cleartext wire image* (the 15-byte header +
# payload). The AEAD AAD is a SEPARATE 47-byte v4-style image
# (version‖session_id‖the-14), reconstructed off-wire — NOT what these vectors
# freeze. The on-wire [0:15] span is XOR-masked by the per-session HeaderProtector
# (keyed crypto, verified in Rust); this independent decoder stays crypto-free and
# decodes the cleartext pre-mask image.

HEADER_SIZE = 15


def dec_packet_header(b: bytes):
    check(len(b) >= HEADER_SIZE, f"header needs {HEADER_SIZE} bytes, got {len(b)}")
    return {
        "version": b[0],
        "packet_number": struct.unpack(">Q", b[1:9])[0],
        "flags": struct.unpack(">H", b[9:11])[0],
        "stream_id": struct.unpack(">H", b[11:13])[0],
        "epoch": b[13],
        "path_id": b[14],
    }


def enc_packet_header(h) -> bytes:
    return (
        bytes([h["version"]])
        + struct.pack(">Q", h["packet_number"])
        + struct.pack(">H", h["flags"])
        + struct.pack(">H", h["stream_id"])
        + bytes([h["epoch"], h["path_id"]])
    )


def dec_phantom_packet(b: bytes):
    # WIRE v6 (anti-fingerprint diet): no cleartext length prefixes — the payload
    # is simply the message remainder after the 15-byte header; `extensions` are
    # off the data-plane wire (always empty).
    header = dec_packet_header(b)
    payload = bytes(b[HEADER_SIZE:])
    return {"header": header, "payload": payload, "extensions": b""}


def enc_phantom_packet(p) -> bytes:
    # WIRE v6: header(15) || payload  (no length prefixes, no extensions on wire).
    return enc_packet_header(p["header"]) + p["payload"]


# ─── per-vector checks ──────────────────────────────────────────────────────


def load(name: str) -> bytes:
    path = VECTORS_DIR / name
    check(path.is_file(), f"missing fixture {name} (regenerate the wire vectors from Rust)")
    return path.read_bytes()


def borsh_roundtrip(name: str, decode, encode) -> dict:
    raw = load(name)
    r = BorshReader(raw)
    value = decode(r)
    r.finish()  # no trailing bytes — grammar fully understood
    w = BorshWriter()
    encode(w, value)
    check(bytes(w.buf) == raw, f"{name}: Python re-encode != fixture (grammar mismatch)")
    return value


CHECKS = []


def vector(fn):
    CHECKS.append(fn)
    return fn


@vector
def hybrid_key_package():
    v = borsh_roundtrip("hybrid_key_package.bin", dec_key_package, enc_key_package)
    check(v["classical_pk"] == arr32(0x10), "key_package classical_pk filler")
    check(v["ml_kem_pk"] == pat(0x20, ML_KEM_PK_LEN), "key_package ml_kem_pk filler/length")


@vector
def hybrid_ciphertext():
    v = borsh_roundtrip("hybrid_ciphertext.bin", dec_ciphertext, enc_ciphertext)
    check(v["classical_pk"] == arr32(0x30), "ciphertext classical_pk filler")
    check(v["ml_kem_ct"] == pat(0x40, ML_KEM_CT_LEN), "ciphertext ml_kem_ct filler/length")


@vector
def hybrid_verifying_key():
    v = borsh_roundtrip("hybrid_verifying_key.bin", dec_verify_key, enc_verify_key)
    check(v["ed25519_pk"] == arr32(0x50), "verify_key ed25519 filler")
    check(v["ml_dsa_pk"] == pat(0x60, ML_DSA_PK_LEN), "verify_key ml_dsa filler/length")


@vector
def hybrid_signature():
    v = borsh_roundtrip("hybrid_signature.bin", dec_signature, enc_signature)
    check(v["ed25519_sig"] == pat(0x70, 64), "signature ed25519 filler")
    check(v["ml_dsa_sig"] == pat(0x80, ML_DSA_SIG_LEN), "signature ml_dsa filler/length")


@vector
def pow_challenge():
    v = borsh_roundtrip("pow_challenge.bin", dec_pow_challenge, enc_pow_challenge)
    check(v["nonce"] == arr32(0x90), "pow_challenge nonce filler")
    check(v["difficulty"] == 20, "pow_challenge difficulty")


@vector
def pow_solution():
    v = borsh_roundtrip("pow_solution.bin", dec_pow_solution, enc_pow_solution)
    check(v["nonce"] == arr32(0x90), "pow_solution nonce filler")
    check(v["solution"] == 0x0123456789ABCDEF, "pow_solution solution")


@vector
def client_hello_minimal():
    v = borsh_roundtrip("client_hello_minimal.bin", dec_client_hello, enc_client_hello)
    check(v["version"] == PROTOCOL_VERSION, "client_hello version pin")
    check(v["nonce"] == arr32(0xA0), "client_hello nonce filler")
    check(v["protocol_variant"] == PROTOCOL_VARIANT, "client_hello protocol_variant")
    check(v["cookie"] is None, "minimal cookie None")
    check(v["pow_solution"] is None, "minimal pow None")
    check(v["resume_session_id"] is None, "minimal resume None")
    check(v["early_data"] is None, "minimal early_data None")


@vector
def client_hello_full():
    v = borsh_roundtrip("client_hello_full.bin", dec_client_hello, enc_client_hello)
    check(v["version"] == PROTOCOL_VERSION, "client_hello_full version pin")
    check(v["cookie"] == arr32(0xB0), "full cookie filler")
    check(v["pow_solution"]["solution"] == 0x0123456789ABCDEF, "full pow solution")
    check(v["resume_session_id"] == arr32(0xC0), "full resume filler")
    check(v["early_data"] == pat(0xD0, 48), "full early_data filler")


@vector
def server_hello():
    v = borsh_roundtrip("server_hello.bin", dec_server_hello, enc_server_hello)
    check(v["early_data_accepted"] is True, "server_hello accepted=true")
    check(v["server_nonce"] == arr32(0x70), "server_hello server_nonce filler (T4.3)")
    check(v["session_id"] == arr32(0xE0), "server_hello session_id filler")
    check(v["ciphertext"]["ml_kem_ct"] == pat(0x40, ML_KEM_CT_LEN), "server_hello ct filler")
    check(v["signature"]["ml_dsa_sig"] == pat(0x80, ML_DSA_SIG_LEN), "server_hello sig filler")


@vector
def server_hello_rejected():
    v = borsh_roundtrip("server_hello_rejected.bin", dec_server_hello, enc_server_hello)
    check(v["early_data_accepted"] is False, "server_hello_rejected accepted=false")


@vector
def hello_retry_request_cookie():
    v = borsh_roundtrip("hello_retry_request_cookie.bin", dec_hrr, enc_hrr)
    check(v["challenge"] is None, "hrr_cookie challenge None")
    check(v["cookie"] == arr32(0xF0), "hrr_cookie cookie filler")


@vector
def hello_retry_request_pow():
    v = borsh_roundtrip("hello_retry_request_pow.bin", dec_hrr, enc_hrr)
    check(v["cookie"] is None, "hrr_pow cookie None")
    check(v["challenge"]["difficulty"] == 20, "hrr_pow difficulty")
    check(v["challenge"]["nonce"] == arr32(0x90), "hrr_pow nonce filler")


@vector
def packet_header():
    raw = load("packet_header.bin")
    check(len(raw) == HEADER_SIZE, f"header must be {HEADER_SIZE} bytes")
    h = dec_packet_header(raw)
    check(h["version"] == WIRE_VERSION, "header version pin (byte 0)")
    # session_id is off-wire in v5 — no longer a wire field to check.
    check(h["stream_id"] == 7, "header stream_id")
    check(h["packet_number"] == 42, "header packet_number")
    check(h["flags"] == 0x0021, "header flags ENCRYPTED|RELIABLE")
    check(h["epoch"] == 3, "header epoch")
    check(h["path_id"] == 1, "header path_id")
    check(enc_packet_header(h) == raw, "header re-encode != fixture")


def _packet_roundtrip(name: str, payload: bytes):
    # No `extensions` comparison here: the decoder returns a constant empty slice,
    # so comparing it to an empty literal would assert nothing about the fixture.
    # What actually pins "extensions are off the wire" is that the payload the
    # caller writes out is the whole remainder after the 15-byte header.
    raw = load(name)
    p = dec_phantom_packet(raw)
    check(p["payload"] == payload, f"{name}: payload")
    check(p["header"]["version"] == WIRE_VERSION, f"{name}: header version")
    check(enc_phantom_packet(p) == raw, f"{name}: re-encode != fixture")
    return p


@vector
def phantom_packet_data():
    p = _packet_roundtrip("phantom_packet_data.bin", pat(0x11, 64))
    fl = p["header"]["flags"]
    check(fl & 0x0020 != 0 and fl & 0x0001 != 0, "data packet ENCRYPTED|RELIABLE")


@vector
def phantom_packet_ack():
    p = _packet_roundtrip("phantom_packet_ack.bin", b"")
    check(p["header"]["flags"] == 0x0002, "ack packet flags == ACK only")


@vector
def phantom_packet_extensions():
    # WIRE v6: the struct that produced this fixture had extensions set, but
    # they are DROPPED from the wire — the fixture is just header(15) ‖ payload(16),
    # and decoding yields EMPTY extensions. This pins "extensions off the wire".
    _packet_roundtrip("phantom_packet_extensions.bin", pat(0x11, 16))
    check(len(load("phantom_packet_extensions.bin")) == HEADER_SIZE + 16,
          "v6 ext fixture is header || payload only (no extension bytes)")


def enc_window_update(limit: int) -> bytes:
    """WINDOW_UPDATE AEAD plaintext: the cumulative limit, big-endian u64."""
    return struct.pack(">Q", limit)


def dec_window_update(raw: bytes) -> int:
    check(len(raw) == WINDOW_UPDATE_PAYLOAD_LEN,
          f"WINDOW_UPDATE plaintext must be exactly {WINDOW_UPDATE_PAYLOAD_LEN} bytes")
    return struct.unpack(">Q", raw)[0]


def apply_window_limit(held: int, sent: int, advertised: int) -> tuple[int, str]:
    """Fold one WINDOW_UPDATE into the state a sender is already holding.

    The state is two numbers, not one. ``held`` is the highest limit honoured so
    far; ``sent`` is the total this side has already put on the wire, counted the
    way § 4.5 counts it — each reliable application byte once, retransmissions not
    counted again, **and a first transmission the transport refused subtracted
    back**, since those bytes never left. Both are needed, because half the rule is
    a bound the peer's number is measured against rather than a comparison between
    two peer numbers, and a model carrying only ``held`` cannot express that half
    at all.

    That ``sent`` can fall is what makes the two halves independent rather than one
    rule wearing two names: the ceiling it fixes can drop below a limit already
    honoured, and the transcript exercises that state deliberately.

    Deliberately not written as ``max``. This file earns its keep by stating the
    rule a second implementation has to follow, and ``max(a, b)`` states nothing a
    reader could disagree with — it asserts that a builtin behaves like itself.
    Worse, it states the wrong rule: it honours whatever number arrives, and the
    number arrives from a peer that is authenticated but not trusted.

    Returns the settled total *and* which of the four cases the frame fell into.
    The case is returned because two of them settle on the same total — a
    duplicate and a stale frame both leave ``held`` where it was — so a rule that
    only reports the total makes "a duplicate grants nothing extra" and "a stale
    frame is discarded" one claim wearing two names, and the second of them is
    unverifiable prose. § 4.5 lists them as separate properties; naming which one
    a frame exercised is what keeps them separate here.
    """
    # What this side is willing to honour, whoever is writing the number. A peer
    # advertising u64::MAX buys exactly one window of permission beyond what has
    # already gone out and must send another frame for more — so the field is a
    # rate of permission per frame rather than a lever the peer can hold down.
    # Saturating in the normative implementation, where both are u64
    # (`core/src/transport/stream.rs`, `apply_peer_window_limit`). Python's integers
    # do not overflow, so the plain sum here is right by accident rather than by
    # construction — a port to a fixed-width language has to saturate, or a peer
    # writing a total near the type's maximum wraps the ceiling to a small number and
    # stops the stream.
    ceiling = sent + MAX_SEND_WINDOW
    if advertised > ceiling:
        # The local bound, not the peer's number, decided the outcome. It still
        # settles by maximum against `held`: a clamp is not a revocation, so an
        # oversized frame arriving after the ceiling has already been spent
        # leaves the total exactly where it was.
        return max(held, ceiling), "clamped"
    if advertised > held:
        # A genuine grant: the receiver has drained, and the total it is now
        # willing to have sent is the number on the wire — not that number added
        # to anything. The field counts from the stream's first byte, so adding
        # would credit the same bytes a second time and let the sender overrun a
        # receiver that never opened that much room.
        return advertised, "grant"
    if advertised == held:
        # A duplicate — the same frame retransmitted, or a peer restating an
        # unchanged total. It must move nothing. That idempotence is precisely
        # why the frame carries no sequence number and needs no acknowledgement.
        return held, "duplicate"
    # A smaller total is an older frame that lost the race with a newer one.
    # Discarding it is what keeps the window monotone: a receiver never revokes
    # room it has already granted, so a sender that acted on the larger total
    # cannot be retroactively put in the wrong by the network's ordering.
    return held, "stale"


@vector
def window_update_codec():
    """The flow-control plaintext's bytes, stated independently of the Rust.

    There is no frozen fixture — this is an AEAD plaintext, not an outer container —
    so the encoding is pinned against written-out byte strings rather than against
    itself. One of them needs all 64 bits on purpose: a reader that quietly truncated
    the cumulative total to 32 bits agrees with every small limit and diverges only on
    a long-lived stream, which is the hardest place to notice it.
    """
    for limit, encoded in [
        (165_536, "00000000000286a0"),
        (281_474_976_710_657, "0001000000000001"),
        (18_446_744_073_709_551_615, "ffffffffffffffff"),
    ]:
        raw = enc_window_update(limit)
        check(raw.hex() == encoded,
              f"WINDOW_UPDATE encoding of {limit}: got {raw.hex()}, expected {encoded}")
        check(dec_window_update(bytes.fromhex(encoded)) == limit,
              f"WINDOW_UPDATE decode of {encoded}: got "
              f"{dec_window_update(bytes.fromhex(encoded))}, expected {limit}")

    for bad in (b"", b"\x00\x00\x00\x01", b"\x00" * 9):
        try:
            dec_window_update(bad)
        except Failure:
            continue
        raise Failure(f"a {len(bad)}-byte WINDOW_UPDATE plaintext was accepted")


@vector
def window_update_limit_rule():
    """The rule a receiver of a WINDOW_UPDATE has to apply, on decoded frames.

    Every advertised total below reaches the rule the way a real one does — through
    the decoder — so a codec that misreads the field and a rule that misapplies it
    both land on this check instead of only one of them. The expected columns are
    written out rather than computed, because a table filled in by the very
    expression under test grades its own homework and would accept any rule at all.
    """
    # The two ends of the ledger are the same figure, and the spec says so in both
    # directions. Checked rather than arranged: were the sender's ceiling the smaller
    # of the two, a receiver advertising the whole window it is entitled to would have
    # the top of its grant silently discarded, and the stall that follows looks like a
    # slow path rather than a disagreement about a constant.
    check(MAX_SEND_WINDOW == MAX_RECV_WINDOW,
          f"the sender honours at most {MAX_SEND_WINDOW} but the receiver may advertise "
          f"up to {MAX_RECV_WINDOW}; § 4.5 makes them the same figure")

    # The rule's shape is part of what is being stated, and it is checked before anything
    # is asked of its arithmetic. A rule that reports only a total cannot tell a duplicate
    # from a stale frame — they settle on the same number — so collapsing this back to
    # `max(held, advertised)` is not a simplification but the loss of a claim, and it is
    # the exact restatement this vector exists to refuse. Checked here rather than inside
    # a loop so the collapse is reported as a broken contract and not as an unpacking
    # accident three assertions later.
    shape = apply_window_limit(INITIAL_STREAM_WINDOW, INITIAL_STREAM_WINDOW, 165_536)
    check(isinstance(shape, tuple) and len(shape) == 2 and isinstance(shape[1], str),
          f"the rule must report the settled total and which case it took, got {shape!r}")

    # Stated first among the arithmetic, and by name, because a sum also grows: "the
    # total went up" is not evidence against one, so a summing rule caught below would
    # be reported as an arithmetic mismatch rather than as the wrong rule. Summing is
    # what a port of the older relative-credit frame arrives at by inertia, and it is
    # the single wrong rule this second implementation exists to refuse.
    for held, sent, advertised in [(65_536, 65_536, 165_536), (165_536, 65_536, 165_536)]:
        settled, _ = apply_window_limit(held, sent, advertised)
        check(settled != held + advertised,
              f"applying {advertised} to {held} summed to {held + advertised}")

    # (frame bytes, held, already sent, held afterwards, which case the frame was)
    transcript = [
        # An opening grant against the limit every stream starts at.
        ("00000000000286a0", INITIAL_STREAM_WINDOW, 65_536, 165_536, "grant"),
        ("00000000000286a0", 165_536, 65_536, 165_536, "duplicate"),
        ("0000000000010000", 165_536, 65_536, 165_536, "stale"),
        ("00000000000286a1", 165_536, 65_536, 165_537, "grant"),
        # 0x0001_0000_0000_0001 is 281_474_976_710_657 — a peer buying itself room it
        # never granted. What it actually buys is one MAX_SEND_WINDOW past the 165_537
        # bytes already sent, and it has to send another frame for more.
        ("0001000000000001", 165_537, 165_537, 1_214_113, "clamped"),
        # Absurd again with nothing sent since: the ceiling is where it was, so this
        # frame moves nothing at all. The permission is per frame, not cumulative.
        ("ffffffffffffffff", 1_214_113, 165_537, 1_214_113, "clamped"),
        # ...and once those bytes have gone out, the same absurd number buys exactly
        # one more window. The clamp tracks what was sent; it is not a one-off ceiling.
        ("ffffffffffffffff", 1_214_113, 1_214_113, 2_262_689, "clamped"),
        # The ceiling below a limit already honoured — the one state that tells a clamp
        # apart from a revocation, and the reason the rule settles by maximum rather
        # than returning the ceiling outright. It is reachable, not hypothetical: § 4.5
        # subtracts a first transmission the transport refused back out of the sent
        # total, so the ceiling falls while the honoured limit stays where it was. A
        # rule that answered with the ceiling here would take back room this side has
        # already told itself it may use, and the sender would stop with permission it
        # had been granted.
        ("ffffffffffffffff", 1_214_113, 100_000, 1_214_113, "clamped"),
        # Exactly on the ceiling. § 4.5 bounds what a sender honours *at most* at one
        # window past the bytes already sent, so the boundary belongs to the grant: a
        # rule that clamps here settles on the same total by a different route and
        # reports a peer within its rights as one exceeding them.
        ("0000000000110000", 165_536, 65_536, 1_114_112, "grant"),
        # A total below the limit every stream starts at, offered before anything has
        # moved. It is stale, and only because that opening limit is 64 KiB: a second
        # implementation that started lower would read this frame as a duplicate and
        # conclude the peer had restated an unchanged total.
        ("0000000000008000", INITIAL_STREAM_WINDOW, 0, INITIAL_STREAM_WINDOW, "stale"),
        # A grant genuinely past 2^32 and genuinely under the ceiling, so nothing but
        # the decoder's width decides it. A reader that took only the low four bytes
        # sees 0 here and calls a real grant stale — the one failure that stays hidden
        # until a stream has run past four gigabytes, where it reads as a stall.
        ("0000000100000000", 4_294_000_000, 4_294_000_000, 4_294_967_296, "grant"),
        ("00000000ffffffff", 4_294_967_296, 4_294_000_000, 4_294_967_296, "stale"),
    ]
    for encoded, held, sent, expected, expected_case in transcript:
        advertised = dec_window_update(bytes.fromhex(encoded))
        after, case = apply_window_limit(held, sent, advertised)
        check(after == expected,
              f"applying {advertised} to a held total of {held} with {sent} sent gave "
              f"{after}, expected {expected}")
        check(case == expected_case,
              f"applying {advertised} to a held total of {held} with {sent} sent was "
              f"read as {case!r}, expected {expected_case!r}")

    # Order-independence is the property the frame is built around: the same grants
    # delivered in any order have to leave the sender holding one settled total. The
    # clamp does not disturb it — the ceiling is fixed by what this side has sent, not
    # by what arrived when — so a peer's oversized frame is free to sit anywhere in the
    # order. Only which frame gets *called* clamped moves with the order, which is why
    # this checks the settled total alone.
    sent = 65_536
    grants = [0x0000_0000_0002_86A0, 0x0000_0000_0002_8000, 0x0001_0000_0000_0001]
    for order in permutations(grants):
        held = INITIAL_STREAM_WINDOW
        for grant in order:
            held, _ = apply_window_limit(
                held, sent, dec_window_update(enc_window_update(grant)))
        check(held == 1_114_112,
              f"grants delivered as {[hex(g) for g in order]} settled at {held}, "
              "expected 1114112")


def main() -> int:
    check(VECTORS_DIR.is_dir(), f"vectors dir not found: {VECTORS_DIR}")
    passed = 0
    failed = 0
    for fn in CHECKS:
        try:
            fn()
            print(f"  ok    {fn.__name__}")
            passed += 1
        except (Failure, struct.error, IndexError, ValueError) as e:
            # struct.error / IndexError surface from a corrupt length prefix that
            # overruns the buffer — still a clean per-vector FAIL, not a traceback.
            print(f"  FAIL  {fn.__name__}: {e}")
            failed += 1
    print(f"\n{passed} passed, {failed} failed (independent decode of {VECTORS_DIR.name}/)")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
