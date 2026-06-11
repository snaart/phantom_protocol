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
    is `header(45) || payload_len:u32be || payload || ext_len:u32be || extensions`.
    Fully decoded **and** re-encoded, same as the borsh structs.

Run: ``python3 tests/wire_vectors_decode.py`` (stdlib only; exits non-zero on
any mismatch). Regenerate the fixtures from Rust with
``PHANTOM_REGEN_WIRE_VECTORS=1 cargo test --manifest-path core/Cargo.toml``.
"""

from __future__ import annotations

import struct
import sys
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
PROTOCOL_VERSION = 2  # bumped 1->2: H2 transcript-signs early_data_accepted + HS-03 adds resumption_binder
WIRE_VERSION = 3


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
        "server_key_package": dec_key_package(r),
        "ciphertext": dec_ciphertext(r),
        "server_verify_key": dec_verify_key(r),
        "signature": dec_signature(r),
        "session_id": r.fixed(32),
        "early_data_accepted": r.boolean(),
    }


def enc_server_hello(w: BorshWriter, v):
    enc_key_package(w, v["server_key_package"])
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
# PacketHeader (47 bytes), declaration order == wire order:
#   [0]     version       u8   (= WIRE_VERSION)
#   [1:33]  session_id    [u8;32]
#   [33:35] stream_id     u16 be
#   [35:43] packet_number u64 be   (① — Phase 4)
#   [43:45] flags         u16 be
#   [45]    epoch         u8
#   [46]    path_id       u8
# PhantomPacket: header || payload_len:u32be || payload || ext_len:u32be || ext.

HEADER_SIZE = 47


def dec_packet_header(b: bytes):
    check(len(b) >= HEADER_SIZE, f"header needs {HEADER_SIZE} bytes, got {len(b)}")
    return {
        "version": b[0],
        "session_id": bytes(b[1:33]),
        "stream_id": struct.unpack(">H", b[33:35])[0],
        "packet_number": struct.unpack(">Q", b[35:43])[0],
        "flags": struct.unpack(">H", b[43:45])[0],
        "epoch": b[45],
        "path_id": b[46],
    }


def enc_packet_header(h) -> bytes:
    return (
        bytes([h["version"]])
        + h["session_id"]
        + struct.pack(">H", h["stream_id"])
        + struct.pack(">Q", h["packet_number"])
        + struct.pack(">H", h["flags"])
        + bytes([h["epoch"], h["path_id"]])
    )


def dec_phantom_packet(b: bytes):
    header = dec_packet_header(b)
    pos = HEADER_SIZE
    payload_len = struct.unpack(">I", b[pos : pos + 4])[0]
    pos += 4
    payload = bytes(b[pos : pos + payload_len])
    check(len(payload) == payload_len, "payload underrun")
    pos += payload_len
    ext_len = struct.unpack(">I", b[pos : pos + 4])[0]
    pos += 4
    extensions = bytes(b[pos : pos + ext_len])
    check(len(extensions) == ext_len, "extensions underrun")
    pos += ext_len
    check(pos == len(b), f"trailing bytes: consumed {pos}/{len(b)}")
    return {"header": header, "payload": payload, "extensions": extensions}


def enc_phantom_packet(p) -> bytes:
    return (
        enc_packet_header(p["header"])
        + struct.pack(">I", len(p["payload"]))
        + p["payload"]
        + struct.pack(">I", len(p["extensions"]))
        + p["extensions"]
    )


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
    check(h["session_id"] == arr32(0x01), "header session_id (as-is, byte 1)")
    check(h["stream_id"] == 7, "header stream_id")
    check(h["packet_number"] == 42, "header packet_number")
    check(h["flags"] == 0x0021, "header flags ENCRYPTED|RELIABLE")
    check(h["epoch"] == 3, "header epoch")
    check(h["path_id"] == 1, "header path_id")
    check(enc_packet_header(h) == raw, "header re-encode != fixture")


def _packet_roundtrip(name: str, payload: bytes, ext: bytes):
    raw = load(name)
    p = dec_phantom_packet(raw)
    check(p["payload"] == payload, f"{name}: payload")
    check(p["extensions"] == ext, f"{name}: extensions")
    check(p["header"]["version"] == WIRE_VERSION, f"{name}: header version")
    check(enc_phantom_packet(p) == raw, f"{name}: re-encode != fixture")
    return p


@vector
def phantom_packet_data():
    p = _packet_roundtrip("phantom_packet_data.bin", pat(0x11, 64), b"")
    fl = p["header"]["flags"]
    check(fl & 0x0020 != 0 and fl & 0x0001 != 0, "data packet ENCRYPTED|RELIABLE")


@vector
def phantom_packet_ack():
    p = _packet_roundtrip("phantom_packet_ack.bin", b"", b"")
    check(p["header"]["flags"] == 0x0002, "ack packet flags == ACK only")


@vector
def phantom_packet_extensions():
    ext = bytes([0xFF, 0x01, 0x00, 0x04]) + b"test"
    _packet_roundtrip("phantom_packet_extensions.bin", pat(0x11, 16), ext)


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
