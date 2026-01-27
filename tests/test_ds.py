import socket
import struct
import time
import os

# Constants
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 3001
ZERO_GROUP = b'\x00' * 16

# Simple rkyv serialization is complex to verify in Python without bindings.
# However, we can use the FFI binding if we update it, or just send raw bytes that *look* like rkyv if we knew the format.
# A better approach: Create a specific Rust generic client binary `phantom_cli` with a `ds-test` command?
# OR: Update `run_test.py` to use `PhantomClient` but exposing new methods.
# Since `ControlMessage` is internal to `core`'s network stack, passing it via `PhantomClient` requires new FFI methods.

# Let's create a minimal Rust test binary instead of Python because rkyv serialization is binary-specific.
# Creating `tests/ds_test.rs` which uses `phantom_core` directly.
