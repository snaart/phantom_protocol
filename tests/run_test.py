import sys
import os
import asyncio
import time

# Add bindings directory to path
bindings_path = os.path.join(os.path.dirname(__file__), "bindings")
sys.path.append(bindings_path)

try:
    import phantom_core
except ImportError as e:
    print(f"Failed to import phantom_core: {e}")
    print(f"Ensure phantom_core.py is in {bindings_path}")
    sys.exit(1)

async def main():
    print("--- Phantom Core FFI Test ---")
    
    # Connection Config
    addr = "127.0.0.1:3001"
    group_id = bytes.fromhex("0102030405060708090a0b0c0d0e0f10")
    # Identity (ignored for now)
    identity = b"Alice"
    
    print(f"Connecting to {addr}...")
    try:
        # Read server cert for pinning
        with open("server.crt", "r") as f:
            cert_pem = f.read()

        # Connect returns Arc<PhantomClient>, which UniFFI exposes as the object
        # shared_secret removed. Added client_cert_pem=None, client_key_pem=None for mTLS
        client = await phantom_core.PhantomClient.connect(addr, group_id, identity, cert_pem, None, None)
        print("Connected!")
        
        # Send JOIN (as bytes)
        print("Sending JOIN...")
        await client.send_message(b"JOIN")
        
        # Listen for response (Echo)
        print("Waiting for message...")
        # In this demo, if we send a message, we might receive it back if we listen properly?
        # But recv_message is a single frame read.
        # If the server broadcasts, and we are the sender, do we get it back?
        # The server implementation broadcasts to "active" connections.
        # If we just connected, are we "active"? Yes.
        # Does the broadcast context include the sender?
        # In broadcast::channel, sender receives if it subscribes.
        # But we create a NEW tx for the group if not exists.
        # Code: `let tx = state.get_or_create_tx...; let rx = tx.subscribe(); ... tx.send(...)`
        # So yes, subscribers receive what is sent to the channel.
        # Since we subscribe immediately upon connection, we should receive our own JOIN message?
        # Maybe.
        
        rx_msg = await client.recv_message()
        print(f"Received: {rx_msg}")
        
        msg = b"Hello from Python"
        print(f"Sending: {msg}")
        await client.send_message(msg)
        
        rx_msg_2 = await client.recv_message()
        print(f"Received: {rx_msg_2}")
        
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(main())
