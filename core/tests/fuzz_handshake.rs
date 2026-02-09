//! Fuzzing tests for Unified Handshake Protocol
//! 
//! Uses `rand` to generate random inputs and verify robustness of
//! state transitions and parsing logic.

use phantom_core::transport::handshake::{HandshakeServer, HandshakeClient, ClientHello, HandshakeResponse};
use rand::Rng;

const FUZZ_ITERATIONS: usize = 1000;

#[test]
fn fuzz_process_client_hello() {
    let mut rng = rand::thread_rng();
    let server = HandshakeServer::new().unwrap();
    let client_ip = "127.0.0.1".parse().unwrap();
    
    for _ in 0..FUZZ_ITERATIONS {
        let mut bytes = vec![0u8; 1024];
        rng.fill(&mut bytes[..]);
        
        // Attempt to deserialize random bytes as ClientHello
        if let Ok(hello) = borsh::from_slice::<ClientHello>(&bytes) {
            // This should return Success, Retry, or Fail, but never panic
            let _ = server.process_client_hello(&hello, 0, client_ip);
        }
    }
}

#[test]
fn fuzz_garbage_input_to_server() {
    let mut rng = rand::thread_rng();
    let server = HandshakeServer::new().unwrap();
    let client_ip = "127.0.0.1".parse().unwrap();

    for _ in 0..FUZZ_ITERATIONS {
        let len = rng.gen_range(0..5000);
        let mut bytes = vec![0u8; len];
        rng.fill(&mut bytes[..]);

        // Handshake protocol logic usually involves Borsh deserialization first
        let res = borsh::from_slice::<ClientHello>(&bytes);
        if let Ok(hello) = res {
             let _ = server.process_client_hello(&hello, 5, client_ip);
        }
    }
}

#[test]
fn test_valid_handshake_flow() {
    let server = HandshakeServer::new().unwrap();
    let client = HandshakeClient::new().expect("HandshakeClient::new");
    let client_ip = "127.0.0.1".parse().unwrap();

    // 1. Client creates Hello
    let hello = client.create_client_hello();
    
    // 2. Server processes (should demand cookie/pow if difficulty > 0, but here 0)
    // Actually our server implementation currently always demands a cookie if it's missing.
    let response = server.process_client_hello(&hello, 0, client_ip);
    
    match response {
        HandshakeResponse::Retry(r) => {
            assert!(r.cookie.is_some());
            
            // 3. Client retries with cookie
            let mut hello_retry = hello.clone();
            hello_retry.cookie = r.cookie;
            
            let response2 = server.process_client_hello(&hello_retry, 0, client_ip);
            match response2 {
                HandshakeResponse::Success(server_hello, _) => {
                    // 4. Client processes server hello
                    client.process_server_hello(&hello_retry, &server_hello, Some(server.verifying_key())).expect("Handshake failed");
                }
                _ => panic!("Expected success on second try"),
            }
        }
        HandshakeResponse::Success(server_hello, _) => {
             client.process_server_hello(&hello, &server_hello, Some(server.verifying_key())).expect("Handshake failed");
        }
        HandshakeResponse::Fail(e) => panic!("Handshake failed: {:?}", e),
    }
}
