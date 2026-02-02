use phantom_core::client::PhantomClient;
use std::time::Duration;
use tokio::time::sleep;

#[tokio::test]
async fn test_welcome_flow() -> anyhow::Result<()> {
    // Requires a running server at localhost:3001
    let addr = "127.0.0.1:3001".to_string();
    
    let cert_path = if std::path::Path::new("server.crt").exists() {
        "server.crt"
    } else {
        "../server.crt" // In case running from core/
    };
    
    let server_ca_pem = if std::path::Path::new(cert_path).exists() {
         Some(std::fs::read_to_string(cert_path).expect("Read cert"))
    } else {
         println!("Warning: server.crt not found. TLS might fail if not in test env.");
         None
    };

    println!("--- 1. Bob Setup (The Joiner) ---");
    // Bob needs to register his KeyPackage first so Alice can add him.
    let bob_group_id = vec![0u8; 16]; // No group yet
    let bob_temp_identity = b"bob_init".to_vec(); // Temp identity for connection
    
    let bob = PhantomClient::connect(
        addr.clone(),
        bob_group_id.clone(),
        bob_temp_identity,
        server_ca_pem.clone(),
        vec![] 
    ).await.expect("Bob Connect");
    
    let kp_res = bob.generate_key_package_details()?;
    println!("Bob generated identity: {:?}", kp_res.identity);
    
    bob.register(kp_res.clone()).await.expect("Bob Register");
    println!("Bob Registered!");
    
    // Keep bob client alive to fetch invites later.
    // `fetch_welcomes` takes `identity` arg, so we use Bob's real identity.
    
    println!("--- 2. Alice Setup (The Creator) ---");
    let alice_group_id = b"test_group_wlcm".to_vec();
    let alice_identity = b"alice_user".to_vec();
    
    let alice = PhantomClient::connect(
        addr.clone(),
        alice_group_id.clone(),
        alice_identity,
        server_ca_pem.clone(),
        vec![]
    ).await.expect("Alice Connect");
    
    // Alice is now in a single-user group (created in connect)
    
    println!("--- 3. Alice Adds Bob ---");
    alice.add_member(kp_res.identity.clone()).await.expect("Alice Add Member");
    println!("Alice added Bob (Welcome sent via Server)");
    
    println!("--- 4. Bob Fetches Welcome ---");
    // Bob needs to connect using his REAL identity? Or just fetch using his real ID.
    // The previous `bob` client is connected.
    
    // Wait for server to process/store welcome
    sleep(Duration::from_millis(500)).await;
    
    let welcomes = bob.fetch_welcomes(kp_res.identity.clone()).await.expect("Fetch Welcomes");
    assert!(!welcomes.is_empty(), "Bob should have received a welcome");
    
    let welcome_bytes = welcomes[0].clone();
    println!("Bob received {} bytes of welcome", welcome_bytes.len());
    
    println!("--- 5. Bob Joins Group ---");
    bob.join_group(welcome_bytes).await.expect("Bob Join");
    
    println!("--- 6. E2EE Test ---");
    let msg_content = b"Hello Bob, welcome to the Matrix!".to_vec();
    alice.send_message(msg_content.clone()).await.expect("Alice Send");
    
    // Bob waits for message
    sleep(Duration::from_millis(500)).await;
    
    let received = bob.recv_message().await.expect("Bob Recv");
    println!("Bob Received: {:?}", String::from_utf8_lossy(&received));
    
    assert_eq!(received, msg_content);
    
    Ok(())
}
