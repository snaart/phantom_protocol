use phantom_core::network::framing::Framer;
use tokio::sync::broadcast;
use tokio::sync::RwLock;
use std::sync::Arc;
use std::collections::HashMap;
use anyhow::Result;
use log::{info, error};
use crate::db::Db;
use tokio::io::{AsyncRead, AsyncWrite};
use phantom_core::network::control::ControlMessage;


type GroupId = Vec<u8>;
type Tx = broadcast::Sender<Vec<u8>>;

use std::time::{Instant, Duration};
use std::net::IpAddr;

    // Pending Welcomes: RecipientIdentity -> List of Welcome Messages
    pub pending_welcomes: RwLock<HashMap<Vec<u8>, Vec<Vec<u8>>>>,
}

impl SharedState {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            groups: RwLock::new(HashMap::new()),
            ip_tracker: RwLock::new(HashMap::new()),
            key_packages: RwLock::new(HashMap::new()),
            pending_welcomes: RwLock::new(HashMap::new()),
        })
    }
// ... unchanged until get_or_create_tx ...
    
    pub async fn check_rate_limit(&self, ip: IpAddr) -> bool {
        let mut tracker = self.ip_tracker.write().await;
        let entry = tracker.entry(ip).or_insert((0, Instant::now()));
        
        if entry.1.elapsed() > Duration::from_secs(60) {
            *entry = (1, Instant::now());
            return true;
        }
        
        if entry.0 >= 10 {
            return false; // Limit exceeded
        }
        
        entry.0 += 1;
        true
    }

    pub async fn get_or_create_tx(&self, group_id: &[u8], auth_token: &[u8]) -> Result<Tx> {
        let mut map = self.groups.write().await;
        if let Some(tx) = map.get(group_id) {
            return Ok(tx.clone()); // Join existing: Allowed without token (Assumption: ID is secret)
        }
        
        // Creating NEW group: Require Auth Token
        // From Environment Variable or Default
        let env_token = std::env::var("PHANTOM_AUTH_TOKEN").unwrap_or_else(|_| "secret_token_123".to_string());
        let valid_token = env_token.as_bytes();
        
        if auth_token != valid_token {
             // Rejects empty tokens implicitly because valid_token is not empty.
             return Err(anyhow::anyhow!("Unauthorized: Invalid Token"));
        }

        // H-01: Limit Max Groups to prevent DoS (Memory Exhaustion)
        if map.len() >= 1000 {
            return Err(anyhow::anyhow!("Server at capacity: Max groups reached"));
        }
        
        let (tx, _) = broadcast::channel(100);
        map.insert(group_id.to_vec(), tx.clone());
        Ok(tx)
    }
    
    pub async fn cleanup(&self, group_id: &[u8]) {
        let mut map = self.groups.write().await;
        if let Some(tx) = map.get(group_id) {
            if tx.receiver_count() == 0 {
                info!("Garbage Collecting Group: {:?}", group_id);
                map.remove(group_id);
            }
        }
    }
}

pub async fn handle_connection<S>(mut stream: S, peer_ip: IpAddr, db: Option<Db>, state: Arc<SharedState>) -> Result<()> 
where S: AsyncRead + AsyncWrite + Unpin
{
    // Rate Limit Check
    if !state.check_rate_limit(peer_ip).await {
        error!("Rate Limit Exceeded for IP: {}", peer_ip);
        return Ok(()); // Drop connection silently or error
    }

    // Need to pin or split. stream.split() works on TcpStream.
    // For Generic, we can try verify split.
    // TlsStream<TcpStream> has split? 
    // Tokio I/O split works on generic.
    
    // Actually, TlsStream/TcpStream impl AsyncRead/Write required by Framer functions.
    // But Framer functions take &mut S.
    // We want full duplex loop.
    // We cannot easily split a generic S without Arc/Mutex or specific impl support.
    // tokio::io::split(stream) returns (ReadHalf, WriteHalf) using locking internally if needed.
    
    let (mut rd, mut wr) = tokio::io::split(stream);
    
    // Read first frame
    let (group_id, epoch, payload, auth_token) = Framer::read_frame(&mut rd).await?;
    info!("New Peer for Group: {:?} Epoch {}", group_id, epoch);
    
    // DB
    if let Some(database) = &db {
        if let Err(e) = database.insert_message(&group_id, epoch, &payload).await {
             error!("DB Insert Error: {}", e);
        }
    }
    
    // Auth Check Logic: If group_id is Zero ([0;16]), it's Control Plane.
    let zero_id = [0u8; 16];
    
    if group_id == zero_id {
        // Control Plane Handling: Loop for multiple commands
        
        // Handle FIRST message
        process_control_msg(&payload, &db, &state, &mut wr).await?;
        
        loop {
            // Read NEXT frame
             match Framer::read_frame(&mut rd).await {
                Ok((gid, _, pay, _)) => {
                    if gid != zero_id {
                        error!("Protocol Error: Mixed Group IDs on Control Stream");
                        break;
                    }
                    process_control_msg(&pay, &db, &state, &mut wr).await?;
                }
                Err(_) => break, // EOF or Error
             }
        }
        
        return Ok(()); 
    }

    // Normal Chat Group Logic

    // Normal Chat Group Logic
    // If group needs creation, check auth_token.
    let tx = match state.get_or_create_tx(&group_id, &auth_token).await {
        Ok(tx) => tx,
        Err(e) => {
            error!("Connection Refused: {}", e);
            return Ok(());
        }
    };
    let mut rx = tx.subscribe();
    
    // Broadcast first message (convert Bytes -> Vec<u8>)
    let _ = tx.send(payload.to_vec());

    loop {
        tokio::select! {
            res = Framer::read_frame(&mut rd) => {
                match res {
                    Ok((g_id, ep, pay, _)) => { // Ignore auth_token on subsequent frames
                        if let Some(database) = &db {
                            if let Err(e) = database.insert_message(&g_id, ep, &pay).await {
                                 error!("DB Error: {}", e);
                            }
                        }
                        // Broadcast
                        let _ = tx.send(pay.to_vec());
                    }
                    Err(_) => break, 
                }
            }
            Ok(msg_payload) = rx.recv() => {
                // Write frame (Server auth token empty? Yes)
                if let Err(e) = Framer::write_frame(&mut wr, &group_id, 0, &msg_payload, &[]).await {
                    error!("Write error: {}", e);
                    break;
                }
            }
        }
    }
    
    // Cleanup on disconnect
    drop(rx); // Drop receiver first so receiver_count decreases
    state.cleanup(&group_id).await;
    
    Ok(())
}

// We need to pass State to process_control_msg
async fn process_control_msg<W>(payload: &[u8], db: &Option<Db>, state: &SharedState, wr: &mut W) -> Result<()> 
where W: AsyncWrite + Unpin
{
    use phantom_core::network::serialization::deserialize;
    use phantom_core::network::control::ControlMessage;
    
    // Rkyv requires alignment. Frame header is 30 bytes (not 4-byte aligned).
    // Copy to new Vec to ensure alignment.
    let payload_aligned = payload.to_vec();
    
    info!("Processing Control Payload: {} bytes, Data: {:?}", payload_aligned.len(), &payload_aligned[0..std::cmp::min(20, payload_aligned.len())]);
    
    let control_msg: ControlMessage = match deserialize(&payload_aligned) {
        Ok(m) => m,
        Err(e) => {
            error!("Invalid Control Message: {}", e);
            return Ok(());
        }
    };
    
    match control_msg {
        ControlMessage::Register { identity, key_package, signature, verifying_key } => {
            info!("Control: Register Identity {:?}", identity);
            
            // 1. Verify Identity Binding (Identity == BLAKE3(VerifyingKey))
            let calculated_identity = blake3::hash(&verifying_key).as_bytes().to_vec();
            if identity != calculated_identity {
                 error!("Security Alert: Identity Spoofing Attempt! Claimed: {:?}, Calculated: {:?}", identity, calculated_identity);
                 return Ok(());
            }

            // 2. Verify Signature
            // Signature covers: Identity ++ KeyPackage
            use ed25519_dalek::{Verifier, VerifyingKey, Signature};
            
            let key_bytes: &[u8; 32] = match verifying_key.as_slice().try_into() {
                Ok(bytes) => bytes,
                Err(_) => {
                    error!("Invalid verifying key length: expected 32 bytes, got {}", verifying_key.len());
                    return Ok(());
                }
            };

            let vk = match VerifyingKey::from_bytes(key_bytes) {
                Ok(k) => k,
                Err(e) => {
                     error!("Invalid Verifying Key bytes: {}", e);
                     return Ok(());
                }
            };
            
            let sig = match Signature::from_slice(&signature) {
                Ok(s) => s,
                Err(_) => {
                    error!("Invalid Signature format");
                    return Ok(());
                }
            };
            
            let mut msg = Vec::new();
            msg.extend_from_slice(&identity);
            msg.extend_from_slice(&key_package);
            
            if let Err(e) = vk.verify(&msg, &sig) {
                 error!("Security Alert: Invalid Signature! {}", e);
                 return Ok(());
            }

            info!("Identity Verified. Proceeding to Upload.");

            if let Some(database) = &db {
                if let Err(e) = database.upload_key_package(&identity, &key_package).await {
                     error!("DB Upload Error: {}", e);
                }
            } else {
                // In-Memory Fallback
                info!("Using In-Memory Store for Register");
                let mut guard = state.key_packages.write().await;
                guard.insert(identity.clone(), key_package);
            }
            // Ack? MVP: No Ack for Register.
        }
        ControlMessage::FetchKeyPackage { identity } => {
            info!("Control: Fetch Identity {:?}", identity);
            
            let pkg_opt = if let Some(database) = &db {
                 match database.fetch_key_package(&identity).await {
                     Ok(pkg) => pkg,
                     Err(e) => {
                         error!("DB Fetch Error: {}", e);
                         None
                     },
                 }
            } else {
                 // In-Memory Fallback
                 info!("Using In-Memory Store for Fetch");
                 let guard = state.key_packages.read().await;
                 guard.get(&identity).cloned()
            };

            let resp = ControlMessage::KeyPackageResponse { key_package: pkg_opt };
             
             // Serialize Response
             use phantom_core::network::serialization::serialize;
             let resp_bytes = serialize(&resp).unwrap_or_default();
             
             // Reply 
             let zero_id = [0u8; 16];
             if let Err(e) = Framer::write_frame(wr, &zero_id, 0, &resp_bytes, &[]).await {
                 error!("Write Response Error: {}", e);
             }
        }
        ControlMessage::DeliverWelcome { recipient_identity, welcome_message } => {
            info!("Control: DeliverWelcome to {:?}", recipient_identity);
            // Store in Memory (Demo Mode)
            // In Production: DB.insert_welcome(...)
            let mut guard = state.pending_welcomes.write().await;
            let entry = guard.entry(recipient_identity).or_insert(Vec::new());
            entry.push(welcome_message);
            info!("Welcome Stored. Pending count: {}", entry.len());
        }
        ControlMessage::FetchWelcome { identity } => {
            info!("Control: FetchWelcome for {:?}", identity);
            
            // In Production: DB.fetch_and_delete_welcomes(...)
            let mut guard = state.pending_welcomes.write().await;
            let messages = guard.remove(&identity).unwrap_or_default();
            
            info!("Returning {} pending Welcomes", messages.len());
            
            let resp = ControlMessage::WelcomeResponse { welcomes: messages };
             
             // Serialize Response
             use phantom_core::network::serialization::serialize;
             let resp_bytes = serialize(&resp).unwrap_or_default();
             
             let zero_id = [0u8; 16];
             if let Err(e) = Framer::write_frame(wr, &zero_id, 0, &resp_bytes, &[]).await {
                 error!("Write Response Error: {}", e);
             }
        }
        _ => {
            // Check for previous handlers match logic if mixed
            // Assuming this is exhaustive for new enum variants if we remove `_ => {}`
        }
    }
    Ok(())
}
