use anyhow::Result;
use clap::{Parser, Subcommand};
use phantom_core::client::PhantomClient;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Connect to server and listen for messages
    Listen {
        #[arg(long, default_value = "127.0.0.1:3001")]
        addr: String,
        #[arg(long)]
        group_id: String, // Hex string
    },
    /// Send a message to a group
    Send {
        #[arg(long, default_value = "127.0.0.1:3001")]
        addr: String,
        #[arg(long)]
        group_id: String, // Hex string
        #[arg(long)]
        msg: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    match &cli.command {
        Commands::Listen { addr, group_id } => {
            let gid_bytes = hex::decode(group_id).expect("Invalid Hex GroupID");
            let client = PhantomClient::connect(
                addr.clone(),
                gid_bytes,
                vec![],           // identity (unused)
                None,             // server_ca_pem (no pinning)
                vec![],           // shared_secret
            ).await
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            
            // Send JOIN frame to register subscription
            client.send_message(b"JOIN".to_vec()).await
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("Connected to {}. Listening on Group {}...", addr, group_id);
            
            loop {
                let payload = client.recv_message().await
                    .map_err(|e| anyhow::anyhow!("{}", e))?;
                println!("Received: {:?}", String::from_utf8_lossy(&payload));
            }
        }
        Commands::Send { addr, group_id, msg } => {
            let gid_bytes = hex::decode(group_id).expect("Invalid Hex GroupID");
            let client = PhantomClient::connect(
                addr.clone(),
                gid_bytes,
                vec![],           // identity (unused)
                None,             // server_ca_pem (no pinning)
                vec![],           // shared_secret
            ).await
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            
            client.send_message(msg.as_bytes().to_vec()).await
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("Message sent!");
        }
    }
    Ok(())
}
