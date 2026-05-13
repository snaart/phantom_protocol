use std::time::Instant;

use anyhow::{Context, Result};
use clap::Args as ClapArgs;
use tokio::time::Duration;

#[derive(ClapArgs, Debug)]
pub struct Args {
    /// Target hostname or IP address.
    #[arg(long)]
    pub host: String,

    /// Target port number.
    #[arg(long)]
    pub port: u16,

    /// Server's verifying-key hex (for pinning). Obtain via `phantom-cli pubkey`.
    #[arg(long)]
    pub pinned_key_hex: String,

    /// Message payload to send (default: "ping").
    #[arg(long, default_value = "ping")]
    pub msg: String,

    /// Whole-flow timeout in seconds (default: 5).
    #[arg(long, default_value_t = 5)]
    pub timeout_secs: u64,
}

pub async fn run(args: Args) -> Result<()> {
    let pinned_key_bytes =
        hex::decode(&args.pinned_key_hex).context("pinned-key-hex is not valid hex")?;

    let timeout = Duration::from_secs(args.timeout_secs);
    let msg_bytes = args.msg.as_bytes().to_vec();

    let start = Instant::now();

    let result = tokio::time::timeout(timeout, async {
        let session = phantom_core::api::session::connect_pinned(
            args.host.clone(),
            args.port,
            pinned_key_bytes,
        )
        .await
        .context("connect_pinned failed")?;

        session.send(msg_bytes).await.context("send failed")?;

        let reply = session.recv().await.context("recv failed")?;
        anyhow::Ok(reply)
    })
    .await
    .context("operation timed out")?;

    let rtt = start.elapsed();
    let reply = result?;

    println!("rtt: {:?}", rtt);
    println!("reply ({} bytes): {}", reply.len(), hex::encode(&reply));

    Ok(())
}
