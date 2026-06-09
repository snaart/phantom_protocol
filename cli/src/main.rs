use clap::{Parser, Subcommand};

mod keygen;
mod ping;
mod pubkey;
mod version;

#[derive(Parser, Debug)]
#[command(name = "phantom-cli", version, about = "Phantom Protocol admin CLI")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Generate a new HybridSigningKey and save it to a file.
    Keygen(keygen::Args),
    /// Print the verifying-key hex from a signing-key file (for client pinning).
    Pubkey(pubkey::Args),
    /// Connect via connect_pinned, send a message, await echo, print round-trip.
    Ping(ping::Args),
    /// Print version and compile-time feature set.
    Version,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Keygen(args) => keygen::run(args),
        Cmd::Pubkey(args) => pubkey::run(args),
        Cmd::Ping(args) => ping::run(args).await,
        Cmd::Version => version::run(),
    }
}
