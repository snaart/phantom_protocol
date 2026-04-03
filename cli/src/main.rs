use phantom_core::crypto::hybrid_kem::HybridSecretKey;

fn main() {
    println!("--- Quantum Rust Teapot CLI ---");
    println!("Generating Hybrid Keypair (X25519 + ML-KEM-768)...");

    let (sk, pk) = HybridSecretKey::generate();

    println!("Keys generated successfully!");
    // println!("X25519 PK: {:?}", pk.x25519_pk); // Bytes
    println!("X25519 PK: [32 bytes]");
    println!("ML-KEM-768 PK Size: {} bytes (Expected ~1184)", pk.ml_kem_pk.len());
    println!("Secret Key Debug: {:?}", sk);

    println!("\nCore library functional.");
}
