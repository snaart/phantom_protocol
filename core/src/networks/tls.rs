use anyhow::Result;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ServerConfig, ClientConfig, RootCertStore};
use rcgen::generate_simple_self_signed;

/// Generate self-signed certificate for testing
pub fn generate_self_signed_cert(subject_alt_names: Vec<String>) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let certified_key = generate_simple_self_signed(subject_alt_names)?;
    let cert_der = CertificateDer::from(certified_key.cert.der().to_vec());
    let priv_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certified_key.key_pair.serialize_der()));

    Ok((vec![cert_der], priv_key))
}

/// Configure TLS for server with self-signed certificate
pub fn configure_server_tls() -> Result<(ServerConfig, String)> {
    // Install default crypto provider for rustls 0.23
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Generate certificate for localhost and IP (for testing)
    let certified_key = generate_simple_self_signed(vec!["localhost".to_string(), "127.0.0.1".to_string()])?;
    let cert_der = CertificateDer::from(certified_key.cert.der().to_vec());
    let priv_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certified_key.key_pair.serialize_der()));
    let cert_pem = certified_key.cert.pem();

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], priv_key)?;

    Ok((config, cert_pem))
}

/// Configure TLS for client with optional certificate pinning
pub fn configure_client_tls(server_ca_pem: Option<String>) -> Result<ClientConfig> {
    // Install default crypto provider for rustls 0.23
    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut root_store = RootCertStore::empty();

    // If CA provided (Pinning Mode)
    if let Some(pem) = server_ca_pem {
        let mut reader = std::io::BufReader::new(pem.as_bytes());
        let certs = rustls_pemfile::certs(&mut reader)
            .collect::<Result<Vec<_>, _>>()?;
        for cert in certs {
            root_store.add(cert)?;
        }
    } else {
        // Use system WebPKI root certificates
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }

    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    Ok(config)
}