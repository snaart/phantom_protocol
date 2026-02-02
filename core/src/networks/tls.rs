use anyhow::Result;
use rustls::pki_types::PrivateKeyDer;
use rustls::{ClientConfig, RootCertStore};

/// Configure TLS for client with optional certificate pinning
pub fn configure_client_tls(
    server_ca_pem: Option<String>,
    client_cert: Option<String>,
    client_key: Option<String>
) -> Result<ClientConfig> {
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
        // SECURITY: Certificate pinning is REQUIRED for production
        // Falling back to system roots is a security risk
        if !cfg!(debug_assertions) {
             return Err(anyhow::anyhow!(
                "Certificate pinning is required. \
                 Provide server CA certificate via server_ca_pem parameter. \
                 Using system WebPKI roots is disabled for security in release mode."
            ));
        }
        log::warn!("Using system WebPKI roots (DEBUG MODE ONLY)");
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }

    let builder = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_root_certificates(root_store);

    let config = if let (Some(cert_pem), Some(key_pem)) = (client_cert, client_key) {
        let mut cert_reader = std::io::BufReader::new(cert_pem.as_bytes());
        let certs = rustls_pemfile::certs(&mut cert_reader).collect::<Result<Vec<_>, _>>()?;
        
        // Parse key
        let mut key_reader = std::io::BufReader::new(key_pem.as_bytes());
        // Try pkcs8
        let key = if let Some(pkcs8) = rustls_pemfile::pkcs8_private_keys(&mut key_reader).next() {
             PrivateKeyDer::Pkcs8(pkcs8?)
        } else {
            // Reset reader
             let mut key_reader = std::io::BufReader::new(key_pem.as_bytes());
             if let Some(rsa) = rustls_pemfile::private_key(&mut key_reader)? {
                 rsa
             } else {
                 return Err(anyhow::anyhow!("No private key found"));
             }
        };

        builder.with_client_auth_cert(certs, key)?
    } else {
        builder.with_no_client_auth()
    };

    Ok(config)
}