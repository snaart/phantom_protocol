use anyhow::Result;
use rustls::{Certificate, PrivateKey, ServerConfig, ClientConfig};
use std::sync::Arc;
use rcgen::generate_simple_self_signed;

pub fn generate_self_signed_cert(subject_alt_names: Vec<String>) -> Result<(Vec<Certificate>, PrivateKey)> {
    let cert = generate_simple_self_signed(subject_alt_names)?;
    let cert_der = cert.serialize_der()?;
    let priv_key = cert.serialize_private_key_der();
    
    Ok((
        vec![Certificate(cert_der)],
        PrivateKey(priv_key)
    ))
}

pub fn configure_server_tls() -> Result<(ServerConfig, String)> {
    let cert = generate_simple_self_signed(vec!["localhost".to_string(), "127.0.0.1".to_string()])?;
    let cert_der = cert.serialize_der()?;
    let priv_key = cert.serialize_private_key_der();
    let cert_pem = cert.serialize_pem()?;
    
    let config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(vec![Certificate(cert_der)], PrivateKey(priv_key))?;
        
    Ok((config, cert_pem))
}



pub fn configure_client_tls(server_ca_pem: Option<String>) -> Result<ClientConfig> {
    let mut root_store = rustls::RootCertStore::empty();
    
    // If CA provided, use it (Pinning Mode)
    if let Some(pem) = server_ca_pem {
        let mut reader = std::io::BufReader::new(pem.as_bytes());
        let certs = rustls_pemfile::certs(&mut reader)?;
        for cert in certs {
            root_store.add(&Certificate(cert))?;
        }
    } else {
        // Fallback or System Roots (Here empty for strictness or use webpki-roots)
        root_store.add_server_trust_anchors(
            webpki_roots::TLS_SERVER_ROOTS
                .iter()
                .map(|ta| {
                    rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                        ta.subject,
                        ta.spki,
                        ta.name_constraints,
                    )
                })
        );
    }
    
    let config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();
        
    Ok(config)
}
