//! Syslog over TLS (RFC 5425): rustls on a non-blocking connection,
//! read when poll(2) finds it readable, as plain TCP is.

use crate::alloy::ListenerTls;
use rustls::RootCertStore;
use rustls::crypto::ring;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ServerConfig, ServerConnection, WebPkiClientVerifier};
use std::io::{self, Read};
use std::net::TcpStream;
use std::sync::Arc;

/// The listener's server settings, from its PEM certificates and key.
pub fn config(tls: &ListenerTls) -> Result<Arc<ServerConfig>, String> {
    let provider = Arc::new(ring::default_provider());
    let versions: &[_] = if tls.tls13_only {
        &[&rustls::version::TLS13]
    } else {
        &[&rustls::version::TLS13, &rustls::version::TLS12]
    };
    let builder = ServerConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(versions)
        .map_err(|e| e.to_string())?;
    let builder = match &tls.ca {
        None => builder.with_no_client_auth(),
        Some(ca) => {
            let mut roots = RootCertStore::empty();
            for cert in certificates(ca)? {
                roots.add(cert).map_err(|e| format!("ca: {e}"))?;
            }
            let verifier = WebPkiClientVerifier::builder_with_provider(
                Arc::new(roots),
                provider,
            );
            let verifier = verifier.build().map_err(|e| e.to_string())?;
            builder.with_client_cert_verifier(verifier)
        }
    };
    let key = PrivateKeyDer::from_pem_slice(tls.key.as_bytes())
        .map_err(|e| format!("key: {e}"))?;
    let config = builder
        .with_single_cert(certificates(&tls.cert)?, key)
        .map_err(|e| format!("cert: {e}"))?;
    Ok(Arc::new(config))
}

fn certificates(pem: &str) -> Result<Vec<CertificateDer<'static>>, String> {
    let certs = CertificateDer::pem_slice_iter(pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("certificate: {e}"))?;
    match certs.is_empty() {
        true => Err("no certificate in PEM".into()),
        false => Ok(certs),
    }
}

/// Reads what arrived on `stream` into `out`, decrypted, and sends the
/// handshake's answers; false when the connection ended or failed.
pub fn fill(
    tls: &mut ServerConnection,
    stream: &mut TcpStream,
    out: &mut Vec<u8>,
    chunk: &mut [u8],
) -> bool {
    let mut open = match tls.read_tls(stream) {
        Ok(0) => false,
        Ok(_) => true,
        Err(error) => error.kind() == io::ErrorKind::WouldBlock,
    };
    if let Err(error) = tls.process_new_packets() {
        eprintln!("Syslog: TLS: {error}");
        open = false;
    }
    loop {
        match tls.reader().read(chunk) {
            // The client's close_notify.
            Ok(0) => open = false,
            Ok(read) => {
                out.extend_from_slice(&chunk[..read]);
                continue;
            }
            Err(_) => {}
        }
        break;
    }
    while tls.wants_write() {
        if tls.write_tls(stream).is_err() {
            break;
        }
    }
    open
}
