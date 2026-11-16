//! HTTPS: rustls as Go's crypto/tls client is configured by a
//! tls_config, verifying against the system's roots by default.

use super::{Stream, Url};
use rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use rustls::crypto::{CryptoProvider, ring};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, RootCertStore,
    SignatureScheme, StreamOwned,
};
use std::io;
use std::net::TcpStream;
use std::sync::{Arc, OnceLock};

/// Where Go looks for the system's roots, in its order.
const ROOT_FILES: [&str; 6] = [
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/ca-bundle.pem",
    "/etc/pki/tls/cacert.pem",
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
    "/etc/ssl/cert.pem",
];

/// A tls_config, as PEM text.
#[derive(Default)]
pub struct Settings {
    pub ca: Option<String>,
    pub cert: Option<String>,
    pub key: Option<String>,
    pub server_name: Option<String>,
    pub insecure_skip_verify: bool,
    pub tls13_only: bool,
}

#[derive(Clone)]
pub struct Tls {
    config: Arc<ClientConfig>,
    /// The same, offering h2 then http/1.1 by ALPN, as Go's client.
    #[cfg(feature = "http2")]
    alpn: Arc<ClientConfig>,
    server_name: Option<String>,
}

pub fn certificates(pem: &str) -> Result<Vec<CertificateDer<'static>>, String> {
    let certs = CertificateDer::pem_slice_iter(pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("certificate: {e}"))?;
    match certs.is_empty() {
        true => Err("no certificate in PEM".into()),
        false => Ok(certs),
    }
}

type Version = &'static rustls::SupportedProtocolVersion;

/// TLS 1.2 and 1.3, or 1.3 only (min_version).
pub fn versions(tls13_only: bool) -> &'static [Version] {
    static BOTH: [Version; 2] =
        [&rustls::version::TLS13, &rustls::version::TLS12];
    match tls13_only {
        true => &BOTH[..1],
        false => &BOTH,
    }
}

impl Tls {
    pub fn new(settings: &Settings) -> Result<Tls, String> {
        let provider = Arc::new(ring::default_provider());
        let builder =
            ClientConfig::builder_with_provider(Arc::clone(&provider))
                .with_protocol_versions(versions(settings.tls13_only))
                .map_err(|e| e.to_string())?;
        let builder =
            match settings.insecure_skip_verify {
                true => builder.dangerous().with_custom_certificate_verifier(
                    Arc::new(Unverified(provider)),
                ),
                false => builder
                    .with_root_certificates(roots(settings.ca.as_deref())?),
            };
        let config = match (&settings.cert, &settings.key) {
            (Some(cert), Some(key)) => {
                let key = PrivateKeyDer::from_pem_slice(key.as_bytes())
                    .map_err(|e| format!("key: {e}"))?;
                builder
                    .with_client_auth_cert(certificates(cert)?, key)
                    .map_err(|e| format!("cert: {e}"))?
            }
            _ => builder.with_no_client_auth(),
        };
        #[cfg(feature = "http2")]
        let alpn = {
            let mut alpn = config.clone();
            alpn.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
            alpn
        };
        Ok(Tls {
            config: Arc::new(config),
            #[cfg(feature = "http2")]
            alpn: Arc::new(alpn),
            server_name: settings.server_name.clone(),
        })
    }
}

/// The CA given, or the system's: SSL_CERT_FILE, else the first of
/// Go's files found.
fn roots(ca: Option<&str>) -> Result<RootCertStore, String> {
    let mut store = RootCertStore::empty();
    let pem = match ca {
        Some(ca) => ca.to_owned(),
        None => {
            let env = std::env::var("SSL_CERT_FILE").ok();
            let mut files = env.iter().map(String::as_str).chain(ROOT_FILES);
            files
                .find_map(|file| std::fs::read_to_string(file).ok())
                .ok_or("no system roots: set ca_pem or ca_file")?
        }
    };
    for cert in certificates(&pem)? {
        // A bundle may hold certificates rustls cannot use: as Go,
        // the rest still count.
        if store.add(cert).is_err() && ca.is_some() {
            return Err("ca: a certificate rustls cannot use".into());
        }
    }
    Ok(store)
}

/// TLS over `stream` to `url`; no tls_config, the system's roots.
pub fn wrap(
    stream: TcpStream,
    url: &Url,
    tls: Option<&Tls>,
) -> io::Result<Box<dyn Stream>> {
    let tls = or_default(tls)?;
    let connection =
        ClientConnection::new(Arc::clone(&tls.config), server(url, tls)?)
            .map_err(io::Error::other)?;
    Ok(Box::new(StreamOwned::new(connection, stream)))
}

/// What a TLS connection to `url` offering h2 is made with.
#[cfg(feature = "http2")]
pub fn alpn(
    url: &Url,
    tls: Option<&Tls>,
) -> io::Result<(Arc<ClientConfig>, ServerName<'static>)> {
    let tls = or_default(tls)?;
    Ok((Arc::clone(&tls.alpn), server(url, tls)?))
}

fn or_default(tls: Option<&Tls>) -> io::Result<&Tls> {
    static DEFAULT: OnceLock<Result<Tls, String>> = OnceLock::new();
    match tls {
        Some(tls) => Ok(tls),
        None => DEFAULT
            .get_or_init(|| Tls::new(&Settings::default()))
            .as_ref()
            .map_err(|e| io::Error::other(e.clone())),
    }
}

fn server(url: &Url, tls: &Tls) -> io::Result<ServerName<'static>> {
    let name = tls.server_name.as_deref().unwrap_or(&url.name);
    ServerName::try_from(name.to_owned())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))
}

/// insecure_skip_verify: any certificate, signatures still checked.
#[derive(Debug)]
struct Unverified(Arc<CryptoProvider>);

impl ServerCertVerifier for Unverified {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        let algorithms = &self.0.signature_verification_algorithms;
        rustls::crypto::verify_tls12_signature(message, cert, dss, algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        let algorithms = &self.0.signature_verification_algorithms;
        rustls::crypto::verify_tls13_signature(message, cert, dss, algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{Client, get};
    use crate::testing::{self, CA, CLIENT_CERT, CLIENT_KEY, response};

    fn client(settings: Settings) -> Client {
        Client {
            tls: Some(Tls::new(&settings).unwrap()),
            ..Client::default()
        }
    }

    fn ca() -> Settings {
        Settings {
            ca: Some(CA.into()),
            ..Settings::default()
        }
    }

    /// HTTPS to a server whose certificate the given CA signed, by its
    /// name or address; not to one the CA does not vouch for.
    #[test]
    fn verifies_the_server_against_the_ca() {
        let server = testing::serve_tls(|r| {
            response("200 OK", "text/plain", &format!("hello {}", r.path))
        });
        let port = server.address.port();
        let by_ip = Url::parse(&format!("https://127.0.0.1:{port}/a")).unwrap();
        let answer = get(&by_ip, &client(ca()), "text/plain").unwrap();
        assert_eq!((answer.status, &answer.body[..]), (200, &b"hello /a"[..]));
        let by_name =
            Url::parse(&format!("https://localhost:{port}/b")).unwrap();
        let tls13 = Settings {
            tls13_only: true,
            ..ca()
        };
        assert!(get(&by_name, &client(tls13), "*/*").unwrap().ok());
        let other = Settings {
            server_name: Some("other.example".into()),
            ..ca()
        };
        let error = get(&by_ip, &client(other), "*/*").err().unwrap();
        assert!(error.to_string().contains("certificate"), "{error}");
        // The system's roots, where the host has them, do not know it.
        if let Ok(system) = Tls::new(&Settings::default()) {
            let system = Client {
                tls: Some(system),
                ..Client::default()
            };
            let error = get(&by_ip, &system, "*/*").err().unwrap();
            assert!(error.to_string().contains("certificate"), "{error}");
        }
        let insecure = Settings {
            insecure_skip_verify: true,
            ..Settings::default()
        };
        assert!(get(&by_ip, &client(insecure), "*/*").unwrap().ok());
    }

    #[test]
    fn reads_pem_settings() {
        assert_eq!(certificates(CA).unwrap().len(), 1);
        let error = certificates("no pem here").unwrap_err();
        assert_eq!(error, "no certificate in PEM");
        let with_client = Settings {
            cert: Some(CLIENT_CERT.into()),
            key: Some(CLIENT_KEY.into()),
            ..ca()
        };
        assert!(Tls::new(&with_client).is_ok());
        let bad_key = Settings {
            key: Some(
                "-----BEGIN PRIVATE KEY-----\nAA==\n\
                 -----END PRIVATE KEY-----\n"
                    .into(),
            ),
            ..with_client
        };
        assert!(Tls::new(&bad_key).err().unwrap().starts_with("cert:"));
        let not_ca = Settings {
            ca: Some(CLIENT_KEY.into()),
            ..Settings::default()
        };
        assert!(Tls::new(&not_ca).is_err());
        assert_eq!(versions(true).len(), 1);
        assert_eq!(versions(false).len(), 2);
    }
}
