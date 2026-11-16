//! Helpers the tests share: an HTTP server on loopback that answers
//! each request as a test says and keeps what it was sent, over TLS
//! too, and a scratch directory of the test's own.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;

/// A CA of the tests' own, and the server (`localhost`, 127.0.0.1) and
/// client certificates it signed, valid for 100 years: made by openssl
/// (P-256), the CA's key thrown away.
#[cfg(feature = "tls")]
pub const CA: &str = include_str!("testdata/ca.pem");
#[cfg(feature = "tls")]
pub const SERVER_CERT: &str = include_str!("testdata/server.pem");
#[cfg(feature = "tls")]
pub const SERVER_KEY: &str = include_str!("testdata/server.key");
#[cfg(feature = "tls")]
pub const CLIENT_CERT: &str = include_str!("testdata/client.pem");
#[cfg(feature = "tls")]
pub const CLIENT_KEY: &str = include_str!("testdata/client.key");
/// An RSA key (2048 bits, PKCS #8), as Google's service accounts have.
#[cfg(feature = "tls")]
pub const RSA_KEY: &str = include_str!("testdata/rsa.key");

/// A request as the server read it: its head's lines and its body.
#[derive(Clone)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Request {
    /// A header's value, its name in any case.
    pub fn header(&self, name: &str) -> Option<&str> {
        let found = self
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name));
        found.map(|(_, v)| v.as_str())
    }
}

pub struct Server {
    pub address: SocketAddr,
    requests: Arc<Mutex<Vec<Request>>>,
}

impl Server {
    /// `http://127.0.0.1:port` and `path`.
    pub fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.address)
    }

    /// What it was sent so far.
    pub fn requests(&self) -> Vec<Request> {
        self.requests.lock().unwrap().clone()
    }
}

/// A server answering one request per connection, as this agent's
/// client makes them, with `answer`'s raw response. It lives as long
/// as the test process: tests run in threads of one.
pub fn serve<F>(answer: F) -> Server
where
    F: Fn(&Request) -> String + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let kept = Arc::clone(&requests);
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            exchange(stream, &answer, &kept);
        }
    });
    Server { address, requests }
}

/// A TLS server's settings with SERVER_CERT, no client certificate.
#[cfg(feature = "tls")]
pub fn server_config() -> rustls::ServerConfig {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let chain = CertificateDer::pem_slice_iter(SERVER_CERT.as_bytes());
    let key = PrivateKeyDer::from_pem_slice(SERVER_KEY.as_bytes()).unwrap();
    rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain.map(Result::unwrap).collect(), key)
        .unwrap()
}

/// As `serve`, over TLS with SERVER_CERT.
#[cfg(feature = "tls")]
pub fn serve_tls<F>(answer: F) -> Server
where
    F: Fn(&Request) -> String + Send + 'static,
{
    let config = Arc::new(server_config());
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let kept = Arc::clone(&requests);
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let tls = rustls::ServerConnection::new(Arc::clone(&config));
            let stream = rustls::StreamOwned::new(tls.unwrap(), stream);
            exchange(stream, &answer, &kept);
        }
    });
    Server { address, requests }
}

/// As `serve`, on a Unix socket at `path`: Docker's API.
pub fn serve_unix<F>(path: &Path, answer: F)
where
    F: Fn(&Request) -> String + Send + 'static,
{
    let listener = UnixListener::bind(path).unwrap();
    let kept = Arc::default();
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            exchange(stream, &answer, &kept);
        }
    });
}

fn exchange<S, F>(mut stream: S, answer: &F, kept: &Mutex<Vec<Request>>)
where
    S: Read + Write,
    F: Fn(&Request) -> String,
{
    let Some(request) = read(&mut BufReader::new(&mut stream)) else {
        return;
    };
    let response = answer(&request);
    kept.lock().unwrap().push(request);
    let _ = stream.write_all(response.as_bytes());
}

fn read(reader: &mut impl BufRead) -> Option<Request> {
    let mut line = String::new();
    reader.read_line(&mut line).ok()?;
    let mut first = line.split_whitespace();
    let method = first.next()?.to_owned();
    let path = first.next()?.to_owned();
    let mut headers = Vec::new();
    loop {
        line.clear();
        reader.read_line(&mut line).ok()?;
        let Some((name, value)) = line.trim_end().split_once(':') else {
            break;
        };
        headers.push((name.to_owned(), value.trim().to_owned()));
    }
    let mut request = Request {
        method,
        path,
        headers,
        body: Vec::new(),
    };
    let length = request.header("Content-Length").map(str::parse::<usize>);
    request.body = vec![0; length.and_then(Result::ok).unwrap_or(0)];
    reader.read_exact(&mut request.body).ok()?;
    Some(request)
}

/// A whole response: `status` (`200 OK`), `kind` and `body`.
pub fn response(status: &str, kind: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: {kind}\r\n\
         Content-Length: {}\r\n\r\n{body}",
        body.len()
    )
}

/// A new, empty directory for the test `name`.
pub fn scratch(name: &str) -> PathBuf {
    let id = std::process::id();
    let dir = std::env::temp_dir().join(format!("host-agent-{name}-{id}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}
