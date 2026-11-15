//! An HTTP/1.1 client for scrapes and pushes, as Alloy's HTTP client
//! settings configure it (auth, headers, proxy, redirects, TLS), and
//! for Docker's socket: one request per connection (`Connection:
//! close`), so a response ends where the stream does.

pub mod auth;
mod aws_profile;
pub mod azure;
#[cfg(feature = "tls")]
mod azure_cert;
#[cfg(feature = "tls")]
pub mod google;
#[cfg(feature = "http2")]
mod h2;
pub mod proxy;
pub mod sigv4;
#[cfg(feature = "tls")]
pub mod tls;

use auth::Auth;
use proxy::Proxy;
use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

pub const TIMEOUT: Duration = Duration::from_secs(10);
/// A runaway response stops here instead of taking the host's memory.
const MAX_RESPONSE: u64 = 64 << 20;
/// Go's http.Client gives up after as many.
const MAX_REDIRECTS: usize = 10;

/// How requests to an endpoint are made: Alloy's HTTP client settings.
#[derive(Clone)]
pub struct Client {
    pub timeout: Duration,
    /// Header lines sent with every request, each ending in CR LF.
    pub headers: String,
    pub auth: Auth,
    pub follow_redirects: bool,
    pub proxy: Proxy,
    /// tls_config; None, the system's roots.
    #[cfg(feature = "tls")]
    pub tls: Option<tls::Tls>,
    /// enable_http2: offered over TLS.
    #[cfg(feature = "http2")]
    pub http2: bool,
}

impl Default for Client {
    fn default() -> Client {
        Client {
            timeout: TIMEOUT,
            headers: String::new(),
            auth: Auth::None,
            follow_redirects: true,
            proxy: Proxy::Direct,
            #[cfg(feature = "tls")]
            tls: None,
            #[cfg(feature = "http2")]
            http2: false,
        }
    }
}

#[derive(Clone)]
pub struct Url {
    /// `host:port`, the port filled in: where to connect.
    pub authority: String,
    /// The host as the URL has it, for the Host header.
    pub host: String,
    /// The host without port or brackets, for TLS.
    pub name: String,
    pub path: String,
    pub tls: bool,
}

impl Url {
    /// An http:// URL, or https:// with feature `tls`.
    pub fn parse(url: &str) -> Option<Url> {
        let (tls, rest) = match url.strip_prefix("http://") {
            Some(rest) => (false, rest),
            None if cfg!(feature = "tls") => {
                (true, url.strip_prefix("https://")?)
            }
            None => return None,
        };
        let (host, path) = match rest.find(['/', '?']) {
            Some(at) => rest.split_at(at),
            None => (rest, "/"),
        };
        let path = match path.starts_with('?') {
            true => format!("/{path}"),
            false => path.to_owned(),
        };
        let (name, port) = split_port(host)?;
        if name.is_empty() || host.contains('@') {
            return None;
        }
        let port = port.unwrap_or(if tls { "443" } else { "80" });
        let bracketed = name.contains(':');
        let authority = match bracketed {
            true => format!("[{name}]:{port}"),
            false => format!("{name}:{port}"),
        };
        Some(Url {
            authority,
            host: host.to_owned(),
            name: name.to_owned(),
            path,
            tls,
        })
    }

    /// `Location`, absolute or relative to this URL.
    fn join(&self, location: &str) -> Option<Url> {
        let scheme = if self.tls { "https" } else { "http" };
        if location.contains("://") {
            return Url::parse(location);
        }
        if let Some(rest) = location.strip_prefix("//") {
            return Url::parse(&format!("{scheme}://{rest}"));
        }
        let path = match location.starts_with('/') {
            true => location.to_owned(),
            false => {
                let path = self.path.split('?').next().unwrap_or("/");
                let dir = &path[..=path.rfind('/').unwrap_or(0)];
                format!("{dir}{location}")
            }
        };
        Url::parse(&format!("{scheme}://{}{path}", self.host))
    }
}

/// `host`, `host:port`, `[v6]` or `[v6]:port`: the name and the port.
fn split_port(host: &str) -> Option<(&str, Option<&str>)> {
    if let Some(rest) = host.strip_prefix('[') {
        let (name, rest) = rest.split_once(']')?;
        let port = match rest {
            "" => None,
            _ => Some(rest.strip_prefix(':')?),
        };
        return Some((name, port));
    }
    match host.split_once(':') {
        Some((name, port)) => Some((name, Some(port))),
        None => Some((host, None)),
    }
}

/// How a push that fails is retried: its backoff, and whether a 429
/// waits (retry_on_http_429) or drops what was sent.
#[derive(Clone, Copy)]
pub struct Retry {
    pub min: Duration,
    pub max: Duration,
    pub on_429: bool,
}

impl Retry {
    pub fn next(&self, backoff: Duration) -> Duration {
        (backoff * 2).clamp(self.min, self.max)
    }

    /// Whether a response with `status` is tried again.
    pub fn again(&self, status: u16) -> bool {
        status >= 500 || (status == 429 && self.on_429)
    }
}

pub struct Response {
    pub status: u16,
    pub body: Vec<u8>,
}

impl Response {
    pub fn ok(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

pub fn post(
    url: &Url,
    client: &Client,
    headers: &str,
    body: &[u8],
) -> io::Result<Response> {
    request(url, client, "POST", headers, body)
}

pub fn get(url: &Url, client: &Client, accept: &str) -> io::Result<Response> {
    request(url, client, "GET", &format!("Accept: {accept}\r\n"), &[])
}

/// One request, and the redirects after it as Go's client follows
/// them: 307 and 308 keep the method and body, the others turn into a
/// GET without one.
pub fn request(
    url: &Url,
    client: &Client,
    method: &str,
    headers: &str,
    body: &[u8],
) -> io::Result<Response> {
    let (mut url, mut method, mut body) = (url.clone(), method, body);
    for _ in 0..=MAX_REDIRECTS {
        let (response, location) = once(&url, client, method, headers, body)?;
        let redirect = matches!(response.status, 301 | 302 | 303 | 307 | 308);
        let Some(location) = location.filter(|_| redirect) else {
            return Ok(response);
        };
        if !client.follow_redirects {
            return Ok(response);
        }
        url = url
            .join(&location)
            .ok_or_else(|| broken(&format!("redirect to `{location}`")))?;
        if !matches!(response.status, 307 | 308) && method != "HEAD" {
            (method, body) = ("GET", &[]);
        }
    }
    Err(io::Error::other(format!(
        "stopped after {MAX_REDIRECTS} redirects"
    )))
}

fn once(
    url: &Url,
    client: &Client,
    method: &str,
    headers: &str,
    body: &[u8],
) -> io::Result<(Response, Option<String>)> {
    let route = client.proxy.route(url);
    let length = match method {
        "GET" | "HEAD" if body.is_empty() => String::new(),
        _ => format!("Content-Length: {}\r\n", body.len()),
    };
    let headers = format!("{headers}{}", client.headers);
    let request = auth::Request {
        method,
        url,
        headers: &headers,
        body,
    };
    let lines = format!("{length}{headers}{}", client.auth.header(&request)?);
    let head = head(method, url, route.as_ref(), &lines);
    #[cfg(feature = "http2")]
    if url.tls && client.http2 {
        let stream = tcp(url, client, route.as_ref())?;
        let request = h2::Request {
            method,
            url,
            lines: &lines,
            head: head.as_bytes(),
            body,
        };
        return h2::exchange(stream, client, &request);
    }
    let stream = open(url, client, route.as_ref())?;
    exchange(stream, head.as_bytes(), body)
}

/// An HTTP/1.1 request's head; to a proxy without TLS, with the whole
/// URL as its target and the proxy's credentials.
fn head(
    method: &str,
    url: &Url,
    route: Option<&proxy::Route>,
    lines: &str,
) -> String {
    let (target, proxy_auth) = match route {
        Some(proxy) if !url.tls => (
            format!("http://{}{}", url.host, url.path),
            proxy.authorization(),
        ),
        _ => (url.path.clone(), String::new()),
    };
    format!(
        "{method} {target} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\
         {lines}{proxy_auth}\r\n",
        url.host,
    )
}

/// A stream a request is exchanged on: TCP, through TLS or not.
pub trait Stream: Read + Write {}

impl<S: Read + Write> Stream for S {}

fn open(
    url: &Url,
    client: &Client,
    proxy: Option<&proxy::Route>,
) -> io::Result<Box<dyn Stream>> {
    let stream = tcp(url, client, proxy)?;
    if !url.tls {
        return Ok(Box::new(stream));
    }
    #[cfg(feature = "tls")]
    return tls::wrap(stream, url, client.tls.as_ref());
    #[cfg(not(feature = "tls"))]
    Err(io::Error::other("https: built without feature tls"))
}

/// A connection to `url`, through the proxy's tunnel for TLS.
fn tcp(
    url: &Url,
    client: &Client,
    proxy: Option<&proxy::Route>,
) -> io::Result<TcpStream> {
    let Some(proxy) = proxy else {
        return connect(&url.authority, client.timeout);
    };
    let stream = connect(&proxy.authority, client.timeout)?;
    match url.tls {
        true => proxy.tunnel(stream, url),
        false => Ok(stream),
    }
}

pub fn unix_get(socket: &Path, path: &str) -> io::Result<Response> {
    let stream = UnixStream::connect(socket)?;
    stream.set_read_timeout(Some(TIMEOUT))?;
    stream.set_write_timeout(Some(TIMEOUT))?;
    let head = format!(
        "GET {path} HTTP/1.1\r\nHost: docker\r\nConnection: close\r\n\r\n"
    );
    Ok(exchange(stream, head.as_bytes(), &[])?.0)
}

fn connect(authority: &str, timeout: Duration) -> io::Result<TcpStream> {
    let mut last = io::Error::other(format!("{authority} has no address"));
    for address in authority.to_socket_addrs()? {
        match TcpStream::connect_timeout(&address, timeout) {
            Ok(stream) => {
                stream.set_read_timeout(Some(timeout))?;
                stream.set_write_timeout(Some(timeout))?;
                return Ok(stream);
            }
            Err(error) => last = error,
        }
    }
    Err(last)
}

fn exchange<S: Read + Write>(
    mut stream: S,
    head: &[u8],
    body: &[u8],
) -> io::Result<(Response, Option<String>)> {
    stream.write_all(head)?;
    stream.write_all(body)?;
    stream.flush()?;
    let mut raw = Vec::new();
    ended(stream.take(MAX_RESPONSE).read_to_end(&mut raw))?;
    parse_response(raw)
}

/// A response read to its end: a TLS peer that closes without
/// close_notify, as many do after `Connection: close`, ends it too.
fn ended(read: io::Result<usize>) -> io::Result<()> {
    match read {
        Err(e) if e.kind() != io::ErrorKind::UnexpectedEof => Err(e),
        _ => Ok(()),
    }
}

/// An HTTP/1.1 response, and its Location.
fn parse_response(mut raw: Vec<u8>) -> io::Result<(Response, Option<String>)> {
    let end = head_end(&raw).ok_or_else(|| broken("no end of headers"))?;
    let head = parse_head(&raw[..end])?;
    let mut body = raw.split_off(end);
    if head.chunked {
        let mut data = Vec::with_capacity(body.len());
        Dechunk::default().feed(&mut body, &mut data);
        body = data;
    } else if let Some(length) = head.length {
        body.truncate(length);
    }
    let response = Response {
        status: head.status,
        body,
    };
    Ok((response, head.location))
}

pub struct Head {
    pub status: u16,
    pub chunked: bool,
    pub length: Option<usize>,
    pub location: Option<String>,
}

/// Where the body starts: after the empty line ending the headers.
pub fn head_end(raw: &[u8]) -> Option<usize> {
    raw.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|at| at + 4)
}

pub fn parse_head(raw: &[u8]) -> io::Result<Head> {
    let text = String::from_utf8_lossy(raw);
    let mut lines = text.split("\r\n");
    let status = lines.next().and_then(|line| line.split(' ').nth(1));
    let status = status.and_then(|code| code.parse().ok());
    let status = status.ok_or_else(|| broken("no status"))?;
    let mut head = Head {
        status,
        chunked: false,
        length: None,
        location: None,
    };
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("transfer-encoding") {
            head.chunked = value.eq_ignore_ascii_case("chunked");
        } else if name.eq_ignore_ascii_case("content-length") {
            head.length = value.parse().ok();
        } else if name.eq_ignore_ascii_case("location") {
            head.location = Some(value.to_owned());
        }
    }
    Ok(head)
}

pub fn broken(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("HTTP: {what}"))
}

/// Chunked transfer coding undone as data arrives: Docker's log streams
/// never end, so the body cannot be read whole first.
#[derive(Default)]
pub struct Dechunk {
    /// Data bytes of the current chunk not yet seen.
    left: usize,
    /// Bytes of the CR LF after a chunk's data not yet seen.
    crlf: usize,
    done: bool,
}

impl Dechunk {
    /// Moves the chunks' data at the front of `raw` to `out`; a size line
    /// not yet whole stays in `raw`.
    pub fn feed(&mut self, raw: &mut Vec<u8>, out: &mut Vec<u8>) {
        let mut at = 0;
        while at < raw.len() && !self.done {
            if self.left > 0 {
                let take = self.left.min(raw.len() - at);
                out.extend_from_slice(&raw[at..at + take]);
                at += take;
                self.left -= take;
                if self.left == 0 {
                    self.crlf = 2;
                }
            } else if self.crlf > 0 {
                at += 1;
                self.crlf -= 1;
            } else {
                let rest = &raw[at..];
                let Some(eol) = rest.windows(2).position(|w| w == b"\r\n")
                else {
                    break;
                };
                let size = chunk_size(&rest[..eol]);
                at += eol + 2;
                match size {
                    Some(0) | None => self.done = true,
                    Some(size) => self.left = size,
                }
            }
        }
        raw.drain(..at);
    }

    /// The last chunk came, or a size line could not be read.
    pub fn done(&self) -> bool {
        self.done
    }
}

/// A chunk's size line: hexadecimal digits, maybe `;extensions`.
fn chunk_size(line: &[u8]) -> Option<usize> {
    let digits = line.split(|&b| b == b';').next()?;
    let digits = std::str::from_utf8(digits).ok()?.trim();
    usize::from_str_radix(digits, 16).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_urls() {
        let url = Url::parse("http://10.0.0.1:9090/api/v1/write").unwrap();
        assert_eq!(url.authority, "10.0.0.1:9090");
        assert_eq!(url.path, "/api/v1/write");
        let url = Url::parse("http://mon/x").unwrap();
        assert_eq!(
            (url.authority.as_str(), url.host.as_str()),
            ("mon:80", "mon")
        );
        let url = Url::parse("http://[::1]:9/a?b").unwrap();
        assert_eq!(
            (url.authority.as_str(), url.name.as_str()),
            ("[::1]:9", "::1")
        );
        assert_eq!(url.join("c").unwrap().path, "/c");
        assert_eq!(url.join("/d/e").unwrap().join("f").unwrap().path, "/d/f");
        assert_eq!(url.join("http://o/").unwrap().authority, "o:80");
        assert_eq!(Url::parse("http://mon").unwrap().path, "/");
        assert!(Url::parse("ftp://mon/x").is_none());
        assert_eq!(
            Url::parse("https://mon/x").is_some(),
            cfg!(feature = "tls")
        );
    }

    #[test]
    fn undoes_chunks_split_anywhere() {
        let wire = b"5\r\nhello\r\n6;x=y\r\n world\r\n0\r\n\r\n";
        for split in 0..wire.len() {
            let mut dechunk = Dechunk::default();
            let (mut raw, mut out) = (wire[..split].to_vec(), Vec::new());
            dechunk.feed(&mut raw, &mut out);
            raw.extend_from_slice(&wire[split..]);
            dechunk.feed(&mut raw, &mut out);
            assert_eq!(out, b"hello world", "split at {split}");
            assert!(dechunk.done());
        }
    }

    #[test]
    fn reads_heads() {
        let raw = b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n";
        let end = head_end(raw).unwrap();
        let head = parse_head(&raw[..end]).unwrap();
        assert_eq!((head.status, head.length), (204, Some(0)));
    }
}
