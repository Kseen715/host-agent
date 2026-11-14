//! An HTTP/1.1 client for plain-HTTP endpoints on the LAN and on
//! loopback, and for Docker's socket: one request per connection
//! (`Connection: close`), so a response ends where the stream does.

use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

pub const TIMEOUT: Duration = Duration::from_secs(10);
/// A runaway response stops here instead of taking the host's memory.
const MAX_RESPONSE: u64 = 64 << 20;

pub struct Url {
    /// `host:port`, the port filled in.
    pub authority: String,
    pub path: String,
}

impl Url {
    pub fn parse(url: &str) -> Option<Url> {
        let rest = url.strip_prefix("http://")?;
        let (authority, path) = rest.split_at(rest.find('/')?);
        if authority.is_empty() {
            return None;
        }
        let authority = if authority.contains(':') {
            authority.to_owned()
        } else {
            format!("{authority}:80")
        };
        let path = path.to_owned();
        Some(Url { authority, path })
    }

    /// An exporter's metrics at `host:port`.
    pub fn metrics(address: &str) -> Url {
        let authority = address.to_owned();
        let path = String::from("/metrics");
        Url { authority, path }
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

pub fn post(url: &Url, headers: &str, body: &[u8]) -> io::Result<Response> {
    let head = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\n\
         Connection: close\r\n{headers}\r\n",
        url.path,
        url.authority,
        body.len()
    );
    exchange(connect(&url.authority)?, head.as_bytes(), body)
}

pub fn get(url: &Url) -> io::Result<Response> {
    let head = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nAccept: text/plain\r\n\
         Connection: close\r\n\r\n",
        url.path, url.authority
    );
    exchange(connect(&url.authority)?, head.as_bytes(), &[])
}

pub fn unix_get(socket: &Path, path: &str) -> io::Result<Response> {
    let stream = UnixStream::connect(socket)?;
    stream.set_read_timeout(Some(TIMEOUT))?;
    stream.set_write_timeout(Some(TIMEOUT))?;
    let head = format!(
        "GET {path} HTTP/1.1\r\nHost: docker\r\nConnection: close\r\n\r\n"
    );
    exchange(stream, head.as_bytes(), &[])
}

fn connect(authority: &str) -> io::Result<TcpStream> {
    let mut last = io::Error::other(format!("{authority} has no address"));
    for address in authority.to_socket_addrs()? {
        match TcpStream::connect_timeout(&address, TIMEOUT) {
            Ok(stream) => {
                stream.set_read_timeout(Some(TIMEOUT))?;
                stream.set_write_timeout(Some(TIMEOUT))?;
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
) -> io::Result<Response> {
    stream.write_all(head)?;
    stream.write_all(body)?;
    let mut raw = Vec::new();
    stream.take(MAX_RESPONSE).read_to_end(&mut raw)?;

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
    Ok(Response {
        status: head.status,
        body,
    })
}

pub struct Head {
    pub status: u16,
    pub chunked: bool,
    pub length: Option<usize>,
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
        }
    }
    Ok(head)
}

fn broken(what: &str) -> io::Error {
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
        assert_eq!(Url::parse("http://mon/x").unwrap().authority, "mon:80");
        assert!(Url::parse("https://mon/x").is_none());
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
