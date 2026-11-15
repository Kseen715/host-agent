//! Alloy's HTTP server, as much of it as looking into the agent takes:
//! a status page, the agent's own metrics, health, reload and live
//! views of the metrics and log lines sent (crate::tap). Served from
//! the agent's poll(2) loop, one request at a time, nothing kept
//! between them.

use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::fd::{AsRawFd, RawFd};
use std::time::{Duration, Instant};

/// A client has this long to ask, and to take a response: the loop
/// waits on it.
const TIMEOUT: Duration = Duration::from_secs(1);
const MAX_REQUEST: usize = 4096;

pub enum Route {
    Page,
    Metrics,
    Ready,
    Healthy,
    Reload,
    MetricsTap,
    LogsTap,
    NotFound,
    NotAllowed,
}

pub struct Server(TcpListener);

impl Server {
    pub fn bind(address: &str) -> io::Result<Server> {
        let listener = TcpListener::bind(address)?;
        listener.set_nonblocking(true)?;
        Ok(Server(listener))
    }

    pub fn fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }

    /// A waiting client and what it asks for; None when none waits.
    pub fn accept(&self) -> Option<(TcpStream, Route)> {
        loop {
            let (mut stream, _) = self.0.accept().ok()?;
            let ready = stream.set_nonblocking(false).is_ok()
                && stream.set_write_timeout(Some(TIMEOUT)).is_ok();
            if let Some(route) = read_route(&mut stream).filter(|_| ready) {
                return Some((stream, route));
            }
        }
    }
}

/// The request's head, up to its blank line, read for its first line.
fn read_route(stream: &mut TcpStream) -> Option<Route> {
    let mut head = Vec::new();
    let mut buf = [0; 512];
    let deadline = Instant::now() + TIMEOUT;
    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
        let left = deadline.checked_duration_since(Instant::now())?;
        stream.set_read_timeout(Some(left)).ok()?;
        let length = stream.read(&mut buf).ok().filter(|&n| n > 0)?;
        head.extend_from_slice(&buf[..length]);
        if head.len() > MAX_REQUEST {
            return None;
        }
    }
    let line = String::from_utf8_lossy(&head);
    let mut words = line.split_whitespace();
    let (method, target) = (words.next()?, words.next()?);
    let path = target.split('?').next().unwrap_or_default();
    Some(route(method, path))
}

fn route(method: &str, path: &str) -> Route {
    let route = match path {
        "/" => Route::Page,
        "/metrics" => Route::Metrics,
        "/-/ready" => Route::Ready,
        "/-/healthy" => Route::Healthy,
        "/-/reload" => Route::Reload,
        "/debug/metrics" => Route::MetricsTap,
        "/debug/logs" => Route::LogsTap,
        _ => return Route::NotFound,
    };
    // Alloy reloads on GET or POST; the rest only read.
    match (method, &route) {
        ("GET" | "POST", Route::Reload) | ("GET" | "HEAD", _) => route,
        _ => Route::NotAllowed,
    }
}

/// A whole response; the client is closed after it.
pub fn respond(mut stream: TcpStream, status: &str, kind: &str, body: &str) {
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {kind}\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(body.as_bytes());
}

/// The head of a response whose body is a tap's lines, until either
/// side closes.
pub fn start_stream(stream: &mut TcpStream) -> bool {
    let head = "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\n\
                Cache-Control: no-store\r\nConnection: close\r\n\r\n";
    stream.write_all(head.as_bytes()).is_ok()
}

pub fn escape_html(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routes_as_alloy_does() {
        assert!(matches!(route("GET", "/metrics"), Route::Metrics));
        assert!(matches!(route("POST", "/-/reload"), Route::Reload));
        assert!(matches!(route("POST", "/metrics"), Route::NotAllowed));
        assert!(matches!(route("GET", "/nope"), Route::NotFound));
    }

    #[test]
    fn answers_over_tcp() {
        let server = Server::bind("127.0.0.1:0").unwrap();
        let address = server.0.local_addr().unwrap();
        let mut client = TcpStream::connect(address).unwrap();
        client
            .write_all(b"GET /-/ready?x=1 HTTP/1.1\r\n\r\n")
            .unwrap();
        let (stream, route) = loop {
            if let Some(accepted) = server.accept() {
                break accepted;
            }
        };
        assert!(matches!(route, Route::Ready));
        respond(stream, "200 OK", "text/plain", "Alloy is ready.\n");
        let mut answer = String::new();
        client.read_to_string(&mut answer).unwrap();
        assert!(answer.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(answer.ends_with("\r\n\r\nAlloy is ready.\n"));
    }
}
