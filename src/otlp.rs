//! otelcol.receiver.otlp's HTTP endpoint (such as 127.0.0.1:4318),
//! which passes each request on as it came to its signal's backend,
//! the otelcol.exporter.otlphttp its output leads to: Loki and
//! Prometheus take OTLP themselves. The client
//! gets the backend's answer, so its own retries cover an outage, and
//! nothing waits here. One request per connection, read whole: the
//! clients are local.

use crate::http::{self, Url};
use crate::logs::Logs;
use crate::parts::Part;
use crate::state::Positions;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::fd::{AsRawFd, RawFd};
use std::time::Duration;

/// OTLP's paths by signal.
const PATHS: [(&str, &str); 4] = [
    ("logs", "/v1/logs"),
    ("metrics", "/v1/metrics"),
    ("traces", "/v1/traces"),
    ("profiles", "/v1development/profiles"),
];
const TIMEOUT: Duration = Duration::from_secs(2);
const MAX_HEAD: usize = 16 << 10;
const MAX_BODY: usize = 16 << 20;

pub struct Otlp {
    listener: TcpListener,
    /// A request path and where it goes.
    routes: Vec<(&'static str, Url)>,
}

impl Otlp {
    pub fn bind(
        address: &str,
        forwards: &[(String, String)],
    ) -> Result<Otlp, String> {
        let mut routes = Vec::new();
        for (signal, url) in forwards {
            let path = PATHS.iter().find(|(name, _)| name == signal);
            let (_, path) = path.ok_or(format!("no OTLP signal `{signal}`"))?;
            let url = Url::parse(url).ok_or(format!("{url}: not http://"))?;
            routes.push((*path, url));
        }
        let listener = TcpListener::bind(address)
            .map_err(|e| format!("{address}: {e}"))?;
        listener.set_nonblocking(true).map_err(|e| e.to_string())?;
        Ok(Otlp { listener, routes })
    }
}

impl Part for Otlp {
    fn fds(&self) -> Vec<RawFd> {
        vec![self.listener.as_raw_fd()]
    }

    /// Its logs go to Loki's own OTLP endpoint, not through the batch.
    fn feeds_loki(&self) -> bool {
        false
    }

    fn read(&mut self, _index: usize, _logs: &mut Logs, _p: &mut Positions) {
        while let Ok((stream, _)) = self.listener.accept() {
            if let Err(error) = self.serve(stream) {
                eprintln!("OTLP: {error}");
            }
        }
    }
}

struct Request {
    path: String,
    headers: String,
    body: Vec<u8>,
}

impl Otlp {
    fn serve(&self, mut stream: TcpStream) -> io::Result<()> {
        stream.set_nonblocking(false)?;
        stream.set_read_timeout(Some(TIMEOUT))?;
        stream.set_write_timeout(Some(TIMEOUT))?;
        let (status, headers, body) = match read_request(&mut stream)? {
            Err(status) => (status, String::new(), Vec::new()),
            Ok(request) => self.forward(&request),
        };
        let head = format!(
            "HTTP/1.1 {status} {}\r\nContent-Length: {}\r\n{headers}\
             Connection: close\r\n\r\n",
            if status < 300 { "OK" } else { "Error" },
            body.len()
        );
        stream.write_all(head.as_bytes())?;
        stream.write_all(&body)
    }

    /// The backend's status and body, under the request's content type.
    fn forward(&self, request: &Request) -> (u16, String, Vec<u8>) {
        let route = self.routes.iter().find(|(path, _)| *path == request.path);
        let Some((_, url)) = route else {
            return (404, String::new(), Vec::new());
        };
        match http::post(url, &request.headers, &request.body) {
            Ok(response) => {
                let kind = request.headers.lines().find(|line| {
                    line.to_ascii_lowercase().starts_with("content-type:")
                });
                let kind = kind.map(|k| format!("{k}\r\n")).unwrap_or_default();
                (response.status, kind, response.body)
            }
            Err(error) => {
                eprintln!("OTLP: {}: {error}", url.authority);
                (503, String::new(), Vec::new())
            }
        }
    }
}

/// A POST and its body, with the headers passed on (content type and
/// encoding); Err the status to answer with.
fn read_request(stream: &mut TcpStream) -> io::Result<Result<Request, u16>> {
    let mut raw = Vec::new();
    let mut chunk = [0; 4096];
    let end = loop {
        if let Some(end) = http::head_end(&raw) {
            break end;
        }
        let read = stream.read(&mut chunk)?;
        if read == 0 || raw.len() > MAX_HEAD {
            return Ok(Err(400));
        }
        raw.extend_from_slice(&chunk[..read]);
    };
    let head = String::from_utf8_lossy(&raw[..end]).into_owned();
    let mut lines = head.lines();
    let line = lines.next().unwrap_or_default();
    let mut words = line.split(' ');
    let (Some("POST"), Some(path)) = (words.next(), words.next()) else {
        return Ok(Err(405));
    };
    let mut headers = String::new();
    let mut length = None;
    for line in lines {
        let lower = line.to_ascii_lowercase();
        if let Some(value) = lower.strip_prefix("content-length:") {
            length = value.trim().parse::<usize>().ok();
        } else if lower.starts_with("content-type:")
            || lower.starts_with("content-encoding:")
        {
            headers.push_str(&format!("{line}\r\n"));
        }
    }
    let Some(length) = length.filter(|&l| l <= MAX_BODY) else {
        return Ok(Err(411));
    };
    let mut body = raw.split_off(end);
    body.truncate(length);
    let have = body.len();
    body.resize(length, 0);
    stream.read_exact(&mut body[have..])?;
    let path = path.to_owned();
    Ok(Ok(Request {
        path,
        headers,
        body,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    /// A client's request through the receiver to a backend and back.
    #[test]
    fn passes_requests_on() {
        let backend = TcpListener::bind("127.0.0.1:0").unwrap();
        let backend_address = backend.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = backend.accept().unwrap();
            // Head and body may come apart: up to the body's end.
            let mut seen = Vec::new();
            let mut chunk = [0; 4096];
            while !seen.ends_with(b"abc") {
                let read = stream.read(&mut chunk).unwrap();
                seen.extend_from_slice(&chunk[..read]);
            }
            stream.write_all(b"HTTP/1.1 200 OK\r\n\r\nok").unwrap();
            String::from_utf8_lossy(&seen).into_owned()
        });
        let forwards = [(
            "logs".to_owned(),
            format!("http://{backend_address}/otlp/v1/logs"),
        )];
        let otlp = Otlp::bind("127.0.0.1:0", &forwards).unwrap();
        let address = otlp.listener.local_addr().unwrap();
        let client = thread::spawn(move || {
            let mut stream = TcpStream::connect(address).unwrap();
            stream
                .write_all(
                    b"POST /v1/logs HTTP/1.1\r\nContent-Type: \
                      application/x-protobuf\r\nContent-Length: 3\r\n\r\nabc",
                )
                .unwrap();
            let mut answer = String::new();
            stream.read_to_string(&mut answer).unwrap();
            answer
        });
        let (stream, _) = loop {
            if let Ok(accepted) = otlp.listener.accept() {
                break accepted;
            }
        };
        otlp.serve(stream).unwrap();
        let seen = server.join().unwrap();
        assert!(seen.starts_with("POST /otlp/v1/logs HTTP/1.1"));
        assert!(seen.contains("Content-Type: application/x-protobuf"));
        assert!(seen.ends_with("abc"));
        let answer = client.join().unwrap();
        assert!(answer.starts_with("HTTP/1.1 200 OK"));
        assert!(answer.ends_with("ok"));
    }
}
