//! loki.source.syslog's listeners, UDP or TCP: each message with the
//! `__syslog_*` labels Alloy gives it, for the source's rules. Over TCP
//! a message is framed by its length (`123 <PRI>...`, RFC 6587's octet
//! counting) or ends at a newline, as each one starts; with feature
//! `tls`, inside TLS where the listener has a `tls_config`.

mod format;
#[cfg(feature = "tls")]
mod tls;

use crate::alloy::{SyslogFormat, SyslogListener};
use crate::logs::Logs;
use crate::parts::Part;
use crate::relabel::Labels;
use crate::state::Positions;
use crate::time;
use format::Message;
use std::io::{self, Read};
use std::net::{IpAddr, TcpListener, TcpStream, UdpSocket};
use std::os::fd::{AsRawFd, RawFd};
use std::time::{Duration, Instant};

/// Datagrams or reads per wake: other sources wait meanwhile.
const READ_AT_ONCE: usize = 256;
const READ_SIZE: usize = 64 << 10;
// A client may hold a connection with a byte now and then of a
// handshake, which idle_timeout alone would never end.
#[cfg(feature = "tls")]
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

enum Socket {
    Udp(UdpSocket),
    Tcp(TcpListener, Vec<Connection>),
}

struct Connection {
    stream: TcpStream,
    from: IpAddr,
    buf: Vec<u8>,
    last: Instant,
    #[cfg(feature = "tls")]
    opened: Instant,
    #[cfg(feature = "tls")]
    tls: Option<rustls::ServerConnection>,
}

impl Connection {
    /// Silent for `idle` (zero: never), or not through its handshake.
    fn expired(&self, idle: Duration) -> bool {
        #[cfg(feature = "tls")]
        if self.tls.as_ref().is_some_and(|t| t.is_handshaking())
            && self.opened.elapsed() >= HANDSHAKE_TIMEOUT
        {
            return true;
        }
        !idle.is_zero() && self.last.elapsed() >= idle
    }

    /// Reads what arrived into `buf`; false when the stream ended.
    fn fill(&mut self, chunk: &mut [u8]) -> bool {
        self.last = Instant::now();
        #[cfg(feature = "tls")]
        if let Some(session) = &mut self.tls {
            return tls::fill(session, &mut self.stream, &mut self.buf, chunk);
        }
        match self.stream.read(chunk) {
            Ok(0) => false,
            Ok(length) => {
                self.buf.extend_from_slice(&chunk[..length]);
                true
            }
            Err(e) => e.kind() == io::ErrorKind::WouldBlock,
        }
    }
}

pub struct Syslog {
    socket: Socket,
    listener: SyslogListener,
    buf: Vec<u8>,
    #[cfg(feature = "tls")]
    tls: Option<std::sync::Arc<rustls::ServerConfig>>,
}

impl Syslog {
    pub fn bind(listener: SyslogListener) -> io::Result<Syslog> {
        let socket = if listener.tcp {
            let socket = TcpListener::bind(&listener.address)?;
            socket.set_nonblocking(true)?;
            Socket::Tcp(socket, Vec::new())
        } else {
            let socket = UdpSocket::bind(&listener.address)?;
            socket.set_nonblocking(true)?;
            Socket::Udp(socket)
        };
        #[cfg(feature = "tls")]
        let tls = listener.tls.as_ref().map(tls::config).transpose();
        Ok(Syslog {
            socket,
            buf: vec![0; listener.max_message_length.max(READ_SIZE)],
            listener,
            #[cfg(feature = "tls")]
            tls: tls.map_err(io::Error::other)?,
        })
    }

    fn datagrams(&mut self, logs: &mut Logs) {
        let Socket::Udp(socket) = &self.socket else {
            return;
        };
        for _ in 0..READ_AT_ONCE {
            if logs.blocked(Instant::now()) {
                return;
            }
            match socket.recv_from(&mut self.buf) {
                Ok((length, from)) => {
                    let length = length.min(self.listener.max_message_length);
                    let datagram = self.buf[..length].to_vec();
                    self.datagram(logs, from.ip(), datagram);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return,
                Err(error) => return eprintln!("Syslog: {error}"),
            }
        }
    }

    /// One datagram: a message, or in raw format the lines it holds.
    fn datagram(&self, logs: &mut Logs, from: IpAddr, mut datagram: Vec<u8>) {
        let SyslogFormat::Raw { nul } = self.listener.format else {
            let raw = String::from_utf8_lossy(&datagram);
            let raw = raw.trim_end_matches(['\n', '\r', '\0']);
            return emit(&self.listener, logs, from, raw);
        };
        let max = self.listener.max_message_length;
        while let Some(raw) = frame(&mut datagram, max, true, delimiter(nul)) {
            emit(&self.listener, logs, from, &String::from_utf8_lossy(&raw));
        }
    }

    fn accept(&mut self) {
        let Socket::Tcp(socket, connections) = &mut self.socket else {
            return;
        };
        while let Ok((stream, from)) = socket.accept() {
            if stream.set_nonblocking(true).is_err() {
                continue;
            }
            #[cfg(feature = "tls")]
            let tls = match self.tls.as_ref().map(|config| {
                rustls::ServerConnection::new(std::sync::Arc::clone(config))
            }) {
                Some(Err(error)) => {
                    eprintln!("Syslog: TLS: {error}");
                    continue;
                }
                session => session.and_then(Result::ok),
            };
            connections.push(Connection {
                stream,
                from: from.ip(),
                buf: Vec::new(),
                last: Instant::now(),
                #[cfg(feature = "tls")]
                opened: Instant::now(),
                #[cfg(feature = "tls")]
                tls,
            });
        }
    }

    /// Reads connection `index`; one that ended is closed.
    fn receive(&mut self, index: usize, logs: &mut Logs) {
        let Socket::Tcp(_, connections) = &mut self.socket else {
            return;
        };
        let Some(connection) = connections.get_mut(index) else {
            return;
        };
        let open = connection.fill(&mut self.buf);
        let max = self.listener.max_message_length;
        let delimiter = match self.listener.format {
            SyslogFormat::Raw { nul } => delimiter(nul),
            _ => b'\n',
        };
        while let Some(raw) = frame(&mut connection.buf, max, !open, delimiter)
        {
            let raw = String::from_utf8_lossy(&raw);
            emit(&self.listener, logs, connection.from, raw.trim_end());
        }
        if !open {
            connections.remove(index);
        }
    }
}

impl Part for Syslog {
    fn prepare(&mut self, _positions: &Positions) {
        let idle = self.listener.idle_timeout;
        if let Socket::Tcp(_, connections) = &mut self.socket {
            connections.retain(|c| !c.expired(idle));
        }
    }

    fn fds(&self) -> Vec<RawFd> {
        match &self.socket {
            Socket::Udp(socket) => vec![socket.as_raw_fd()],
            Socket::Tcp(socket, connections) => std::iter::once(socket)
                .map(AsRawFd::as_raw_fd)
                .chain(connections.iter().map(|c| c.stream.as_raw_fd()))
                .collect(),
        }
    }

    fn read(&mut self, index: usize, logs: &mut Logs, _p: &mut Positions) {
        match (&self.socket, index) {
            (Socket::Udp(_), _) => self.datagrams(logs),
            (Socket::Tcp(..), 0) => self.accept(),
            (Socket::Tcp(..), _) => self.receive(index - 1, logs),
        }
    }
}

fn delimiter(nul: bool) -> u8 {
    if nul { b'\0' } else { b'\n' }
}

/// The next whole message in `buf`, taken out: `length message` or up
/// to `delimiter`; at the end of the stream, what is left. A message
/// longer than `max` is cut.
fn frame(
    buf: &mut Vec<u8>,
    max: usize,
    end: bool,
    delimiter: u8,
) -> Option<Vec<u8>> {
    let digits = buf.iter().take_while(|b| b.is_ascii_digit()).count();
    if digits > 0 && buf.get(digits) == Some(&b' ') {
        let length: usize =
            std::str::from_utf8(&buf[..digits]).ok()?.parse().ok()?;
        let start = digits + 1;
        if buf.len() < start + length {
            return None;
        }
        let mut message: Vec<u8> = buf.drain(..start + length).collect();
        message.drain(..start);
        message.truncate(max);
        return Some(message);
    }
    let line = buf.iter().position(|&b| b == delimiter);
    let take = match line {
        Some(at) => at + 1,
        None if end && !buf.is_empty() => buf.len(),
        None if buf.len() > max => max,
        None => return None,
    };
    let mut message: Vec<u8> = buf.drain(..take).collect();
    message.truncate(max);
    Some(message)
}

fn emit(listener: &SyslogListener, logs: &mut Logs, from: IpAddr, raw: &str) {
    let parsed = match listener.format {
        SyslogFormat::Rfc5424 => format::rfc5424(raw),
        SyslogFormat::Rfc3164 => format::rfc3164(raw),
        SyslogFormat::Raw { .. } => {
            return raw_line(listener, logs, from, raw);
        }
    };
    let Some(message) = parsed else {
        return;
    };
    let ns = message.ns.filter(|_| listener.use_incoming_timestamp);
    let line = if listener.use_rfc5424_message {
        raw
    } else {
        message.text
    };
    let labels = labels(&message, from, listener.label_structured_data);
    let ns = ns.unwrap_or_else(time::now_ns);
    listener.source.emit(logs, labels, ns, line);
}

/// A raw line: its priority, if it has one, gives the severity and
/// facility; an empty line is dropped; the time is now.
fn raw_line(
    listener: &SyslogListener,
    logs: &mut Logs,
    from: IpAddr,
    raw: &str,
) {
    let (severity, facility, text) = format::raw(raw.trim());
    let text = text.trim();
    if text.is_empty() {
        return;
    }
    let message = Message {
        severity,
        facility,
        ..Message::default()
    };
    let labels = labels(&message, from, false);
    listener.source.emit(logs, labels, time::now_ns(), text);
}

/// Alloy's `__syslog_*` labels; fields the message lacks are left out.
fn labels(message: &Message, from: IpAddr, data: bool) -> Labels {
    let fields = [
        ("connection_ip_address", from.to_string()),
        ("message_severity", message.severity.to_owned()),
        ("message_facility", message.facility.to_owned()),
        ("message_hostname", message.hostname.to_owned()),
        ("message_app_name", message.app.to_owned()),
        ("message_proc_id", message.pid.to_owned()),
        ("message_msg_id", message.msg_id.to_owned()),
    ];
    let mut labels: Labels = fields
        .into_iter()
        .filter(|(_, value)| !value.is_empty())
        .map(|(name, value)| (format!("__syslog_{name}"), value))
        .collect();
    if data {
        for (id, params) in &message.data {
            let id = id.replace('@', "_");
            for (name, value) in params {
                let name = format!("__syslog_message_sd_{id}_{name}");
                labels.push((name, value.clone()));
            }
        }
    }
    labels
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_tcp_streams() {
        let mut buf = b"17 <14>1 - - - - - -<14>x\n<14>y".to_vec();
        let nl = b'\n';
        let first = frame(&mut buf, 8192, false, nl).unwrap();
        assert_eq!(first, b"<14>1 - - - - - -");
        assert_eq!(frame(&mut buf, 8192, false, nl).unwrap(), b"<14>x\n");
        assert_eq!(frame(&mut buf, 8192, false, nl), None);
        assert_eq!(frame(&mut buf, 8192, true, nl).unwrap(), b"<14>y");
        assert!(buf.is_empty());
        let mut long = vec![b'a'; 20];
        assert_eq!(frame(&mut long, 8, false, nl).unwrap().len(), 8);
        let mut raw = b"a\0b".to_vec();
        assert_eq!(frame(&mut raw, 8, false, b'\0').unwrap(), b"a\0");
        assert_eq!(long.len(), 12);
    }
}
