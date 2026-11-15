//! loki.source.syslog's listeners, UDP or TCP: each message with the
//! `__syslog_*` labels Alloy gives it, for the source's rules. Over TCP
//! a message is framed by its length (`123 <PRI>...`, RFC 6587's octet
//! counting) or ends at a newline, as each one starts.

mod format;

use crate::alloy::SyslogListener;
use crate::logs::Logs;
use crate::parts::Part;
use crate::relabel::Labels;
use crate::state::Positions;
use crate::time;
use format::Message;
use std::io::{self, Read};
use std::net::{IpAddr, TcpListener, TcpStream, UdpSocket};
use std::os::fd::{AsRawFd, RawFd};
use std::time::Instant;

/// Datagrams or reads per wake: other sources wait meanwhile.
const READ_AT_ONCE: usize = 256;
const READ_SIZE: usize = 64 << 10;

enum Socket {
    Udp(UdpSocket),
    Tcp(TcpListener, Vec<Connection>),
}

struct Connection {
    stream: TcpStream,
    from: IpAddr,
    buf: Vec<u8>,
    last: Instant,
}

pub struct Syslog {
    socket: Socket,
    listener: SyslogListener,
    buf: Vec<u8>,
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
        Ok(Syslog {
            socket,
            buf: vec![0; listener.max_message_length.max(READ_SIZE)],
            listener,
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
                    let raw = String::from_utf8_lossy(&self.buf[..length]);
                    let raw = raw.trim_end_matches(['\n', '\r', '\0']);
                    emit(&self.listener, logs, from.ip(), raw);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return,
                Err(error) => return eprintln!("Syslog: {error}"),
            }
        }
    }

    fn accept(&mut self) {
        let Socket::Tcp(socket, connections) = &mut self.socket else {
            return;
        };
        while let Ok((stream, from)) = socket.accept() {
            if stream.set_nonblocking(true).is_ok() {
                connections.push(Connection {
                    stream,
                    from: from.ip(),
                    buf: Vec::new(),
                    last: Instant::now(),
                });
            }
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
        let read = connection.stream.read(&mut self.buf);
        let open = match read {
            Ok(0) => false,
            Ok(length) => {
                connection.buf.extend_from_slice(&self.buf[..length]);
                connection.last = Instant::now();
                true
            }
            Err(e) => e.kind() == io::ErrorKind::WouldBlock,
        };
        let max = self.listener.max_message_length;
        while let Some(raw) = frame(&mut connection.buf, max, !open) {
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
            connections.retain(|c| idle.is_zero() || c.last.elapsed() < idle);
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

/// The next whole message in `buf`, taken out: `length message` or up
/// to a newline; at the end of the stream, what is left. A message
/// longer than `max` is cut.
fn frame(buf: &mut Vec<u8>, max: usize, end: bool) -> Option<Vec<u8>> {
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
    let line = buf.iter().position(|&b| b == b'\n');
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
    let parsed = if listener.rfc5424 {
        format::rfc5424(raw)
    } else {
        format::rfc3164(raw)
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
        assert_eq!(frame(&mut buf, 8192, false).unwrap(), b"<14>1 - - - - - -");
        assert_eq!(frame(&mut buf, 8192, false).unwrap(), b"<14>x\n");
        assert_eq!(frame(&mut buf, 8192, false), None);
        assert_eq!(frame(&mut buf, 8192, true).unwrap(), b"<14>y");
        assert!(buf.is_empty());
        let mut long = vec![b'a'; 20];
        assert_eq!(frame(&mut long, 8, false).unwrap().len(), 8);
        assert_eq!(long.len(), 12);
    }
}
