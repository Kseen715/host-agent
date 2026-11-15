//! Network devices' syslog over UDP, as Alloy's loki.source.syslog in
//! RFC 3164 format with the homelab's relabel rules: lines from the
//! listed devices only, `host` the device's name, `app` the sender's tag
//! and `level` the journal's word for the severity. A BSD timestamp has
//! no year and no time zone, so lines keep their arrival time.

use crate::levels::PRIORITIES;
use crate::loki::Loki;
use crate::parts::Part;
use crate::state::Positions;
use crate::time;
use std::io;
use std::net::{IpAddr, UdpSocket};
use std::os::fd::{AsRawFd, RawFd};
use std::time::Instant;

/// Alloy's longest message; the rest of a datagram is cut.
const MAX_LENGTH: usize = 8192;
/// Datagrams read per wake: other sources wait meanwhile.
const READ_AT_ONCE: usize = 256;

pub struct Syslog {
    socket: UdpSocket,
    devices: Vec<(String, IpAddr)>,
    buf: Vec<u8>,
}

impl Syslog {
    pub fn bind(
        port: u16,
        devices: Vec<(String, IpAddr)>,
    ) -> io::Result<Syslog> {
        let socket = UdpSocket::bind(("0.0.0.0", port))?;
        socket.set_nonblocking(true)?;
        Ok(Syslog {
            socket,
            devices,
            buf: vec![0; MAX_LENGTH],
        })
    }
}

impl Part for Syslog {
    fn fds(&self) -> Vec<RawFd> {
        vec![self.socket.as_raw_fd()]
    }

    fn read(&mut self, _index: usize, loki: &mut Loki, _p: &mut Positions) {
        for _ in 0..READ_AT_ONCE {
            if loki.blocked(Instant::now()) {
                return;
            }
            let (length, from) = match self.socket.recv_from(&mut self.buf) {
                Ok(received) => received,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    return;
                }
                Err(error) => {
                    eprintln!("Syslog: {error}");
                    return;
                }
            };
            let device = self.devices.iter().find(|(_, ip)| *ip == from.ip());
            let Some((name, _)) = device else {
                continue;
            };
            let datagram = String::from_utf8_lossy(&self.buf[..length]);
            if let Some(message) = parse(&datagram) {
                let labels = [
                    ("job", "syslog"),
                    ("host", name.as_str()),
                    ("app", message.app),
                    ("level", message.level),
                ];
                loki.add(&labels, time::now_ns(), message.text);
            }
        }
    }
}

struct Message<'a> {
    level: &'static str,
    app: &'a str,
    text: &'a str,
}

/// `<PRI>` and as much of RFC 3164's header as there is: a timestamp,
/// the sender's name, `tag[pid]:`.
fn parse(datagram: &str) -> Option<Message<'_>> {
    let (priority, rest) = datagram.strip_prefix('<')?.split_once('>')?;
    let priority: u8 = priority.parse().ok()?;
    let rest = after_timestamp(rest);
    let after_host = rest.split_once(' ').map(|(_, after)| after);
    let (app, text) =
        tag(rest).or_else(|| tag(after_host?)).unwrap_or(("", rest));
    Some(Message {
        level: PRIORITIES[usize::from(priority & 7)],
        app,
        text,
    })
}

/// `rest` after a BSD timestamp (`Nov  5 02:36:24 `) or an RFC 3339 one.
fn after_timestamp(rest: &str) -> &str {
    let b = rest.as_bytes();
    let bsd = b.len() > 16
        && [(3, b' '), (6, b' '), (9, b':'), (12, b':'), (15, b' ')]
            .iter()
            .all(|&(at, byte)| b[at] == byte);
    if bsd {
        return &rest[16..];
    }
    let rfc3339 =
        b.len() > 5 && b[..4].iter().all(u8::is_ascii_digit) && b[4] == b'-';
    match rest.split_once(' ') {
        Some((_, after)) if rfc3339 => after,
        _ => rest,
    }
}

/// `tag[pid]: text` as the tag and the text; None if `rest` does not
/// start with one.
fn tag(rest: &str) -> Option<(&str, &str)> {
    let (head, text) = rest.split_once(':')?;
    if head.is_empty() || head.contains(' ') {
        return None;
    }
    let app = head.split('[').next()?;
    Some((app, text.strip_prefix(' ').unwrap_or(text)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fields(datagram: &str) -> (&'static str, &str, &str) {
        let m = parse(datagram).unwrap();
        (m.level, m.app, m.text)
    }

    #[test]
    fn reads_bsd_syslog() {
        assert_eq!(
            fields("<30>Nov 15 02:36:24 ndhcps: sending ACK. "),
            ("info", "ndhcps", "sending ACK. ")
        );
        assert_eq!(
            fields("<27>Nov  5 02:36:24 keenetic ndm: Core::Syslog: x"),
            ("err", "ndm", "Core::Syslog: x")
        );
        assert_eq!(
            fields("<12>2026-11-15T02:36:24Z dropbear[42]: login"),
            ("warning", "dropbear", "login")
        );
        assert_eq!(fields("<14>just text"), ("info", "", "just text"));
        assert!(parse("no priority").is_none());
    }
}
