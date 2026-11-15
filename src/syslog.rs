//! loki.source.syslog's UDP listener in RFC 3164 format: each line
//! with the `__syslog_*` labels Alloy gives it, for the source's rules.
//! A BSD timestamp has no year and no time zone, so lines keep their
//! arrival time.

use crate::logs::{Logs, Source};
use crate::parts::Part;
use crate::state::Positions;
use crate::time;
use std::io;
use std::net::UdpSocket;
use std::os::fd::{AsRawFd, RawFd};
use std::time::Instant;

/// Alloy's longest message; the rest of a datagram is cut.
const MAX_LENGTH: usize = 8192;
/// Datagrams read per wake: other sources wait meanwhile.
const READ_AT_ONCE: usize = 256;

/// RFC 5424's words for the severities 0 to 7, as Alloy's labels have
/// them.
const SEVERITIES: [&str; 8] = [
    "emergency",
    "alert",
    "critical",
    "error",
    "warning",
    "notice",
    "informational",
    "debug",
];

const FACILITIES: [&str; 24] = [
    "kern",
    "user",
    "mail",
    "daemon",
    "auth",
    "syslog",
    "lpr",
    "news",
    "uucp",
    "cron",
    "authpriv",
    "ftp",
    "ntp",
    "security",
    "console",
    "solaris-cron",
    "local0",
    "local1",
    "local2",
    "local3",
    "local4",
    "local5",
    "local6",
    "local7",
];

pub struct Syslog {
    socket: UdpSocket,
    source: Source,
    buf: Vec<u8>,
}

impl Syslog {
    pub fn bind(address: &str, source: Source) -> io::Result<Syslog> {
        let socket = UdpSocket::bind(address)?;
        socket.set_nonblocking(true)?;
        Ok(Syslog {
            socket,
            source,
            buf: vec![0; MAX_LENGTH],
        })
    }
}

impl Part for Syslog {
    fn fds(&self) -> Vec<RawFd> {
        vec![self.socket.as_raw_fd()]
    }

    fn read(&mut self, _index: usize, logs: &mut Logs, _p: &mut Positions) {
        for _ in 0..READ_AT_ONCE {
            if logs.blocked(Instant::now()) {
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
            let datagram = String::from_utf8_lossy(&self.buf[..length]);
            let Some(message) = parse(&datagram) else {
                continue;
            };
            let label = |name: &str, value: &str| {
                (format!("__syslog_{name}"), value.to_owned())
            };
            let labels = vec![
                label("connection_ip_address", &from.ip().to_string()),
                label("message_severity", message.severity),
                label("message_facility", message.facility),
                label("message_hostname", message.hostname),
                label("message_app_name", message.app),
                label("message_proc_id", message.pid),
            ];
            self.source.emit(logs, labels, time::now_ns(), message.text);
        }
    }
}

struct Message<'a> {
    severity: &'static str,
    facility: &'static str,
    hostname: &'a str,
    app: &'a str,
    pid: &'a str,
    text: &'a str,
}

/// `<PRI>` and as much of RFC 3164's header as there is: a timestamp,
/// the sender's name, `tag[pid]:`.
fn parse(datagram: &str) -> Option<Message<'_>> {
    let (priority, rest) = datagram.strip_prefix('<')?.split_once('>')?;
    let priority: u8 = priority.parse().ok()?;
    let rest = after_timestamp(rest);
    let (host, after_host) = rest.split_once(' ').unwrap_or(("", rest));
    let (hostname, (app, pid, text)) = match tag(rest) {
        Some(tagged) => ("", tagged),
        None => (host, tag(after_host).unwrap_or(("", "", rest))),
    };
    let text = if app.is_empty() { rest } else { text };
    Some(Message {
        severity: SEVERITIES[usize::from(priority & 7)],
        facility: FACILITIES.get(usize::from(priority >> 3)).unwrap_or(&""),
        hostname: if app.is_empty() { "" } else { hostname },
        app,
        pid,
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

/// `tag[pid]: text` as the tag, the pid and the text; None if `rest`
/// does not start with one.
fn tag(rest: &str) -> Option<(&str, &str, &str)> {
    let (head, text) = rest.split_once(':')?;
    if head.is_empty() || head.contains(' ') {
        return None;
    }
    let (app, pid) = head.split_once('[').unwrap_or((head, ""));
    let pid = pid.trim_end_matches(']');
    Some((app, pid, text.strip_prefix(' ').unwrap_or(text)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fields(datagram: &str) -> (&'static str, &str, &str) {
        let m = parse(datagram).unwrap();
        (m.severity, m.app, m.text)
    }

    #[test]
    fn reads_bsd_syslog() {
        assert_eq!(
            fields("<30>Nov 15 02:36:24 ndhcps: sending ACK. "),
            ("informational", "ndhcps", "sending ACK. ")
        );
        assert_eq!(
            fields("<27>Nov  5 02:36:24 keenetic ndm: Core::Syslog: x"),
            ("error", "ndm", "Core::Syslog: x")
        );
        assert_eq!(
            fields("<12>2026-11-15T02:36:24Z dropbear[42]: login"),
            ("warning", "dropbear", "login")
        );
        assert_eq!(fields("<14>just text"), ("informational", "", "just text"));
        let m = parse("<27>Nov  5 02:36:24 keenetic ndm[7]: x").unwrap();
        assert_eq!(
            (m.hostname, m.pid, m.facility),
            ("keenetic", "7", "daemon")
        );
        assert!(parse("no priority").is_none());
    }
}
