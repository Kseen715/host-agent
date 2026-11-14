//! The systemd journal, read through `journalctl --output=export`: the
//! binary links no libsystemd (it is static, for any host), and the
//! journal files stay mapped in journalctl, not here. Each entry's
//! cursor is kept, so a restart resumes after the last line sent.

use crate::host;
use crate::levels::PRIORITIES;
use crate::loki::Loki;
use crate::state::Positions;
use regex_lite::Regex;
use std::io::{self, Read};
use std::os::fd::{AsRawFd, RawFd};
use std::process::{Child, ChildStdout, Command, Stdio};
use std::time::{Duration, Instant};

const RESTART_AFTER: Duration = Duration::from_secs(5);
const READ_AT_ONCE: usize = 64 << 10;

pub struct Journal {
    child: Option<(Child, ChildStdout)>,
    /// An entry came since journalctl started.
    read_any: bool,
    buf: Vec<u8>,
    restart_at: Instant,
    max_age: String,
    drops: Vec<Regex>,
}

/// The fields of one entry that are used.
#[derive(Default)]
struct Entry<'a> {
    cursor: Option<&'a [u8]>,
    realtime_us: Option<&'a [u8]>,
    message: Option<&'a [u8]>,
    priority: Option<&'a [u8]>,
    unit: Option<&'a [u8]>,
}

impl Journal {
    /// None on a host without systemd.
    pub fn new(max_age: &str, drops: Vec<Regex>) -> Option<Journal> {
        host::path("/run/systemd/system").is_dir().then(|| Journal {
            child: None,
            read_any: false,
            buf: Vec::new(),
            restart_at: Instant::now(),
            max_age: max_age.to_owned(),
            drops,
        })
    }

    pub fn fd(&self) -> Option<RawFd> {
        self.child.as_ref().map(|(_, stdout)| stdout.as_raw_fd())
    }

    /// Starts journalctl if it is not running and its restart is due.
    pub fn ensure_running(&mut self, cursor: Option<&str>) {
        if self.child.is_some() || Instant::now() < self.restart_at {
            return;
        }
        let mut command = Command::new("journalctl");
        command.args(["--follow", "--output=export", "--no-pager"]);
        match cursor {
            Some(cursor) => command.arg(format!("--after-cursor={cursor}")),
            None => command.arg(format!("--since=-{}", self.max_age)),
        };
        command.stdin(Stdio::null()).stdout(Stdio::piped());
        match command.spawn() {
            Ok(mut child) => {
                let stdout = child.stdout.take().expect("piped");
                set_nonblocking(stdout.as_raw_fd());
                self.child = Some((child, stdout));
                self.read_any = false;
            }
            Err(error) => {
                eprintln!("Journal: cannot run journalctl: {error}");
                self.restart_at = Instant::now() + RESTART_AFTER;
            }
        }
    }

    /// Reads what journalctl wrote and adds its whole entries to `loki`.
    pub fn read(&mut self, loki: &mut Loki, positions: &mut Positions) {
        let Some((_, stdout)) = &mut self.child else {
            return;
        };
        let start = self.buf.len();
        self.buf.resize(start + READ_AT_ONCE, 0);
        let (read, ended) = match stdout.read(&mut self.buf[start..]) {
            Ok(read) => (read, read == 0),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                (0, false)
            }
            Err(error) => {
                eprintln!("Journal: {error}");
                (0, false)
            }
        };
        self.buf.truncate(start + read);
        if ended {
            self.stopped(positions);
        }
        self.take_entries(loki, positions);
    }

    /// A journalctl that failed before its first entry may have been
    /// given a cursor no journal file holds any more: the next start
    /// goes by age instead.
    fn stopped(&mut self, positions: &mut Positions) {
        if let Some((mut child, _)) = self.child.take() {
            let status = child.wait();
            eprintln!("Journal: journalctl stopped: {status:?}");
            let failed = !status.is_ok_and(|status| status.success());
            if failed && !self.read_any && positions.journal.take().is_some() {
                positions.touch();
            }
        }
        self.buf.clear();
        self.restart_at = Instant::now() + RESTART_AFTER;
    }

    fn take_entries(&mut self, loki: &mut Loki, positions: &mut Positions) {
        let mut at = 0;
        while let Some((entry, used)) = parse_entry(&self.buf[at..]) {
            at += used;
            self.read_any = true;
            if let Some(cursor) = entry.cursor {
                let cursor = String::from_utf8_lossy(cursor).into_owned();
                positions.journal = Some(cursor);
                positions.touch();
            }
            self.add(&entry, loki);
        }
        self.buf.drain(..at);
        if self.buf.capacity() > 4 * READ_AT_ONCE
            && self.buf.len() < READ_AT_ONCE
        {
            self.buf.shrink_to(READ_AT_ONCE);
        }
    }

    fn add(&self, entry: &Entry, loki: &mut Loki) {
        let Some(message) = entry.message else {
            return;
        };
        let message = String::from_utf8_lossy(message);
        if self.drops.iter().any(|drop| drop.is_match(&message)) {
            return;
        }
        let number = |field: Option<&[u8]>| -> Option<i64> {
            std::str::from_utf8(field?).ok()?.parse().ok()
        };
        let ns = number(entry.realtime_us).unwrap_or(0) * 1000;
        let level = number(entry.priority)
            .and_then(|p| PRIORITIES.get(usize::try_from(p).ok()?));
        let unit = entry.unit.map(String::from_utf8_lossy);
        let labels = [
            ("job", "journal"),
            ("unit", unit.as_deref().unwrap_or("")),
            ("level", level.copied().unwrap_or("")),
        ];
        loki.add(&labels, ns, &message);
    }
}

impl Drop for Journal {
    fn drop(&mut self) {
        if let Some((child, _)) = &mut self.child {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

pub fn set_nonblocking(fd: RawFd) {
    // SAFETY: fcntl on a descriptor this process owns.
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
    }
}

/// One entry of the export format and the bytes it took, if it is whole:
/// `KEY=value` lines, or `KEY`, a little-endian u64 size, the data and a
/// newline for a binary value; an empty line ends the entry.
fn parse_entry(buf: &[u8]) -> Option<(Entry<'_>, usize)> {
    let mut entry = Entry::default();
    let mut at = 0;
    loop {
        let eol = at + buf[at..].iter().position(|&b| b == b'\n')?;
        if eol == at {
            return Some((entry, at + 1));
        }
        let line = &buf[at..eol];
        let (key, value) = match line.iter().position(|&b| b == b'=') {
            Some(eq) => {
                at = eol + 1;
                (&line[..eq], &line[eq + 1..])
            }
            None => {
                let size = buf.get(eol + 1..eol + 9)?;
                let size = u64::from_le_bytes(size.try_into().ok()?) as usize;
                let data = eol + 9;
                buf.get(data + size)?;
                at = data + size + 1;
                (line, &buf[data..data + size])
            }
        };
        match key {
            b"__CURSOR" => entry.cursor = Some(value),
            b"__REALTIME_TIMESTAMP" => entry.realtime_us = Some(value),
            b"MESSAGE" => entry.message = Some(value),
            b"PRIORITY" => entry.priority = Some(value),
            b"_SYSTEMD_UNIT" => entry.unit = Some(value),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_text_and_binary_fields() {
        let mut wire =
            b"__CURSOR=s=1\n__REALTIME_TIMESTAMP=5\nMESSAGE\n".to_vec();
        wire.extend_from_slice(&3u64.to_le_bytes());
        wire.extend_from_slice(b"a\nb\nPRIORITY=3\n\nMESSAGE=next\n");
        let (entry, used) = parse_entry(&wire).unwrap();
        assert_eq!(entry.cursor, Some(&b"s=1"[..]));
        assert_eq!(entry.message, Some(&b"a\nb"[..]));
        assert_eq!(entry.priority, Some(&b"3"[..]));
        assert!(parse_entry(&wire[used..]).is_none(), "not whole yet");
        for cut in 0..used {
            assert!(parse_entry(&wire[..cut]).is_none(), "cut at {cut}");
        }
    }
}
