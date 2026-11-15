//! The journal through `journalctl --output=export`: the binary links
//! no libsystemd (it is static, for any host), and the journal files
//! stay mapped in journalctl, not here. Each entry's cursor is kept, so
//! a restart resumes after the last line sent.

use super::{Fields, deliver};
use crate::host;
use crate::logs::{Logs, Source};
use crate::parts::Part;
use crate::state::Positions;
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
    max_age: Duration,
    source: Source,
    /// The component's id: where its cursor is kept.
    id: String,
}

/// An entry's cursor and the fields sent.
#[derive(Default)]
struct Entry<'a> {
    cursor: Option<&'a [u8]>,
    fields: Fields<'a>,
}

impl Journal {
    /// None on a host without systemd.
    pub fn new(
        id: String,
        max_age: Duration,
        source: Source,
    ) -> Option<Journal> {
        host::path("/run/systemd/system").is_dir().then(|| Journal {
            child: None,
            read_any: false,
            buf: Vec::new(),
            restart_at: Instant::now(),
            max_age,
            source,
            id,
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
            None => {
                command.arg(format!("--since=-{}s", self.max_age.as_secs()))
            }
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

    /// Reads what journalctl wrote and sends its whole entries.
    pub fn read(&mut self, logs: &mut Logs, positions: &mut Positions) {
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
        self.take_entries(logs, positions);
    }

    /// A journalctl that failed before its first entry may have been
    /// given a cursor no journal file holds any more: the next start
    /// goes by age instead.
    fn stopped(&mut self, positions: &mut Positions) {
        if let Some((mut child, _)) = self.child.take() {
            let status = child.wait();
            eprintln!("Journal: journalctl stopped: {status:?}");
            let failed = !status.is_ok_and(|status| status.success());
            if failed && !self.read_any {
                positions.forget_cursor(&self.id);
            }
        }
        self.buf.clear();
        self.restart_at = Instant::now() + RESTART_AFTER;
    }

    fn take_entries(&mut self, logs: &mut Logs, positions: &mut Positions) {
        let mut at = 0;
        while let Some((entry, used)) = parse_entry(&self.buf[at..]) {
            at += used;
            self.read_any = true;
            if let Some(cursor) = entry.cursor {
                let cursor = String::from_utf8_lossy(cursor).into_owned();
                positions.set_cursor(&self.id, cursor);
            }
            deliver(&self.source, &entry.fields, logs);
        }
        self.buf.drain(..at);
        if self.buf.capacity() > 4 * READ_AT_ONCE
            && self.buf.len() < READ_AT_ONCE
        {
            self.buf.shrink_to(READ_AT_ONCE);
        }
    }
}

impl Part for Journal {
    fn prepare(&mut self, positions: &Positions) {
        self.ensure_running(positions.cursor(&self.id));
    }

    fn fds(&self) -> Vec<RawFd> {
        self.fd().into_iter().collect()
    }

    fn read(&mut self, _index: usize, logs: &mut Logs, p: &mut Positions) {
        Journal::read(self, logs, p);
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
            b"__REALTIME_TIMESTAMP" => {
                let text = std::str::from_utf8(value).ok();
                entry.fields.realtime_us = text.and_then(|t| t.parse().ok());
            }
            name if name.starts_with(b"__") => {}
            name => entry.fields.pairs.push((name, value)),
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
        let message = (&b"MESSAGE"[..], &b"a\nb"[..]);
        let priority = (&b"PRIORITY"[..], &b"3"[..]);
        assert_eq!(entry.fields.pairs, [message, priority]);
        assert!(parse_entry(&wire[used..]).is_none(), "not whole yet");
        for cut in 0..used {
            assert!(parse_entry(&wire[..cut]).is_none(), "cut at {cut}");
        }
    }
}
