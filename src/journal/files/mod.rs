//! The journal read from its files, without journalctl: the
//! local machine's directories under /var/log/journal and
//! /run/log/journal (crate::host, so a container reads the host's).
//! inotify wakes it when journald writes. The files' entries are
//! merged as journalctl merges them, so the cursor kept, journalctl's,
//! marks everything before it as read: either reader resumes where the
//! other stopped.

mod format;

use super::{Fields, deliver};
use crate::host;
use crate::logs::{Logs, Source};
use crate::parts::Part;
use crate::state::Positions;
use format::JournalFile;
use std::collections::HashSet;
use std::fs::{self, File};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// Entries read per wake: the loop has other sources.
const ENTRIES_AT_ONCE: usize = 512;

pub struct Journal {
    dirs: Vec<PathBuf>,
    inotify: OwnedFd,
    /// Readable while entries are left to read.
    behind: OwnedFd,
    files: Vec<Reading>,
    /// Files opened or passed over, by device and inode.
    seen: HashSet<(u64, u64)>,
    /// None until the saved cursor is known (`prepare`).
    start: Option<Start>,
    max_age: Duration,
    source: Source,
    /// The component's id: where its cursor is kept.
    id: String,
}

/// An entry's seqnum_id, seqnum and realtime.
type Place = ([u8; 16], u64, u64);

/// Whether `a` was written before `b`, as journalctl orders entries:
/// by seqnum in one sequence (journald's, across its files), else by
/// time.
fn before(a: Place, b: Place) -> bool {
    if a.0 == b.0 { a.1 < b.1 } else { a.2 < b.2 }
}

/// A file being read and its next entry, if it has one yet.
struct Reading {
    file: JournalFile,
    next: Option<(u64, Place)>,
}

impl Reading {
    fn peek(&mut self) {
        let offset = self
            .file
            .next_entries()
            .ok()
            .and_then(|o| o.first().copied());
        self.next = offset.and_then(|o| Some((o, self.file.place(o).ok()?)));
    }
}

/// Where reading begins in a file present at the start.
enum Start {
    /// After this entry (a cursor's seqnum_id and seqnum, realtime).
    After([u8; 16], u64, u64),
    /// No earlier than this realtime.
    Since(u64),
}

impl Start {
    /// Whether the entry at `place` (seqnum_id, seqnum, realtime) was
    /// read before: by seqnum in the cursor's sequence, else by time.
    fn covers(&self, place: Place) -> bool {
        match *self {
            Start::After(id, seqnum, realtime) => {
                !before((id, seqnum, realtime), place)
            }
            Start::Since(since) => place.2 < since,
        }
    }
}

impl Journal {
    /// None on a host without journal directories.
    pub fn new(
        id: String,
        max_age: Duration,
        source: Source,
    ) -> Option<Journal> {
        let machine = fs::read_to_string(host::path("/etc/machine-id")).ok()?;
        let dirs: Vec<PathBuf> = ["/var/log/journal", "/run/log/journal"]
            .iter()
            .map(|root| host::path(&format!("{root}/{}", machine.trim())))
            .filter(|dir| dir.is_dir())
            .collect();
        if dirs.is_empty() {
            return None;
        }
        Some(Journal {
            inotify: watch(&dirs)?,
            behind: event_fd()?,
            dirs,
            files: Vec::new(),
            seen: HashSet::new(),
            start: None,
            max_age,
            source,
            id,
        })
    }

    /// Opens files not seen before, oldest first: those present at the
    /// start from `start`, later ones from their first entry.
    fn open_new(&mut self) {
        let mut found = Vec::new();
        for dir in &self.dirs {
            let Ok(entries) = fs::read_dir(dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                let name =
                    path.file_name().unwrap_or_default().to_string_lossy();
                let Ok(meta) = entry.metadata() else {
                    continue;
                };
                let key = (meta.dev(), meta.ino());
                if name.contains(".journal") && self.seen.insert(key) {
                    found.push((meta.mtime(), path));
                }
            }
        }
        found.sort();
        for (_, path) in found {
            match File::open(&path).and_then(JournalFile::open) {
                Ok((file, header)) => self.add_file(file, &header),
                Err(error) => eprintln!("Journal: {}: {error}", path.display()),
            }
        }
        self.start = Some(Start::Since(0));
    }

    /// An archived file wholly before `start` is passed over; another is
    /// read from the first entry after it.
    fn add_file(&mut self, mut file: JournalFile, header: &format::Header) {
        let tail = (header.seqnum_id, header.tail_seqnum, header.tail_realtime);
        let start = self.start.as_ref().expect("started");
        if header.archived && start.covers(tail) {
            return;
        }
        if let Err(error) = self.skip(&mut file) {
            eprintln!("Journal: {error}");
            return;
        }
        self.files.push(Reading { file, next: None });
    }

    fn skip(&self, file: &mut JournalFile) -> io::Result<()> {
        let start = self.start.as_ref().expect("started");
        loop {
            let offsets = file.next_entries()?;
            let mut before = 0;
            for &offset in &offsets {
                if !start.covers(file.place(offset)?) {
                    break;
                }
                before += 1;
            }
            file.advance(before);
            if before < offsets.len() || offsets.is_empty() {
                return Ok(());
            }
        }
    }

    /// Reads up to ENTRIES_AT_ONCE entries, the earliest first;
    /// whether all were read.
    fn read_entries(
        &mut self,
        logs: &mut Logs,
        positions: &mut Positions,
    ) -> bool {
        for reading in &mut self.files {
            reading.peek();
        }
        self.files.retain(|r| {
            r.next.is_some() || r.file.header().is_ok_and(|h| !h.archived)
        });
        for _ in 0..ENTRIES_AT_ONCE {
            if logs.blocked(Instant::now()) {
                return false;
            }
            let next = self.files.iter().map(|r| r.next.map(|n| n.1));
            let Some(index) = earliest(next) else {
                return true;
            };
            let reading = &mut self.files[index];
            let (offset, _) = reading.next.expect("earliest has one");
            match reading.file.entry(offset) {
                Ok(entry) => {
                    send((&self.source, &self.id), &entry, logs, positions)
                }
                Err(error) => eprintln!("Journal: entry {offset}: {error}"),
            }
            reading.file.advance(1);
            reading.peek();
        }
        false
    }
}

impl Part for Journal {
    /// The first time: the files from the saved cursor, or from
    /// `max_age` ago.
    fn prepare(&mut self, positions: &Positions) {
        if self.start.is_some() {
            return;
        }
        let cursor = positions.cursor(&self.id).and_then(parse_cursor);
        self.start = Some(cursor.unwrap_or_else(|| {
            let now_us = crate::time::now_ns() as u64 / 1000;
            let age_us = self.max_age.as_micros() as u64;
            Start::Since(now_us.saturating_sub(age_us))
        }));
        self.open_new();
    }

    fn fds(&self) -> Vec<RawFd> {
        vec![self.inotify.as_raw_fd(), self.behind.as_raw_fd()]
    }

    fn read(&mut self, _index: usize, logs: &mut Logs, p: &mut Positions) {
        drain(&self.inotify);
        self.open_new();
        if self.read_entries(logs, p) {
            drain(&self.behind);
        } else {
            signal(&self.behind);
        }
    }
}

/// The index of the place written first.
fn earliest(places: impl Iterator<Item = Option<Place>>) -> Option<usize> {
    let places = places.enumerate().filter_map(|(i, p)| Some((i, p?)));
    let first = places.reduce(|a, b| if before(b.1, a.1) { b } else { a });
    first.map(|(index, _)| index)
}

fn send(
    (source, id): (&Source, &str),
    entry: &format::Entry,
    logs: &mut Logs,
    p: &mut Positions,
) {
    let pairs = entry.fields.iter().filter_map(|f| {
        let eq = f.iter().position(|&b| b == b'=')?;
        Some((&f[..eq], &f[eq + 1..]))
    });
    let fields = Fields {
        realtime_us: i64::try_from(entry.realtime).ok(),
        pairs: pairs.collect(),
    };
    deliver(source, &fields, logs);
    p.set_cursor(id, cursor(entry));
}

/// journalctl's cursor for an entry.
fn cursor(entry: &format::Entry) -> String {
    format!(
        "s={};i={:x};b={};m={:x};t={:x};x={:x}",
        hex(&entry.seqnum_id),
        entry.seqnum,
        hex(&entry.boot_id),
        entry.monotonic,
        entry.realtime,
        entry.xor_hash
    )
}

/// A cursor's place: `s` (seqnum_id), `i` (seqnum), `t` (realtime).
fn parse_cursor(cursor: &str) -> Option<Start> {
    let field = |key: &str| {
        cursor
            .split(';')
            .find_map(|f| f.strip_prefix(key)?.strip_prefix('='))
    };
    let id = field("s")?;
    let mut seqnum_id = [0; 16];
    for (i, byte) in seqnum_id.iter_mut().enumerate() {
        *byte = u8::from_str_radix(id.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    let number = |key| u64::from_str_radix(field(key)?, 16).ok();
    Some(Start::After(seqnum_id, number("i")?, number("t")?))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// An inotify descriptor on the directories: journald writing,
/// creating and renaming files.
fn watch(dirs: &[PathBuf]) -> Option<OwnedFd> {
    // SAFETY: a new descriptor, owned from here on.
    let fd =
        unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
    if fd < 0 {
        return None;
    }
    // SAFETY: fd was just made.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let events = libc::IN_MODIFY | libc::IN_CREATE | libc::IN_MOVED_TO;
    for dir in dirs {
        let path =
            std::ffi::CString::new(dir.as_os_str().as_encoded_bytes()).ok()?;
        // SAFETY: a NUL-terminated path.
        unsafe {
            libc::inotify_add_watch(fd.as_raw_fd(), path.as_ptr(), events)
        };
    }
    Some(fd)
}

/// An eventfd: readable while its count is not zero.
fn event_fd() -> Option<OwnedFd> {
    // SAFETY: a new descriptor, owned from here on.
    let fd =
        unsafe { libc::eventfd(1, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC) };
    // SAFETY: fd was just made.
    (fd >= 0).then(|| unsafe { OwnedFd::from_raw_fd(fd) })
}

fn signal(fd: &OwnedFd) {
    let one = 1u64.to_ne_bytes();
    // SAFETY: 8 bytes from a live buffer, as eventfd takes.
    unsafe { libc::write(fd.as_raw_fd(), one.as_ptr().cast(), 8) };
}

/// Reads what is pending: inotify's events, an eventfd's count.
fn drain(fd: &OwnedFd) {
    let mut buf = [0u8; 4096];
    // SAFETY: reads into a live buffer of its length.
    while unsafe {
        libc::read(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len())
    } > 0
    {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_cursors() {
        let cursor = "s=0123456789abcdef0123456789abcdef;i=1f;\
                      b=00;m=5;t=64;x=9";
        let Some(Start::After(id, seqnum, realtime)) = parse_cursor(cursor)
        else {
            panic!("not read");
        };
        assert_eq!(hex(&id), "0123456789abcdef0123456789abcdef");
        assert_eq!((seqnum, realtime), (31, 100));
        let start = Start::After(id, 31, 100);
        assert!(start.covers((id, 31, 500)));
        assert!(!start.covers((id, 32, 50)));
        assert!(start.covers(([0; 16], 99, 100)));
    }

    #[test]
    fn merges_by_seqnum_else_time() {
        let (a, b) = ([1; 16], [2; 16]);
        let places = [Some((a, 7, 900)), None, Some((a, 5, 950))];
        assert_eq!(earliest(places.into_iter()), Some(2));
        let places = [Some((a, 5, 950)), Some((b, 1, 940))];
        assert_eq!(earliest(places.into_iter()), Some(1));
        assert_eq!(earliest([None].into_iter()), None);
    }
}
