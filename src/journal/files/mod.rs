//! The journal read from its files, without journalctl: the
//! local machine's directories under /var/log/journal and
//! /run/log/journal (crate::host, so a container reads the host's).
//! inotify wakes it when journald writes. The files' entries are
//! merged as journalctl merges them, so the cursor kept, journalctl's,
//! marks everything before it as read: either reader resumes where the
//! other stopped.

mod format;

use super::{Fields, deliver};
use crate::alloy::JournalSource;
use crate::host;
use crate::logs::Logs;
use crate::parts::Part;
use crate::state::Positions;
use format::JournalFile;
use std::collections::HashSet;
use std::fs::{self, File};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::time::Instant;

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
    config: JournalSource,
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
    pub fn new(config: JournalSource) -> Option<Journal> {
        let dirs = match &config.path {
            Some(path) => directory(path),
            None => system_dirs()?,
        };
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
            config,
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
                Ok(entry) => send(&self.config, &entry, logs, positions),
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
        let cursor = positions.cursor(&self.config.id).and_then(parse_cursor);
        self.start = Some(cursor.unwrap_or_else(|| {
            let now_us = crate::time::now_ns() as u64 / 1000;
            let age_us = self.config.max_age.as_micros() as u64;
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
    config: &JournalSource,
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
    deliver(config, &fields, logs);
    p.set_cursor(&config.id, cursor(entry));
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
/// The machine's journal directories, persistent and volatile.
fn system_dirs() -> Option<Vec<PathBuf>> {
    let machine = fs::read_to_string(host::path("/etc/machine-id")).ok()?;
    let dirs = ["/var/log/journal", "/run/log/journal"]
        .iter()
        .map(|root| host::path(&format!("{root}/{}", machine.trim())));
    Some(dirs.filter(|dir| dir.is_dir()).collect())
}

/// `path` and the directories in it, as journald keeps a machine's
/// files in one named by its id.
fn directory(path: &str) -> Vec<PathBuf> {
    let root = host::path(path);
    let below = fs::read_dir(&root).into_iter().flatten().flatten();
    let below = below.map(|entry| entry.path()).filter(|p| p.is_dir());
    let mut dirs: Vec<PathBuf> = below.collect();
    dirs.sort();
    dirs.insert(0, root.clone());
    dirs.into_iter().filter(|dir| dir.is_dir()).collect()
}

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

    /// One entry of a test journal: its seqnum, realtime and fields,
    /// each stored as is, or compressed with flag 2 (LZ4) or 4 (zstd).
    struct Written<'a> {
        seqnum: u64,
        realtime: u64,
        fields: &'a [(&'a [u8], u8)],
    }

    const SEQNUM_ID: [u8; 16] = [7; 16];

    /// An LZ4 block of literals only: valid LZ4, as a block that found
    /// nothing to match is.
    fn lz4_literals(data: &[u8]) -> Vec<u8> {
        let mut block = vec![(data.len().min(15) as u8) << 4];
        if data.len() >= 15 {
            let mut rest = data.len() - 15;
            while rest >= 255 {
                block.push(255);
                rest -= 255;
            }
            block.push(rest as u8);
        }
        block.extend(data);
        block
    }

    fn object(out: &mut Vec<u8>, kind: u8, flags: u8, body: &[u8]) -> u64 {
        let at = out.len() as u64;
        out.extend([kind, flags, 0, 0, 0, 0, 0, 0]);
        out.extend((16 + body.len() as u64).to_le_bytes());
        out.extend(body);
        out.resize(out.len().next_multiple_of(8), 0);
        at
    }

    fn put(out: &mut [u8], at: usize, bytes: &[u8]) {
        out[at..at + bytes.len()].copy_from_slice(bytes);
    }

    /// A journal file as journald lays one out
    /// (JOURNAL_FILE_FORMAT.md), with only what a reader follows:
    /// the header, data and entry objects, and entry arrays of two
    /// items chained.
    fn journal(compact: bool, archived: bool, entries: &[Written]) -> Vec<u8> {
        let mut out = vec![0; 256];
        let flags: u32 = if compact { 16 | 2 | 8 } else { 2 | 8 };
        put(&mut out, 0, b"LPKSHHRH");
        put(&mut out, 12, &flags.to_le_bytes());
        out[16] = if archived { 2 } else { 1 };
        put(&mut out, 72, &SEQNUM_ID);
        let mut offsets = Vec::new();
        for entry in entries {
            let mut items = Vec::new();
            for (field, compression) in entry.fields {
                let stored = match compression {
                    2 => {
                        let mut sized =
                            (field.len() as u64).to_le_bytes().to_vec();
                        sized.extend(lz4_literals(field));
                        sized
                    }
                    4 => ruzstd::encoding::compress_to_vec(
                        *field,
                        ruzstd::encoding::CompressionLevel::Fastest,
                    ),
                    _ => field.to_vec(),
                };
                let mut body = vec![0; if compact { 56 } else { 48 }];
                body.extend(stored);
                let at = object(&mut out, 1, *compression, &body);
                match compact {
                    true => items.extend((at as u32).to_le_bytes()),
                    false => items.extend([at.to_le_bytes(), [0; 8]].concat()),
                }
            }
            let mut body = Vec::new();
            body.extend(entry.seqnum.to_le_bytes());
            body.extend(entry.realtime.to_le_bytes());
            body.extend(entry.seqnum.to_le_bytes());
            body.extend([9; 16]);
            body.extend(0u64.to_le_bytes());
            body.extend(items);
            offsets.push(object(&mut out, 3, 0, &body));
        }
        let mut next = 0u64;
        for pair in offsets.chunks(2).rev() {
            let mut body = next.to_le_bytes().to_vec();
            for offset in pair {
                match compact {
                    true => body.extend((*offset as u32).to_le_bytes()),
                    false => body.extend(offset.to_le_bytes()),
                }
            }
            next = object(&mut out, 6, 0, &body);
        }
        put(&mut out, 176, &next.to_le_bytes());
        if let Some(last) = entries.last() {
            put(&mut out, 160, &last.seqnum.to_le_bytes());
            put(&mut out, 192, &last.realtime.to_le_bytes());
        }
        out
    }

    fn now_us() -> u64 {
        crate::time::now_ns() as u64 / 1000
    }

    /// A machine's directory with an archived file and the active one,
    /// in the compact layout with compressed fields.
    fn machine_dir(test: &str) -> PathBuf {
        let root = crate::testing::scratch(test);
        let dir = root.join("0123456789abcdef0123456789abcdef");
        fs::create_dir_all(&dir).unwrap();
        let t = now_us() - 60_000_000;
        let archived = [
            Written {
                seqnum: 1,
                realtime: t,
                fields: &[(b"MESSAGE=boot", 0), (b"PRIORITY=6", 0)],
            },
            Written {
                seqnum: 2,
                realtime: t + 1,
                fields: &[(b"MESSAGE=disk ok", 0), (b"PRIORITY=5", 0)],
            },
            Written {
                seqnum: 3,
                realtime: t + 2,
                fields: &[(b"MESSAGE=net up", 0), (b"PRIORITY=6", 0)],
            },
        ];
        let active = [
            Written {
                seqnum: 4,
                realtime: t + 3,
                fields: &[(b"MESSAGE=lz4 line", 2), (b"PRIORITY=3", 0)],
            },
            Written {
                seqnum: 5,
                realtime: t + 4,
                fields: &[(b"MESSAGE=zstd line", 4), (b"PRIORITY=4", 4)],
            },
        ];
        fs::write(
            dir.join("system@a-1-2.journal"),
            journal(false, true, &archived),
        )
        .unwrap();
        fs::write(dir.join("system.journal"), journal(true, false, &active))
            .unwrap();
        fs::write(dir.join("notes.txt"), "not a journal").unwrap();
        root
    }

    /// Every entry of every file, in journald's order, its priority's
    /// word for the rules; the cursor kept is the last entry's.
    #[test]
    fn reads_journal_files() {
        use crate::testing::{self, response};
        let loki =
            testing::serve(|_| response("204 No Content", "text/plain", ""));
        let root = machine_dir("journal-read");
        let text = format!(
            r#"loki.write "w" {{ endpoint {{ url = "{}" }} }}
            loki.relabel "j" {{
                rule {{
                    source_labels = ["__journal_priority_keyword"]
                    target_label = "level"
                }}
                forward_to = []
            }}
            loki.source.journal "j" {{
                path = "{}"
                relabel_rules = loki.relabel.j.rules
                forward_to = [loki.write.w.receiver]
            }}"#,
            loki.url("/push"),
            root.display(),
        );
        let stmts = crate::alloy::parse(&text).unwrap();
        let mut plan = crate::alloy::compile(&stmts, false).unwrap();
        let mut logs = std::mem::take(&mut plan.logs);
        let mut positions = Positions::load(root.join("positions"));
        let mut journal = Journal::new(plan.journal.remove(0)).unwrap();
        journal.prepare(&positions);
        journal.read(0, &mut logs, &mut positions);
        logs.flush();
        let pushed =
            String::from_utf8_lossy(&loki.requests()[0].body).into_owned();
        // Loki's batch groups lines by labels: in time, they are in
        // journald's order, each at its entry's realtime.
        let value = regex_lite::Regex::new(r#"\["(\d+)","([^"]+)"\]"#).unwrap();
        let mut sent: Vec<(u64, &str)> = value
            .captures_iter(&pushed)
            .map(|c| (c[1].parse().unwrap(), c.get(2).unwrap().as_str()))
            .collect();
        sent.sort();
        let lines: Vec<&str> = sent.iter().map(|(_, line)| *line).collect();
        assert_eq!(
            lines,
            ["boot", "disk ok", "net up", "lz4 line", "zstd line"]
        );
        assert!(sent.windows(2).all(|w| w[1].0 - w[0].0 == 1000));
        assert!(pushed.contains(r#""level":"err""#), "{pushed}");
        assert!(pushed.contains(r#""level":"warning""#), "{pushed}");
        let cursor = positions.cursor("loki.source.journal.j").unwrap();
        assert!(
            cursor.starts_with(&format!("s={};i=5;", hex(&SEQNUM_ID))),
            "{cursor}"
        );
        assert_eq!(logs.sinks[0].sent, 5);
    }

    /// From a saved cursor: the archived file wholly before it is
    /// passed over, the active one read after it.
    #[test]
    fn resumes_after_the_cursor() {
        let root = machine_dir("journal-resume");
        let source = JournalSource {
            id: "j".into(),
            max_age: std::time::Duration::from_secs(3600),
            path: Some(root.display().to_string()),
            matches: Vec::new(),
            source: crate::logs::Source::default(),
        };
        let mut positions = Positions::load(root.join("positions"));
        let id = hex(&SEQNUM_ID);
        positions.set_cursor("j", format!("s={id};i=4;b=00;m=4;t=0;x=0"));
        let mut journal = Journal::new(source).unwrap();
        journal.prepare(&positions);
        assert_eq!(journal.files.len(), 1, "the archived file is read");
        let mut logs = Logs::default();
        journal.read(0, &mut logs, &mut positions);
        let cursor = positions.cursor("j").unwrap();
        assert!(cursor.starts_with(&format!("s={id};i=5;")), "{cursor}");
        assert!(
            Journal::new(JournalSource {
                path: Some("/no/such/journal".into()),
                ..journal.config
            })
            .is_none()
        );
    }

    #[test]
    fn refuses_files_it_cannot_read() {
        let dir = crate::testing::scratch("journal-bad");
        let mut unknown = journal(false, false, &[]);
        put(&mut unknown, 12, &(1u32 << 9).to_le_bytes());
        for (name, bytes) in
            [("flags", unknown), ("short", b"LPKSHHRH".to_vec())]
        {
            let path = dir.join(name);
            fs::write(&path, bytes).unwrap();
            assert!(
                File::open(&path).and_then(JournalFile::open).is_err(),
                "{name}"
            );
        }
        let empty = dir.join("empty.journal");
        fs::write(&empty, journal(true, false, &[])).unwrap();
        let (mut file, header) =
            File::open(&empty).and_then(JournalFile::open).unwrap();
        assert!(!header.archived);
        assert!(file.next_entries().unwrap().is_empty());
        assert!(file.entry(0).is_err());
    }
}
