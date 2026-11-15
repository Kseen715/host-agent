//! loki.source.file: the files its targets' `__path__` name or match
//! (crate::glob), less those `__path_exclude__` matches; a target's
//! other labels go with its lines, plus `filename`. With
//! `tail_from_end`, a file without a saved position is first read from
//! the start of its last line, as Alloy reads it, also one that appears
//! later; a new inode or a shorter file (rotation) from its start.
//! Lines are decoded as Alloy's tailer decodes them (crate::charset);
//! with `decompression`, a file is read once to its end, decompressed,
//! its position counted in decompressed bytes.

use crate::charset::{self, Charset};
use crate::host;
use crate::logs::{Logs, Source};
use crate::relabel::Labels;
use crate::state::{FilePos, Positions};
use crate::targets::{self, Targets};
use crate::time;
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::time::{Duration, Instant};

const READ_AT_ONCE: u64 = 64 << 10;
/// A line longer than this goes in pieces.
const MAX_LINE: usize = 64 << 10;

/// How a source's files are read: its `encoding` and `decompression`
/// with its initial delay.
#[derive(Clone, Copy, Default)]
pub struct Reading {
    pub charset: Option<Charset>,
    pub compression: Option<(Compression, Duration)>,
}

#[derive(Clone, Copy)]
pub enum Compression {
    Gzip,
    Zlib,
    Bzip2,
}

struct Tail {
    path: String,
    /// What its lines go with, made by the source.
    labels: Labels,
    pos: Option<FilePos>,
    /// Without a saved position: read from the start, not the end.
    from_start: bool,
    partial: Vec<u8>,
    /// The file's encoding: its byte order mark's, else the source's;
    /// None, its bytes as they are.
    charset: Option<Charset>,
    /// Whether the mark was looked for, and its length.
    marked: Option<u64>,
    /// A compressed file being read, and whether it has been to its end.
    stream: Option<Box<dyn Read>>,
    done: bool,
    since: Instant,
}

pub struct Files {
    targets: Targets,
    tail_from_end: bool,
    reading: Reading,
    source: Source,
    tails: Vec<Tail>,
}

impl Files {
    pub fn new(
        targets: Targets,
        tail_from_end: bool,
        reading: Reading,
        source: Source,
    ) -> Files {
        Files {
            targets,
            tail_from_end,
            reading,
            source,
            tails: Vec::new(),
        }
    }

    /// Resolves the targets and matches the patterns again; positions
    /// of files no longer listed are forgotten.
    pub fn refresh(&mut self, docker: &[Labels], positions: &mut Positions) {
        let files = files(self.targets.resolve(docker));
        self.tails
            .retain(|t| files.iter().any(|(p, _)| *p == t.path));
        for (path, mut found) in files {
            found.push(("filename".into(), path.clone()));
            let Some(labels) = self.source.labels_for(found) else {
                continue;
            };
            match self.tails.iter_mut().find(|t| t.path == path) {
                Some(tail) => tail.labels = labels,
                None => {
                    let pos = positions.files.get(&path).copied();
                    self.tails.push(Tail {
                        path,
                        labels,
                        pos,
                        from_start: !self.tail_from_end,
                        partial: Vec::new(),
                        charset: None,
                        marked: None,
                        stream: None,
                        done: false,
                        since: Instant::now(),
                    });
                }
            }
        }
    }

    /// Reads what the files gained since the last call.
    pub fn read(&mut self, logs: &mut Logs, positions: &mut Positions) {
        for tail in &mut self.tails {
            if logs.blocked(std::time::Instant::now()) {
                return;
            }
            let read = match self.reading.compression {
                None => tail.read(&self.reading, &self.source, logs, positions),
                Some(compression) => tail.read_compressed(
                    compression,
                    self.reading.charset,
                    (&self.source, logs),
                    positions,
                ),
            };
            if let Err(error) = read {
                if error.kind() != std::io::ErrorKind::NotFound {
                    eprintln!("Logs: {}: {error}", tail.path);
                }
            }
        }
    }

    pub fn has(&self, path: &str) -> bool {
        self.tails.iter().any(|t| t.path == path)
    }
}

/// Forgets the positions of files no source reads.
pub fn forget_others(sources: &[Files], positions: &mut Positions) {
    let before = positions.files.len();
    positions
        .files
        .retain(|p, _| sources.iter().any(|f| f.has(p)));
    if positions.files.len() != before {
        positions.touch();
    }
}

impl Tail {
    fn read(
        &mut self,
        reading: &Reading,
        source: &Source,
        logs: &mut Logs,
        positions: &mut Positions,
    ) -> io::Result<()> {
        let meta = fs::metadata(host::path(&self.path))?;
        let (dev, ino, len) = (meta.dev(), meta.ino(), meta.len());
        let rotated = self
            .pos
            .is_some_and(|p| p.dev != dev || p.ino != ino || p.offset > len);
        let skip = match self.marked.filter(|_| !rotated) {
            Some(skip) => skip,
            None => self.mark(reading.charset)?,
        };
        let offset = match self.pos {
            None if self.from_start => 0,
            None => last_line(&self.path, len, self.newline())?,
            Some(_) if rotated => 0,
            Some(p) => p.offset,
        };
        let offset = offset.max(skip);
        if offset != self.pos.map_or(u64::MAX, |p| p.offset) {
            self.partial.clear();
        }
        let mut pos = FilePos { dev, ino, offset };
        if offset < len {
            let mut file = File::open(host::path(&self.path))?;
            file.seek(SeekFrom::Start(offset))?;
            let mut buf = Vec::new();
            file.take(READ_AT_ONCE).read_to_end(&mut buf)?;
            pos.offset += buf.len() as u64;
            self.lines(&buf, source, logs);
        }
        self.save(pos, positions);
        Ok(())
    }

    /// Looks for a byte order mark: the encoding is the mark's, else
    /// `charset`. Gives the mark's length.
    fn mark(&mut self, charset: Option<Charset>) -> io::Result<u64> {
        let mut head = Vec::new();
        File::open(host::path(&self.path))?
            .take(4)
            .read_to_end(&mut head)?;
        let (skip, found) = charset::bom(&head);
        self.charset = found.or(charset);
        self.marked = Some(skip);
        Ok(skip)
    }

    /// A compressed file, read once to its end: a little more each
    /// round, its last line without a newline sent at the end.
    fn read_compressed(
        &mut self,
        (compression, delay): (Compression, Duration),
        charset: Option<Charset>,
        (source, logs): (&Source, &mut Logs),
        positions: &mut Positions,
    ) -> io::Result<()> {
        let meta = fs::metadata(host::path(&self.path))?;
        let (dev, ino) = (meta.dev(), meta.ino());
        let replaced = self.pos.is_some_and(|p| p.dev != dev || p.ino != ino);
        if replaced {
            (self.pos, self.stream, self.done) = (None, None, false);
            self.partial.clear();
        }
        if self.done || self.since.elapsed() < delay {
            return Ok(());
        }
        if self.stream.is_none() {
            self.open_compressed(
                compression,
                charset,
                (dev, ino),
                (source, logs),
            )?;
        }
        let stream = self.stream.as_mut().expect("opened above");
        let mut buf = Vec::new();
        let read = stream.take(READ_AT_ONCE).read_to_end(&mut buf);
        let mut pos = self.pos.expect("set when opened");
        if let Err(error) = read {
            // Alloy's tailer stops at a broken file too.
            (self.stream, self.done) = (None, true);
            return Err(error);
        }
        pos.offset += buf.len() as u64;
        self.lines(&buf, source, logs);
        if buf.is_empty() {
            let line = std::mem::take(&mut self.partial);
            if !line.is_empty() {
                let line = self.decode(&line);
                self.add(&line, source, logs);
            }
            (self.stream, self.done) = (None, true);
        }
        self.save(pos, positions);
        Ok(())
    }

    /// Opens the file's decompressed stream past what was read before
    /// and its byte order mark.
    fn open_compressed(
        &mut self,
        compression: Compression,
        charset: Option<Charset>,
        (dev, ino): (u64, u64),
        (source, logs): (&Source, &mut Logs),
    ) -> io::Result<()> {
        let file = File::open(host::path(&self.path))?;
        let mut stream = decompressor(compression, file)?;
        let mut head = Vec::new();
        (&mut stream).take(4).read_to_end(&mut head)?;
        let (skip, found) = charset::bom(&head);
        self.charset = found.or(charset);
        let offset = self.pos.map_or(0, |p| p.offset).max(skip);
        let consumed = head.len() as u64;
        if offset > consumed {
            io::copy(
                &mut (&mut stream).take(offset - consumed),
                &mut io::sink(),
            )?;
        }
        self.partial.clear();
        let rest = head.get(offset as usize..).unwrap_or_default();
        self.lines(rest, source, logs);
        let offset = offset.max(consumed);
        self.pos = Some(FilePos { dev, ino, offset });
        self.stream = Some(stream);
        Ok(())
    }

    /// Keeps `pos`, less the partial line, as the saved position.
    fn save(&mut self, pos: FilePos, positions: &mut Positions) {
        if self.pos != Some(pos) || !positions.files.contains_key(&self.path) {
            self.pos = Some(pos);
            let mut saved = pos;
            saved.offset -= self.partial.len() as u64;
            positions.files.insert(self.path.clone(), saved);
            positions.touch();
        }
    }

    fn newline(&self) -> &'static [u8] {
        self.charset.map_or(b"\n".as_slice(), Charset::newline)
    }

    fn decode(&self, line: &[u8]) -> String {
        let cr: &[u8] = self.charset.map_or(b"\r", Charset::carriage_return);
        let line = line.strip_suffix(cr).unwrap_or(line);
        match self.charset {
            Some(charset) => charset.decode(line),
            None => String::from_utf8_lossy(line).into_owned(),
        }
    }

    fn lines(&mut self, buf: &[u8], source: &Source, logs: &mut Logs) {
        self.partial.extend_from_slice(buf);
        let newline = self.newline();
        let mut start = 0;
        while let Some(eol) = find(&self.partial[start..], newline) {
            let line = self.decode(&self.partial[start..start + eol]);
            self.add(&line, source, logs);
            start += eol + newline.len();
        }
        self.partial.drain(..start);
        if self.partial.len() > MAX_LINE {
            let line = self.decode(&self.partial);
            self.add(&line, source, logs);
            self.partial.clear();
        }
    }

    fn add(&self, line: &str, source: &Source, logs: &mut Logs) {
        source.send(logs, self.labels.clone(), time::now_ns(), line);
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(feature = "decompression")]
fn decompressor(
    compression: Compression,
    file: File,
) -> io::Result<Box<dyn Read>> {
    use flate2::read::{MultiGzDecoder, ZlibDecoder};
    let file = io::BufReader::new(file);
    Ok(match compression {
        Compression::Gzip => Box::new(MultiGzDecoder::new(file)),
        Compression::Zlib => Box::new(ZlibDecoder::new(file)),
        Compression::Bzip2 => Box::new(bzip2_rs::DecoderReader::new(file)),
    })
}

// A configuration that asks for it is refused without the feature.
#[cfg(not(feature = "decompression"))]
fn decompressor(_: Compression, _: File) -> io::Result<Box<dyn Read>> {
    Err(io::Error::other("built without feature decompression"))
}

/// Where the file's last line starts: after its last newline, or 0.
fn last_line(path: &str, len: u64, newline: &[u8]) -> io::Result<u64> {
    let mut file = File::open(host::path(path))?;
    // Chunks overlap so a newline of two bytes across an edge is seen.
    let overlap = newline.len() as u64 - 1;
    let mut end = len;
    let mut buf = Vec::new();
    while end > 0 {
        let start = end.saturating_sub(READ_AT_ONCE);
        let stop = (end + overlap).min(len);
        file.seek(SeekFrom::Start(start))?;
        buf.clear();
        (&mut file).take(stop - start).read_to_end(&mut buf)?;
        if let Some(i) = buf.windows(newline.len()).rposition(|w| w == newline)
        {
            return Ok(start + (i + newline.len()) as u64);
        }
        end = start;
    }
    Ok(0)
}

/// Each file the targets name or match, with its target's labels; the
/// first target to name a file wins.
fn files(targets: Vec<Labels>) -> Vec<(String, Labels)> {
    let mut files: Vec<(String, Labels)> = Vec::new();
    for target in targets {
        for found in targets::paths(&target) {
            if !files.iter().any(|(p, _)| *p == found) {
                files.push((found, target.clone()));
            }
        }
    }
    files
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logs::{Kind, Node};
    use crate::loki::Loki;
    use std::rc::Rc;

    #[test]
    fn tails_from_the_end_then_follows_rotation() {
        let dir = std::env::temp_dir()
            .join(format!("ha-files-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let log = dir.join("latest.log");
        fs::write(&log, "old line\nhalf").unwrap();
        let target = format!(
            r#"[{{"targets":["localhost"],"labels":
                {{"__path__":"{}/*.log","job":"minecraft"}}}}]"#,
            dir.display()
        );
        fs::write(dir.join("t.json"), target).unwrap();

        let mut positions = Positions::load(dir.join("positions"));
        let host = vec![("host".into(), "h".into())];
        let loki =
            Loki::new("http://127.0.0.1:1/push", "c", host, Default::default())
                .unwrap();
        let mut logs = Logs {
            nodes: vec![Node {
                kind: Kind::Write(0),
                to: Rc::from([]),
            }],
            sinks: vec![loki],
        };
        let source = Source {
            to: Rc::from([0]),
            ..Source::default()
        };
        let pattern = format!("{}/t.json", dir.display());
        let targets = Targets::Files(vec![pattern]);
        let mut files = Files::new(targets, true, Reading::default(), source);
        files.refresh(&[], &mut positions);
        files.read(&mut logs, &mut positions);
        fs::write(&log, "old line\nhalf\nnew [WARN] one\npart").unwrap();
        files.read(&mut logs, &mut positions);
        let pos = positions.files[&log.display().to_string()];
        let read = "old line\nhalf\nnew [WARN] one\n";
        assert_eq!(pos.offset, read.len() as u64);

        fs::remove_file(&log).unwrap();
        fs::write(&log, "rotated\n").unwrap();
        fs::write(dir.join("other.log"), "appeared\n").unwrap();
        files.refresh(&[], &mut positions);
        files.read(&mut logs, &mut positions);
        let values = logs.sinks[0].values();
        assert!(
            values.contains("new [WARN] one") && values.contains("rotated")
        );
        assert!(values.contains("half") && !values.contains("appeared"));
        assert!(!values.contains("old line") && !values.contains("part"));
        fs::remove_dir_all(dir).unwrap();
    }

    fn read_once(dir: &std::path::Path, reading: Reading) -> String {
        let mut positions = Positions::load(dir.join("positions"));
        let loki = Loki::new(
            "http://127.0.0.1:1/push",
            "c",
            vec![],
            Default::default(),
        )
        .unwrap();
        let mut logs = Logs {
            nodes: vec![Node {
                kind: Kind::Write(0),
                to: Rc::from([]),
            }],
            sinks: vec![loki],
        };
        let source = Source {
            to: Rc::from([0]),
            ..Source::default()
        };
        let target = vec![
            ("__address__".into(), "localhost".into()),
            ("__path__".into(), format!("{}/*.log*", dir.display())),
        ];
        let targets = Targets::Static(vec![target]);
        let mut files = Files::new(targets, false, reading, source);
        files.refresh(&[], &mut positions);
        for _ in 0..3 {
            files.read(&mut logs, &mut positions);
        }
        logs.sinks[0].values()
    }

    #[test]
    fn decodes_by_byte_order_mark() {
        let dir = std::env::temp_dir()
            .join(format!("ha-charset-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let text: Vec<u8> = "\u{feff}héllo\r\nwörld\n"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        fs::write(dir.join("a.log"), text).unwrap();
        let values = read_once(&dir, Reading::default());
        assert!(
            values.contains("héllo") && values.contains("wörld"),
            "{values}"
        );
        assert!(!values.contains('\r') && !values.contains('\u{feff}'));
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(feature = "decompression")]
    #[test]
    fn reads_compressed_files_once() {
        use std::io::Write;
        let dir = std::env::temp_dir()
            .join(format!("ha-gzip-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let file = File::create(dir.join("a.log.gz")).unwrap();
        let level = flate2::Compression::default();
        let mut gz = flate2::write::GzEncoder::new(file, level);
        gz.write_all(b"one\ntwo\nlast").unwrap();
        gz.finish().unwrap();
        let reading = Reading {
            compression: Some((Compression::Gzip, Duration::ZERO)),
            ..Reading::default()
        };
        let values = read_once(&dir, reading);
        assert!(
            values.contains("one") && values.contains("last"),
            "{values}"
        );
        fs::remove_dir_all(dir).unwrap();
    }
}
