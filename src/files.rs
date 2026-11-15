//! loki.source.file: the files its targets' `__path__` name or match
//! (crate::glob), less those `__path_exclude__` matches; a target's
//! other labels go with its lines, plus `filename`. With
//! `tail_from_end`, a file there at the first start is first read from
//! its end; one that appears later, a new inode or a shorter file
//! (rotation) from its start.

use crate::glob;
use crate::host;
use crate::logs::{Logs, Source};
use crate::relabel::Labels;
use crate::state::{FilePos, Positions};
use crate::targets::{self, Targets};
use crate::time;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;

const READ_AT_ONCE: u64 = 64 << 10;
/// A line longer than this goes in pieces.
const MAX_LINE: usize = 64 << 10;

struct Tail {
    path: String,
    /// What its lines go with, made by the source.
    labels: Labels,
    pos: Option<FilePos>,
    /// Without a saved position: read from the start, not the end.
    from_start: bool,
    partial: Vec<u8>,
}

pub struct Files {
    targets: Targets,
    tail_from_end: bool,
    source: Source,
    tails: Vec<Tail>,
    refreshed: bool,
}

impl Files {
    pub fn new(targets: Targets, tail_from_end: bool, source: Source) -> Files {
        Files {
            targets,
            tail_from_end,
            source,
            tails: Vec::new(),
            refreshed: false,
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
                    let from_start = !self.tail_from_end
                        || self.refreshed
                        || !host::path(&path).exists();
                    self.tails.push(Tail {
                        path,
                        labels,
                        pos,
                        from_start,
                        partial: Vec::new(),
                    });
                }
            }
        }
        self.refreshed = true;
    }

    /// Reads what the files gained since the last call.
    pub fn read(&mut self, logs: &mut Logs, positions: &mut Positions) {
        for tail in &mut self.tails {
            if logs.blocked(std::time::Instant::now()) {
                return;
            }
            if let Err(error) = tail.read(&self.source, logs, positions) {
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
        source: &Source,
        logs: &mut Logs,
        positions: &mut Positions,
    ) -> std::io::Result<()> {
        let meta = fs::metadata(host::path(&self.path))?;
        let (dev, ino, len) = (meta.dev(), meta.ino(), meta.len());
        let offset = match self.pos {
            None if self.from_start => 0,
            None => len,
            Some(p) if p.dev != dev || p.ino != ino || p.offset > len => 0,
            Some(p) => p.offset,
        };
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
        if self.pos != Some(pos) {
            self.pos = Some(pos);
            let mut saved = pos;
            saved.offset -= self.partial.len() as u64;
            positions.files.insert(self.path.clone(), saved);
            positions.touch();
        }
        Ok(())
    }

    fn lines(&mut self, buf: &[u8], source: &Source, logs: &mut Logs) {
        self.partial.extend_from_slice(buf);
        let mut start = 0;
        while let Some(eol) =
            self.partial[start..].iter().position(|&b| b == b'\n')
        {
            let line =
                String::from_utf8_lossy(&self.partial[start..start + eol]);
            self.add(line.trim_end_matches('\r'), source, logs);
            start += eol + 1;
        }
        self.partial.drain(..start);
        if self.partial.len() > MAX_LINE {
            let line = String::from_utf8_lossy(&self.partial).into_owned();
            self.add(&line, source, logs);
            self.partial.clear();
        }
    }

    fn add(&self, line: &str, source: &Source, logs: &mut Logs) {
        source.send(logs, self.labels.clone(), time::now_ns(), line);
    }
}

/// Each file the targets name or match, with its target's labels; the
/// first target to name a file wins.
fn files(targets: Vec<Labels>) -> Vec<(String, Labels)> {
    let mut files: Vec<(String, Labels)> = Vec::new();
    for target in targets {
        let path = targets::get(&target, "__path__");
        let exclude = targets::get(&target, "__path_exclude__");
        let paths = if glob::is_pattern(path) {
            glob::expand(path)
        } else {
            vec![path.to_owned()]
        };
        let excluded =
            |p: &str| !exclude.is_empty() && glob::matches(exclude, p);
        for found in paths {
            if !found.is_empty()
                && !excluded(&found)
                && !files.iter().any(|(p, _)| *p == found)
            {
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
        fs::write(&log, "old line\n").unwrap();
        let target = format!(
            r#"[{{"targets":["localhost"],"labels":
                {{"__path__":"{}/*.log","job":"minecraft"}}}}]"#,
            dir.display()
        );
        fs::write(dir.join("t.json"), target).unwrap();

        let mut positions = Positions::load(dir.join("positions"));
        let host = vec![("host".into(), "h".into())];
        let loki = Loki::new("http://127.0.0.1:1/push", "c", host).unwrap();
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
        let mut files = Files::new(targets, true, source);
        files.refresh(&[], &mut positions);
        files.read(&mut logs, &mut positions);
        fs::write(&log, "old line\nnew [WARN] one\npart").unwrap();
        files.read(&mut logs, &mut positions);
        let pos = positions.files[&log.display().to_string()];
        assert_eq!(pos.offset, "old line\nnew [WARN] one\n".len() as u64);

        fs::remove_file(&log).unwrap();
        fs::write(&log, "rotated\n").unwrap();
        fs::write(dir.join("other.log"), "appeared\n").unwrap();
        files.refresh(&[], &mut positions);
        files.read(&mut logs, &mut positions);
        let values = logs.sinks[0].values();
        assert!(
            values.contains("new [WARN] one") && values.contains("rotated")
        );
        assert!(values.contains("appeared"));
        assert!(!values.contains("old line") && !values.contains("part"));
        fs::remove_dir_all(dir).unwrap();
    }
}
