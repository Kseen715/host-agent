//! Log files: the settings' `log` lines, and the targets jobs on this
//! host list in file_sd JSON (`*.json` in the log targets directory).
//! A target's `__path__` is a file or a pattern (crate::glob), less
//! those `__path_exclude__` matches; its other labels go with its lines,
//! plus `filename`. A file there at the first start is first read from
//! its end; one that appears later, a new inode or a shorter file
//! (rotation) from its start.

use crate::glob;
use crate::host;
use crate::json::Json;
use crate::levels;
use crate::loki::Loki;
use crate::state::{FilePos, Positions};
use crate::time;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

const READ_AT_ONCE: u64 = 64 << 10;
/// A line longer than this goes in pieces.
const MAX_LINE: usize = 64 << 10;

type Labels = Vec<(String, String)>;

/// A `__path__`, its `__path_exclude__`, and the labels of its lines.
pub struct Target {
    pub path: String,
    pub exclude: Option<String>,
    pub labels: Labels,
}

struct Tail {
    path: String,
    labels: Labels,
    pos: Option<FilePos>,
    /// Without a saved position: read from the start, not the end.
    from_start: bool,
    partial: Vec<u8>,
}

pub struct Files {
    dir: Option<PathBuf>,
    fixed: Vec<Target>,
    tails: Vec<Tail>,
    refreshed: bool,
}

impl Files {
    /// `fixed`: the settings' targets, besides those listed in `dir`.
    pub fn new(dir: Option<PathBuf>, fixed: Vec<Target>) -> Files {
        Files {
            dir,
            fixed,
            tails: Vec::new(),
            refreshed: false,
        }
    }

    /// Reads the target lists and matches the patterns again; positions
    /// of files no longer listed are forgotten.
    pub fn refresh(&mut self, positions: &mut Positions) {
        let listed = self.dir.as_deref().map(read_targets);
        let files = files(self.fixed.iter().chain(listed.iter().flatten()));
        self.tails
            .retain(|t| files.iter().any(|(p, _)| *p == t.path));
        for (path, labels) in files {
            match self.tails.iter_mut().find(|t| t.path == path) {
                Some(tail) => tail.labels = labels,
                None => {
                    let pos = positions.files.get(&path).copied();
                    let from_start =
                        self.refreshed || !host::path(&path).exists();
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
        let before = positions.files.len();
        positions
            .files
            .retain(|p, _| self.tails.iter().any(|t| &t.path == p));
        if positions.files.len() != before {
            positions.touch();
        }
    }

    /// Reads what the files gained since the last call.
    pub fn read(&mut self, loki: &mut Loki, positions: &mut Positions) {
        for tail in &mut self.tails {
            if loki.blocked(std::time::Instant::now()) {
                return;
            }
            if let Err(error) = tail.read(loki, positions) {
                if error.kind() != std::io::ErrorKind::NotFound {
                    eprintln!("Logs: {}: {error}", tail.path);
                }
            }
        }
    }
}

impl Tail {
    fn read(
        &mut self,
        loki: &mut Loki,
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
            self.lines(&buf, loki);
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

    fn lines(&mut self, buf: &[u8], loki: &mut Loki) {
        self.partial.extend_from_slice(buf);
        let mut start = 0;
        while let Some(eol) =
            self.partial[start..].iter().position(|&b| b == b'\n')
        {
            let line =
                String::from_utf8_lossy(&self.partial[start..start + eol]);
            self.add(line.trim_end_matches('\r'), loki);
            start += eol + 1;
        }
        self.partial.drain(..start);
        if self.partial.len() > MAX_LINE {
            let line = String::from_utf8_lossy(&self.partial).into_owned();
            self.add(&line, loki);
            self.partial.clear();
        }
    }

    fn add(&self, line: &str, loki: &mut Loki) {
        let mut labels: Vec<(&str, &str)> = self
            .labels
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        labels.push(("filename", &self.path));
        labels.push(("level", levels::level(line).unwrap_or("")));
        loki.add(&labels, time::now_ns(), line);
    }
}

/// Each file the targets name or match, with its target's labels; the
/// first target to name a file wins.
fn files<'a>(
    targets: impl Iterator<Item = &'a Target>,
) -> Vec<(String, Labels)> {
    let mut files: Vec<(String, Labels)> = Vec::new();
    for target in targets {
        let paths = if glob::is_pattern(&target.path) {
            glob::expand(&target.path)
        } else {
            vec![target.path.clone()]
        };
        let excluded = |path: &str| {
            target
                .exclude
                .as_ref()
                .is_some_and(|e| glob::matches(e, path))
        };
        for path in paths {
            if !excluded(&path) && !files.iter().any(|(p, _)| *p == path) {
                files.push((path, target.labels.clone()));
            }
        }
    }
    files
}

/// Every target in the directory's `*.json` files.
fn read_targets(dir: &Path) -> Vec<Target> {
    let mut names: Vec<PathBuf> = fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|e| e == "json"))
        .collect();
    names.sort();
    let mut targets = Vec::new();
    for name in names {
        let text = fs::read_to_string(&name).unwrap_or_default();
        let Some(json) = Json::parse(&text) else {
            eprintln!("Logs: {} is not JSON", name.display());
            continue;
        };
        targets.extend(json.arr().iter().filter_map(target));
    }
    targets
}

/// A file_sd group: `__path__` and `__path_exclude__`, and its labels
/// other than `__*`.
fn target(group: &Json) -> Option<Target> {
    let labels = group.get("labels").map(Json::obj).unwrap_or_default();
    let label = |key: &str| {
        let (_, value) = labels.iter().find(|(k, _)| k == key)?;
        value.str().map(str::to_owned)
    };
    Some(Target {
        path: label("__path__")?,
        exclude: label("__path_exclude__"),
        labels: labels
            .iter()
            .filter(|(k, _)| !k.starts_with("__"))
            .filter_map(|(k, v)| Some((k.clone(), v.str()?.to_owned())))
            .collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let mut loki = Loki::new("http://127.0.0.1:1/push", "h").unwrap();
        let mut files = Files::new(Some(dir.clone()), Vec::new());
        files.refresh(&mut positions);
        files.read(&mut loki, &mut positions);
        fs::write(&log, "old line\nnew [WARN] one\npart").unwrap();
        files.read(&mut loki, &mut positions);
        let pos = positions.files[&log.display().to_string()];
        assert_eq!(pos.offset, "old line\nnew [WARN] one\n".len() as u64);

        fs::remove_file(&log).unwrap();
        fs::write(&log, "rotated\n").unwrap();
        fs::write(dir.join("other.log"), "appeared\n").unwrap();
        files.refresh(&mut positions);
        files.read(&mut loki, &mut positions);
        let values = loki.values();
        assert!(
            values.contains("new [WARN] one") && values.contains("rotated")
        );
        assert!(values.contains("appeared"));
        assert!(!values.contains("old line") && !values.contains("part"));
        fs::remove_dir_all(dir).unwrap();
    }
}
