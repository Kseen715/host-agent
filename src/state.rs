//! Where each log source stopped, saved once its lines are in Loki: a
//! restart or an outage resumes from there instead of from a buffer in
//! memory. One line per source:
//! `journal <component> <cursor>`, `docker <component>/<container>
//! <ns>`, `file <dev> <inode> <offset> <path>`. A key without the
//! component is a former single source's, read until it is replaced.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// Saved at most this often: a crash replays a few seconds of lines.
const EVERY: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FilePos {
    pub dev: u64,
    pub ino: u64,
    pub offset: u64,
}

pub struct Positions {
    path: PathBuf,
    /// Each loki.source.journal's cursor.
    journal: HashMap<String, String>,
    /// Container id to the time of its last line read.
    pub docker: HashMap<String, i64>,
    pub files: HashMap<String, FilePos>,
    saved_at: Option<Instant>,
    dirty: bool,
}

impl Positions {
    pub fn load(path: PathBuf) -> Positions {
        let mut positions = Positions {
            path,
            journal: HashMap::new(),
            docker: HashMap::new(),
            files: HashMap::new(),
            saved_at: None,
            dirty: false,
        };
        let text = fs::read_to_string(&positions.path).unwrap_or_default();
        for line in text.lines() {
            positions.read_line(line);
        }
        positions
    }

    fn read_line(&mut self, line: &str) {
        let mut words = line.splitn(5, ' ');
        match (words.next(), words.next()) {
            (Some("journal"), Some(first)) => {
                let (id, cursor) = match words.next() {
                    Some(cursor) => (first, cursor),
                    None => ("", first),
                };
                self.journal.insert(id.to_owned(), cursor.to_owned());
            }
            (Some("docker"), Some(id)) => {
                if let Some(ns) = words.next().and_then(|n| n.parse().ok()) {
                    self.docker.insert(id.to_owned(), ns);
                }
            }
            (Some("file"), Some(dev)) => {
                let mut num = || words.next()?.parse().ok();
                let (ino, offset) = (num(), num());
                let path = words.next();
                if let (Ok(dev), Some(ino), Some(offset), Some(path)) =
                    (dev.parse(), ino, offset, path)
                {
                    let pos = FilePos { dev, ino, offset };
                    self.files.insert(path.to_owned(), pos);
                }
            }
            _ => {}
        }
    }

    /// Where the journal source `id` stopped.
    pub fn cursor(&self, id: &str) -> Option<&str> {
        let cursor = self.journal.get(id).or(self.journal.get(""));
        cursor.map(String::as_str)
    }

    pub fn set_cursor(&mut self, id: &str, cursor: String) {
        self.journal.remove("");
        self.journal.insert(id.to_owned(), cursor);
        self.dirty = true;
    }

    /// Forgets source `id`'s cursor.
    #[cfg(all(feature = "journal", not(feature = "journal-files")))]
    pub fn forget_cursor(&mut self, id: &str) {
        let had = self.journal.remove(id).or(self.journal.remove(""));
        self.dirty |= had.is_some();
    }

    pub fn touch(&mut self) {
        self.dirty = true;
    }

    /// Saves if something moved and the last save is old enough, or
    /// now if `force`.
    pub fn save(&mut self, force: bool) -> io::Result<()> {
        let recent = self.saved_at.is_some_and(|at| at.elapsed() < EVERY);
        if !self.dirty || (recent && !force) {
            return Ok(());
        }
        let mut text = String::new();
        for (id, cursor) in &self.journal {
            let separator = if id.is_empty() { "" } else { " " };
            text.push_str(&format!("journal {id}{separator}{cursor}\n"));
        }
        for (id, ns) in &self.docker {
            text.push_str(&format!("docker {id} {ns}\n"));
        }
        for (path, pos) in &self.files {
            let FilePos { dev, ino, offset } = pos;
            text.push_str(&format!("file {dev} {ino} {offset} {path}\n"));
        }
        let temporary = self.path.with_extension("tmp");
        fs::write(&temporary, text)?;
        fs::rename(&temporary, &self.path)?;
        self.saved_at = Some(Instant::now());
        self.dirty = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let dir =
            std::env::temp_dir().join(format!("ha-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("positions");
        let mut positions = Positions::load(path.clone());
        positions.set_cursor("loki.source.journal.read", "s=1;i=2".into());
        positions.docker.insert("abc".into(), 42);
        let pos = FilePos {
            dev: 1,
            ino: 2,
            offset: 3,
        };
        positions.files.insert("/a b/latest.log".into(), pos);
        positions.touch();
        positions.save(true).unwrap();

        let loaded = Positions::load(path);
        let cursor = loaded.cursor("loki.source.journal.read");
        assert_eq!(cursor, Some("s=1;i=2"));
        fs::write(dir.join("former"), "journal s=3\n").unwrap();
        let former = Positions::load(dir.join("former"));
        assert_eq!(former.cursor("loki.source.journal.x"), Some("s=3"));
        assert_eq!(loaded.docker.get("abc"), Some(&42));
        assert_eq!(loaded.files.get("/a b/latest.log"), Some(&pos));
        fs::remove_dir_all(dir).unwrap();
    }
}
