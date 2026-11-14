//! Metrics Prometheus could not take, kept on disk until it can, as
//! Alloy's WAL keeps them: one file per compressed chunk in
//! `state_dir/spool`, named `<sequence>-<samples>-<newest ms>`. Sent
//! oldest first, and new chunks wait behind them, so each series'
//! samples arrive in order. Chunks older than MAX_AGE, or past the size
//! cap, are dropped: Prometheus takes samples no older than an hour
//! behind its newest (without an out-of-order window), so older ones
//! would be refused anyway.

use std::collections::VecDeque;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::time::{Duration, Instant};

const MAX_AGE_MS: i64 = 2 * 3600 * 1000;
/// Time a flush may spend sending kept chunks: the loop has logs to
/// read too.
const DRAIN_FOR: Duration = Duration::from_secs(5);

pub struct Chunk {
    path: PathBuf,
    pub bytes: u64,
    pub samples: u64,
    pub newest_ms: i64,
}

pub struct Spool {
    dir: PathBuf,
    max_bytes: u64,
    chunks: VecDeque<Chunk>,
    next: u64,
}

/// What became of a chunk sent.
pub enum Sent {
    Done,
    /// Refused for good (a 4xx but 429): dropped.
    Refused,
    /// Not taken now (no answer, 5xx, 429): kept.
    Later,
}

impl Spool {
    pub fn open(dir: PathBuf, max_bytes: u64) -> io::Result<Spool> {
        fs::create_dir_all(&dir)?;
        let mut chunks: Vec<(u64, Chunk)> = fs::read_dir(&dir)?
            .flatten()
            .filter_map(|entry| {
                let name = entry.file_name().into_string().ok()?;
                let mut fields = name.split('-').map(str::parse::<i64>);
                let (Some(Ok(sequence)), Some(Ok(samples)), Some(Ok(newest))) =
                    (fields.next(), fields.next(), fields.next())
                else {
                    let _ = fs::remove_file(entry.path());
                    return None;
                };
                let chunk = Chunk {
                    path: entry.path(),
                    bytes: entry.metadata().ok()?.len(),
                    samples: samples as u64,
                    newest_ms: newest,
                };
                Some((sequence as u64, chunk))
            })
            .collect();
        chunks.sort_by_key(|(sequence, _)| *sequence);
        let next = chunks.last().map_or(0, |(sequence, _)| sequence + 1);
        Ok(Spool {
            dir,
            max_bytes,
            chunks: chunks.into_iter().map(|(_, chunk)| chunk).collect(),
            next,
        })
    }

    pub fn is_empty(&self) -> bool {
        self.chunks.is_empty()
    }

    /// Keeps a chunk; returns the samples of chunks dropped to make room.
    pub fn push(&mut self, data: &[u8], samples: u64, newest_ms: i64) -> u64 {
        let name = format!("{:020}-{samples}-{newest_ms}", self.next);
        let path = self.dir.join(name);
        let temporary = path.with_extension("tmp");
        let written = fs::write(&temporary, data)
            .and_then(|()| fs::rename(&temporary, &path));
        if let Err(error) = written {
            eprintln!("Spool: {error}");
            return samples;
        }
        self.next += 1;
        let bytes = data.len() as u64;
        self.chunks.push_back(Chunk {
            path,
            bytes,
            samples,
            newest_ms,
        });
        self.trim(newest_ms)
    }

    /// Drops the oldest chunks past the age or size cap; returns their
    /// samples.
    fn trim(&mut self, now_ms: i64) -> u64 {
        let mut dropped = 0;
        let mut total: u64 = self.chunks.iter().map(|c| c.bytes).sum();
        while let Some(oldest) = self.chunks.front() {
            let old = now_ms - oldest.newest_ms > MAX_AGE_MS;
            if !old && total <= self.max_bytes {
                break;
            }
            total -= oldest.bytes;
            dropped += oldest.samples;
            self.remove_oldest();
        }
        dropped
    }

    fn remove_oldest(&mut self) {
        if let Some(chunk) = self.chunks.pop_front() {
            let _ = fs::remove_file(chunk.path);
        }
    }

    /// Sends kept chunks, oldest first, until one is not taken or
    /// DRAIN_FOR has passed; `done` learns each chunk taken or refused.
    pub fn drain(
        &mut self,
        now_ms: i64,
        mut send: impl FnMut(&[u8]) -> Sent,
        mut done: impl FnMut(&Chunk, bool),
    ) {
        let dropped = self.trim(now_ms);
        if dropped > 0 {
            eprintln!("Spool: dropped {dropped} samples too old to send");
        }
        let start = Instant::now();
        while let Some(chunk) = self.chunks.front() {
            if start.elapsed() > DRAIN_FOR {
                return;
            }
            let Ok(data) = fs::read(&chunk.path) else {
                self.remove_oldest();
                continue;
            };
            match send(&data) {
                Sent::Done => done(chunk, true),
                Sent::Refused => done(chunk, false),
                Sent::Later => return,
            }
            self.remove_oldest();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_order_and_caps() {
        let dir =
            std::env::temp_dir().join(format!("spool-{}", std::process::id()));
        let mut spool = Spool::open(dir.clone(), 10).unwrap();
        assert_eq!(spool.push(b"aaaa", 1, 1000), 0);
        assert_eq!(spool.push(b"bbbb", 2, 2000), 0);
        // Past 10 bytes: the oldest goes.
        assert_eq!(spool.push(b"cccc", 3, 3000), 1);

        let mut spool = Spool::open(dir.clone(), 10).unwrap();
        let mut sent = Vec::new();
        let mut taken = 0;
        spool.drain(
            3000,
            |data| {
                sent.push(data.to_vec());
                if sent.len() == 1 {
                    Sent::Done
                } else {
                    Sent::Later
                }
            },
            |chunk, _| taken += chunk.samples,
        );
        assert_eq!(sent, [b"bbbb".to_vec(), b"cccc".to_vec()]);
        assert_eq!(taken, 2);
        assert!(!spool.is_empty());

        // Two hours on, what is left is too old.
        spool.drain(3000 + MAX_AGE_MS + 1, |_| Sent::Done, |_, _| {});
        assert!(spool.is_empty());
        fs::remove_dir_all(dir).unwrap();
    }
}
