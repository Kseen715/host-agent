//! Metrics Prometheus could not take, kept on disk until it can, as
//! Alloy's WAL keeps them: one file per compressed chunk in
//! `state_dir/spool`, named `<sequence>-<samples>-<newest ms>`. Sent
//! oldest first, and new chunks wait behind them, so each series'
//! samples arrive in order. A chunk goes once sent: nothing reads it
//! again. Unsent ones go as Alloy truncates its WAL: every
//! truncate_frequency, those older than the newest sample sent less
//! min_keepalive_time, or than max_keepalive_time; also, at send time,
//! those past queue_config's sample_age_limit, and past the size cap.

use std::collections::VecDeque;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// Time a flush may spend sending kept chunks: the loop has logs to
/// read too.
const DRAIN_FOR: Duration = Duration::from_secs(5);

pub struct Chunk {
    path: PathBuf,
    pub bytes: u64,
    pub samples: u64,
    pub newest_ms: i64,
}

/// The `wal` block's truncation.
#[derive(Clone, Copy)]
pub struct Truncation {
    pub every: Duration,
    pub min_keep: Duration,
    pub max_keep: Duration,
}

impl Default for Truncation {
    /// Alloy's.
    fn default() -> Truncation {
        Truncation {
            every: Duration::from_secs(2 * 3600),
            min_keep: Duration::from_secs(5 * 60),
            max_keep: Duration::from_secs(8 * 3600),
        }
    }
}

pub struct Spool {
    dir: PathBuf,
    max_bytes: u64,
    /// sample_age_limit, when set.
    age_limit_ms: Option<i64>,
    truncation: Truncation,
    next_truncation: Instant,
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
    pub fn open(
        dir: PathBuf,
        max_bytes: u64,
        age_limit: Option<Duration>,
        truncation: Truncation,
    ) -> io::Result<Spool> {
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
            age_limit_ms: age_limit.map(ms),
            truncation,
            next_truncation: Instant::now() + truncation.every,
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
        let mut dropped = 0;
        let mut total: u64 = self.chunks.iter().map(|c| c.bytes).sum();
        while total > self.max_bytes {
            let Some(oldest) = self.chunks.front() else {
                break;
            };
            total -= oldest.bytes;
            dropped += oldest.samples;
            self.remove_oldest();
        }
        dropped
    }

    /// Truncates as Alloy's WAL, once truncate_frequency has passed
    /// since the last time; returns the samples dropped.
    pub fn truncate(&mut self, now_ms: i64, newest_sent_ms: i64) -> u64 {
        if Instant::now() < self.next_truncation {
            return 0;
        }
        self.next_truncation = Instant::now() + self.truncation.every;
        let t = self.truncation;
        let oldest_kept_ms = (newest_sent_ms - ms(t.min_keep))
            .max(0)
            .max(now_ms - ms(t.max_keep));
        let mut dropped = 0;
        self.chunks.retain(|chunk| {
            let kept = chunk.newest_ms >= oldest_kept_ms;
            if !kept {
                dropped += chunk.samples;
                let _ = fs::remove_file(&chunk.path);
            }
            kept
        });
        dropped
    }

    fn remove_oldest(&mut self) {
        if let Some(chunk) = self.chunks.pop_front() {
            let _ = fs::remove_file(chunk.path);
        }
    }

    /// Sends kept chunks, oldest first, until one is not taken or
    /// DRAIN_FOR has passed; `done` learns each chunk taken or refused.
    /// Returns the samples dropped as past sample_age_limit.
    pub fn drain(
        &mut self,
        now_ms: i64,
        mut send: impl FnMut(&[u8], u64) -> Sent,
        mut done: impl FnMut(&Chunk, bool),
    ) -> u64 {
        let mut dropped = 0;
        while let Some(oldest) = self.chunks.front() {
            let limit = self.age_limit_ms.unwrap_or(i64::MAX);
            if now_ms.saturating_sub(oldest.newest_ms) <= limit {
                break;
            }
            dropped += oldest.samples;
            self.remove_oldest();
        }
        let start = Instant::now();
        while let Some(chunk) = self.chunks.front() {
            if start.elapsed() > DRAIN_FOR {
                break;
            }
            let Ok(data) = fs::read(&chunk.path) else {
                self.remove_oldest();
                continue;
            };
            match send(&data, chunk.samples) {
                Sent::Done => done(chunk, true),
                Sent::Refused => done(chunk, false),
                Sent::Later => break,
            }
            self.remove_oldest();
        }
        dropped
    }
}

fn ms(duration: Duration) -> i64 {
    duration.as_millis() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_order_and_caps() {
        let dir =
            std::env::temp_dir().join(format!("spool-{}", std::process::id()));
        let hour = Some(Duration::from_secs(3600));
        let wal = Truncation::default();
        let mut spool = Spool::open(dir.clone(), 10, hour, wal).unwrap();
        assert_eq!(spool.push(b"aaaa", 1, 1000), 0);
        assert_eq!(spool.push(b"bbbb", 2, 2000), 0);
        // Past 10 bytes: the oldest goes.
        assert_eq!(spool.push(b"cccc", 3, 3000), 1);

        let mut spool = Spool::open(dir.clone(), 10, hour, wal).unwrap();
        let mut sent = Vec::new();
        let mut taken = 0;
        spool.drain(
            3000,
            |data, _| {
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

        // An hour on, what is left is too old.
        let dropped =
            spool.drain(3000 + 3_600_001, |_, _| Sent::Done, |_, _| {});
        assert_eq!(dropped, 3);
        assert!(spool.is_empty());
        fs::remove_dir_all(dir).unwrap();
    }

    /// Older than the newest sent less min_keep, or than max_keep.
    #[test]
    fn truncates_as_alloy() {
        let dir = std::env::temp_dir()
            .join(format!("spool-wal-{}", std::process::id()));
        let wal = Truncation {
            every: Duration::ZERO,
            ..Truncation::default()
        };
        let mut spool = Spool::open(dir.clone(), 100, None, wal).unwrap();
        spool.push(b"a", 1, 0);
        spool.push(b"b", 2, 400_000);
        spool.push(b"c", 4, 600_000);
        assert_eq!(spool.truncate(600_000, 500_000), 1);
        let eight_hours = 8 * 3_600_000;
        assert_eq!(spool.truncate(eight_hours + 500_000, 0), 2);
        assert!(!spool.is_empty());
        fs::remove_dir_all(dir).unwrap();
    }
}
