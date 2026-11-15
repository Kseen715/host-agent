//! Prometheus's queue manager, as a remote write runs it: series are
//! spread over shards by their labels' hash; each shard's samples go
//! in batches of max_samples_per_send, handed to the shard's sender
//! (crate::remote) when full or at batch_send_deadline; and every 10 s
//! the number of shards is fitted to how fast samples come in and go
//! out, as Prometheus's calculateDesiredShards and shouldReshard do.

use crate::remote::put_varint;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::time::{Duration, Instant};

/// How often the shards are fitted, and the latest rates' weight.
const FIT_EVERY: Duration = Duration::from_secs(10);
const WEIGHT: f64 = 0.2;
/// A change by less than this share of the shards is not made.
const TOLERANCE: f64 = 0.3;
/// Seconds behind past which no shard is taken away.
const BEHIND: f64 = 10.0;

/// queue_config's sizes.
#[derive(Clone, Copy)]
pub struct Config {
    pub capacity: u64,
    pub min_shards: usize,
    pub max_shards: usize,
    pub max_samples: u64,
    pub deadline: Duration,
}

impl Default for Config {
    /// Alloy's.
    fn default() -> Config {
        Config {
            capacity: 10_000,
            min_shards: 1,
            max_shards: 50,
            max_samples: 2000,
            deadline: Duration::from_secs(5),
        }
    }
}

impl Config {
    /// Full batches a shard's sender may hold waiting, as Prometheus's
    /// newQueue sizes its channel.
    pub fn batches(&self) -> usize {
        (self.capacity / self.max_samples).max(1) as usize
    }
}

/// Samples snappy-compressed, one request's worth.
pub struct Batch {
    pub data: Vec<u8>,
    pub samples: u64,
    pub newest_ms: i64,
}

/// A shard's batch being filled.
struct Shard {
    body: Vec<u8>,
    samples: u64,
    newest_ms: i64,
    /// When its last batch went, and when this one got its first
    /// sample.
    last: Instant,
    first: Option<Instant>,
}

impl Shard {
    fn new() -> Shard {
        Shard {
            body: Vec::new(),
            samples: 0,
            newest_ms: 0,
            last: Instant::now(),
            first: None,
        }
    }
}

/// An exponentially weighted rate per second, ticked every FIT_EVERY.
#[derive(Default)]
struct Ewma {
    events: f64,
    rate: f64,
    init: bool,
}

impl Ewma {
    fn tick(&mut self) {
        let events = std::mem::take(&mut self.events);
        let instant = events / FIT_EVERY.as_secs_f64();
        if self.init {
            self.rate += WEIGHT * (instant - self.rate);
        } else if events > 0.0 {
            self.init = true;
            self.rate = instant;
        }
    }
}

pub struct Queue {
    pub config: Config,
    shards: Vec<Shard>,
    /// Samples in; sent, taken or refused; dropped unsent; seconds
    /// spent sending.
    input: Ewma,
    out: Ewma,
    dropped: Ewma,
    seconds: Ewma,
    next_fit: Instant,
    /// When the last send ended, taken or refused.
    last_done: Option<Instant>,
    /// No resharding until then: a send waits to be tried again.
    held_until: Option<Instant>,
    /// The last fit's shards, before rounding.
    pub desired: f64,
    /// Samples a batch could not be made of.
    pub lost: u64,
}

impl Queue {
    /// min_shards shards: Prometheus's start.
    pub fn new(config: Config) -> Queue {
        Queue {
            config,
            shards: (0..config.min_shards).map(|_| Shard::new()).collect(),
            input: Ewma::default(),
            out: Ewma::default(),
            dropped: Ewma::default(),
            seconds: Ewma::default(),
            next_fit: Instant::now() + FIT_EVERY,
            last_done: None,
            held_until: None,
            desired: config.min_shards as f64,
            lost: 0,
        }
    }

    pub fn shards(&self) -> usize {
        self.shards.len()
    }

    /// Adds an encoded `TimeSeries` to its shard: that shard's batch,
    /// when full.
    pub fn push(
        &mut self,
        labels: &[(&str, &str)],
        series: &[u8],
        ms: i64,
    ) -> Option<(usize, Batch)> {
        self.input.events += 1.0;
        let index = match self.shards.len() {
            1 => 0,
            n => {
                let mut hasher = DefaultHasher::new();
                labels.hash(&mut hasher);
                (hasher.finish() % n as u64) as usize
            }
        };
        let shard = &mut self.shards[index];
        // The WriteRequest's `timeseries` field.
        shard.body.push(0x0A);
        put_varint(&mut shard.body, series.len() as u64);
        shard.body.extend_from_slice(series);
        shard.samples += 1;
        shard.newest_ms = shard.newest_ms.max(ms);
        shard.first.get_or_insert_with(Instant::now);
        if shard.samples < self.config.max_samples {
            return None;
        }
        Some((index, self.seal(index, Instant::now())?))
    }

    /// When a batch is next due, or the shards' next fit.
    pub fn due(&self) -> Option<Instant> {
        let config = &self.config;
        let fit =
            (config.min_shards < config.max_shards).then_some(self.next_fit);
        self.shards
            .iter()
            .filter_map(|s| self.fires(s))
            .chain(fit)
            .min()
    }

    /// The batches batch_send_deadline has come for, or with `all`
    /// every shard's.
    pub fn due_batches(&mut self, all: bool) -> Vec<(usize, Batch)> {
        let now = Instant::now();
        let due: Vec<usize> = (0..self.shards.len())
            .filter(|&i| {
                let fires = self.fires(&self.shards[i]);
                fires.is_some_and(|at| all || at <= now)
            })
            .collect();
        let sealed = due.into_iter().map(|i| Some((i, self.seal(i, now)?)));
        sealed.flatten().collect()
    }

    /// When the shard's timer, reset at each batch and firing every
    /// batch_send_deadline, first fires after its first sample.
    fn fires(&self, shard: &Shard) -> Option<Instant> {
        let since = shard.first?.saturating_duration_since(shard.last);
        let deadline = self.config.deadline;
        let periods = since.as_nanos().div_ceil(deadline.as_nanos().max(1));
        let periods = periods.clamp(1, u32::MAX as u128) as u32;
        Some(shard.last + deadline.saturating_mul(periods))
    }

    fn seal(&mut self, index: usize, now: Instant) -> Option<Batch> {
        let shard = &mut self.shards[index];
        shard.last = now;
        shard.first = None;
        let samples = std::mem::take(&mut shard.samples);
        let newest_ms = std::mem::take(&mut shard.newest_ms);
        let data = snap::raw::Encoder::new().compress_vec(&shard.body);
        shard.body.clear();
        if data.is_err() {
            self.lost += samples;
        }
        Some(Batch {
            data: data.ok()?,
            samples,
            newest_ms,
        })
    }

    /// A send that ended, taken or refused.
    pub fn done(&mut self, samples: u64, took: Duration) {
        self.out.events += samples as f64;
        self.seconds.events += took.as_secs_f64();
        self.last_done = Some(Instant::now());
    }

    /// A send to try again after `wait`: resharding waits twice that.
    pub fn again(&mut self, took: Duration, wait: Duration) {
        self.seconds.events += took.as_secs_f64();
        let until = Instant::now() + wait * 2;
        self.held_until = self.held_until.max(Some(until));
    }

    pub fn dropped(&mut self, samples: u64) {
        self.dropped.events += samples as f64;
    }

    /// The shards wanted, every FIT_EVERY, when they should change.
    /// `delay`: seconds from the newest sample sent to the newest in.
    pub fn fit(&mut self, delay: f64) -> Option<usize> {
        let now = Instant::now();
        let config = self.config;
        if now < self.next_fit || config.min_shards >= config.max_shards {
            return None;
        }
        self.next_fit = now + FIT_EVERY;
        for rate in [
            &mut self.input,
            &mut self.out,
            &mut self.dropped,
            &mut self.seconds,
        ] {
            rate.tick();
        }
        let desired = self.desired(delay);
        let sent_lately = self
            .last_done
            .is_some_and(|at| now.duration_since(at) <= FIT_EVERY);
        let held = self.held_until.is_some_and(|until| now < until);
        (desired != self.shards.len() && sent_lately && !held)
            .then_some(desired)
    }

    fn desired(&mut self, delay: f64) -> usize {
        let n = self.shards.len();
        let (input, out) = (self.input.rate, self.out.rate);
        if out <= 0.0 {
            return n;
        }
        let kept = out / (self.dropped.rate + out);
        let pending = delay * input * kept;
        let per_sample = self.seconds.rate / out;
        self.desired = per_sample * (input * kept + 0.05 * pending);
        let desired = self.desired.ceil();
        let near = n as f64 * (1.0 - TOLERANCE)..=n as f64 * (1.0 + TOLERANCE);
        if near.contains(&desired) {
            return n;
        }
        let wanted = desired as usize;
        if wanted < n && delay > BEHIND {
            return n;
        }
        // Not clamp: Prometheus checks max first, and min may exceed it.
        if wanted > self.config.max_shards {
            self.config.max_shards
        } else {
            wanted.max(self.config.min_shards)
        }
    }

    /// `n` shards, once every batch is out (`due_batches(true)`).
    pub fn reshard(&mut self, n: usize) {
        self.shards = (0..n).map(|_| Shard::new()).collect();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn queue(min_shards: usize, max_shards: usize) -> Queue {
        Queue::new(Config {
            min_shards,
            max_shards,
            max_samples: 2,
            ..Config::default()
        })
    }

    #[test]
    fn batches_by_shard() {
        let mut queue = queue(3, 3);
        let labels = [("__name__", "a")];
        assert!(queue.push(&labels, b"x", 1).is_none());
        let (index, batch) = queue.push(&labels, b"y", 2).unwrap();
        assert_eq!((batch.samples, batch.newest_ms), (2, 2));
        let body = snap::raw::Decoder::new().decompress_vec(&batch.data);
        assert_eq!(body.unwrap(), b"\x0a\x01x\x0a\x01y");
        queue.push(&labels, b"z", 3);
        assert!(queue.due_batches(false).is_empty());
        let all = queue.due_batches(true);
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].0, index);
        assert!(queue.due().is_none());
    }

    #[test]
    fn fits_shards_to_rates() {
        let mut queue = queue(1, 10);
        // 1000 samples a second in and out, each send of 2 taking 10
        // ms: 5 seconds of sending a second wants 5 shards.
        queue.input.events = 10_000.0;
        for _ in 0..5000 {
            queue.done(2, Duration::from_millis(10));
        }
        queue.next_fit = Instant::now();
        assert_eq!(queue.fit(0.0), Some(5));
        // Within 30% of the shards there are: no change.
        queue.reshard(5);
        queue.input.events = 11_000.0;
        queue.out.events = 11_000.0;
        queue.seconds.events = 55.0;
        queue.next_fit = Instant::now();
        assert_eq!(queue.fit(0.0), None);
        // Behind by more than 10 s: not fewer.
        for _ in 0..30 {
            queue.input.tick();
            queue.out.tick();
            queue.seconds.tick();
        }
        queue.next_fit = Instant::now();
        assert_eq!(queue.fit(11.0), None);
        queue.next_fit = Instant::now();
        assert_eq!(queue.fit(0.0), Some(1));
        // Not while a send waits to be tried again.
        queue.again(Duration::ZERO, Duration::from_secs(60));
        queue.next_fit = Instant::now();
        assert_eq!(queue.fit(0.0), None);
    }
}
