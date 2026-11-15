//! Prometheus remote write: each sample is encoded into the request's
//! protobuf as it is collected, with no table of series kept between
//! rounds, and sent in snappy-compressed chunks of `CHUNK` bytes; a
//! chunk Prometheus does not take now waits on disk (crate::spool).
//! `--print` writes the text exposition format to stdout instead.

use crate::http::{self, Url};
use crate::spool::{Sent, Spool};
use std::collections::HashMap;
use std::fmt::Write as _;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::io::Write as _;
use std::time::{Duration, Instant};

const CHUNK: usize = 256 << 10;
/// Waits between tries while Prometheus does not answer: chunks go
/// straight to the spool meanwhile.
const BACKOFF: (Duration, Duration) =
    (Duration::from_secs(15), Duration::from_secs(120));

#[derive(Default)]
pub struct Stats {
    pub samples: u64,
    pub failed: u64,
    /// Newest sample collected, and newest sent, in seconds.
    pub newest: f64,
    pub newest_sent: f64,
}

/// A target's round in progress, for the series Prometheus adds to
/// every scrape: how long it took, how many samples, how many series new
/// since the last.
struct Scrape {
    key: String,
    start: Instant,
    samples: u64,
    /// Of them, dropped by `metric_relabel`.
    dropped: u64,
    series: Vec<u64>,
}

pub struct Writer {
    /// None: print instead of sending.
    url: Option<Url>,
    pub url_text: String,
    host: String,
    /// The target's labels, set on every series it gives: `job` first.
    target: Vec<(String, String)>,
    scrape: Option<Scrape>,
    /// Each target's series in its last round, by hash, sorted.
    seen: HashMap<String, Vec<u64>>,
    now_ms: i64,
    body: Vec<u8>,
    series: Vec<u8>,
    in_body: u64,
    spool: Option<Spool>,
    backoff: Duration,
    retry_at: Option<Instant>,
    pub stats: Stats,
    #[cfg(feature = "relabel")]
    pub rules: Vec<crate::relabel::Rule>,
}

impl Writer {
    pub fn new(url_text: &str, host: &str, print: bool) -> Option<Writer> {
        let url = if print {
            None
        } else {
            Some(Url::parse(url_text)?)
        };
        Some(Writer {
            url,
            url_text: url_text.to_owned(),
            host: host.to_owned(),
            target: Vec::new(),
            scrape: None,
            seen: HashMap::new(),
            now_ms: 0,
            body: Vec::with_capacity(CHUNK + (16 << 10)),
            series: Vec::new(),
            in_body: 0,
            spool: None,
            backoff: Duration::ZERO,
            retry_at: None,
            stats: Stats::default(),
            #[cfg(feature = "relabel")]
            rules: Vec::new(),
        })
    }

    /// Keeps what Prometheus does not take in `spool`, instead of
    /// dropping it.
    pub fn keep_in(&mut self, spool: Spool) {
        self.spool = Some(spool);
    }

    /// Starts a round: its samples share this time.
    pub fn begin(&mut self, now_ms: i64) {
        self.now_ms = now_ms;
        self.stats.newest = now_ms as f64 / 1000.0;
    }

    /// Series from here on are the target's: `job`, `instance` (this
    /// host unless `extra` has one), and `extra` labels.
    pub fn target(&mut self, job: &str, extra: &[(&str, &str)]) {
        self.end_target();
        self.target.clear();
        self.target.push(("job".into(), job.into()));
        if !extra.iter().any(|(key, _)| *key == "instance") {
            self.target.push(("instance".into(), self.host.clone()));
        }
        for (key, value) in extra {
            self.target.push(((*key).into(), (*value).into()));
        }
        let key = self.target.iter().map(|(k, v)| format!("{k}={v},"));
        self.scrape = Some(Scrape {
            key: key.collect(),
            start: Instant::now(),
            samples: 0,
            dropped: 0,
            series: Vec::new(),
        });
    }

    /// Ends the current target's round with the series a Prometheus
    /// scrape adds; nothing is relabeled, so the samples after metric
    /// relabeling are the samples.
    pub fn end_target(&mut self) {
        let Some(mut scrape) = self.scrape.take() else {
            return;
        };
        scrape.series.sort_unstable();
        scrape.series.dedup();
        let last = self.seen.remove(&scrape.key).unwrap_or_default();
        let added = scrape.series.iter();
        let added = added.filter(|h| last.binary_search(h).is_err()).count();
        let samples = scrape.samples as f64;
        let seconds = scrape.start.elapsed().as_secs_f64();
        self.add("scrape_duration_seconds", &[], seconds);
        self.add("scrape_samples_scraped", &[], samples);
        let kept = (scrape.samples - scrape.dropped) as f64;
        self.add("scrape_samples_post_metric_relabeling", &[], kept);
        self.add("scrape_series_added", &[], added as f64);
        self.seen.insert(scrape.key, scrape.series);
    }

    pub fn up(&mut self, up: bool) {
        self.add("up", &[], if up { 1.0 } else { 0.0 });
    }

    /// One sample. The target's labels win over the series' own, as
    /// Prometheus's scrape does; then `metric_relabel` applies; `host`
    /// is added where the series has none, as an external label is.
    pub fn add(&mut self, name: &str, labels: &[(&str, &str)], value: f64) {
        let mut all: Vec<(&str, &str)> = Vec::with_capacity(labels.len() + 5);
        all.push(("__name__", name));
        let target = &self.target;
        let own = |key: &str| target.iter().any(|(k, _)| k == key);
        all.extend(labels.iter().filter(|(k, v)| !own(k) && !v.is_empty()));
        all.extend(target.iter().map(|(k, v)| (k.as_str(), v.as_str())));
        #[cfg(feature = "relabel")]
        let relabeled;
        // The series a scrape adds itself are not relabeled.
        #[cfg(feature = "relabel")]
        if !self.rules.is_empty()
            && name != "up"
            && !name.starts_with("scrape_")
        {
            let mut labels = owned(&all);
            if !crate::relabel::apply(&self.rules, &mut labels) {
                if let Some(scrape) = self.scrape.as_mut() {
                    scrape.samples += 1;
                    scrape.dropped += 1;
                }
                return;
            }
            relabeled = labels;
            all = relabeled
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect();
        }
        if !all.iter().any(|(k, _)| *k == "host") {
            all.push(("host", &self.host));
        }
        all.sort_unstable_by(|a, b| a.0.cmp(b.0));
        all.dedup_by(|a, b| a.0 == b.0);
        if let Some(scrape) = self.scrape.as_mut().filter(|_| name != "up") {
            let mut hasher = DefaultHasher::new();
            all.hash(&mut hasher);
            scrape.series.push(hasher.finish());
            scrape.samples += 1;
        }

        if self.url.is_none() {
            print_series(&all, value);
            return;
        }
        encode_series(&mut self.series, &all, value, self.now_ms);
        self.body.push(0x0A);
        put_varint(&mut self.body, self.series.len() as u64);
        self.body.extend_from_slice(&self.series);
        self.in_body += 1;
        if self.body.len() >= CHUNK {
            self.flush();
        }
    }

    /// Sends what was added, after any chunks kept from before. A chunk
    /// not taken now is kept, or without a spool dropped and counted:
    /// the next round sends fresh values, as a scrape would.
    pub fn flush(&mut self) {
        if self.url.is_none() || self.body.is_empty() {
            return;
        }
        let samples = std::mem::take(&mut self.in_body);
        let chunk = snap::raw::Encoder::new().compress_vec(&self.body);
        self.body.clear();
        let Ok(chunk) = chunk else {
            self.stats.failed += samples;
            return;
        };
        let newest_ms = self.now_ms;
        self.drain();
        let waiting = self.spool.as_ref().is_some_and(|s| !s.is_empty());
        if waiting || self.backing_off() {
            return self.keep(&chunk, samples, newest_ms);
        }
        match self.send(&chunk) {
            Sent::Done => self.sent(samples, newest_ms),
            Sent::Refused => self.stats.failed += samples,
            Sent::Later => self.keep(&chunk, samples, newest_ms),
        }
    }

    fn drain(&mut self) {
        if self.backing_off() {
            return;
        }
        let Some(mut spool) = self.spool.take() else {
            return;
        };
        let mut taken = Vec::new();
        spool.drain(
            self.now_ms,
            |data| self.send(data),
            |chunk, sent| taken.push((chunk.samples, chunk.newest_ms, sent)),
        );
        self.spool = Some(spool);
        for (samples, newest_ms, sent) in taken {
            if sent {
                self.sent(samples, newest_ms);
            } else {
                self.stats.failed += samples;
            }
        }
    }

    fn keep(&mut self, chunk: &[u8], samples: u64, newest_ms: i64) {
        self.stats.failed += match &mut self.spool {
            Some(spool) => spool.push(chunk, samples, newest_ms),
            None => samples,
        };
    }

    fn sent(&mut self, samples: u64, newest_ms: i64) {
        self.stats.samples += samples;
        let newest = newest_ms as f64 / 1000.0;
        self.stats.newest_sent = self.stats.newest_sent.max(newest);
    }

    fn backing_off(&self) -> bool {
        self.retry_at.is_some_and(|at| Instant::now() < at)
    }

    /// One chunk to Prometheus. Its first failure in a row is logged,
    /// and so is the first success after.
    fn send(&mut self, chunk: &[u8]) -> Sent {
        let Some(url) = &self.url else {
            return Sent::Refused;
        };
        let (sent, error) = post(url, chunk);
        match sent {
            Sent::Later => {
                if self.backoff.is_zero() {
                    eprintln!("Metrics: {error}; kept to send later");
                }
                self.backoff = (self.backoff * 2).clamp(BACKOFF.0, BACKOFF.1);
                self.retry_at = Some(Instant::now() + self.backoff);
            }
            Sent::Done | Sent::Refused => {
                if !std::mem::take(&mut self.backoff).is_zero() {
                    eprintln!("Metrics: sending again");
                }
                self.retry_at = None;
                if let Sent::Refused = sent {
                    eprintln!("Metrics: refused: {error}");
                }
            }
        }
        sent
    }
}

/// Posts a compressed chunk: what became of it, and why if not taken.
fn post(url: &Url, chunk: &[u8]) -> (Sent, String) {
    let headers = "Content-Type: application/x-protobuf\r\n\
        Content-Encoding: snappy\r\n\
        X-Prometheus-Remote-Write-Version: 0.1.0\r\n";
    let response = match http::post(url, headers, chunk) {
        Ok(response) => response,
        Err(error) => return (Sent::Later, error.to_string()),
    };
    if response.ok() {
        return (Sent::Done, String::new());
    }
    let text = String::from_utf8_lossy(&response.body);
    let error = format!("{} {}", response.status, text.trim());
    let error = error.trim_end().to_owned();
    let retry = response.status == 429 || response.status >= 500;
    (if retry { Sent::Later } else { Sent::Refused }, error)
}

/// A `TimeSeries` message: its labels, sorted, then one `Sample`.
fn encode_series(
    out: &mut Vec<u8>,
    labels: &[(&str, &str)],
    value: f64,
    ms: i64,
) {
    out.clear();
    for (key, value) in labels {
        let len = field_len(key.len()) + field_len(value.len());
        out.push(0x0A);
        put_varint(out, len as u64);
        put_field(out, 0x0A, key.as_bytes());
        put_field(out, 0x12, value.as_bytes());
    }
    out.push(0x12);
    put_varint(out, (1 + 8 + 1 + varint_len(ms as u64)) as u64);
    out.push(0x09);
    out.extend_from_slice(&value.to_le_bytes());
    out.push(0x10);
    put_varint(out, ms as u64);
}

fn put_field(out: &mut Vec<u8>, tag: u8, data: &[u8]) {
    out.push(tag);
    put_varint(out, data.len() as u64);
    out.extend_from_slice(data);
}

/// A length-delimited field's size: tag, length, data.
fn field_len(len: usize) -> usize {
    1 + varint_len(len as u64) + len
}

fn put_varint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push(value as u8 | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

fn varint_len(value: u64) -> usize {
    (64 - value.leading_zeros() as usize).max(1).div_ceil(7)
}

fn print_series(labels: &[(&str, &str)], value: f64) {
    let mut line = String::from(labels[0].1);
    let mut separator = '{';
    for (key, value) in &labels[1..] {
        let value = value.replace('\\', r"\\").replace('"', "\\\"");
        let value = value.replace('\n', r"\n");
        let _ = write!(line, "{separator}{key}=\"{value}\"");
        separator = ',';
    }
    let close = if separator == ',' { "}" } else { "" };
    let _ = writeln!(std::io::stdout(), "{line}{close} {value}");
}

#[cfg(feature = "relabel")]
pub fn owned(labels: &[(&str, &str)]) -> crate::relabel::Labels {
    labels
        .iter()
        .map(|(k, v)| ((*k).into(), (*v).into()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varints_match_their_length() {
        for value in [0, 1, 127, 128, 16_383, 16_384, u64::MAX] {
            let mut out = Vec::new();
            put_varint(&mut out, value);
            assert_eq!(out.len(), varint_len(value), "{value}");
        }
    }

    #[test]
    fn encodes_a_series() {
        let mut out = Vec::new();
        encode_series(&mut out, &[("__name__", "up")], 1.0, 300);
        let label = [0x0A, 0x0E, 0x0A, 0x08];
        assert_eq!(out[..4], label);
        assert_eq!(&out[4..12], b"__name__");
        assert_eq!(out[12..16], [0x12, 0x02, b'u', b'p']);
        let sample = [0x12, 0x0C, 0x09];
        assert_eq!(out[16..19], sample);
        assert_eq!(out[19..27], 1.0f64.to_le_bytes());
        assert_eq!(out[27..], [0x10, 0xAC, 0x02]);
    }
}
