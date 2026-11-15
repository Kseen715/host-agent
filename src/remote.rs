//! Prometheus remote write: each sample is encoded into the request's
//! protobuf as it is collected, with no table of series kept between
//! rounds, into its shard's batch (crate::queue); each shard's thread
//! posts its batches, snappy-compressed, in turn. A batch Prometheus
//! does not take now waits on disk (crate::spool), and every batch
//! after it, until it is sent.
//! Samples reach each prometheus.remote_write through the
//! prometheus.relabel components their scrape forwards to. `--print`
//! writes the text exposition format to stdout instead.

use crate::http::{self, Client, Retry, Url};
use crate::queue::{self, Batch, Queue};
use crate::relabel::{self, Labels, Rule};
use crate::spool::{Sent, Spool, Truncation};
use crate::tap::Tap;
use std::collections::HashMap;
use std::fmt::Write as _;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
/// Waits between tries while Prometheus does not answer, unless
/// queue_config says otherwise: chunks go straight to the spool
/// meanwhile.
const BACKOFF: (Duration, Duration) =
    (Duration::from_secs(15), Duration::from_secs(120));

#[derive(Clone, Copy, Default)]
pub struct Stats {
    pub samples: u64,
    pub failed: u64,
    /// Newest sample collected, and newest sent, in seconds.
    pub newest: f64,
    pub newest_sent: f64,
    pub shards: f64,
    pub shards_desired: f64,
    pub shards_min: f64,
    pub shards_max: f64,
    pub shard_capacity: f64,
}

/// A target's scrape in progress, for the series Prometheus adds to
/// every scrape: how long it took, how many samples, how many series
/// new since the last.
struct Scrape {
    key: String,
    up: Option<bool>,
    start: Instant,
    /// A poll made apart from the round: when, and how long it took.
    polled: Option<(i64, Duration)>,
    samples: u64,
    series: Vec<u64>,
}

/// Where samples go: prometheus.relabel and prometheus.remote_write
/// components, as `forward_to` lists connect them.
pub enum Kind {
    Relabel(Rc<Vec<Rule>>),
    /// A prometheus.relabel: its rules, results cached.
    Cached(Rc<Vec<Rule>>, relabel::Cache),
    /// Its index in `sinks`.
    Write(usize),
}

pub struct Node {
    pub kind: Kind,
    pub to: Rc<[usize]>,
}

#[derive(Default)]
pub struct Metrics {
    pub nodes: Vec<Node>,
    pub sinks: Vec<RemoteWrite>,
}

impl Metrics {
    fn send(&mut self, to: &[usize], labels: &[(&str, &str)], v: f64, ms: i64) {
        for &node in to {
            let next = Rc::clone(&self.nodes[node].to);
            let owned = || -> Labels {
                labels
                    .iter()
                    .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                    .collect()
            };
            let kept = match &mut self.nodes[node].kind {
                Kind::Write(sink) => {
                    self.sinks[*sink].add(labels, v, ms);
                    continue;
                }
                Kind::Relabel(rules) if rules.is_empty() => {
                    self.send(&next, labels, v, ms);
                    continue;
                }
                Kind::Relabel(rules) => {
                    let mut owned = owned();
                    relabel::apply(rules, &mut owned).then_some(owned)
                }
                Kind::Cached(rules, cache) => cache.apply(rules, owned()),
            };
            if let Some(kept) = kept {
                let pairs: Vec<(&str, &str)> = kept
                    .iter()
                    .map(|(k, v)| (k.as_str(), v.as_str()))
                    .collect();
                self.send(&next, &pairs, v, ms);
            }
        }
    }
}

/// What scrapes write to: the current target's labels go on each of
/// its samples, which then go where its scrape forwards them.
pub struct Writer {
    pub metrics: Metrics,
    to: Rc<[usize]>,
    /// The series' own labels win over the target's, else they are
    /// kept as `exported_<name>`.
    honor_labels: bool,
    target: Labels,
    scrape: Option<Scrape>,
    /// Each target's series in its last scrape, by hash, sorted.
    seen: HashMap<String, Vec<u64>>,
    now_ms: i64,
    /// The current target's time, when not the round's (`polled`).
    stamp_ms: Option<i64>,
    /// Into this text instead (crate::server's `/metrics`).
    text: Option<String>,
    pub tap: Tap,
    /// Each target's last scrape, for the status page.
    pub targets: Vec<Summary>,
}

pub struct Summary {
    pub labels: Labels,
    pub up: Option<bool>,
    pub samples: u64,
    pub seconds: f64,
}

impl Writer {
    pub fn new(metrics: Metrics) -> Writer {
        Writer {
            metrics,
            to: Rc::from([]),
            honor_labels: false,
            target: Vec::new(),
            scrape: None,
            seen: HashMap::new(),
            now_ms: 0,
            stamp_ms: None,
            text: None,
            tap: Tap::default(),
            targets: Vec::new(),
        }
    }

    /// Writes the exposition format into a text: what a scrape of the
    /// agent reads.
    pub fn text() -> Writer {
        let mut w = Writer::new(Metrics::default());
        w.text = Some(String::new());
        w
    }

    pub fn into_text(self) -> String {
        self.text.unwrap_or_default()
    }

    /// Starts a round: its samples share this time.
    pub fn begin(&mut self, now_ms: i64) {
        self.now_ms = now_ms;
    }

    /// Series from here on are the target's, sent to `to`.
    pub fn target(&mut self, labels: Labels, to: Rc<[usize]>, honor: bool) {
        self.end_target();
        let key = labels.iter().map(|(k, v)| format!("{k}={v},"));
        self.scrape = Some(Scrape {
            key: key.collect(),
            start: Instant::now(),
            up: None,
            polled: None,
            samples: 0,
            series: Vec::new(),
        });
        self.target = labels;
        self.to = to;
        self.honor_labels = honor;
    }

    /// Ends the current target's scrape with the series a Prometheus
    /// scrape adds; a scrape has no metric relabeling of its own here,
    /// so the samples after it are the samples.
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
        let took = scrape.polled.map(|p| p.1);
        let seconds = took.unwrap_or(scrape.start.elapsed()).as_secs_f64();
        self.add("scrape_duration_seconds", &[], seconds);
        self.add("scrape_samples_scraped", &[], samples);
        self.add("scrape_samples_post_metric_relabeling", &[], samples);
        self.add("scrape_series_added", &[], added as f64);
        self.seen.insert(scrape.key, scrape.series);
        self.stamp_ms = None;
        self.summarize(scrape.up, samples as u64, seconds);
    }

    fn summarize(&mut self, up: Option<bool>, samples: u64, seconds: f64) {
        let labels = self.target.clone();
        let summary = Summary {
            labels,
            up,
            samples,
            seconds,
        };
        match self.targets.iter_mut().find(|t| t.labels == summary.labels) {
            Some(old) => *old = summary,
            None => self.targets.push(summary),
        }
    }

    /// The current target's series are a poll's from `at_ms`, which
    /// took `took`, not the round's.
    pub fn polled(&mut self, at_ms: i64, took: Duration) {
        if let Some(scrape) = self.scrape.as_mut() {
            scrape.polled = Some((at_ms, took));
            self.stamp_ms = Some(at_ms);
        }
    }

    pub fn up(&mut self, up: bool) {
        if let Some(scrape) = self.scrape.as_mut() {
            scrape.up = Some(up);
        }
        self.add("up", &[], if up { 1.0 } else { 0.0 });
    }

    /// One sample, with the target's labels, as Prometheus's scrape
    /// gives them.
    pub fn add(&mut self, name: &str, labels: &[(&str, &str)], value: f64) {
        self.add_at(name, labels, value, None);
    }

    /// As `add`, at the sample's own time if it has one.
    pub fn add_at(
        &mut self,
        name: &str,
        labels: &[(&str, &str)],
        value: f64,
        at_ms: Option<i64>,
    ) {
        let target = &self.target;
        let theirs = |key: &str| target.iter().any(|(k, _)| k == key);
        let exported: Vec<(String, &str)> = labels
            .iter()
            .filter(|(k, v)| !self.honor_labels && !v.is_empty() && theirs(k))
            .map(|(k, v)| (format!("exported_{k}"), *v))
            .collect();
        let mut all: Vec<(&str, &str)> = Vec::with_capacity(labels.len() + 6);
        all.push(("__name__", name));
        let own = labels.iter().filter(|(k, v)| {
            !v.is_empty() && (self.honor_labels || !theirs(k))
        });
        all.extend(own);
        all.extend(exported.iter().map(|(k, v)| (k.as_str(), *v)));
        all.extend(target.iter().map(|(k, v)| (k.as_str(), v.as_str())));
        all.sort_by(|a, b| a.0.cmp(b.0));
        all.dedup_by(|a, b| a.0 == b.0);
        if let Some(scrape) = self.scrape.as_mut().filter(|_| name != "up") {
            let mut hasher = DefaultHasher::new();
            all.hash(&mut hasher);
            scrape.series.push(hasher.finish());
            scrape.samples += 1;
        }
        if self.tap.is_open() {
            self.tap.line(&series_text(&all, value));
        }
        if let Some(text) = &mut self.text {
            let _ = writeln!(text, "{}", series_text(&all, value));
            return;
        }
        let to = Rc::clone(&self.to);
        let at_ms = at_ms.or(self.stamp_ms).unwrap_or(self.now_ms);
        self.metrics.send(&to, &all, value, at_ms);
    }

    /// When a remote write next has a batch due.
    pub fn due(&self) -> Option<Instant> {
        self.metrics.sinks.iter().filter_map(RemoteWrite::due).min()
    }

    pub fn tick(&mut self) {
        for sink in &mut self.metrics.sinks {
            sink.tick();
        }
    }

    pub fn close(&mut self) {
        for sink in &mut self.metrics.sinks {
            sink.close();
        }
    }
}

/// One prometheus.remote_write.
pub struct RemoteWrite {
    /// None: print instead of sending.
    url: Option<Url>,
    client: Arc<Client>,
    pub url_text: String,
    /// Its component's label.
    pub name: String,
    /// Set on each series that lacks them.
    external: Labels,
    series: Vec<u8>,
    pub queue: Queue,
    /// Each shard's sender, started with its first batch.
    senders: Vec<Option<Sender>>,
    results: (mpsc::Sender<Posted>, Receiver<Posted>),
    /// Batches handed to senders and not back.
    in_flight: usize,
    /// Set while the spool holds chunks: senders hand batches back
    /// unsent, to be kept behind them, so each series stays in order.
    holding: Arc<AtomicBool>,
    spool: Option<Spool>,
    backoff: Duration,
    retry_at: Option<Instant>,
    pub retry: Retry,
    /// queue_config's sample_age_limit, and the WAL's truncation.
    pub age_limit: Option<Duration>,
    pub truncation: Truncation,
    stats: Stats,
}

/// A shard's thread, posting the batches it is handed in turn.
struct Sender {
    batches: SyncSender<Batch>,
    thread: JoinHandle<()>,
}

/// A batch back from its sender: what became of it, why if not taken,
/// and how long it took; None when handed back unsent.
struct Posted {
    batch: Batch,
    tried: Option<(Sent, String, Duration)>,
}

impl RemoteWrite {
    pub fn new(
        url_text: &str,
        name: &str,
        external: Labels,
        client: Client,
        print: bool,
    ) -> Option<RemoteWrite> {
        let url = if print {
            None
        } else {
            Some(Url::parse(url_text)?)
        };
        Some(RemoteWrite {
            url,
            client: Arc::new(client),
            url_text: url_text.to_owned(),
            name: name.to_owned(),
            external,
            series: Vec::new(),
            queue: Queue::new(queue::Config::default()),
            senders: Vec::new(),
            results: mpsc::channel(),
            in_flight: 0,
            holding: Arc::default(),
            spool: None,
            backoff: Duration::ZERO,
            retry_at: None,
            retry: Retry {
                min: BACKOFF.0,
                max: BACKOFF.1,
                on_429: true,
            },
            age_limit: None,
            truncation: Truncation::default(),
            stats: Stats::default(),
        })
    }

    /// Keeps what Prometheus does not take in `spool`, instead of
    /// dropping it.
    pub fn keep_in(&mut self, spool: Spool) {
        self.holding.store(!spool.is_empty(), Ordering::Relaxed);
        self.spool = Some(spool);
    }

    pub fn stats(&self) -> Stats {
        let config = &self.queue.config;
        Stats {
            shards: self.queue.shards() as f64,
            shards_desired: self.queue.desired,
            shards_min: config.min_shards as f64,
            shards_max: config.max_shards as f64,
            shard_capacity: config.capacity as f64,
            ..self.stats
        }
    }

    fn add(&mut self, labels: &[(&str, &str)], value: f64, ms: i64) {
        let mut labels = labels.to_vec();
        for (key, external) in &self.external {
            if !labels.iter().any(|(k, _)| k == key) {
                labels.push((key, external));
            }
        }
        labels.sort_unstable_by(|a, b| a.0.cmp(b.0));
        self.stats.newest = self.stats.newest.max(ms as f64 / 1000.0);
        if self.url.is_none() {
            println!("{}", series_text(&labels, value));
            return;
        }
        encode_series(&mut self.series, &labels, value, ms);
        if let Some((shard, batch)) = self.queue.push(&labels, &self.series, ms)
        {
            self.hand(shard, batch);
        }
    }

    /// When a batch is next due, or the shards' next fit.
    pub fn due(&self) -> Option<Instant> {
        self.url.as_ref().and(self.queue.due())
    }

    /// Takes the senders' results, hands out the batches due, fits the
    /// shards, and once the backoff is over sends what the spool holds.
    pub fn tick(&mut self) {
        if self.url.is_none() {
            return;
        }
        self.collect();
        for (shard, batch) in self.queue.due_batches(false) {
            self.hand(shard, batch);
        }
        let delay = self.stats.newest - self.stats.newest_sent;
        if let Some(shards) = self.queue.fit(delay) {
            let from = self.queue.shards();
            eprintln!("Metrics: resharding from {from} to {shards}");
            self.stop_senders();
            self.queue.reshard(shards);
        }
        let now_ms = crate::time::now_ms();
        let sent_ms = (self.stats.newest_sent * 1000.0) as i64;
        let truncated = match &mut self.spool {
            Some(spool) => spool.truncate(now_ms, sent_ms),
            None => 0,
        };
        self.queue.dropped(truncated);
        self.retry_kept();
        self.stats.failed += std::mem::take(&mut self.queue.lost);
    }

    /// Sends every batch, as Alloy flushes its queue when it stops;
    /// what Prometheus does not take is kept for the next agent.
    pub fn close(&mut self) {
        if self.url.is_some() {
            self.stop_senders();
        }
    }

    /// Hands a batch to its shard's sender, waiting while the sender
    /// holds `capacity` samples: Prometheus's backpressure.
    fn hand(&mut self, shard: usize, batch: Batch) {
        if self.senders.len() <= shard {
            self.senders.resize_with(shard + 1, || None);
        }
        if self.senders[shard].is_none() {
            self.senders[shard] = self.spawn();
        }
        let Some(sender) = &self.senders[shard] else {
            return self.keep(batch);
        };
        match sender.batches.send(batch) {
            Ok(()) => self.in_flight += 1,
            Err(mpsc::SendError(batch)) => self.keep(batch),
        }
    }

    fn spawn(&self) -> Option<Sender> {
        let (batches, from_main) =
            mpsc::sync_channel(self.queue.config.batches());
        let url = self.url.clone()?;
        let (client, retry) = (Arc::clone(&self.client), self.retry);
        let (results, holding) =
            (self.results.0.clone(), Arc::clone(&self.holding));
        let thread = thread::Builder::new()
            .name(format!("remote_write {}", self.name))
            .spawn(move || {
                for batch in from_main {
                    let posted = send(&url, &client, &retry, &holding, batch);
                    if results.send(posted).is_err() {
                        return;
                    }
                }
            });
        match thread {
            Ok(thread) => Some(Sender { batches, thread }),
            Err(error) => {
                eprintln!("Metrics: no thread to send with: {error}");
                None
            }
        }
    }

    /// Hands out every shard's batch and ends the senders once they
    /// have sent what they hold.
    fn stop_senders(&mut self) {
        for (shard, batch) in self.queue.due_batches(true) {
            self.hand(shard, batch);
        }
        for sender in self.senders.drain(..).flatten() {
            drop(sender.batches);
            let _ = sender.thread.join();
        }
        self.collect();
        self.stats.failed += std::mem::take(&mut self.queue.lost);
    }

    fn collect(&mut self) {
        while let Ok(Posted { batch, tried }) = self.results.1.try_recv() {
            self.in_flight -= 1;
            let Some((sent, error, took)) = tried else {
                self.keep(batch);
                continue;
            };
            self.posted(&sent, &error, batch.samples, took);
            match sent {
                Sent::Done => self.sent(batch.samples, batch.newest_ms),
                Sent::Refused => self.stats.failed += batch.samples,
                Sent::Later => self.keep(batch),
            }
        }
    }

    /// Sends the spool, oldest first, once every sender is idle and the
    /// backoff is over; when it is empty, senders send again.
    fn retry_kept(&mut self) {
        let holding = self.holding.load(Ordering::Relaxed);
        if !holding || self.in_flight > 0 || self.backing_off() {
            return;
        }
        let Some(mut spool) = self.spool.take() else {
            return self.holding.store(false, Ordering::Relaxed);
        };
        let mut taken = Vec::new();
        let too_old = spool.drain(
            crate::time::now_ms(),
            |data, samples| self.post_one(data, samples),
            |chunk, sent| taken.push((chunk.samples, chunk.newest_ms, sent)),
        );
        self.queue.dropped(too_old);
        if too_old > 0 {
            eprintln!("Spool: dropped {too_old} samples too old to send");
        }
        self.holding.store(!spool.is_empty(), Ordering::Relaxed);
        self.spool = Some(spool);
        for (samples, newest_ms, sent) in taken {
            if sent {
                self.sent(samples, newest_ms);
            } else {
                self.stats.failed += samples;
            }
        }
    }

    fn keep(&mut self, batch: Batch) {
        self.holding.store(true, Ordering::Relaxed);
        let dropped = match &mut self.spool {
            Some(spool) => {
                spool.push(&batch.data, batch.samples, batch.newest_ms)
            }
            None => batch.samples,
        };
        self.stats.failed += dropped;
        self.queue.dropped(dropped);
    }

    fn sent(&mut self, samples: u64, newest_ms: i64) {
        self.stats.samples += samples;
        let newest = newest_ms as f64 / 1000.0;
        self.stats.newest_sent = self.stats.newest_sent.max(newest);
    }

    fn backing_off(&self) -> bool {
        self.retry_at.is_some_and(|at| Instant::now() < at)
    }

    /// One chunk from the spool to Prometheus.
    fn post_one(&mut self, chunk: &[u8], samples: u64) -> Sent {
        let Some(url) = &self.url else {
            return Sent::Refused;
        };
        let start = Instant::now();
        let (sent, error) = post(url, &self.client, &self.retry, chunk);
        self.posted(&sent, &error, samples, start.elapsed());
        sent
    }

    /// Counts a send for the shards' fit; its first failure in a row
    /// is logged, and so is the first success after.
    fn posted(
        &mut self,
        sent: &Sent,
        error: &str,
        samples: u64,
        took: Duration,
    ) {
        match sent {
            Sent::Later => {
                if self.backoff.is_zero() {
                    eprintln!("Metrics: {error}; kept to send later");
                }
                self.backoff = self.retry.next(self.backoff);
                self.retry_at = Some(Instant::now() + self.backoff);
                self.queue.again(took, self.backoff);
            }
            Sent::Done | Sent::Refused => {
                if !std::mem::take(&mut self.backoff).is_zero() {
                    eprintln!("Metrics: sending again");
                }
                self.retry_at = None;
                if let Sent::Refused = sent {
                    eprintln!("Metrics: refused: {error}");
                }
                self.queue.done(samples, took);
            }
        }
    }
}

/// A sender's post of one batch: none while the spool holds chunks,
/// and none after one is to be tried again, until it is sent.
fn send(
    url: &Url,
    client: &Client,
    retry: &Retry,
    holding: &AtomicBool,
    batch: Batch,
) -> Posted {
    if holding.load(Ordering::Relaxed) {
        return Posted { batch, tried: None };
    }
    let start = Instant::now();
    let (sent, error) = post(url, client, retry, &batch.data);
    if let Sent::Later = sent {
        holding.store(true, Ordering::Relaxed);
    }
    let tried = Some((sent, error, start.elapsed()));
    Posted { batch, tried }
}

/// Posts a compressed chunk: what became of it, and why if not taken.
fn post(
    url: &Url,
    client: &Client,
    retry: &Retry,
    chunk: &[u8],
) -> (Sent, String) {
    let headers = "Content-Type: application/x-protobuf\r\n\
        Content-Encoding: snappy\r\n\
        X-Prometheus-Remote-Write-Version: 0.1.0\r\n";
    let response = match http::post(url, client, headers, chunk) {
        Ok(response) => response,
        Err(error) => return (Sent::Later, error.to_string()),
    };
    if response.ok() {
        return (Sent::Done, String::new());
    }
    let text = String::from_utf8_lossy(&response.body);
    let error = format!("{} {}", response.status, text.trim());
    let error = error.trim_end().to_owned();
    let again = retry.again(response.status);
    (if again { Sent::Later } else { Sent::Refused }, error)
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

pub fn put_varint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push(value as u8 | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

fn varint_len(value: u64) -> usize {
    (64 - value.leading_zeros() as usize).max(1).div_ceil(7)
}

fn series_text(labels: &[(&str, &str)], value: f64) -> String {
    let mut line = String::from(labels[0].1);
    let mut separator = '{';
    for (key, value) in &labels[1..] {
        let value = value.replace('\\', r"\\").replace('"', "\\\"");
        let value = value.replace('\n', r"\n");
        let _ = write!(line, "{separator}{key}=\"{value}\"");
        separator = ',';
    }
    let close = if separator == ',' { "}" } else { "" };
    format!("{line}{close} {value}")
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
