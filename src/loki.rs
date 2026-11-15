//! Loki's push API: lines are grouped by label set into one JSON batch,
//! sent after `wait` or at `max_batch` bytes. A batch Loki cannot take
//! now (429, 5xx, no answer) is kept and retried with backoff; while it
//! waits the sources are not read, and the journal, Docker and the files
//! hold the lines instead of this process. After max_backoff_retries
//! failed tries (0: never) the batch is dropped, as Alloy drops it.

use crate::http::{self, Client, Retry, Url};
use crate::json::escape;
use crate::relabel::Labels;
use std::time::{Duration, Instant};

/// Unless batch_size, batch_wait, the backoff periods and
/// max_backoff_retries say otherwise.
const MAX_BATCH: usize = 256 << 10;
const MAX_RETRIES: u32 = 10;
const WAIT: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(30);

struct Stream {
    /// The label set as a JSON object: the stream's key.
    labels: String,
    /// `["ns","line"],...`
    values: String,
    count: u64,
}

pub enum Flushed {
    /// Sent, or refused for good and dropped: the read positions may be
    /// saved.
    Done,
    /// Kept for a retry.
    Kept,
}

pub struct Loki {
    url: Url,
    client: Client,
    pub address: String,
    /// Its component's label: `central` of loki.write "central".
    pub name: String,
    /// Set on each line that lacks them.
    external: Labels,
    streams: Vec<Stream>,
    bytes: usize,
    first: Option<Instant>,
    retry_at: Option<Instant>,
    backoff: Duration,
    pub retry: Retry,
    pub wait: Duration,
    pub max_batch: usize,
    pub max_retries: u32,
    /// Lines of a stream past this many in a batch are dropped; 0: none.
    pub max_streams: usize,
    failures: u32,
    pub sent: u64,
    pub dropped: u64,
    pub tap: crate::tap::Tap,
}

impl Loki {
    pub fn new(
        url_text: &str,
        name: &str,
        external: Labels,
        client: Client,
    ) -> Option<Loki> {
        let url = Url::parse(url_text)?;
        Some(Loki {
            address: url.authority.clone(),
            url,
            client,
            name: name.to_owned(),
            external,
            streams: Vec::new(),
            bytes: 0,
            first: None,
            retry_at: None,
            backoff: Duration::ZERO,
            retry: Retry {
                min: WAIT,
                max: MAX_BACKOFF,
                on_429: true,
            },
            wait: WAIT,
            max_batch: MAX_BATCH,
            max_retries: MAX_RETRIES,
            max_streams: 0,
            failures: 0,
            sent: 0,
            dropped: 0,
            tap: crate::tap::Tap::default(),
        })
    }

    /// One line. Labels with empty values are left out.
    pub fn add(&mut self, labels: &Labels, ns: i64, line: &str) {
        let key = self.key(labels);
        if self.tap.is_open() {
            self.tap.line(&format!("{key} {line}"));
        }
        let index = match self.streams.iter().position(|s| s.labels == key) {
            Some(index) => index,
            None if self.max_streams > 0
                && self.streams.len() >= self.max_streams =>
            {
                self.dropped += 1;
                return;
            }
            None => {
                let stream = Stream {
                    labels: key,
                    values: String::new(),
                    count: 0,
                };
                self.streams.push(stream);
                self.streams.len() - 1
            }
        };
        let stream = &mut self.streams[index];
        let before = stream.values.len();
        if stream.count > 0 {
            stream.values.push(',');
        }
        stream.values.push_str(&format!("[\"{ns}\",\""));
        escape(&mut stream.values, line);
        stream.values.push_str("\"]");
        stream.count += 1;
        self.bytes += stream.values.len() - before;
        self.first.get_or_insert_with(Instant::now);
    }

    fn key(&self, labels: &Labels) -> String {
        let mut all: Vec<(&str, &str)> = labels
            .iter()
            .chain(&self.external)
            .filter(|(_, value)| !value.is_empty())
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        // Stable: of two, the line's own comes first and stays.
        all.sort_by(|a, b| a.0.cmp(b.0));
        all.dedup_by(|a, b| a.0 == b.0);
        let mut key = String::from("{");
        for (i, (name, value)) in all.iter().enumerate() {
            key.push_str(if i == 0 { "\"" } else { ",\"" });
            key.push_str(name);
            key.push_str("\":\"");
            escape(&mut key, value);
            key.push('"');
        }
        key.push('}');
        key
    }

    /// No more lines now: the batch is full or waits for a retry.
    pub fn blocked(&self, now: Instant) -> bool {
        self.bytes >= self.max_batch || self.retry_at.is_some_and(|at| now < at)
    }

    /// When the batch should go, if it has lines.
    pub fn due_at(&self) -> Option<Instant> {
        let first = self.first?;
        if self.bytes >= self.max_batch {
            return Some(self.retry_at.unwrap_or(first));
        }
        Some(self.retry_at.unwrap_or(first + self.wait))
    }

    pub fn flush(&mut self) -> Flushed {
        if self.streams.is_empty() {
            return Flushed::Done;
        }
        let count: u64 = self.streams.iter().map(|s| s.count).sum();
        let result =
            http::post(&self.url, &self.client, JSON, self.body().as_bytes());
        let failed = match result {
            Ok(response) if response.ok() => {
                if !self.backoff.is_zero() {
                    eprintln!("Logs: sending again");
                }
                self.sent += count;
                None
            }
            Ok(response) if !self.retry.again(response.status) => {
                let text = String::from_utf8_lossy(&response.body);
                eprintln!(
                    "Logs: {} {}, lines dropped",
                    response.status,
                    text.trim()
                );
                self.dropped += count;
                None
            }
            Ok(response) => Some(response.status.to_string()),
            Err(error) => Some(error.to_string()),
        };
        if let Some(error) = failed {
            if !self.retry(&error) {
                return Flushed::Kept;
            }
            self.dropped += count;
        }
        self.clear();
        Flushed::Done
    }

    /// Empty, with no retry pending: after a batch is sent or dropped.
    fn clear(&mut self) {
        self.streams.clear();
        self.bytes = 0;
        self.first = None;
        self.retry_at = None;
        self.backoff = Duration::ZERO;
        self.failures = 0;
    }

    /// A failed try: kept for another (false), or, past the retries,
    /// to be dropped (true).
    fn retry(&mut self, error: &str) -> bool {
        self.failures += 1;
        if self.max_retries > 0 && self.failures >= self.max_retries {
            eprintln!(
                "Logs: {error}, lines dropped after {} tries",
                self.failures
            );
            return true;
        }
        if self.backoff.is_zero() {
            eprintln!("Logs: {error}, retrying");
        }
        self.backoff = self.retry.next(self.backoff);
        self.retry_at = Some(Instant::now() + self.backoff);
        false
    }

    fn body(&self) -> String {
        let mut body =
            String::with_capacity(self.bytes + 64 * self.streams.len());
        body.push_str("{\"streams\":[");
        for (i, stream) in self.streams.iter().enumerate() {
            if i > 0 {
                body.push(',');
            }
            body.push_str("{\"stream\":");
            body.push_str(&stream.labels);
            body.push_str(",\"values\":[");
            body.push_str(&stream.values);
            body.push_str("]}");
        }
        body.push_str("]}");
        body
    }
}

#[cfg(test)]
impl Loki {
    /// Every line's JSON pair, for tests.
    pub fn values(&self) -> String {
        let values = self.streams.iter().map(|s| s.values.as_str());
        values.collect::<Vec<_>>().join(",")
    }
}

const JSON: &str = "Content-Type: application/json\r\n";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json::Json;

    #[test]
    fn groups_lines_by_labels() {
        let host = vec![("host".into(), "h".into())];
        let mut loki = Loki::new(
            "http://127.0.0.1:1/push",
            "central",
            host,
            Default::default(),
        )
        .unwrap();
        let labels = |pairs: &[(&str, &str)]| -> Labels {
            pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect()
        };
        loki.add(&labels(&[("job", "docker"), ("level", "")]), 1, "a \"q\"");
        loki.add(&labels(&[("job", "journal")]), 2, "b");
        loki.add(&labels(&[("job", "docker")]), 3, "c");
        let body = Json::parse(&loki.body()).unwrap();
        let streams = body.get("streams").unwrap().arr();
        assert_eq!(streams.len(), 2);
        let stream = streams[0].get("stream").unwrap();
        assert_eq!(stream.get("host").and_then(Json::str), Some("h"));
        assert!(stream.get("level").is_none());
        let values = streams[0].get("values").unwrap().arr();
        assert_eq!(values[0].arr()[1].str(), Some("a \"q\""));
        assert_eq!(values[1].arr()[0].str(), Some("3"));
    }

    #[test]
    fn drops_past_the_limits() {
        let url = "http://127.0.0.1:1/push";
        let new = Loki::new(url, "w", Vec::new(), Default::default());
        let mut loki = new.unwrap();
        loki.max_streams = 1;
        loki.max_retries = 2;
        let job = |name: &str| vec![("job".to_owned(), name.to_owned())];
        loki.add(&job("a"), 1, "kept");
        loki.add(&job("b"), 2, "a second stream");
        assert_eq!(loki.dropped, 1);
        assert!(matches!(loki.flush(), Flushed::Kept));
        assert!(matches!(loki.flush(), Flushed::Done));
        assert_eq!(loki.dropped, 2);
    }
}
