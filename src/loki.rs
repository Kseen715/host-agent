//! Loki's push API: lines are grouped by label set into one JSON batch,
//! sent after `WAIT` or at `MAX_BATCH` bytes. A batch Loki cannot take
//! now (429, 5xx, no answer) is kept and retried with backoff; while it
//! waits the sources are not read, and the journal, Docker and the files
//! hold the lines instead of this process.

use crate::http::{self, Url};
use crate::json::escape;
use std::time::{Duration, Instant};

const MAX_BATCH: usize = 256 << 10;
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
    pub address: String,
    host: String,
    streams: Vec<Stream>,
    bytes: usize,
    first: Option<Instant>,
    retry_at: Option<Instant>,
    backoff: Duration,
    pub sent: u64,
    pub dropped: u64,
}

impl Loki {
    pub fn new(url_text: &str, host: &str) -> Option<Loki> {
        let url = Url::parse(url_text)?;
        Some(Loki {
            address: url.authority.clone(),
            url,
            host: host.to_owned(),
            streams: Vec::new(),
            bytes: 0,
            first: None,
            retry_at: None,
            backoff: Duration::ZERO,
            sent: 0,
            dropped: 0,
        })
    }

    /// One line. Labels with empty values are left out; `host` is added.
    pub fn add(&mut self, labels: &[(&str, &str)], ns: i64, line: &str) {
        let key = self.key(labels);
        let index = match self.streams.iter().position(|s| s.labels == key) {
            Some(index) => index,
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

    fn key(&self, labels: &[(&str, &str)]) -> String {
        let mut all: Vec<(&str, &str)> = labels
            .iter()
            .filter(|(_, value)| !value.is_empty())
            .copied()
            .collect();
        all.push(("host", &self.host));
        all.sort_unstable_by(|a, b| a.0.cmp(b.0));
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
        self.bytes >= MAX_BATCH || self.retry_at.is_some_and(|at| now < at)
    }

    /// When the batch should go, if it has lines.
    pub fn due_at(&self) -> Option<Instant> {
        let first = self.first?;
        if self.bytes >= MAX_BATCH {
            return Some(self.retry_at.unwrap_or(first));
        }
        Some(self.retry_at.unwrap_or(first + WAIT))
    }

    pub fn flush(&mut self) -> Flushed {
        if self.streams.is_empty() {
            return Flushed::Done;
        }
        let count: u64 = self.streams.iter().map(|s| s.count).sum();
        let result = http::post(&self.url, JSON, self.body().as_bytes());
        match result {
            Ok(response) if response.ok() => self.sent += count,
            Ok(response) if response.status != 429 && response.status < 500 => {
                let text = String::from_utf8_lossy(&response.body);
                eprintln!(
                    "Logs: {} {}, lines dropped",
                    response.status,
                    text.trim()
                );
                self.dropped += count;
            }
            Ok(response) => return self.retry(&response.status.to_string()),
            Err(error) => return self.retry(&error.to_string()),
        }
        if !self.backoff.is_zero() {
            eprintln!("Logs: sending again");
        }
        self.streams.clear();
        self.bytes = 0;
        self.first = None;
        self.retry_at = None;
        self.backoff = Duration::ZERO;
        Flushed::Done
    }

    fn retry(&mut self, error: &str) -> Flushed {
        if self.backoff.is_zero() {
            eprintln!("Logs: {error}, retrying");
        }
        self.backoff = (self.backoff * 2).clamp(WAIT, MAX_BACKOFF);
        self.retry_at = Some(Instant::now() + self.backoff);
        Flushed::Kept
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
        let mut loki = Loki::new("http://127.0.0.1:1/push", "h").unwrap();
        loki.add(&[("job", "docker"), ("level", "")], 1, "a \"q\"");
        loki.add(&[("job", "journal")], 2, "b");
        loki.add(&[("job", "docker")], 3, "c");
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
}
