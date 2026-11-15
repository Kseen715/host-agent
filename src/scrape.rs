//! Exporters scraped over HTTP: each target's samples, and `up`.

use crate::exposition;
use crate::http::{self, Client, Url};
use crate::remote::Writer;

/// The classic text format, whose timestamps are milliseconds.
const ACCEPT: &str = "text/plain";

/// `honor_timestamps`: samples keep the exporter's own timestamps.
pub fn scrape(w: &mut Writer, url: &Url, client: &Client, honor: bool) {
    let response = http::get(url, client, ACCEPT);
    let body = match response {
        Ok(response) if response.ok() => response.body,
        Ok(response) => {
            eprintln!("Scrape {}: {}", url.authority, response.status);
            return w.up(false);
        }
        Err(error) => {
            eprintln!("Scrape {}: {error}", url.authority);
            return w.up(false);
        }
    };
    w.up(true);
    let text = String::from_utf8_lossy(&body);
    exposition::parse(&text, |name, labels, value, at| {
        let pairs: Vec<(&str, &str)> =
            labels.iter().map(|(k, v)| (*k, v.as_ref())).collect();
        w.add_at(name, &pairs, value, at.filter(|_| honor));
    });
}
