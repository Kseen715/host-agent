//! Exporters scraped over HTTP: each target's samples, and `up`.

use crate::exposition;
use crate::http::{self, Url};
use crate::remote::Writer;

pub fn scrape(w: &mut Writer, url: &Url) {
    let response = http::get(url);
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
    exposition::parse(&text, |name, labels, value| {
        let pairs: Vec<(&str, &str)> =
            labels.iter().map(|(k, v)| (*k, v.as_ref())).collect();
        w.add(name, &pairs, value);
    });
}
