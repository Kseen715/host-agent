//! Exporters on this host, scraped over HTTP and pushed with the rest:
//! each gets `up` and its job's labels.

use crate::exposition;
use crate::http::{self, Url};
use crate::remote::Writer;

/// mc-monitor names a Minecraft server by its port: `server` gets its
/// name from minecraft_servers, as the dashboards show it.
pub struct ServerPort {
    pub port: String,
    pub name: String,
}

pub fn scrape(w: &mut Writer, url: &Url, servers: &[ServerPort]) {
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
        let mut pairs: Vec<(&str, &str)> =
            labels.iter().map(|(k, v)| (*k, v.as_ref())).collect();
        let port = pairs
            .iter()
            .find(|(k, _)| *k == "server_port")
            .map(|(_, v)| *v);
        if let Some(server) =
            port.and_then(|p| servers.iter().find(|s| s.port == p))
        {
            pairs.retain(|(k, _)| *k != "server");
            pairs.push(("server", &server.name));
        }
        w.add(name, &pairs, value);
    });
}
