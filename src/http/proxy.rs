//! HTTP proxies, as Go's httpproxy picks them: proxy_url with
//! no_proxy, or the environment's HTTP_PROXY, HTTPS_PROXY, NO_PROXY.
//! Plain requests go to the proxy whole; TLS ones through CONNECT.

use super::{Url, broken, head_end, parse_head, split_port};
use crate::encoding::{base64, unescape};
use std::env;
use std::io::{self, Read, Write};
use std::net::{IpAddr, TcpStream};

#[derive(Clone, Default)]
pub enum Proxy {
    #[default]
    Direct,
    Fixed {
        route: Route,
        no_proxy: String,
    },
    Environment {
        connect_headers: String,
    },
}

/// A proxy to go through.
#[derive(Clone)]
pub struct Route {
    pub authority: String,
    /// Basic credentials from the proxy URL's user info.
    user: Option<String>,
    /// Header lines sent with CONNECT, each ending in CR LF.
    connect_headers: String,
}

impl Proxy {
    /// The proxy for a request to `url`, if one is used.
    pub fn route(&self, url: &Url) -> Option<Route> {
        let (route, no_proxy) = match self {
            Proxy::Direct => return None,
            Proxy::Fixed { route, no_proxy } => {
                (route.clone(), no_proxy.clone())
            }
            Proxy::Environment { connect_headers } => {
                let names = match url.tls {
                    true => ["HTTPS_PROXY", "https_proxy"],
                    false => ["HTTP_PROXY", "http_proxy"],
                };
                let text = variable(&names)?;
                let route = Route::parse(&text, connect_headers);
                let no_proxy = variable(&["NO_PROXY", "no_proxy"]);
                // An unusable proxy is a failed request, as in Go.
                let route = route.unwrap_or_else(|| Route::invalid(&text));
                (route, no_proxy.unwrap_or_default())
            }
        };
        (!bypassed(url, &no_proxy)).then_some(route)
    }
}

fn variable(names: &[&str]) -> Option<String> {
    names
        .iter()
        .find_map(|name| env::var(name).ok().filter(|v| !v.is_empty()))
}

impl Route {
    /// `http://[user:password@]host[:port]`; no scheme means http.
    pub fn parse(text: &str, connect_headers: &str) -> Option<Route> {
        let rest = match text.split_once("://") {
            Some(("http", rest)) => rest,
            Some(_) => return None,
            None => text,
        };
        let rest = rest.split('/').next().unwrap_or("");
        let (user, host) = match rest.rsplit_once('@') {
            Some((user, host)) => (Some(user), host),
            None => (None, rest),
        };
        let (name, port) = split_port(host)?;
        if name.is_empty() {
            return None;
        }
        let port = port.unwrap_or("80");
        let authority = match name.contains(':') {
            true => format!("[{name}]:{port}"),
            false => format!("{name}:{port}"),
        };
        let user = match user {
            Some(user) => Some(credentials(user)?),
            None => None,
        };
        Some(Route {
            authority,
            user,
            connect_headers: connect_headers.to_owned(),
        })
    }

    /// A route no connection is made through: its requests fail.
    fn invalid(text: &str) -> Route {
        Route {
            authority: format!("invalid proxy `{text}`:0"),
            user: None,
            connect_headers: String::new(),
        }
    }

    pub fn authorization(&self) -> String {
        match &self.user {
            Some(basic) => format!("Proxy-Authorization: Basic {basic}\r\n"),
            None => String::new(),
        }
    }

    /// A CONNECT tunnel to `url` through the proxy on `stream`.
    pub fn tunnel(
        &self,
        mut stream: TcpStream,
        url: &Url,
    ) -> io::Result<TcpStream> {
        let head = format!(
            "CONNECT {0} HTTP/1.1\r\nHost: {0}\r\n{1}{2}\r\n",
            url.authority,
            self.authorization(),
            self.connect_headers,
        );
        stream.write_all(head.as_bytes())?;
        let mut raw = Vec::new();
        let mut chunk = [0; 1024];
        let end = loop {
            if let Some(end) = head_end(&raw) {
                break end;
            }
            let read = stream.read(&mut chunk)?;
            if read == 0 || raw.len() > 64 << 10 {
                return Err(broken("proxy: no answer to CONNECT"));
            }
            raw.extend_from_slice(&chunk[..read]);
        };
        let status = parse_head(&raw[..end])?.status;
        if status != 200 {
            return Err(io::Error::other(format!("proxy: CONNECT: {status}")));
        }
        Ok(stream)
    }
}

/// `user:password`, percent-decoded, in base64.
fn credentials(text: &str) -> Option<String> {
    let (user, password) = text.split_once(':').unwrap_or((text, ""));
    let user = unescape(user, false)?;
    let password = unescape(password, false)?;
    Some(base64(format!("{user}:{password}").as_bytes()))
}

/// Whether `url` goes direct: loopback always, or a no_proxy entry
/// matches it (`*`, an IP, a CIDR, a domain and its subdomains,
/// `.domain` its subdomains only; each maybe with a port).
fn bypassed(url: &Url, no_proxy: &str) -> bool {
    let host = url.name.to_ascii_lowercase();
    let ip: Option<IpAddr> = host.parse().ok();
    if host == "localhost" || ip.is_some_and(|ip| ip.is_loopback()) {
        return true;
    }
    let port = url.authority.rsplit(':').next().unwrap_or("");
    no_proxy.split(',').any(|entry| {
        let entry = entry.trim().to_ascii_lowercase();
        entry == "*" || matches(&entry, &host, ip, port)
    })
}

fn matches(entry: &str, host: &str, ip: Option<IpAddr>, port: &str) -> bool {
    if entry.is_empty() {
        return false;
    }
    if let Some((network, bits)) = entry.split_once('/') {
        return ip.is_some_and(|ip| in_network(ip, network, bits));
    }
    if let Ok(entry_ip) = entry.parse::<IpAddr>() {
        return ip == Some(entry_ip);
    }
    let (name, wanted) = match split_port(entry) {
        Some((name, Some(p))) if !p.is_empty() => (name, Some(p)),
        _ => (entry.trim_matches(['[', ']']), None),
    };
    let port_ok = wanted.is_none_or(|p| p == port);
    if let Ok(entry_ip) = name.parse::<IpAddr>() {
        return ip == Some(entry_ip) && port_ok;
    }
    let name = name.strip_prefix('*').unwrap_or(name);
    let found = match name.strip_prefix('.') {
        Some(domain) => host.ends_with(&format!(".{domain}")),
        None => host == name || host.ends_with(&format!(".{name}")),
    };
    found && port_ok
}

fn in_network(ip: IpAddr, network: &str, bits: &str) -> bool {
    let (Ok(network), Ok(bits)) =
        (network.parse::<IpAddr>(), bits.parse::<u32>())
    else {
        return false;
    };
    let wide = |ip: IpAddr| match ip {
        IpAddr::V4(v4) => (u128::from(u32::from(v4)), 32),
        IpAddr::V6(v6) => (u128::from(v6), 128),
    };
    let ((a, width), (b, other)) = (wide(ip), wide(network));
    if width != other || bits > width {
        return false;
    }
    let shift = width - bits;
    shift >= 128 || a >> shift == b >> shift
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn picks_routes() {
        let url = |text: &str| Url::parse(text).unwrap();
        let no = "*.example.com,.internal,10.0.0.0/8,host:8080,::2";
        assert!(bypassed(&url("http://a.example.com/"), no));
        assert!(!bypassed(&url("http://example.com/"), no));
        assert!(!bypassed(&url("http://internal/"), no));
        assert!(bypassed(&url("http://x.internal/"), no));
        assert!(bypassed(&url("http://10.1.2.3/"), no));
        assert!(bypassed(&url("http://host:8080/"), no));
        assert!(!bypassed(&url("http://host/"), no));
        assert!(bypassed(&url("http://[::2]/"), no));
        assert!(bypassed(&url("http://127.0.0.1/"), ""));
        let route = Route::parse("http://u:p%40@proxy", "").unwrap();
        assert_eq!(route.authority, "proxy:80");
        assert_eq!(
            route.authorization(),
            "Proxy-Authorization: Basic dTpwQA==\r\n"
        );
        assert!(Route::parse("socks5://proxy", "").is_none());
    }
}
