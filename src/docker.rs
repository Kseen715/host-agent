//! Docker's containers, from its API on the local socket: the list
//! every round (for their metrics, their logs and the Minecraft
//! servers' addresses) and one log stream per running container.

use crate::config::Minecraft;
use crate::http::{self, Dechunk, Url};
use crate::json::Json;
use crate::levels;
use crate::loki::Loki;
use crate::parts::Part;
use crate::remote::Writer;
use crate::state::Positions;
use crate::time;
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

pub const SOCKET: &str = "/var/run/docker.sock";
const COMPOSE: &str = "com.docker.compose.";

pub struct Container {
    pub id: String,
    pub name: String,
    pub image: String,
    pub project: String,
    pub service: String,
    pub ips: Vec<String>,
    /// Ports the container exposes, inside it.
    pub ports: Vec<u16>,
    /// Its labels as cAdvisor gives them: `container_label_<key>` with
    /// `[^a-zA-Z0-9_]` as `_`.
    pub labels: Vec<(String, String)>,
    pub created: f64,
    /// cAdvisor's container_health_state: 1 healthy, -1 no check, else 0.
    pub health: f64,
    pub details: Details,
}

/// What only inspecting a container tells: asked once per container.
#[derive(Clone, Copy)]
pub struct Details {
    pub pid: u32,
    pub tty: bool,
    pub started_ns: i64,
}

pub struct Docker {
    socket: PathBuf,
    details: HashMap<String, Details>,
    pub containers: Vec<Container>,
    streams: Vec<LogStream>,
    /// Containers started after this are read from their start.
    since_ns: i64,
    minecraft: Vec<Minecraft>,
}

impl Docker {
    /// None where Docker does not run.
    pub fn new(minecraft: Vec<Minecraft>) -> Option<Docker> {
        let socket = PathBuf::from(SOCKET);
        socket.exists().then(|| Docker {
            socket,
            details: HashMap::new(),
            containers: Vec::new(),
            streams: Vec::new(),
            since_ns: time::now_ns(),
            minecraft,
        })
    }

    /// Lists the running containers; true if Docker answered.
    pub fn refresh(&mut self) -> bool {
        match self.list() {
            Ok(containers) => {
                self.details
                    .retain(|id, _| containers.iter().any(|c| &c.id == id));
                self.containers = containers;
                true
            }
            Err(error) => {
                eprintln!("Docker: {error}");
                self.containers.clear();
                false
            }
        }
    }

    fn list(&mut self) -> io::Result<Vec<Container>> {
        let list = get_json(&self.socket, "/containers/json")?;
        let mut containers = Vec::new();
        for item in list.arr() {
            let Some(id) = item.get("Id").and_then(Json::str) else {
                continue;
            };
            let details = match self.details.get(id) {
                Some(details) => *details,
                None => match self.inspect(id) {
                    Ok(details) => details,
                    Err(error) => {
                        eprintln!("Docker: inspecting {id}: {error}");
                        continue;
                    }
                },
            };
            self.details.insert(id.to_owned(), details);
            containers.push(container(item, id, details));
        }
        Ok(containers)
    }

    fn inspect(&self, id: &str) -> io::Result<Details> {
        let json = get_json(&self.socket, &format!("/containers/{id}/json"))?;
        let state = json.get("State");
        let pid = state.and_then(|s| s.get("Pid")).and_then(Json::num);
        let started =
            state.and_then(|s| s.get("StartedAt")).and_then(Json::str);
        let tty = json.get("Config").and_then(|c| c.get("Tty"));
        Ok(Details {
            pid: pid.unwrap_or(0.0) as u32,
            tty: tty.is_some_and(Json::bool),
            started_ns: started.and_then(time::parse_rfc3339).unwrap_or(0),
        })
    }

    /// Opens a log stream for each running container that has none and
    /// forgets the positions of containers gone.
    pub fn follow_logs(&mut self, loki: &mut Loki, positions: &mut Positions) {
        self.streams
            .retain(|s| self.containers.iter().any(|c| c.id == s.id));
        let before = positions.docker.len();
        positions
            .docker
            .retain(|id, _| self.containers.iter().any(|c| &c.id == id));
        if positions.docker.len() != before {
            positions.touch();
        }
        for container in &self.containers {
            if self.streams.iter().any(|s| s.id == container.id) {
                continue;
            }
            let since = positions.docker.get(&container.id).copied();
            let start = container.details.started_ns;
            let since = since.unwrap_or(if start > self.since_ns {
                start - 1_000_000_000
            } else {
                time::now_ns()
            });
            match LogStream::open(&self.socket, container, since) {
                // Lines that came with the headers wait for no poll.
                Ok(mut stream) => {
                    if stream.read(loki, positions) {
                        self.streams.push(stream);
                    }
                }
                Err(error) => {
                    eprintln!("Docker: logs of {}: {error}", container.name)
                }
            }
        }
    }

    /// Reads the stream polled at `index`; a stream that ended is closed
    /// and opened again next round if its container still runs.
    pub fn read(
        &mut self,
        index: usize,
        loki: &mut Loki,
        positions: &mut Positions,
    ) {
        let Some(stream) = self.streams.get_mut(index) else {
            return;
        };
        if !stream.read(loki, positions) {
            self.streams.remove(index);
        }
    }
}

fn container(item: &Json, id: &str, details: Details) -> Container {
    let text = |value: Option<&Json>| {
        value.and_then(Json::str).unwrap_or("").to_owned()
    };
    let labels = item.get("Labels");
    let label = |key: &str| {
        text(labels.and_then(|l| l.get(&format!("{COMPOSE}{key}"))))
    };
    let name = item.get("Names").map(|n| n.arr()).and_then(<[Json]>::first);
    let networks = item.get("NetworkSettings").and_then(|n| n.get("Networks"));
    let ips = networks.map(Json::obj).unwrap_or_default().iter();
    let ips = ips.filter_map(|(_, net)| net.get("IPAddress")?.str());
    let ports = item.get("Ports").map(Json::arr).unwrap_or_default().iter();
    let ports = ports.filter_map(|p| p.get("PrivatePort")?.num());
    let mut ports: Vec<u16> = ports.map(|p| p as u16).collect();
    ports.sort_unstable();
    ports.dedup();
    Container {
        id: id.to_owned(),
        name: text(name).trim_start_matches('/').to_owned(),
        image: text(item.get("Image")),
        project: label("project"),
        service: label("service"),
        ips: ips.filter(|ip| !ip.is_empty()).map(str::to_owned).collect(),
        ports,
        labels: cadvisor_labels(labels.map(Json::obj).unwrap_or_default()),
        created: item.get("Created").and_then(Json::num).unwrap_or(0.0),
        health: health(item.get("Status").and_then(Json::str).unwrap_or("")),
        details,
    }
}

fn cadvisor_labels(labels: &[(String, Json)]) -> Vec<(String, String)> {
    let label = |(key, value): &(String, Json)| {
        let key: String = key
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .collect();
        let value = value.str().unwrap_or("").to_owned();
        (format!("container_label_{key}"), value)
    };
    labels.iter().map(label).collect()
}

/// From the list's status: `Up 2 hours (healthy)`, `(health: starting)`.
fn health(status: &str) -> f64 {
    if status.ends_with("(healthy)") {
        1.0
    } else if status.ends_with(')') {
        0.0
    } else {
        -1.0
    }
}

fn get_json(socket: &Path, path: &str) -> io::Result<Json> {
    let response = http::unix_get(socket, path)?;
    if !response.ok() {
        return Err(io::Error::other(format!("{path}: {}", response.status)));
    }
    let text = String::from_utf8_lossy(&response.body);
    Json::parse(&text)
        .ok_or_else(|| io::Error::other(format!("{path}: not JSON")))
}

/// One container's output: chunked HTTP carrying, without a TTY,
/// frames of an 8-byte header (stream, 0, 0, 0, size big-endian) and a
/// line that starts with its RFC 3339 time.
struct LogStream {
    id: String,
    labels: [(&'static str, String); 3],
    socket: UnixStream,
    tty: bool,
    raw: Vec<u8>,
    data: Vec<u8>,
    dechunk: Dechunk,
    /// The newest line read: Docker's `since` repeats it.
    last_ns: i64,
}

impl LogStream {
    fn open(
        socket: &Path,
        container: &Container,
        since_ns: i64,
    ) -> io::Result<LogStream> {
        let mut stream = UnixStream::connect(socket)?;
        stream.set_read_timeout(Some(http::TIMEOUT))?;
        let since = format!(
            "{}.{:09}",
            since_ns.div_euclid(1_000_000_000),
            since_ns.rem_euclid(1_000_000_000)
        );
        write!(
            stream,
            "GET /containers/{}/logs?follow=1&stdout=1&stderr=1\
             &timestamps=1&since={since} HTTP/1.1\r\nHost: docker\r\n\r\n",
            container.id
        )?;
        let raw = read_head(&mut stream)?;
        stream.set_nonblocking(true)?;
        Ok(LogStream {
            id: container.id.clone(),
            labels: [
                ("container", container.name.clone()),
                ("compose_project", container.project.clone()),
                ("compose_service", container.service.clone()),
            ],
            socket: stream,
            tty: container.details.tty,
            raw,
            data: Vec::new(),
            dechunk: Dechunk::default(),
            last_ns: since_ns,
        })
    }

    /// Reads what arrived; false when the stream ended.
    fn read(&mut self, loki: &mut Loki, positions: &mut Positions) -> bool {
        let mut chunk = [0; 16 << 10];
        let open = match self.socket.read(&mut chunk) {
            Ok(0) => false,
            Ok(read) => {
                self.raw.extend_from_slice(&chunk[..read]);
                true
            }
            Err(error) => error.kind() == io::ErrorKind::WouldBlock,
        };
        self.dechunk.feed(&mut self.raw, &mut self.data);
        let used = if self.tty {
            self.take_lines(loki)
        } else {
            self.take_frames(loki)
        };
        self.data.drain(..used);
        if positions.docker.get(&self.id) != Some(&self.last_ns) {
            positions.docker.insert(self.id.clone(), self.last_ns);
            positions.touch();
        }
        open && !self.dechunk.done()
    }

    fn take_frames(&mut self, loki: &mut Loki) -> usize {
        let mut at = 0;
        while let Some(header) = self.data.get(at..at + 8) {
            let size = u32::from_be_bytes([
                header[4], header[5], header[6], header[7],
            ]);
            let end = at + 8 + size as usize;
            if end > self.data.len() {
                break;
            }
            let payload =
                String::from_utf8_lossy(&self.data[at + 8..end]).into_owned();
            for line in payload.lines() {
                self.add(line, loki);
            }
            at = end;
        }
        at
    }

    fn take_lines(&mut self, loki: &mut Loki) -> usize {
        let Some(end) = self.data.iter().rposition(|&b| b == b'\n') else {
            return 0;
        };
        let text = String::from_utf8_lossy(&self.data[..end]).into_owned();
        for line in text.lines() {
            self.add(line.trim_end_matches('\r'), loki);
        }
        end + 1
    }

    fn add(&mut self, line: &str, loki: &mut Loki) {
        let (stamp, text) = line.split_once(' ').unwrap_or((line, ""));
        let Some(ns) = time::parse_rfc3339(stamp) else {
            return;
        };
        if ns <= self.last_ns {
            return;
        }
        self.last_ns = ns;
        let [(k1, v1), (k2, v2), (k3, v3)] = &self.labels;
        let labels = [
            ("job", "docker"),
            (*k1, v1.as_str()),
            (*k2, v2.as_str()),
            (*k3, v3.as_str()),
            ("level", levels::level(text).unwrap_or("")),
        ];
        loki.add(&labels, ns, text);
    }
}

/// Reads up to the end of the response's headers, blocking; returns
/// the body bytes read with them.
fn read_head(stream: &mut UnixStream) -> io::Result<Vec<u8>> {
    let mut raw = Vec::new();
    let mut chunk = [0; 4096];
    loop {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            return Err(io::Error::other("closed before its headers"));
        }
        raw.extend_from_slice(&chunk[..read]);
        if let Some(end) = http::head_end(&raw) {
            let head = http::parse_head(&raw[..end])?;
            if head.status != 200 {
                return Err(io::Error::other(format!(
                    "status {}",
                    head.status
                )));
            }
            return Ok(raw.split_off(end));
        }
    }
}

/// Containers' metrics under cAdvisor's job, the Minecraft plugins in
/// them, and their logs.
impl Part for Docker {
    fn round(&mut self, w: &mut Writer, now_ms: i64) {
        let up = self.refresh();
        w.target("cadvisor", &[]);
        w.up(up);
        crate::agent::build_info(w, "cadvisor_build_info");
        crate::containers::collect(w, &self.containers, now_ms as f64 / 1e3);
        #[cfg(feature = "minecraft")]
        self.minecraft(w);
    }

    fn follow(&mut self, loki: &mut Loki, positions: &mut Positions) {
        self.follow_logs(loki, positions);
    }

    fn fds(&self) -> Vec<RawFd> {
        self.streams.iter().map(|s| s.socket.as_raw_fd()).collect()
    }

    fn read(&mut self, index: usize, loki: &mut Loki, p: &mut Positions) {
        Docker::read(self, index, loki, p);
    }
}

impl Docker {
    /// Each server's plugin at the addresses of the service's containers
    /// that expose the server's port.
    #[cfg(feature = "minecraft")]
    fn minecraft(&self, w: &mut Writer) {
        for server in &self.minecraft {
            let hosts = self.containers.iter().filter(|c| {
                c.service == server.service && c.ports.contains(&server.port)
            });
            for ip in hosts.flat_map(|c| &c.ips) {
                w.target("minecraft", &[("server", &server.server)]);
                let address = format!("{ip}:{}", server.metrics_port);
                crate::scrape::scrape(w, &Url::metrics(&address), &[]);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_container_list() {
        let text = r#"[{"Id":"abc","Names":["/crafty-crafty-1"],
            "Image":"crafty:4","Labels":{
            "com.docker.compose.project":"crafty",
            "com.docker.compose.service":"crafty"},
            "Ports":[{"PrivatePort":25565},{"PrivatePort":25565,
            "PublicPort":1}],
            "NetworkSettings":{"Networks":{"crafty_default":
            {"IPAddress":"172.18.0.2"}}}}]"#;
        let json = Json::parse(text).unwrap();
        let details = Details {
            pid: 1,
            tty: false,
            started_ns: 0,
        };
        let c = container(&json.arr()[0], "abc", details);
        assert_eq!(c.name, "crafty-crafty-1");
        assert_eq!(
            (c.project.as_str(), c.service.as_str()),
            ("crafty", "crafty")
        );
        assert_eq!(c.ips, ["172.18.0.2"]);
        assert_eq!(c.ports, [25565]);
    }
}
