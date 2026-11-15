//! Docker's containers, from its API on the local socket: the list
//! every round (cAdvisor's metrics, discovery.docker's targets) and,
//! for loki.source.docker, one log stream per container it targets.

use crate::http::{self, Dechunk};
use crate::json::Json;
use crate::logs::{Logs, Source};
use crate::parts::Part;
use crate::relabel::Labels;
use crate::state::Positions;
use crate::targets::{self, Targets};
use crate::time;
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

pub struct Container {
    pub id: String,
    pub name: String,
    pub image: String,
    pub network_mode: String,
    /// Each network's name, id and the container's address there.
    pub networks: Vec<[String; 3]>,
    pub ports: Vec<Port>,
    /// Its labels as cAdvisor gives them: `container_label_<key>` with
    /// `[^a-zA-Z0-9_]` as `_`.
    pub labels: Vec<(String, String)>,
    pub created: f64,
    /// cAdvisor's container_health_state: 1 healthy, -1 no check, else 0.
    pub health: f64,
    pub details: Details,
}

/// A port the container exposes, and where it is published.
pub struct Port {
    pub private: u16,
    pub public: Option<u16>,
    pub public_ip: String,
    pub tcp: bool,
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
    /// Whether Docker answered the last listing.
    pub up: bool,
    /// Each loki.source.docker: its id, targets and what it does with
    /// lines.
    logs: Vec<(String, Targets, Source)>,
    streams: Vec<LogStream>,
    /// Containers started after this are read from their start.
    since_ns: i64,
}

impl Docker {
    /// Docker on its socket, whether it runs yet or not.
    pub fn new(
        socket: PathBuf,
        logs: Vec<(String, Targets, Source)>,
    ) -> Docker {
        Docker {
            socket,
            details: HashMap::new(),
            containers: Vec::new(),
            up: false,
            logs,
            streams: Vec::new(),
            since_ns: time::now_ns(),
        }
    }

    /// Lists the running containers.
    pub fn refresh(&mut self) {
        match self.list() {
            Ok(containers) => {
                self.details
                    .retain(|id, _| containers.iter().any(|c| &c.id == id));
                self.containers = containers;
                self.up = true;
            }
            Err(error) => {
                if self.up || self.containers.is_empty() {
                    eprintln!("Docker: {error}");
                }
                self.containers.clear();
                self.up = false;
            }
        }
    }

    /// discovery.docker's targets, as Prometheus's docker_sd makes
    /// them: one per container, network and TCP port, or port 80 for
    /// a container that exposes none.
    pub fn targets(&self) -> Vec<Labels> {
        let mut targets = Vec::new();
        for c in &self.containers {
            let mut common = vec![
                ("__meta_docker_container_id".into(), c.id.clone()),
                (
                    "__meta_docker_container_name".into(),
                    format!("/{}", c.name),
                ),
                (
                    "__meta_docker_container_network_mode".into(),
                    c.network_mode.clone(),
                ),
            ];
            let labels = c
                .labels
                .iter()
                .map(|(k, v)| (format!("__meta_docker_{k}"), v.clone()));
            common.extend(labels);
            for [name, id, ip] in &c.networks {
                let mut network = common.clone();
                network
                    .push(("__meta_docker_network_name".into(), name.clone()));
                network.push(("__meta_docker_network_id".into(), id.clone()));
                network.push(("__meta_docker_network_ip".into(), ip.clone()));
                targets.extend(port_targets(&network, ip, &c.ports));
            }
        }
        targets
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

    /// The positions of streams no source reads, forgotten.
    fn forget_gone(positions: &mut Positions, keys: &[String]) {
        let before = positions.docker.len();
        positions.docker.retain(|key, _| keys.contains(key));
        if positions.docker.len() != before {
            positions.touch();
        }
    }

    /// Each source's containers, by id, each with its first target.
    fn wanted(&self) -> Vec<(usize, String, Labels)> {
        let found = self.targets();
        let mut wanted: Vec<(usize, String, Labels)> = Vec::new();
        for (index, (_, targets, _)) in self.logs.iter().enumerate() {
            for target in targets.resolve(&found) {
                let id = targets::get(&target, "__meta_docker_container_id");
                let seen =
                    wanted.iter().any(|(i, w, _)| *i == index && w == id);
                if !id.is_empty() && !seen {
                    wanted.push((index, id.to_owned(), target));
                }
            }
        }
        wanted
    }

    /// Opens a log stream for each container a source targets that has
    /// none, and forgets the positions of streams gone. A position is
    /// kept by source and container; one by container alone is the
    /// single source's of before.
    pub fn follow_logs(&mut self, logs: &mut Logs, positions: &mut Positions) {
        let wanted = self.wanted();
        let keys: Vec<String> = wanted
            .iter()
            .map(|(index, id, _)| format!("{}/{id}", self.logs[*index].0))
            .collect();
        self.streams.retain(|s| keys.contains(&s.key));
        for ((index, id, target), key) in wanted.into_iter().zip(&keys) {
            let container = self.containers.iter().find(|c| c.id == id);
            let Some(container) = container else {
                continue;
            };
            if self.streams.iter().any(|s| s.key == *key) {
                continue;
            }
            let source = &self.logs[index].2;
            let Some(labels) = source.labels_for(target) else {
                continue;
            };
            let saved = positions.docker.get(key).or(positions.docker.get(&id));
            let since = saved.copied().unwrap_or_else(|| self.since(container));
            let opened =
                LogStream::open(&self.socket, container, since, labels);
            match opened {
                // Lines that came with the headers wait for no poll.
                Ok(mut stream) => {
                    stream.key.clone_from(key);
                    stream.source = index;
                    if stream.read(source, logs, positions) {
                        self.streams.push(stream);
                    }
                }
                Err(error) => {
                    eprintln!("Docker: logs of {}: {error}", container.name)
                }
            }
        }
        Self::forget_gone(positions, &keys);
    }

    /// Where a container's log is first read: from its start if it
    /// started after the agent, else from now.
    fn since(&self, container: &Container) -> i64 {
        let start = container.details.started_ns;
        if start > self.since_ns {
            start - 1_000_000_000
        } else {
            time::now_ns()
        }
    }

    /// Reads the stream polled at `index`; a stream that ended is closed
    /// and opened again next round if its container still runs.
    pub fn read(
        &mut self,
        index: usize,
        logs: &mut Logs,
        positions: &mut Positions,
    ) {
        let Some(stream) = self.streams.get_mut(index) else {
            return;
        };
        let Some((_, _, source)) = self.logs.get(stream.source) else {
            return;
        };
        if !stream.read(source, logs, positions) {
            self.streams.remove(index);
        }
    }
}

fn container(item: &Json, id: &str, details: Details) -> Container {
    let text = |value: Option<&Json>| {
        value.and_then(Json::str).unwrap_or("").to_owned()
    };
    let labels = item.get("Labels");
    let name = item.get("Names").map(|n| n.arr()).and_then(<[Json]>::first);
    let networks = item.get("NetworkSettings").and_then(|n| n.get("Networks"));
    let networks = networks.map(Json::obj).unwrap_or_default().iter();
    let networks = networks.map(|(name, net)| {
        let field = |key: &str| text(net.get(key));
        [name.clone(), field("NetworkID"), field("IPAddress")]
    });
    let ports = item.get("Ports").map(Json::arr).unwrap_or_default().iter();
    let ports = ports.filter_map(|p| {
        Some(Port {
            private: p.get("PrivatePort")?.num()? as u16,
            public: p.get("PublicPort").and_then(Json::num).map(|n| n as u16),
            public_ip: text(p.get("IP")),
            tcp: p.get("Type").and_then(Json::str).unwrap_or("tcp") == "tcp",
        })
    });
    let mode = item.get("HostConfig").and_then(|h| h.get("NetworkMode"));
    Container {
        id: id.to_owned(),
        name: text(name).trim_start_matches('/').to_owned(),
        image: text(item.get("Image")),
        network_mode: text(mode),
        networks: networks.collect(),
        ports: ports.collect(),
        labels: cadvisor_labels(labels.map(Json::obj).unwrap_or_default()),
        created: item.get("Created").and_then(Json::num).unwrap_or(0.0),
        health: health(item.get("Status").and_then(Json::str).unwrap_or("")),
        details,
    }
}

fn port_targets(network: &Labels, ip: &str, ports: &[Port]) -> Vec<Labels> {
    let address =
        |port: u16| ("__address__".to_owned(), format!("{ip}:{port}"));
    let mut targets = Vec::new();
    for port in ports.iter().filter(|p| p.tcp) {
        let mut target = network.clone();
        let private = port.private.to_string();
        target.push(("__meta_docker_port_private".into(), private));
        if let Some(public) = port.public {
            let public = public.to_string();
            target.push(("__meta_docker_port_public".into(), public));
            let ip = port.public_ip.clone();
            target.push(("__meta_docker_port_public_ip".into(), ip));
        }
        target.push(address(port.private));
        targets.push(target);
    }
    if targets.is_empty() {
        let mut target = network.clone();
        target.push(address(80));
        targets.push(target);
    }
    targets
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
    /// Where its position is kept: the source's id and the container's.
    key: String,
    /// Its source, in Docker's `logs`.
    source: usize,
    labels: Labels,
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
        labels: Labels,
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
            key: container.id.clone(),
            source: 0,
            labels,
            socket: stream,
            tty: container.details.tty,
            raw,
            data: Vec::new(),
            dechunk: Dechunk::default(),
            last_ns: since_ns,
        })
    }

    /// Reads what arrived; false when the stream ended.
    fn read(
        &mut self,
        source: &Source,
        logs: &mut Logs,
        positions: &mut Positions,
    ) -> bool {
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
            self.take_lines(source, logs)
        } else {
            self.take_frames(source, logs)
        };
        self.data.drain(..used);
        if positions.docker.get(&self.key) != Some(&self.last_ns) {
            positions.docker.insert(self.key.clone(), self.last_ns);
            positions.touch();
        }
        open && !self.dechunk.done()
    }

    fn take_frames(&mut self, source: &Source, logs: &mut Logs) -> usize {
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
                self.add(line, source, logs);
            }
            at = end;
        }
        at
    }

    fn take_lines(&mut self, source: &Source, logs: &mut Logs) -> usize {
        let Some(end) = self.data.iter().rposition(|&b| b == b'\n') else {
            return 0;
        };
        let text = String::from_utf8_lossy(&self.data[..end]).into_owned();
        for line in text.lines() {
            self.add(line.trim_end_matches('\r'), source, logs);
        }
        end + 1
    }

    fn add(&mut self, line: &str, source: &Source, logs: &mut Logs) {
        let (stamp, text) = line.split_once(' ').unwrap_or((line, ""));
        let Some(ns) = time::parse_rfc3339(stamp) else {
            return;
        };
        if ns <= self.last_ns {
            return;
        }
        self.last_ns = ns;
        source.send(logs, self.labels.clone(), ns, text);
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

/// The containers' log streams.
impl Part for Docker {
    fn fds(&self) -> Vec<RawFd> {
        self.streams.iter().map(|s| s.socket.as_raw_fd()).collect()
    }

    fn read(&mut self, index: usize, logs: &mut Logs, p: &mut Positions) {
        Docker::read(self, index, logs, p);
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
        let docker = Docker {
            containers: vec![c],
            ..Docker::new("/var/run/docker.sock".into(), Vec::new())
        };
        let targets = docker.targets();
        assert_eq!(targets.len(), 2);
        let get = |name| targets::get(&targets[0], name);
        assert_eq!(get("__address__"), "172.18.0.2:25565");
        assert_eq!(get("__meta_docker_container_name"), "/crafty-crafty-1");
        let service =
            "__meta_docker_container_label_com_docker_compose_service";
        assert_eq!(get(service), "crafty");
        assert_eq!(targets::get(&targets[1], "__meta_docker_port_public"), "1");
    }
}
