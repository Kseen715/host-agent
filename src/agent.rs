//! One thread around poll(2): log sources are read as lines arrive and
//! sent within a second; metrics are collected and sent every interval.
//! Nothing is buffered beyond one log batch and one metrics chunk.

use crate::config::Config;
use crate::containers;
use crate::docker::Docker;
use crate::files::Files;
use crate::http::Url;
use crate::journal::Journal;
use crate::loki::{Flushed, Loki};
use crate::node::Node;
use crate::remote::Writer;
use crate::scrape;
use crate::spool::Spool;
use crate::state::Positions;
use crate::time;
use std::fs;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// How often the log files are checked for new lines.
const FILES_EVERY: Duration = Duration::from_secs(1);

static STOP: AtomicBool = AtomicBool::new(false);

pub struct Agent {
    config: Config,
    writer: Writer,
    node: Node,
    scrapes: Vec<(String, Url)>,
    loki: Loki,
    journal: Option<Journal>,
    docker: Option<Docker>,
    files: Files,
    positions: Positions,
}

enum Source {
    Journal,
    Docker(usize),
}

impl Agent {
    pub fn new(mut config: Config, print: bool) -> Result<Agent, String> {
        if let Some(root) = config.root.clone() {
            crate::host::set_root(root);
        }
        let mut writer = Writer::new(&config.metrics_url, &config.host, print)
            .ok_or("metrics_url is not an http:// URL")?;
        let loki = Loki::new(&config.logs_url, &config.host)
            .ok_or("logs_url is not an http:// URL")?;
        let node = Node::new(
            std::mem::take(&mut config.disabled),
            config.textfile_dir.clone(),
        );
        let scrapes = config
            .scrapes
            .iter()
            .map(|s| (s.job.clone(), Url::metrics(&s.address)));
        let drops = std::mem::take(&mut config.journal_drops);
        let journal = if print {
            None
        } else {
            Journal::new(&config.journal_max_age, drops)
        };
        if !print {
            fs::create_dir_all(&config.state_dir)
                .map_err(|e| format!("{}: {e}", config.state_dir.display()))?;
        }
        if !print && config.spool_max_mb > 0 {
            let dir = config.state_dir.join("spool");
            let spool = Spool::open(dir.clone(), config.spool_max_mb << 20)
                .map_err(|e| format!("{}: {e}", dir.display()))?;
            writer.keep_in(spool);
        }
        Ok(Agent {
            positions: Positions::load(config.state_dir.join("positions")),
            files: Files::new(
                config.log_targets_dir.clone(),
                std::mem::take(&mut config.logs),
            ),
            scrapes: scrapes.collect(),
            docker: Docker::new(),
            journal,
            config,
            writer,
            node,
            loki,
        })
    }

    /// Collects and sends one round of metrics.
    pub fn round(&mut self) {
        let now_ms = time::now_ms();
        self.writer.begin(now_ms);
        self.node.collect(&mut self.writer);
        if let Some(docker) = &mut self.docker {
            let up = docker.refresh();
            self.writer.target("cadvisor", &[]);
            self.writer.up(up);
            containers::collect(
                &mut self.writer,
                &docker.containers,
                now_ms as f64 / 1e3,
            );
        }
        for (job, url) in &self.scrapes {
            self.writer.target(job, &[]);
            scrape::scrape(&mut self.writer, url, &self.config.server_ports);
        }
        self.minecraft();
        self.own_metrics();
        self.writer.flush();
    }

    fn minecraft(&mut self) {
        let Some(docker) = &self.docker else { return };
        for server in &self.config.minecraft {
            let hosts = docker.containers.iter().filter(|c| {
                c.service == server.service && c.ports.contains(&server.port)
            });
            for ip in hosts.flat_map(|c| &c.ips) {
                self.writer
                    .target("minecraft", &[("server", &server.server)]);
                let url =
                    Url::metrics(&format!("{ip}:{}", server.metrics_port));
                scrape::scrape(&mut self.writer, &url, &[]);
            }
        }
    }

    /// This agent's own numbers as Alloy's, job `alloy`, under its
    /// names and components' labels: dashboards and alerts on the agents
    /// read both alike. Its version says which it is.
    fn own_metrics(&mut self) {
        let w = &mut self.writer;
        w.target("alloy", &[]);
        w.up(true);
        let version = concat!("host-agent-v", env!("CARGO_PKG_VERSION"));
        w.add("alloy_build_info", &[("version", version)], 1.0);
        w.add("alloy_config_last_load_successful", &[], 1.0);
        crate::process::collect(w);

        let stats = std::mem::take(&mut w.stats);
        let url = w.url_text.clone();
        let component = ("component_id", "prometheus.remote_write.central");
        let remote = [
            component,
            ("component_path", "/"),
            ("remote_name", "central"),
            ("url", url.as_str()),
        ];
        let prefix = "prometheus_remote_storage_";
        let values = [
            ("samples_total", &remote[..], stats.samples as f64),
            ("samples_failed_total", &remote[..], stats.failed as f64),
            ("highest_timestamp_in_seconds", &remote[..2], stats.newest),
            (
                "queue_highest_sent_timestamp_seconds",
                &remote[..],
                stats.newest_sent,
            ),
        ];
        for (name, labels, value) in values {
            w.add(&format!("{prefix}{name}"), labels, value);
        }
        w.stats = stats;

        // Loki's address in `host`, as Alloy's loki.write metrics carry it.
        let loki = [
            ("component_id", "loki.write.central"),
            ("component_path", "/"),
            ("host", self.loki.address.as_str()),
        ];
        let sent = self.loki.sent as f64;
        w.add("loki_write_sent_entries_total", &loki, sent);
        let mut dropped = loki.to_vec();
        dropped.push(("reason", "ingester_error"));
        let count = self.loki.dropped as f64;
        w.add("loki_write_dropped_entries_total", &dropped, count);
    }

    pub fn run(&mut self) {
        handle_signals();
        let interval = self.config.interval;
        let mut next_round = Instant::now();
        let mut next_files = Instant::now();
        while !STOP.load(Ordering::Relaxed) {
            if Instant::now() >= next_round {
                self.round();
                self.follow_logs();
                next_round = (next_round + interval).max(Instant::now());
            }
            if let Some(journal) = &mut self.journal {
                journal.ensure_running(self.positions.journal.as_deref());
            }
            let wake = [Some(next_round), Some(next_files), self.loki.due_at()];
            let wake = wake.into_iter().flatten().min().unwrap_or(next_round);
            self.poll_sources(wake);

            if Instant::now() >= next_files {
                self.files.read(&mut self.loki, &mut self.positions);
                next_files = Instant::now() + FILES_EVERY;
            }
            if self.loki.due_at().is_some_and(|at| Instant::now() >= at) {
                self.flush_logs(false);
            }
        }
        self.flush_logs(true);
    }

    fn follow_logs(&mut self) {
        if let Some(docker) = &mut self.docker {
            docker.follow_logs(&mut self.loki, &mut self.positions);
        }
        self.files.refresh(&mut self.positions);
    }

    /// Waits until `wake` for a source to have lines, and reads those
    /// that do; a blocked batch reads none.
    fn poll_sources(&mut self, wake: Instant) {
        let mut sources = Vec::new();
        let mut fds = Vec::new();
        if !self.loki.blocked(Instant::now()) {
            if let Some(fd) = self.journal.as_ref().and_then(Journal::fd) {
                sources.push(Source::Journal);
                fds.push(fd);
            }
            for (index, fd) in
                self.docker.iter().flat_map(Docker::fds).enumerate()
            {
                sources.push(Source::Docker(index));
                fds.push(fd);
            }
        }
        let timeout = wake.saturating_duration_since(Instant::now());
        let ready = crate::process::poll(&fds, timeout);
        // From the last: reading may close a Docker stream and shift the
        // ones after it.
        for (source, _) in sources.iter().zip(ready).rev().filter(|(_, r)| *r) {
            match source {
                Source::Journal => {
                    if let Some(journal) = &mut self.journal {
                        journal.read(&mut self.loki, &mut self.positions);
                    }
                }
                Source::Docker(index) => {
                    if let Some(docker) = &mut self.docker {
                        docker.read(
                            *index,
                            &mut self.loki,
                            &mut self.positions,
                        );
                    }
                }
            }
        }
    }

    fn flush_logs(&mut self, last: bool) {
        if let Flushed::Done = self.loki.flush() {
            if let Err(error) = self.positions.save(last) {
                eprintln!("Positions: {error}");
            }
        }
    }
}

extern "C" fn stop(_: libc::c_int) {
    STOP.store(true, Ordering::Relaxed);
}

/// SIGTERM and SIGINT end the loop after a last send. No SA_RESTART:
/// poll returns at once.
fn handle_signals() {
    // SAFETY: the handler only stores to an atomic.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = stop as *const () as usize;
        for signal in [libc::SIGTERM, libc::SIGINT] {
            libc::sigaction(signal, &action, std::ptr::null_mut());
        }
    }
}
