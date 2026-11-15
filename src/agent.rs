//! One thread around poll(2): log sources are read as lines arrive and
//! sent within a second; metrics are collected and sent every interval
//! (SNMP devices are polled apart: crate::snmp).
//! Nothing is buffered beyond one log batch and one metrics chunk.

use crate::config::Config;
use crate::files::Files;
use crate::http::Url;
use crate::loki::{Flushed, Loki};
use crate::node::Node;
use crate::parts::{self, Part};
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
static RELOAD: AtomicBool = AtomicBool::new(false);

/// Why `run` returned.
pub enum Ended {
    Stop,
    /// SIGHUP: logs sent and positions saved, for a new agent to go on.
    Reload,
}

pub struct Agent {
    config: Config,
    writer: Writer,
    node: Node,
    scrapes: Vec<(String, Url)>,
    loki: Loki,
    parts: Vec<Box<dyn Part>>,
    files: Files,
    positions: Positions,
    config_loaded: bool,
}

impl Agent {
    pub fn new(mut config: Config, print: bool) -> Result<Agent, String> {
        if let Some(root) = config.root.clone() {
            crate::host::set_root(root);
        }
        let mut writer = Writer::new(&config.metrics_url, &config.host, print)
            .ok_or("metrics_url is not an http:// URL")?;
        let mut loki = Loki::new(&config.logs_url, &config.host)
            .ok_or("logs_url is not an http:// URL")?;
        let node = Node::new(
            std::mem::take(&mut config.disabled),
            config.textfile_dir.clone(),
        );
        let scrapes = config
            .scrapes
            .iter()
            .map(|s| (s.job.clone(), Url::metrics(&s.address)))
            .collect();
        let parts = parts::build(&mut config, print)?;
        #[cfg(feature = "relabel")]
        {
            let parse = |rules: &[String]| -> Result<Vec<_>, String> {
                rules
                    .iter()
                    .map(|r| crate::relabel::Rule::parse(r))
                    .collect()
            };
            writer.rules = parse(&config.metric_relabel)?;
            loki.rules = parse(&config.log_relabel)?;
        }
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
            scrapes,
            parts,
            config,
            writer,
            node,
            loki,
            config_loaded: true,
        })
    }

    /// Collects and sends one round of metrics.
    pub fn round(&mut self) {
        let now_ms = time::now_ms();
        self.writer.begin(now_ms);
        self.node.collect(&mut self.writer);
        for part in &mut self.parts {
            part.round(&mut self.writer, now_ms);
        }
        for (job, url) in &self.scrapes {
            self.writer.target(job, &[]);
            scrape::scrape(&mut self.writer, url, &self.config.server_ports);
        }
        self.own_metrics();
        self.writer.end_target();
        self.writer.flush();
    }

    /// This agent's own numbers as Alloy's, job `alloy`, under its
    /// names and components' labels: dashboards and alerts on the agents
    /// read both alike. Its version says which it is.
    fn own_metrics(&mut self) {
        let w = &mut self.writer;
        w.target("alloy", &[]);
        w.up(true);
        build_info(w, "alloy_build_info");
        let loaded = f64::from(self.config_loaded);
        w.add("alloy_config_last_load_successful", &[], loaded);
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

    /// A reload failed: this agent goes on with its configuration.
    pub fn config_failed(&mut self) {
        self.config_loaded = false;
    }

    pub fn run(&mut self) -> Ended {
        handle_signals();
        let interval = self.config.interval;
        let mut next_round = Instant::now();
        let mut next_files = Instant::now();
        while !STOP.load(Ordering::Relaxed) {
            if RELOAD.swap(false, Ordering::Relaxed) {
                self.flush_logs(true);
                return Ended::Reload;
            }
            if Instant::now() >= next_round {
                self.round();
                self.follow_logs();
                next_round = (next_round + interval).max(Instant::now());
            }
            for part in &mut self.parts {
                part.prepare(&self.positions);
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
        Ended::Stop
    }

    fn follow_logs(&mut self) {
        for part in &mut self.parts {
            part.follow(&mut self.loki, &mut self.positions);
        }
        self.files.refresh(&mut self.positions);
    }

    /// Waits until `wake` for a source to have lines, and reads those
    /// that do; a blocked batch reads none.
    fn poll_sources(&mut self, wake: Instant) {
        let mut sources = Vec::new();
        let mut fds = Vec::new();
        let blocked = self.loki.blocked(Instant::now());
        for (part, owner) in self.parts.iter().enumerate() {
            if blocked && owner.feeds_loki() {
                continue;
            }
            for (index, fd) in owner.fds().into_iter().enumerate() {
                sources.push((part, index));
                fds.push(fd);
            }
        }
        let timeout = wake.saturating_duration_since(Instant::now());
        let ready = crate::process::poll(&fds, timeout);
        // From the last: reading may close a stream and shift the ones
        // after it.
        let ready = sources.iter().zip(ready).rev().filter(|(_, r)| *r);
        for ((part, index), _) in ready {
            let (loki, positions) = (&mut self.loki, &mut self.positions);
            self.parts[*part].read(*index, loki, positions);
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

/// `name`'s build labels, as Go programs give them, for this build:
/// dashboards read the version.
pub fn build_info(w: &mut Writer, name: &str) {
    let arch = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    };
    let labels = [
        ("goarch", arch),
        ("goos", "linux"),
        (
            "version",
            concat!("host-agent-v", env!("CARGO_PKG_VERSION")),
        ),
    ];
    w.add(name, &labels, 1.0);
}

extern "C" fn stop(_: libc::c_int) {
    STOP.store(true, Ordering::Relaxed);
}

extern "C" fn reload(_: libc::c_int) {
    RELOAD.store(true, Ordering::Relaxed);
}

/// SIGTERM and SIGINT end the loop after a last send, SIGHUP reloads.
/// No SA_RESTART: poll returns at once.
fn handle_signals() {
    let handlers: [(libc::c_int, extern "C" fn(libc::c_int)); 3] = [
        (libc::SIGTERM, stop),
        (libc::SIGINT, stop),
        (libc::SIGHUP, reload),
    ];
    for (signal, handler) in handlers {
        // SAFETY: the handlers only store to an atomic.
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = handler as *const () as usize;
            libc::sigaction(signal, &action, std::ptr::null_mut());
        }
    }
}
