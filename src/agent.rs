//! One thread around poll(2): log sources are read as lines arrive and
//! sent within a second; each prometheus.scrape scrapes its targets
//! every scrape_interval (SNMP devices are polled apart: crate::snmp).
//! Nothing is buffered beyond one log batch per Loki and each remote
//! write's queue, whose shards' threads post the metrics.

use crate::alloy::syntax::Stmt;
use crate::alloy::{self, Exporter, Plan, ScrapeJob};
use crate::encoding::query_escape;
use crate::files::{self, Files};
use crate::http::Url;
use crate::logs::Logs;
use crate::loki::Flushed;
use crate::parts::{self, Part};
use crate::relabel::Labels;
use crate::remote::{Stats, Writer};
use crate::spool::Spool;
use crate::state::Positions;
use crate::targets;
use crate::time;
use std::fs;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// How often the log files are checked for new lines.
const FILES_EVERY: Duration = Duration::from_secs(1);
/// How often sources look for new containers and files when no scrape
/// comes sooner.
const FOLLOW_EVERY: Duration = Duration::from_secs(15);
/// Metrics kept on disk per remote write while Prometheus is away.
const SPOOL_MAX: u64 = 256 << 20;

static STOP: AtomicBool = AtomicBool::new(false);
static RELOAD: AtomicBool = AtomicBool::new(false);

/// Why `run` returned.
pub enum Ended {
    Stop,
    /// SIGHUP: logs sent and positions saved, for a new agent to go on.
    Reload,
}

/// What Alloy's command line sets.
pub struct Options {
    pub listen: String,
    pub storage: PathBuf,
    /// One round of metrics to stdout, nothing sent.
    pub print: bool,
}

pub struct Agent {
    listen: String,
    writer: Writer,
    logs: Logs,
    /// Each scrape and when it is next due.
    scrapes: Vec<(ScrapeJob, Instant)>,
    exporters: Vec<(String, Exporter)>,
    #[cfg(feature = "docker")]
    docker: Option<crate::docker::Docker>,
    parts: Vec<Box<dyn Part>>,
    files: Vec<Files>,
    positions: Positions,
    config_loaded: bool,
    #[cfg(feature = "server")]
    server: Option<crate::server::Server>,
    /// Scrapes of `/metrics`, as promhttp counts them.
    metrics_requests: u64,
}

impl Agent {
    pub fn new(stmts: &[Stmt], options: &Options) -> Result<Agent, String> {
        let mut plan = alloy::compile(stmts, options.print)?;
        if let Some(root) = plan.root.take() {
            crate::host::set_root(root);
        }
        if !options.print {
            keep_in_spools(&mut plan, &options.storage)?;
        }
        let parts = parts::build(&mut plan)?;
        #[cfg(feature = "docker")]
        let docker = plan.docker.take().map(|socket| {
            let logs = std::mem::take(&mut plan.docker_logs);
            crate::docker::Docker::new(socket.into(), logs)
        });
        let now = Instant::now();
        let scrapes = plan.scrapes.into_iter().map(|s| (s, now)).collect();
        Ok(Agent {
            listen: options.listen.clone(),
            writer: Writer::new(plan.metrics),
            logs: plan.logs,
            scrapes,
            exporters: plan.exporters,
            #[cfg(feature = "docker")]
            docker,
            parts,
            files: plan.files,
            positions: Positions::load(options.storage.join("positions")),
            config_loaded: true,
            #[cfg(feature = "server")]
            server: None,
            metrics_requests: 0,
        })
    }

    /// Scrapes the targets of each scrape due; Docker's targets now.
    pub fn round(&mut self) -> Vec<Labels> {
        let now = Instant::now();
        self.writer.begin(time::now_ms());
        let docker = self.docker_targets();
        for index in 0..self.scrapes.len() {
            let (job, due) = &mut self.scrapes[index];
            if *due > now {
                continue;
            }
            *due = (*due + job.interval).max(now);
            self.scrape(index, &docker);
        }
        self.writer.end_target();
        docker
    }

    fn docker_targets(&mut self) -> Vec<Labels> {
        #[cfg(feature = "docker")]
        if let Some(docker) = &mut self.docker {
            docker.refresh();
            return docker.targets();
        }
        Vec::new()
    }

    fn scrape(&mut self, index: usize, docker: &[Labels]) {
        let job = &self.scrapes[index].0;
        let (to, honor) = (Rc::clone(&job.to), job.honor_labels);
        let interval = job.interval;
        let (client, stamps) = (job.client.clone(), job.honor_timestamps);
        for target in prepare(job, docker) {
            let visible: Labels = target
                .iter()
                .filter(|(k, _)| !k.starts_with("__"))
                .cloned()
                .collect();
            let to = Rc::clone(&to);
            if targets::get(&target, "__address__") == alloy::INTERNAL {
                self.in_process(&target, (visible, to, honor), interval);
            } else {
                self.writer.target(visible, to, honor);
                let Some(url) = url(&target) else {
                    eprintln!("Scrape: no URL for {target:?}");
                    self.writer.up(false);
                    continue;
                };
                crate::scrape::scrape(&mut self.writer, &url, &client, stamps);
            }
        }
    }

    /// A target of an exporter in this process. One arm per exporter:
    /// longer than 40 lines, as a table is read whole.
    fn in_process(
        &mut self,
        target: &Labels,
        (visible, to, honor): (Labels, Rc<[usize]>, bool),
        interval: Duration,
    ) {
        let path = targets::get(target, "__metrics_path__");
        let id = path.strip_prefix("/api/v0/component/");
        let id = id.and_then(|p| p.strip_suffix("/metrics")).unwrap_or("");
        let found = self.exporters.iter_mut().find(|(i, _)| i == id);
        let Some((_, exporter)) = found else {
            eprintln!("Scrape: no component `{id}`");
            self.writer.target(visible, to, honor);
            return self.writer.up(false);
        };
        let w = &mut self.writer;
        match exporter {
            Exporter::Unix(node) => {
                w.target(visible, to, honor);
                w.up(true);
                node.collect(w);
            }
            Exporter::Agent => {
                let own = Own::of(w, &self.logs, self.config_loaded);
                w.target(visible, to, honor);
                w.up(true);
                own.write(w, self.metrics_requests, false);
            }
            #[cfg(feature = "docker")]
            Exporter::Cadvisor(raw) => {
                w.target(visible, to, honor);
                let docker = self.docker.as_ref();
                w.up(docker.is_some_and(|d| d.up));
                build_info(w, "cadvisor_build_info");
                let containers = docker.map(|d| &d.containers[..]);
                let now_s = time::now_ms() as f64 / 1e3;
                let containers = containers.unwrap_or(&[]);
                crate::containers::collect(w, containers, raw, now_s);
            }
            #[cfg(feature = "snmp")]
            Exporter::Snmp(snmp) => {
                let name = targets::get(target, "__param_name");
                if let Some(poll) = snmp.take(name, interval) {
                    w.target(visible, to, honor);
                    poll.write(w);
                }
            }
        }
        let _ = interval;
    }

    fn read_files(&mut self) {
        for files in &mut self.files {
            files.read(&mut self.logs, &mut self.positions);
        }
    }

    /// A reload failed: this agent goes on with its configuration.
    pub fn config_failed(&mut self) {
        self.config_loaded = false;
    }

    pub fn run(&mut self) -> Ended {
        handle_signals();
        // Here, not in `new`: a reloaded agent is made while the one
        // before it still holds the address.
        #[cfg(feature = "server")]
        if self.server.is_none() {
            self.server = serve_at(&self.listen);
        }
        let mut next_follow = Instant::now();
        let mut next_files = Instant::now();
        while !STOP.load(Ordering::Relaxed) {
            if RELOAD.swap(false, Ordering::Relaxed) {
                return self.end(Ended::Reload);
            }
            let now = Instant::now();
            if now >= next_follow || self.scrapes.iter().any(|s| s.1 <= now) {
                let docker = self.round();
                self.follow(&docker);
                next_follow = now + FOLLOW_EVERY;
            }
            for part in &mut self.parts {
                part.prepare(&self.positions);
            }
            let next = [Some(next_follow), Some(next_files)];
            let wake = next.into_iter().chain(self.due()).flatten().min();
            self.poll_sources(wake.unwrap_or(next_follow));
            // Each turn, at least every FILES_EVERY: the senders' results
            // and retries are looked at here.
            self.writer.tick();

            if Instant::now() >= next_files {
                self.read_files();
                next_files = Instant::now() + FILES_EVERY;
            }
            if self.logs.due_at().is_some_and(|at| Instant::now() >= at) {
                self.flush_logs(false);
            }
        }
        self.end(Ended::Stop)
    }

    /// When the next scrape, log batch or metrics batch is due.
    fn due(&self) -> [Option<Instant>; 3] {
        let next_scrape = self.scrapes.iter().map(|s| s.1).min();
        [next_scrape, self.logs.due_at(), self.writer.due()]
    }

    /// The last sends before the agent ends, positions saved.
    fn end(&mut self, ended: Ended) -> Ended {
        self.writer.close();
        self.flush_logs(true);
        ended
    }

    /// Opens or closes log sources for the containers and files now.
    fn follow(&mut self, docker: &[Labels]) {
        #[cfg(feature = "docker")]
        if let Some(d) = &mut self.docker {
            d.follow_logs(&mut self.logs, &mut self.positions);
        }
        for files in &mut self.files {
            files.refresh(docker, &mut self.positions);
        }
        files::forget_others(&self.files, &mut self.positions);
    }

    /// Waits until `wake` for a source to have lines, and reads those
    /// that do; a blocked batch reads none.
    fn poll_sources(&mut self, wake: Instant) {
        let blocked = self.logs.blocked(Instant::now());
        let mut owners: Vec<&mut dyn Part> = self
            .parts
            .iter_mut()
            .map(|p| &mut **p as &mut dyn Part)
            .collect();
        #[cfg(feature = "docker")]
        owners.extend(self.docker.as_mut().map(|d| d as &mut dyn Part));
        let mut sources = Vec::new();
        let mut fds = Vec::new();
        for (owner, part) in owners.iter().enumerate() {
            if blocked && part.feeds_loki() {
                continue;
            }
            for (index, fd) in part.fds().into_iter().enumerate() {
                sources.push((owner, index));
                fds.push(fd);
            }
        }
        #[cfg(feature = "server")]
        let server = self.server.as_ref().map(crate::server::Server::fd);
        #[cfg(feature = "server")]
        fds.extend(server);
        let timeout = wake.saturating_duration_since(Instant::now());
        let mut ready = crate::process::poll(&fds, timeout);
        #[cfg(feature = "server")]
        let serve = server.is_some() && ready.pop() == Some(true);
        // From the last: reading may close a stream and shift the ones
        // after it.
        let ready = sources.iter().zip(ready).rev().filter(|(_, r)| *r);
        for ((owner, index), _) in ready {
            owners[*owner].read(*index, &mut self.logs, &mut self.positions);
        }
        drop(owners);
        #[cfg(feature = "server")]
        if serve {
            self.serve();
        }
    }

    /// Each waiting client's request, answered. One arm per route:
    /// longer than 40 lines, as a table is read whole.
    #[cfg(feature = "server")]
    fn serve(&mut self) {
        use crate::server::{Route, respond, start_stream};
        const TEXT: &str = "text/plain; charset=utf-8";
        while let Some((mut stream, route)) =
            self.server.as_ref().and_then(|s| s.accept())
        {
            match route {
                Route::Page => {
                    let page = self.page();
                    respond(
                        stream,
                        "200 OK",
                        "text/html; charset=utf-8",
                        &page,
                    );
                }
                Route::Metrics => {
                    self.metrics_requests += 1;
                    let mut w = Writer::text();
                    let own =
                        Own::of(&self.writer, &self.logs, self.config_loaded);
                    own.write(&mut w, self.metrics_requests - 1, true);
                    let kind = "text/plain; version=0.0.4; charset=utf-8";
                    respond(stream, "200 OK", kind, &w.into_text());
                }
                Route::Ready => {
                    respond(stream, "200 OK", TEXT, "Alloy is ready.\n")
                }
                Route::Healthy => respond(
                    stream,
                    "200 OK",
                    TEXT,
                    "All Alloy components are healthy.\n",
                ),
                Route::Reload => {
                    RELOAD.store(true, Ordering::Relaxed);
                    respond(stream, "200 OK", TEXT, "config reloaded\n");
                }
                Route::MetricsTap if start_stream(&mut stream) => {
                    self.writer.tap.open(stream);
                }
                Route::LogsTap if start_stream(&mut stream) => {
                    if let Some(loki) = self.logs.sinks.first_mut() {
                        loki.tap.open(stream);
                    }
                }
                Route::MetricsTap | Route::LogsTap => {}
                Route::NotFound => {
                    respond(stream, "404 Not Found", TEXT, "Not found\n")
                }
                Route::NotAllowed => {
                    respond(stream, "405 Method Not Allowed", TEXT, "")
                }
            }
        }
    }

    /// The status page: the agent, where it sends, each target's last
    /// round. Longer than 40 lines: one argument per field of the page.
    #[cfg(feature = "server")]
    fn page(&self) -> String {
        let escape = crate::server::escape_html;
        use std::fmt::Write as _;
        let mut rows = String::new();
        for target in &self.writer.targets {
            let labels: Vec<String> = target
                .labels
                .iter()
                .map(|(k, v)| format!("{k}=\"{}\"", escape(v)))
                .collect();
            let up = match target.up {
                Some(true) => "up",
                Some(false) => "down",
                None => "",
            };
            let _ = write!(
                rows,
                "<tr><td>{}</td><td class={up}>{up}</td><td>{}</td>\
                 <td>{:.3} s</td></tr>",
                labels.join(", "),
                target.samples,
                target.seconds,
            );
        }
        let own = Own::of(&self.writer, &self.logs, self.config_loaded);
        let join = |texts: Vec<&str>| escape(&texts.join(", "));
        let urls = own.remotes.iter().map(|r| r.1.as_str()).collect();
        let lokis = own.lokis.iter().map(|l| l.1.as_str()).collect();
        format!(
            include_str!("page.html"),
            host = escape(&crate::host::hostname()),
            version = env!("CARGO_PKG_VERSION"),
            revision = env!("BUILD_REVISION"),
            loaded = if self.config_loaded {
                "loaded"
            } else {
                "failed"
            },
            metrics_url = join(urls),
            samples = own.remotes.iter().map(|r| r.2.samples).sum::<u64>(),
            failed = own.remotes.iter().map(|r| r.2.failed).sum::<u64>(),
            loki = join(lokis),
            sent = own.lokis.iter().map(|l| l.2).sum::<u64>(),
            dropped = own.lokis.iter().map(|l| l.3).sum::<u64>(),
            rows = rows,
        )
    }

    fn flush_logs(&mut self, last: bool) {
        if let Flushed::Done = self.logs.flush() {
            if let Err(error) = self.positions.save(last) {
                eprintln!("Positions: {error}");
            }
        }
    }
}

/// The HTTP server, unless it cannot listen: the agent works without it.
#[cfg(feature = "server")]
fn serve_at(address: &str) -> Option<crate::server::Server> {
    crate::server::Server::bind(address)
        .inspect_err(|e| eprintln!("HTTP server on {address}: {e}"))
        .ok()
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
        ("branch", env!("BUILD_BRANCH")),
        ("goarch", arch),
        ("goos", "linux"),
        ("goversion", env!("BUILD_RUST")),
        ("revision", env!("BUILD_REVISION")),
        ("tags", env!("BUILD_TAGS")),
        (
            "version",
            concat!("host-agent-v", env!("CARGO_PKG_VERSION")),
        ),
    ];
    w.add(name, &labels, 1.0);
}

/// Prometheus's defaults for a scrape's targets: `job`,
/// `__metrics_path__`, `__scheme__`, `__param_*`, then `instance` the
/// address; targets without one, and repeats, are left out.
fn prepare(job: &ScrapeJob, docker: &[Labels]) -> Vec<Labels> {
    let mut prepared: Vec<Labels> = Vec::new();
    for mut target in job.targets.resolve(docker) {
        let mut default = |name: String, value: &str| {
            if !target.iter().any(|(k, _)| *k == name) {
                target.push((name, value.to_owned()));
            }
        };
        default("job".into(), &job.job);
        default("__metrics_path__".into(), &job.metrics_path);
        default("__scheme__".into(), &job.scheme);
        for (name, value) in &job.params {
            default(format!("__param_{name}"), value);
        }
        let address = targets::get(&target, "__address__").to_owned();
        if address.is_empty() {
            continue;
        }
        if targets::get(&target, "instance").is_empty() {
            target.retain(|(k, _)| k != "instance");
            target.push(("instance".into(), address));
        }
        target.sort();
        if !prepared.contains(&target) {
            prepared.push(target);
        }
    }
    prepared
}

/// A target's URL: its scheme, address, path and `__param_*` as the
/// query.
fn url(target: &Labels) -> Option<Url> {
    let mut path = targets::get(target, "__metrics_path__").to_owned();
    let params = target
        .iter()
        .filter_map(|(k, v)| Some((k.strip_prefix("__param_")?, v)));
    for (i, (name, value)) in params.enumerate() {
        path.push(if i == 0 { '?' } else { '&' });
        path.push_str(&format!(
            "{}={}",
            query_escape(name),
            query_escape(value)
        ));
    }
    let scheme = targets::get(target, "__scheme__");
    let address = targets::get(target, "__address__");
    Url::parse(&format!("{scheme}://{address}{path}"))
}

/// A spool on disk for each remote write, as Alloy keeps a WAL in
/// its component's directory.
fn keep_in_spools(
    plan: &mut Plan,
    storage: &std::path::Path,
) -> Result<(), String> {
    fs::create_dir_all(storage)
        .map_err(|e| format!("{}: {e}", storage.display()))?;
    for sink in &mut plan.metrics.sinks {
        let dir =
            storage.join(format!("prometheus.remote_write.{}", sink.name));
        let spool = Spool::open(
            dir.clone(),
            SPOOL_MAX,
            sink.age_limit,
            sink.truncation,
        )
        .map_err(|e| format!("{}: {e}", dir.display()))?;
        sink.keep_in(spool);
    }
    Ok(())
}

/// The numbers an agent gives of itself, in a scrape and on
/// `/metrics`: each remote write's name, URL and counts, each Loki's
/// name, address, lines sent and dropped.
struct Own {
    remotes: Vec<(String, String, Stats)>,
    lokis: Vec<(String, String, u64, u64)>,
    loaded: bool,
}

impl Own {
    fn of(writer: &Writer, logs: &Logs, loaded: bool) -> Own {
        let remotes = writer.metrics.sinks.iter();
        let remotes =
            remotes.map(|r| (r.name.clone(), r.url_text.clone(), r.stats()));
        let lokis = logs
            .sinks
            .iter()
            .map(|l| (l.name.clone(), l.address.clone(), l.sent, l.dropped));
        Own {
            remotes: remotes.collect(),
            lokis: lokis.collect(),
            loaded,
        }
    }

    /// Under Alloy's names and components' labels: dashboards and
    /// alerts on the agents read both alike. Its version says which it
    /// is. `serving`: for a request to `/metrics`, in flight.
    fn write(&self, w: &mut Writer, requests: u64, serving: bool) {
        build_info(w, "alloy_build_info");
        w.add(
            "alloy_config_last_load_successful",
            &[],
            f64::from(self.loaded),
        );
        crate::process::collect(w);
        for (name, url, stats) in &self.remotes {
            remote_metrics(w, name, url, stats);
        }
        for (name, address, sent, dropped) in &self.lokis {
            // Loki's address in `host`, as Alloy's loki.write metrics
            // carry it.
            let id = format!("loki.write.{name}");
            let loki = [
                ("component_id", id.as_str()),
                ("component_path", "/"),
                ("host", address.as_str()),
            ];
            w.add("loki_write_sent_entries_total", &loki, *sent as f64);
            let mut labels = loki.to_vec();
            labels.push(("reason", "ingester_error"));
            let dropped = *dropped as f64;
            w.add("loki_write_dropped_entries_total", &labels, dropped);
        }
        // Alloy's own /metrics handler, as promhttp counts it.
        for (code, count) in [("200", requests), ("500", 0), ("503", 0)] {
            let name = "promhttp_metric_handler_requests_total";
            w.add(name, &[("code", code)], count as f64);
        }
        let in_flight = f64::from(serving);
        w.add("promhttp_metric_handler_requests_in_flight", &[], in_flight);
    }
}

fn remote_metrics(w: &mut Writer, name: &str, url: &str, stats: &Stats) {
    let id = format!("prometheus.remote_write.{name}");
    let remote = [
        ("component_id", id.as_str()),
        ("component_path", "/"),
        ("remote_name", name),
        ("url", url),
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
        ("shards", &remote[..], stats.shards),
        ("shards_desired", &remote[..], stats.shards_desired),
        ("shards_min", &remote[..], stats.shards_min),
        ("shards_max", &remote[..], stats.shards_max),
        ("shard_capacity", &remote[..], stats.shard_capacity),
    ];
    for (metric, labels, value) in values {
        w.add(&format!("{prefix}{metric}"), labels, value);
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{self, Request, response};
    use std::sync::atomic::AtomicUsize;

    const EXPOSITION: &str = "# TYPE demo_jobs_total counter\n\
        demo_jobs_total{queue=\"mail\"} 3\n";

    /// An app to scrape and a Prometheus to write to, on one server:
    /// the first `refusals` writes get a 503.
    fn backend(refusals: usize) -> testing::Server {
        let writes = AtomicUsize::new(0);
        testing::serve(move |request: &Request| {
            if request.method == "GET" {
                return response("200 OK", "text/plain", EXPOSITION);
            }
            match writes.fetch_add(1, Ordering::Relaxed) < refusals {
                true => response("503 Service Unavailable", "text/plain", ""),
                false => response("204 No Content", "text/plain", ""),
            }
        })
    }

    fn config(server: &testing::Server) -> String {
        format!(
            r#"
            prometheus.exporter.self "agent" {{ }}
            prometheus.scrape "apps" {{
                targets = array.concat(
                    [{{"__address__" = "{}", "team" = "core"}}],
                    prometheus.exporter.self.agent.targets,
                )
                params = {{"debug" = ["1"]}}
                forward_to = [prometheus.relabel.trim.receiver]
            }}
            prometheus.relabel "trim" {{
                rule {{
                    source_labels = ["__name__"]
                    regex = "scrape_.*"
                    action = "drop"
                }}
                forward_to = [prometheus.remote_write.prom.receiver]
            }}
            prometheus.remote_write "prom" {{
                external_labels = {{"site" = "home"}}
                endpoint {{
                    url = "{}"
                    queue_config {{
                        min_backoff = "1ms"
                        max_backoff = "1ms"
                    }}
                }}
            }}"#,
            server.address,
            server.url("/api/v1/write"),
        )
    }

    fn agent(server: &testing::Server, test: &str) -> Agent {
        let options = Options {
            listen: "127.0.0.1:0".into(),
            storage: testing::scratch(test),
            print: false,
        };
        let stmts = alloy::parse(&config(server)).unwrap();
        Agent::new(&stmts, &options).unwrap()
    }

    /// The samples of every write Prometheus took, as protobuf text.
    fn written(server: &testing::Server) -> String {
        let posts = server.requests().into_iter().filter(|r| {
            r.method == "POST" && r.header("Content-Encoding") == Some("snappy")
        });
        let mut decoder = snap::raw::Decoder::new();
        let bodies = posts.map(|r| decoder.decompress_vec(&r.body).unwrap());
        String::from_utf8_lossy(&bodies.collect::<Vec<_>>().concat())
            .into_owned()
    }

    #[test]
    fn scrapes_relabels_and_writes_a_round() {
        let server = backend(0);
        let mut agent = agent(&server, "round");
        agent.round();
        agent.writer.close();
        let scraped = server.requests();
        assert_eq!(scraped[0].path, "/metrics?debug=1");
        let sent = written(&server);
        for wanted in ["demo_jobs_total", "mail", "team", "core", "site"] {
            assert!(sent.contains(wanted), "{wanted} not sent");
        }
        assert!(sent.contains("alloy_build_info"));
        assert!(sent.contains("prometheus_remote_storage_samples_total"));
        assert!(!sent.contains("scrape_samples_scraped"));
        let stats = agent.writer.metrics.sinks[0].stats();
        assert!(stats.samples > 0 && stats.failed == 0);
    }

    /// Prometheus away: the batch waits on disk and goes once it is
    /// back, its samples counted sent, not failed.
    #[test]
    fn keeps_what_prometheus_refuses_until_it_takes_it() {
        let server = backend(1);
        let mut agent = agent(&server, "spool");
        agent.round();
        agent.writer.close();
        assert_eq!(agent.writer.metrics.sinks[0].stats().samples, 0);
        assert!(written(&server).contains("demo_jobs_total"));
        for _ in 0..100 {
            std::thread::sleep(Duration::from_millis(5));
            agent.writer.tick();
            if agent.writer.metrics.sinks[0].stats().samples > 0 {
                break;
            }
        }
        let stats = agent.writer.metrics.sinks[0].stats();
        assert!(stats.samples > 0 && stats.failed == 0);
        let requests = server.requests();
        let posts = requests.iter().filter(|r| r.method == "POST");
        assert_eq!(posts.count(), 2);
    }

    #[test]
    fn an_unknown_component_target_is_down() {
        let server = backend(0);
        let mut agent = agent(&server, "unknown");
        agent.exporters.clear();
        agent.round();
        let team = ("team".to_owned(), "core".to_owned());
        let (app, own): (Vec<_>, Vec<_>) = agent
            .writer
            .targets
            .iter()
            .partition(|t| t.labels.contains(&team));
        assert_eq!((app.len(), own.len()), (1, 1));
        assert_eq!(app[0].up, Some(true));
        assert_eq!(own[0].up, Some(false));
    }

    #[test]
    fn prepares_targets_as_prometheus_does() {
        let server = backend(0);
        let agent = agent(&server, "prepare");
        let job = &agent.scrapes[0].0;
        let targets = prepare(job, &[]);
        assert_eq!(targets.len(), 2, "{targets:?}");
        let app = &targets[0];
        assert_eq!(targets::get(app, "job"), "prometheus.scrape.apps");
        assert_eq!(targets::get(app, "instance"), server.address.to_string());
        assert_eq!(targets::get(app, "__param_debug"), "1");
        let url = url(app).unwrap();
        assert_eq!(url.path, "/metrics?debug=1");
    }

    /// The HTTP server's routes, answered from the agent's loop.
    #[cfg(feature = "server")]
    #[test]
    fn serves_its_page_metrics_and_health() {
        let server = backend(0);
        let mut agent = agent(&server, "serve");
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .and_then(|l| l.local_addr())
            .unwrap()
            .port();
        agent.server = serve_at(&format!("127.0.0.1:{port}"));
        agent.round();
        let ask = |agent: &mut Agent, head: &str| {
            use std::io::{Read, Write};
            let mut client =
                std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
            client.write_all(head.as_bytes()).unwrap();
            agent.poll_sources(Instant::now() + Duration::from_secs(5));
            let mut answer = String::new();
            client.read_to_string(&mut answer).unwrap();
            answer
        };
        let page = ask(&mut agent, "GET / HTTP/1.1\r\n\r\n");
        assert!(page.contains("team=\"core\""), "{page}");
        assert!(page.contains(&server.url("/api/v1/write")));
        let metrics = ask(&mut agent, "GET /metrics HTTP/1.1\r\n\r\n");
        assert!(metrics.contains("alloy_config_last_load_successful 1"));
        let requests = "promhttp_metric_handler_requests_total{code=\"200\"}";
        assert!(metrics.contains(&format!("{requests} 0")));
        let metrics = ask(&mut agent, "GET /metrics HTTP/1.1\r\n\r\n");
        assert!(metrics.contains(&format!("{requests} 1")));
        let ready = ask(&mut agent, "GET /-/ready HTTP/1.1\r\n\r\n");
        assert!(ready.ends_with("Alloy is ready.\n"));
        let healthy = ask(&mut agent, "GET /-/healthy HTTP/1.1\r\n\r\n");
        assert!(healthy.starts_with("HTTP/1.1 200 OK"));
        let missing = ask(&mut agent, "GET /nope HTTP/1.1\r\n\r\n");
        assert!(missing.starts_with("HTTP/1.1 404"));
        let refused = ask(&mut agent, "DELETE /metrics HTTP/1.1\r\n\r\n");
        assert!(refused.starts_with("HTTP/1.1 405"));
        agent.config_failed();
        let page = ask(&mut agent, "GET / HTTP/1.1\r\n\r\n");
        assert!(page.contains("failed"));
    }

    /// A container of Docker's, this test's process standing in for it:
    /// its id is part of the process's cgroup path, as Docker's is.
    #[cfg(feature = "docker")]
    fn fake_docker(socket: &std::path::Path) -> String {
        let cgroup = fs::read_to_string("/proc/self/cgroup").unwrap();
        let path = cgroup.lines().last().unwrap().rsplit(':').next().unwrap();
        let id = path.rsplit('/').next().unwrap().to_owned();
        let pid = std::process::id();
        let list = format!(
            r#"[{{"Id":"{id}","Names":["/web"],"Image":"nginx:1",
            "Created":1700000000,"Status":"Up 1 hour (healthy)",
            "Labels":{{"com.docker.compose.service":"web"}},
            "Ports":[{{"PrivatePort":80,"Type":"tcp"}}],
            "HostConfig":{{"NetworkMode":"bridge"}},
            "NetworkSettings":{{"Networks":{{"bridge":
            {{"NetworkID":"n1","IPAddress":"172.17.0.2"}}}}}}}}]"#
        );
        let inspect = format!(
            r#"{{"State":{{"Pid":{pid},"StartedAt":"2026-01-01T00:00:00Z"}},
            "Config":{{"Tty":false}}}}"#
        );
        let line = b"2099-01-01T00:00:00.000000001Z hello from web\n";
        let mut frame = vec![1, 0, 0, 0];
        frame.extend_from_slice(&(line.len() as u32).to_be_bytes());
        frame.extend_from_slice(line);
        let logs = format!(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
             {:x}\r\n{}\r\n0\r\n\r\n",
            frame.len(),
            String::from_utf8(frame).unwrap(),
        );
        let json = |body: &str| response("200 OK", "application/json", body);
        testing::serve_unix(socket, move |request: &Request| {
            match request.path.as_str() {
                "/containers/json" => json(&list),
                p if p.ends_with("/json") => json(&inspect),
                p if p.contains("/logs?") => logs.clone(),
                _ => response("404 Not Found", "text/plain", ""),
            }
        });
        id
    }

    /// Docker's containers: their targets, their resources under
    /// cAdvisor's names and their output sent to Loki.
    #[cfg(feature = "docker")]
    #[test]
    fn follows_dockers_containers() {
        let server = backend(0);
        let storage = testing::scratch("docker");
        let socket = storage.join("docker.sock");
        let id = fake_docker(&socket);
        let text = format!(
            r#"
            prometheus.exporter.cadvisor "containers" {{
                docker_host = "unix://{socket}"
            }}
            prometheus.scrape "containers" {{
                targets = prometheus.exporter.cadvisor.containers.targets
                forward_to = [prometheus.remote_write.prom.receiver]
            }}
            prometheus.remote_write "prom" {{
                endpoint {{ url = "{}" }}
            }}
            discovery.docker "containers" {{
                host = "unix://{socket}"
            }}
            loki.source.docker "containers" {{
                host = "unix://{socket}"
                targets = discovery.docker.containers.targets
                labels = {{"job" = "docker"}}
                forward_to = [loki.write.loki.receiver]
            }}
            loki.write "loki" {{
                endpoint {{ url = "{}" }}
            }}"#,
            server.url("/api/v1/write"),
            server.url("/loki/api/v1/push"),
            socket = socket.display(),
        );
        let options = Options {
            listen: "127.0.0.1:0".into(),
            storage: storage.join("data"),
            print: false,
        };
        let stmts = alloy::parse(&text).unwrap();
        let mut agent = Agent::new(&stmts, &options).unwrap();
        let docker = agent.round();
        let address = targets::get(&docker[0], "__address__");
        assert_eq!(address, "172.17.0.2:80");
        agent.follow(&docker);
        for _ in 0..100 {
            if agent.logs.sinks[0].sent > 0 {
                break;
            }
            agent.poll_sources(Instant::now() + Duration::from_millis(20));
            agent.flush_logs(true);
        }
        agent.writer.close();
        let metrics = written(&server);
        assert!(metrics.contains("container_cpu_usage_seconds_total"));
        assert!(metrics.contains("container_label_com_docker_compose_service"));
        assert!(metrics.contains(&id), "no series of container {id}");
        assert!(metrics.contains("machine_memory_bytes"));
        let pushes = server.requests();
        let push = pushes.iter().find(|r| r.path == "/loki/api/v1/push");
        let body = String::from_utf8_lossy(&push.unwrap().body).into_owned();
        assert!(body.contains("hello from web"), "{body}");
        assert!(body.contains(r#""job":"docker""#), "{body}");
        assert!(agent.positions.docker.values().any(|ns| *ns > 0));
    }
}
