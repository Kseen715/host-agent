//! The components this agent has: each block built into the plan, its
//! exports returned for the components after it.

use super::compile::{Body, Exporter, Otel, Plan, ScrapeJob, export};
use super::value::{Capsule, Value};
use crate::files::Files;
use crate::logs::{self, Source};
use crate::loki::Loki;
use crate::relabel::Labels;
use crate::remote::{self, RemoteWrite};
use crate::targets::Targets;
use std::rc::Rc;

/// Where in-process exporters' targets point, as Alloy's do.
pub const INTERNAL: &str = "alloy.internal:12345";
const DOCKER_HOST: &str = "unix:///var/run/docker.sock";
const SIGNALS: [&str; 3] = ["logs", "metrics", "traces"];

pub fn build(body: &Body, plan: &mut Plan) -> Result<Value, String> {
    match body.name() {
        "prometheus.remote_write" => remote_write(body, plan),
        "prometheus.relabel" => prometheus_relabel(body, plan),
        "prometheus.scrape" => scrape(body, plan),
        "prometheus.exporter.unix" => unix(body, plan),
        "prometheus.exporter.self" => agent(body, plan),
        "prometheus.exporter.cadvisor" => cadvisor(body, plan),
        "prometheus.exporter.snmp" => super::snmp::build(body, plan),
        "discovery.relabel" => discovery_relabel(body),
        "discovery.docker" => discovery_docker(body, plan),
        "discovery.file" => discovery_file(body),
        "loki.write" => loki_write(body, plan),
        "loki.relabel" => loki_relabel(body, plan),
        "loki.process" => loki_process(body, plan),
        "loki.source.journal" => journal(body, plan),
        "loki.source.file" => file(body, plan),
        "loki.source.docker" => docker_logs(body, plan),
        "loki.source.syslog" => syslog(body, plan),
        "otelcol.receiver.otlp" => otlp_receiver(body, plan),
        "otelcol.processor.batch" => otel_batch(body, plan),
        "otelcol.exporter.otlphttp" => otlp_exporter(body, plan),
        other => {
            let message =
                format!("`{other}` is not a component this agent has");
            Err(body.error(body.block.pos, &message))
        }
    }
}

/// Refuses a component whose part this build was made without.
pub fn built(body: &Body, feature: &str, present: bool) -> Result<(), String> {
    let message = format!("built without feature `{feature}`");
    present
        .then_some(())
        .ok_or_else(|| body.error(body.block.pos, &message))
}

fn metrics_node(capsule: &Capsule) -> Option<usize> {
    match capsule {
        Capsule::Metrics(node) => Some(*node),
        _ => None,
    }
}

fn logs_node(capsule: &Capsule) -> Option<usize> {
    match capsule {
        Capsule::Logs(node) => Some(*node),
        _ => None,
    }
}

fn otel_node(capsule: &Capsule) -> Option<usize> {
    match capsule {
        Capsule::Otel(node) => Some(*node),
        _ => None,
    }
}

fn metrics_at(plan: &mut Plan, kind: remote::Kind, to: Rc<[usize]>) -> usize {
    plan.metrics.nodes.push(remote::Node { kind, to });
    plan.metrics.nodes.len() - 1
}

fn logs_at(plan: &mut Plan, kind: logs::Kind, to: Rc<[usize]>) -> usize {
    plan.logs.nodes.push(logs::Node { kind, to });
    plan.logs.nodes.len() - 1
}

fn receiver(capsule: Capsule) -> Value {
    export(vec![("receiver", Value::Capsule(capsule))])
}

fn remote_write(body: &Body, plan: &mut Plan) -> Result<Value, String> {
    body.check(&["external_labels"], &["endpoint"])?;
    let external = body.labels("external_labels")?;
    let mut writes = Vec::new();
    for (index, endpoint) in body.blocks("endpoint").enumerate() {
        endpoint.check(&["url", "name"], &[])?;
        let url = endpoint.required("url")?;
        let mut name = body.label().to_owned();
        if index > 0 {
            name = format!("{name}-{index}");
        }
        let name = endpoint.string_or("name", &name)?;
        let sink = RemoteWrite::new(&url, &name, external.clone(), plan.print);
        let pos = endpoint.block.pos;
        let sink = sink.ok_or_else(|| body.error(pos, "url: only http://"))?;
        plan.metrics.sinks.push(sink);
        let kind = remote::Kind::Write(plan.metrics.sinks.len() - 1);
        writes.push(metrics_at(plan, kind, Rc::from([])));
    }
    if writes.is_empty() {
        return Err(body.error(body.block.pos, "needs an `endpoint`"));
    }
    let fan_out = remote::Kind::Relabel(Rc::default());
    let node = metrics_at(plan, fan_out, Rc::from(writes));
    Ok(receiver(Capsule::Metrics(node)))
}

fn prometheus_relabel(body: &Body, plan: &mut Plan) -> Result<Value, String> {
    body.check(&["forward_to", "max_cache_size"], &["rule"])?;
    let rules = Rc::new(body.rules()?);
    let to = body.receivers("forward_to", metrics_node)?;
    let kind = remote::Kind::Relabel(Rc::clone(&rules));
    let node = metrics_at(plan, kind, to);
    Ok(export(vec![
        ("receiver", Value::Capsule(Capsule::Metrics(node))),
        ("rules", Value::Capsule(Capsule::Rules(rules))),
    ]))
}

fn scrape(body: &Body, plan: &mut Plan) -> Result<Value, String> {
    body.check(
        &[
            "targets",
            "forward_to",
            "job_name",
            "scrape_interval",
            "scrape_timeout",
            "honor_labels",
            "honor_timestamps",
            "metrics_path",
            "scheme",
            "params",
        ],
        &[],
    )?;
    let scheme = body.string_or("scheme", "http")?;
    if scheme != "http" {
        return Err(body.error(body.block.pos, "only scheme = \"http\""));
    }
    plan.scrapes.push(ScrapeJob {
        targets: body.targets("targets")?,
        to: body.receivers("forward_to", metrics_node)?,
        interval: body.duration_or("scrape_interval", "60s")?,
        job: body.string_or("job_name", body.id)?,
        honor_labels: body.bool_or("honor_labels", false)?,
        metrics_path: body.string_or("metrics_path", "/metrics")?,
        scheme,
        params: params(body)?,
    });
    Ok(export(Vec::new()))
}

/// `params = { name = ["value", ...] }`, each value a pair.
fn params(body: &Body) -> Result<Labels, String> {
    let Some((value, pos)) = body.value("params")? else {
        return Ok(Vec::new());
    };
    let wrong = || body.error(pos, "`params` is an object of string lists");
    let Value::Object(fields) = value else {
        return Err(wrong());
    };
    let mut params = Vec::new();
    for (name, values) in fields {
        let Value::Array(values) = values else {
            return Err(wrong());
        };
        for value in values {
            let Value::String(value) = value else {
                return Err(wrong());
            };
            params.push((name.clone(), value));
        }
    }
    Ok(params)
}

/// The one target an in-process exporter exports.
pub fn internal_target(id: &str, job: &str) -> Labels {
    let path = format!("/api/v0/component/{id}/metrics");
    vec![
        ("__address__".into(), INTERNAL.into()),
        ("__metrics_path__".into(), path),
        ("instance".into(), crate::host::hostname()),
        ("job".into(), format!("integrations/{job}")),
    ]
}

pub fn targets_value(targets: Vec<Labels>) -> Value {
    let object = |target: Labels| {
        let fields = target.into_iter().map(|(k, v)| (k, Value::String(v)));
        Value::Object(fields.collect())
    };
    let targets = Value::Array(targets.into_iter().map(object).collect());
    export(vec![("targets", targets)])
}

fn unix(body: &Body, plan: &mut Plan) -> Result<Value, String> {
    body.check(
        &[
            "rootfs_path",
            "procfs_path",
            "sysfs_path",
            "enable_collectors",
            "disable_collectors",
            "set_collectors",
            "include_exporter_metrics",
        ],
        &["textfile"],
    )?;
    rootfs(body, plan)?;
    let mut settings = crate::node::Settings {
        enable: body.strings("enable_collectors")?,
        disable: body.strings("disable_collectors")?,
        set: body.value("set_collectors")?.map(|_| Vec::new()),
        textfile_dir: None,
    };
    if settings.set.is_some() {
        settings.set = Some(body.strings("set_collectors")?);
    }
    let wanted = settings.enable.iter().chain(settings.set.iter().flatten());
    if let Some(name) =
        wanted.into_iter().find(|n| !crate::node::has_collector(n))
    {
        let message = format!("no collector `{name}` in this agent");
        return Err(body.error(body.block.pos, &message));
    }
    if let Some(textfile) = body.block("textfile") {
        textfile.check(&["directory"], &[])?;
        settings.textfile_dir = textfile.string("directory")?.map(Into::into);
    }
    let node = Box::new(crate::node::Node::new(settings));
    plan.exporters
        .push((body.id.to_owned(), Exporter::Unix(node)));
    Ok(targets_value(vec![internal_target(body.id, "unix")]))
}

/// The unix exporter's rootfs_path, the agent's one root for host paths.
fn rootfs(body: &Body, plan: &mut Plan) -> Result<(), String> {
    let root = body.string_or("rootfs_path", "/")?;
    let under = |dir: &str| format!("{}/{dir}", root.trim_end_matches('/'));
    // crate::host reads /proc and /sys under the root, as it must in an
    // LXC: the paths can only be the root's.
    for (name, dir) in [("procfs_path", "proc"), ("sysfs_path", "sys")] {
        let path = body.string_or(name, &under(dir))?;
        if path != under(dir) && path != format!("/{dir}") {
            let message = format!("`{name}` other than {}", under(dir));
            return Err(body.error(body.block.pos, &message));
        }
    }
    if root != "/" {
        if plan.root.as_ref().is_some_and(|r| *r != *root) {
            return Err(body.error(body.block.pos, "a second rootfs_path"));
        }
        plan.root = Some(root.into());
    }
    Ok(())
}

fn agent(body: &Body, plan: &mut Plan) -> Result<Value, String> {
    body.check(&[], &[])?;
    plan.exporters.push((body.id.to_owned(), Exporter::Agent));
    Ok(targets_value(vec![internal_target(body.id, "alloy")]))
}

fn docker_host(body: &Body) -> Result<(), String> {
    let host = body.string_or("host", DOCKER_HOST)?;
    let host = body.string_or("docker_host", &host)?;
    if host != DOCKER_HOST {
        let message = format!("Docker only at {DOCKER_HOST}");
        return Err(body.error(body.block.pos, &message));
    }
    Ok(())
}

fn cadvisor(body: &Body, plan: &mut Plan) -> Result<Value, String> {
    built(body, "docker", cfg!(feature = "docker"))?;
    body.check(&["docker_host", "docker_only", "storage_duration"], &[])?;
    docker_host(body)?;
    plan.docker = true;
    #[cfg(feature = "docker")]
    plan.exporters
        .push((body.id.to_owned(), Exporter::Cadvisor));
    Ok(targets_value(vec![internal_target(body.id, "cadvisor")]))
}

fn discovery_relabel(body: &Body) -> Result<Value, String> {
    body.check(&["targets"], &["rule"])?;
    let rules = Rc::new(body.rules()?);
    let input = Box::new(body.targets("targets")?);
    let output = Targets::Relabel(input, Rc::clone(&rules));
    Ok(export(vec![
        ("output", Value::Capsule(Capsule::Targets(output))),
        ("rules", Value::Capsule(Capsule::Rules(rules))),
    ]))
}

fn discovery_docker(body: &Body, plan: &mut Plan) -> Result<Value, String> {
    built(body, "docker", cfg!(feature = "docker"))?;
    body.check(&["host", "refresh_interval"], &[])?;
    docker_host(body)?;
    plan.docker = true;
    let targets = Value::Capsule(Capsule::Targets(Targets::Docker));
    Ok(export(vec![("targets", targets)]))
}

fn discovery_file(body: &Body) -> Result<Value, String> {
    body.check(&["files", "refresh_interval"], &[])?;
    let targets = Targets::Files(body.strings("files")?);
    Ok(export(vec![(
        "targets",
        Value::Capsule(Capsule::Targets(targets)),
    )]))
}

fn loki_write(body: &Body, plan: &mut Plan) -> Result<Value, String> {
    body.check(&["external_labels"], &["endpoint"])?;
    let external = body.labels("external_labels")?;
    let mut writes = Vec::new();
    for endpoint in body.blocks("endpoint") {
        endpoint.check(&["url", "name"], &[])?;
        let url = endpoint.required("url")?;
        let sink = Loki::new(&url, body.label(), external.clone());
        let pos = endpoint.block.pos;
        let sink = sink.ok_or_else(|| body.error(pos, "url: only http://"))?;
        plan.logs.sinks.push(sink);
        let kind = logs::Kind::Write(plan.logs.sinks.len() - 1);
        writes.push(logs_at(plan, kind, Rc::from([])));
    }
    if writes.is_empty() {
        return Err(body.error(body.block.pos, "needs an `endpoint`"));
    }
    let fan_out = logs::Kind::Relabel(Rc::default());
    let node = logs_at(plan, fan_out, Rc::from(writes));
    Ok(receiver(Capsule::Logs(node)))
}

fn loki_relabel(body: &Body, plan: &mut Plan) -> Result<Value, String> {
    body.check(&["forward_to", "max_cache_size"], &["rule"])?;
    let rules = Rc::new(body.rules()?);
    let to = body.receivers("forward_to", logs_node)?;
    let node = logs_at(plan, logs::Kind::Relabel(Rc::clone(&rules)), to);
    Ok(export(vec![
        ("receiver", Value::Capsule(Capsule::Logs(node))),
        ("rules", Value::Capsule(Capsule::Rules(rules))),
    ]))
}

fn loki_process(body: &Body, plan: &mut Plan) -> Result<Value, String> {
    body.check(&["forward_to"], &super::process::STAGES)?;
    let stages = super::process::stages(body)?;
    let to = body.receivers("forward_to", logs_node)?;
    let node = logs_at(plan, logs::Kind::Process(stages), to);
    Ok(receiver(Capsule::Logs(node)))
}

/// A source's `labels`, `relabel_rules` and `forward_to`.
fn source(body: &Body) -> Result<Source, String> {
    Ok(Source {
        labels: body.labels("labels")?,
        rules: body.rules_attr("relabel_rules")?,
        to: body.receivers("forward_to", logs_node)?,
    })
}

fn journal(body: &Body, plan: &mut Plan) -> Result<Value, String> {
    built(body, "journal", cfg!(feature = "journal"))?;
    body.check(&["max_age", "labels", "relabel_rules", "forward_to"], &[])?;
    if plan.journal.is_some() {
        return Err(body.error(body.block.pos, "one loki.source.journal only"));
    }
    plan.journal = Some((body.duration_or("max_age", "7h")?, source(body)?));
    Ok(export(Vec::new()))
}

fn file(body: &Body, plan: &mut Plan) -> Result<Value, String> {
    body.check(&["targets", "forward_to", "tail_from_end"], &[])?;
    let targets = body.targets("targets")?;
    let tail = body.bool_or("tail_from_end", false)?;
    plan.files.push(Files::new(targets, tail, source(body)?));
    Ok(export(Vec::new()))
}

fn docker_logs(body: &Body, plan: &mut Plan) -> Result<Value, String> {
    built(body, "docker", cfg!(feature = "docker"))?;
    body.check(
        &["host", "targets", "forward_to", "labels", "relabel_rules"],
        &[],
    )?;
    docker_host(body)?;
    if plan.docker_logs.is_some() {
        return Err(body.error(body.block.pos, "one loki.source.docker only"));
    }
    plan.docker = true;
    plan.docker_logs = Some((body.targets("targets")?, source(body)?));
    Ok(export(Vec::new()))
}

fn syslog(body: &Body, plan: &mut Plan) -> Result<Value, String> {
    built(body, "syslog", cfg!(feature = "syslog"))?;
    body.check(&["relabel_rules", "forward_to"], &["listener"])?;
    let shared = source(body)?;
    for listener in body.blocks("listener") {
        let attrs = ["address", "protocol", "syslog_format", "labels"];
        listener.check(&attrs, &[])?;
        let pos = listener.block.pos;
        if listener.string_or("protocol", "tcp")? != "udp" {
            return Err(listener.error(pos, "only protocol = \"udp\""));
        }
        if listener.string_or("syslog_format", "rfc5424")? != "rfc3164" {
            return Err(listener.error(pos, "only syslog_format = \"rfc3164\""));
        }
        let source = Source {
            labels: listener.labels("labels")?,
            ..shared.clone()
        };
        plan.syslogs.push((listener.required("address")?, source));
    }
    Ok(export(Vec::new()))
}

/// An `output` block's components for each signal.
fn otel_output(body: &Body) -> Result<Vec<(String, Vec<usize>)>, String> {
    let Some(output) = body.block("output") else {
        return Ok(Vec::new());
    };
    output.check(&SIGNALS, &[])?;
    let mut signals = Vec::new();
    for signal in SIGNALS {
        let next = output.receivers(signal, otel_node)?;
        signals.push((signal.to_owned(), next.to_vec()));
    }
    Ok(signals)
}

fn otel_input(plan: &mut Plan, otel: Otel) -> Value {
    plan.otel.push(otel);
    let input = Value::Capsule(Capsule::Otel(plan.otel.len() - 1));
    export(vec![("input", input)])
}

fn otel_batch(body: &Body, plan: &mut Plan) -> Result<Value, String> {
    built(body, "otlp", cfg!(feature = "otlp"))?;
    let attrs = ["timeout", "send_batch_size", "send_batch_max_size"];
    body.check(&attrs, &["output"])?;
    let output = otel_output(body)?;
    Ok(otel_input(plan, Otel::Pass(output)))
}

fn otlp_exporter(body: &Body, plan: &mut Plan) -> Result<Value, String> {
    built(body, "otlp", cfg!(feature = "otlp"))?;
    let attrs = ["logs_endpoint", "metrics_endpoint", "traces_endpoint"];
    body.check(&attrs, &["client"])?;
    let pos = body.block.pos;
    let client = body
        .block("client")
        .ok_or(body.error(pos, "needs `client`"))?;
    client.check(&["endpoint"], &[])?;
    let base = client.required("endpoint")?;
    let mut urls = Vec::new();
    for signal in SIGNALS {
        let url = format!("{}/v1/{signal}", base.trim_end_matches('/'));
        let url = body.string_or(&format!("{signal}_endpoint"), &url)?;
        if !url.starts_with("http://") {
            return Err(body.error(pos, &format!("{url}: only http://")));
        }
        urls.push((signal.to_owned(), url));
    }
    Ok(otel_input(plan, Otel::Export(urls)))
}

fn otlp_receiver(body: &Body, plan: &mut Plan) -> Result<Value, String> {
    built(body, "otlp", cfg!(feature = "otlp"))?;
    body.check(&[], &["http", "output"])?;
    let pos = body.block.pos;
    let http = body.block("http").ok_or(body.error(pos, "needs `http`"))?;
    http.check(&["endpoint"], &[])?;
    let address = http.string_or("endpoint", "0.0.0.0:4318")?;
    let mut forwards = Vec::new();
    for (signal, next) in otel_output(body)? {
        let mut urls = Vec::new();
        ends(&plan.otel, &signal, &next, &mut urls);
        if urls.len() > 1 {
            let message = format!("{signal} to more than one exporter");
            return Err(body.error(pos, &message));
        }
        forwards.extend(urls.into_iter().map(|url| (signal.clone(), url)));
    }
    if plan.otlp.is_some() {
        return Err(body.error(pos, "one otelcol.receiver.otlp only"));
    }
    plan.otlp = Some((address, forwards));
    Ok(export(Vec::new()))
}

/// The URLs a signal reaches from these components.
fn ends(otel: &[Otel], signal: &str, next: &[usize], urls: &mut Vec<String>) {
    for &node in next {
        match &otel[node] {
            Otel::Export(by_signal) => urls.extend(
                by_signal
                    .iter()
                    .filter(|(s, _)| s == signal)
                    .map(|(_, u)| u.clone()),
            ),
            Otel::Pass(outputs) => {
                for (s, after) in outputs.iter().filter(|(s, _)| s == signal) {
                    ends(otel, s, after, urls);
                }
            }
        }
    }
}
