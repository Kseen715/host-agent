//! The components this agent has: each block built into the plan, its
//! exports returned for the components after it.

use super::client;
use super::compile::{
    Body, Exporter, JournalSource, ListenerTls, Otel, Plan, ScrapeJob,
    SyslogFormat, SyslogListener, export,
};
use super::value::{Capsule, Value};
use crate::charset::Charset;
use crate::files::{Compression, Files, Reading};
use crate::http::Retry;
use crate::logs::{self, Source};
use crate::loki::Loki;
use crate::relabel::Labels;
use crate::remote::{self, RemoteWrite};
use crate::targets::Targets;
use std::rc::Rc;
use std::time::Duration;

/// Where in-process exporters' targets point, as Alloy's do.
pub const INTERNAL: &str = "alloy.internal:12345";
const DOCKER_HOST: &str = "unix:///var/run/docker.sock";
const SIGNALS: [&str; 3] = ["logs", "metrics", "traces"];

pub fn build(body: &Body, plan: &mut Plan) -> Result<Value, String> {
    match body.name() {
        "prometheus.remote_write" => remote_write(body, plan),
        "prometheus.relabel" => prometheus_relabel(body, plan),
        "prometheus.scrape" => scrape(body, plan),
        "prometheus.exporter.unix" => super::unix::build(body, plan),
        "prometheus.exporter.self" => agent(body, plan),
        "prometheus.exporter.cadvisor" => cadvisor(body, plan),
        "prometheus.exporter.snmp" => super::snmp::build(body, plan),
        "discovery.relabel" => discovery_relabel(body),
        "discovery.docker" => discovery_docker(body, plan),
        "discovery.file" => discovery_file(body),
        "local.file_match" => file_match(body),
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
    body.check(&["external_labels"], &["endpoint", "wal"])?;
    if let Some(wal) = body.block("wal") {
        let attrs = [
            "truncate_frequency",
            "min_keepalive_time",
            "max_keepalive_time",
        ];
        wal.check(&attrs, &[])?;
        // Kept here in the spool, not a WAL.
        wal.tuning(&attrs, &[])?;
    }
    let external = body.labels("external_labels")?;
    let mut writes = Vec::new();
    for (index, endpoint) in body.blocks("endpoint").enumerate() {
        let mut name = body.label().to_owned();
        if index > 0 {
            name = format!("{name}-{index}");
        }
        let sink = remote_endpoint(&endpoint, &name, external.clone(), plan)?;
        plan.metrics.sinks.push(sink);
        let kind = remote::Kind::Write(plan.metrics.sinks.len() - 1);
        let mut node = metrics_at(plan, kind, Rc::from([]));
        let rules = endpoint.rules_in("write_relabel_config")?;
        if !rules.is_empty() {
            let kind = remote::Kind::Relabel(Rc::new(rules));
            node = metrics_at(plan, kind, Rc::from([node]));
        }
        writes.push(node);
    }
    if writes.is_empty() {
        return Err(body.error(body.block.pos, "needs an `endpoint`"));
    }
    let fan_out = remote::Kind::Relabel(Rc::default());
    let node = metrics_at(plan, fan_out, Rc::from(writes));
    Ok(receiver(Capsule::Metrics(node)))
}

const REMOTE_ATTRS: [&str; 8] = [
    "url",
    "name",
    "remote_timeout",
    "headers",
    "send_exemplars",
    "send_native_histograms",
    "protobuf_message",
    "round_robin_dns",
];

/// One remote_write `endpoint`. sigv4, azuread and google_iam are
/// refused: cloud sign-ins this agent lacks.
fn remote_endpoint(
    endpoint: &Body,
    name: &str,
    external: Labels,
    plan: &Plan,
) -> Result<RemoteWrite, String> {
    let own = ["queue_config", "metadata_config", "write_relabel_config"];
    endpoint.check(
        &client::with(&REMOTE_ATTRS, &client::ATTRS),
        &client::with(&own, &client::BLOCKS),
    )?;
    // Scrapes here give neither exemplars nor native histograms, and
    // the address is resolved on every connection.
    for name in [
        "send_exemplars",
        "send_native_histograms",
        "round_robin_dns",
    ] {
        endpoint.bool_or(name, false)?;
    }
    let message =
        endpoint.string_or("protobuf_message", "prometheus.WriteRequest")?;
    if message != "prometheus.WriteRequest" {
        let pos = endpoint.attr_pos("protobuf_message");
        return Err(endpoint.error(pos, "only `prometheus.WriteRequest`"));
    }
    let url = endpoint.required("url")?;
    let name = endpoint.string_or("name", name)?;
    let timeout = endpoint.duration_or("remote_timeout", "30s")?;
    let mut client = client::http(endpoint, timeout)?;
    client.headers.push_str(&endpoint_headers(endpoint)?);
    let sink = RemoteWrite::new(&url, &name, external, client, plan.print);
    let pos = endpoint.attr_pos("url");
    let mut sink =
        sink.ok_or_else(|| endpoint.error(pos, &client::unusable_url()))?;
    if let Some(queue) = endpoint.block("queue_config") {
        sink.retry = queue_config(&queue, sink.retry)?;
    }
    if let Some(metadata) = endpoint.block("metadata_config") {
        let attrs = ["send", "send_interval", "max_samples_per_send"];
        metadata.check(&attrs, &[])?;
        metadata.bool_or("send", true)?;
        metadata.tuning(&["send_interval"], &["max_samples_per_send"])?;
    }
    Ok(sink)
}

/// queue_config: its backoff and retry_on_http_429 apply; the rest
/// shapes Prometheus's shards, which this agent has not (README).
fn queue_config(queue: &Body, retry: Retry) -> Result<Retry, String> {
    let durations = ["batch_send_deadline", "sample_age_limit"];
    let numbers = [
        "capacity",
        "max_shards",
        "min_shards",
        "max_samples_per_send",
    ];
    let mut attrs = vec!["min_backoff", "max_backoff", "retry_on_http_429"];
    attrs.extend(durations.iter().chain(&numbers));
    queue.check(&attrs, &[])?;
    queue.tuning(&durations, &numbers)?;
    let given = |name: &str, default| match queue.value(name)? {
        Some(_) => queue.duration_or(name, "0s"),
        None => Ok(default),
    };
    Ok(Retry {
        min: given("min_backoff", retry.min)?,
        max: given("max_backoff", retry.max)?,
        on_429: queue.bool_or("retry_on_http_429", true)?,
    })
}

/// An endpoint's `headers`, as Prometheus checks them.
fn endpoint_headers(endpoint: &Body) -> Result<String, String> {
    let pairs = endpoint.labels("headers")?;
    if pairs
        .iter()
        .any(|(n, _)| n.eq_ignore_ascii_case("authorization"))
    {
        let message = "authorization header must be changed via the \
            basic_auth, authorization, oauth2, sigv4, azuread or google_iam \
            parameter";
        return Err(endpoint.error(endpoint.attr_pos("headers"), message));
    }
    client::headers(endpoint, "headers", pairs)
}

fn prometheus_relabel(body: &Body, plan: &mut Plan) -> Result<Value, String> {
    body.check(&["forward_to", "max_cache_size"], &["rule"])?;
    body.tuning(&[], &["max_cache_size"])?;
    let rules = Rc::new(body.rules()?);
    let to = body.receivers("forward_to", metrics_node)?;
    let kind = remote::Kind::Relabel(Rc::clone(&rules));
    let node = metrics_at(plan, kind, to);
    Ok(export(vec![
        ("receiver", Value::Capsule(Capsule::Metrics(node))),
        ("rules", Value::Capsule(Capsule::Rules(rules))),
    ]))
}

const SCRAPE_ATTRS: [&str; 10] = [
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
];

fn scrape(body: &Body, plan: &mut Plan) -> Result<Value, String> {
    let attrs = client::with(&SCRAPE_ATTRS, &client::ATTRS);
    body.check(&attrs, &client::BLOCKS)?;
    let scheme = body.string_or("scheme", "http")?;
    if scheme != "http" && scheme != "https" {
        let message = "scheme: http or https";
        return Err(body.error(body.attr_pos("scheme"), message));
    }
    if scheme == "https" {
        built(body, "tls", cfg!(feature = "tls"))?;
    }
    let interval = body.duration_or("scrape_interval", "60s")?;
    let timeout = body.duration_or("scrape_timeout", "10s")?;
    if timeout > interval {
        let message = "scrape_timeout greater than scrape_interval";
        return Err(body.error(body.block.pos, message));
    }
    let client = client::http(body, timeout)?;
    plan.scrapes.push(ScrapeJob {
        targets: body.targets("targets")?,
        to: body.receivers("forward_to", metrics_node)?,
        interval,
        job: body.string_or("job_name", body.id)?,
        honor_labels: body.bool_or("honor_labels", false)?,
        honor_timestamps: body.bool_or("honor_timestamps", true)?,
        client,
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

fn agent(body: &Body, plan: &mut Plan) -> Result<Value, String> {
    body.check(&[], &[])?;
    plan.exporters.push((body.id.to_owned(), Exporter::Agent));
    Ok(targets_value(vec![internal_target(body.id, "alloy")]))
}

/// The Docker API's socket (Docker's, or Podman's compatible one): one
/// per agent, as one engine's containers are one cAdvisor's.
fn docker_host(body: &Body, plan: &mut Plan) -> Result<(), String> {
    let host = body.string_or("host", DOCKER_HOST)?;
    let host = body.string_or("docker_host", &host)?;
    let pos = body.block.pos;
    let Some(socket) = host.strip_prefix("unix://") else {
        return Err(body.error(pos, &format!("{host}: only unix://")));
    };
    if plan.docker.as_ref().is_some_and(|s| s != socket) {
        let message = format!("{host}: one Docker host per agent");
        return Err(body.error(pos, &message));
    }
    plan.docker = Some(socket.to_owned());
    Ok(())
}

fn cadvisor(body: &Body, plan: &mut Plan) -> Result<Value, String> {
    built(body, "docker", cfg!(feature = "docker"))?;
    body.check(&["docker_host", "docker_only", "storage_duration"], &[])?;
    // Docker's containers and the root: cgroups no engine made are not
    // reported, as cAdvisor's raw factory would.
    body.only("docker_only", true, false)?;
    body.tuning(&["storage_duration"], &[])?;
    docker_host(body, plan)?;
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
    body.tuning(&["refresh_interval"], &[])?;
    docker_host(body, plan)?;
    let targets = Value::Capsule(Capsule::Targets(Targets::Docker));
    Ok(export(vec![("targets", targets)]))
}

fn discovery_file(body: &Body) -> Result<Value, String> {
    body.check(&["files", "refresh_interval"], &[])?;
    body.tuning(&["refresh_interval"], &[])?;
    let targets = Targets::Files(body.strings("files")?);
    Ok(export(vec![(
        "targets",
        Value::Capsule(Capsule::Targets(targets)),
    )]))
}

fn file_match(body: &Body) -> Result<Value, String> {
    let attrs = ["path_targets", "sync_period", "ignore_older_than"];
    body.check(&attrs, &[])?;
    body.tuning(&["sync_period"], &[])?;
    let older = match body.value("ignore_older_than")? {
        Some(_) => Some(body.duration_or("ignore_older_than", "")?),
        None => None,
    };
    let older = older.filter(|d| !d.is_zero());
    let input = Box::new(body.targets("path_targets")?);
    let targets = Targets::FileMatch(input, older);
    Ok(export(vec![(
        "targets",
        Value::Capsule(Capsule::Targets(targets)),
    )]))
}

fn loki_write(body: &Body, plan: &mut Plan) -> Result<Value, String> {
    body.check(&["external_labels", "max_streams"], &["endpoint"])?;
    // Streams are not counted here: a batch holds what came.
    body.tuning(&[], &["max_streams"])?;
    let external = body.labels("external_labels")?;
    let mut writes = Vec::new();
    for endpoint in body.blocks("endpoint") {
        let sink = loki_endpoint(&endpoint, body.label(), external.clone())?;
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

/// A size as alecthomas/units' Base2Bytes reads it: `1MiB`, `512KB`,
/// `1.5MB` (a KB is 1024 bytes), segments added up.
fn base2_bytes(text: &str) -> Option<usize> {
    const UNITS: [(&str, u32); 13] = [
        ("KiB", 1),
        ("MiB", 2),
        ("GiB", 3),
        ("TiB", 4),
        ("PiB", 5),
        ("EiB", 6),
        ("KB", 1),
        ("MB", 2),
        ("GB", 3),
        ("TB", 4),
        ("PB", 5),
        ("EB", 6),
        ("B", 0),
    ];
    let mut rest = text;
    let mut total = 0.0;
    while !rest.is_empty() {
        let digits = rest.find(|c: char| !c.is_ascii_digit() && c != '.')?;
        let number: f64 = rest[..digits].parse().ok()?;
        rest = &rest[digits..];
        let (unit, power) = UNITS.iter().find(|(u, _)| rest.starts_with(u))?;
        total += number * 1024f64.powi(*power as i32);
        rest = &rest[unit.len()..];
    }
    (!text.is_empty()).then_some(total as usize)
}

const LOKI_ATTRS: [&str; 11] = [
    "url",
    "name",
    "batch_wait",
    "batch_size",
    "remote_timeout",
    "headers",
    "min_backoff_period",
    "max_backoff_period",
    "max_backoff_retries",
    "tenant_id",
    "retry_on_http_429",
];

/// One loki.write `endpoint`. A batch is retried without end: sources
/// wait instead of lines being dropped (max_backoff_retries).
fn loki_endpoint(
    endpoint: &Body,
    name: &str,
    external: Labels,
) -> Result<Loki, String> {
    let blocks = client::with(&["queue_config"], &client::BLOCKS);
    endpoint.check(&client::with(&LOKI_ATTRS, &client::ATTRS), &blocks)?;
    endpoint.tuning(&[], &["max_backoff_retries"])?;
    if let Some(queue) = endpoint.block("queue_config") {
        let attrs = [
            "capacity",
            "min_shards",
            "drain_timeout",
            "block_on_overflow",
        ];
        queue.check(&attrs, &[])?;
        queue.tuning(&["drain_timeout"], &["min_shards"])?;
        queue.string_or("capacity", "10MiB")?;
        queue.bool_or("block_on_overflow", false)?;
    }
    let timeout = endpoint.duration_or("remote_timeout", "10s")?;
    let mut client = client::http(endpoint, timeout)?;
    let mut headers = endpoint.labels("headers")?;
    let tenant = endpoint.string_or("tenant_id", "")?;
    if !tenant.is_empty() {
        headers.retain(|(n, _)| !n.eq_ignore_ascii_case("x-scope-orgid"));
        headers.push(("X-Scope-OrgID".into(), tenant));
    }
    client
        .headers
        .push_str(&client::headers(endpoint, "headers", headers)?);
    let url = endpoint.required("url")?;
    let name = endpoint.string_or("name", name)?;
    let sink = Loki::new(&url, &name, external, client);
    let pos = endpoint.attr_pos("url");
    let mut sink =
        sink.ok_or_else(|| endpoint.error(pos, &client::unusable_url()))?;
    let given = |attr: &str, default: Duration| match endpoint.value(attr)? {
        Some(_) => endpoint.duration_or(attr, "0s"),
        None => Ok(default),
    };
    sink.wait = given("batch_wait", sink.wait)?;
    sink.retry = Retry {
        min: given("min_backoff_period", sink.retry.min)?,
        max: given("max_backoff_period", sink.retry.max)?,
        on_429: endpoint.bool_or("retry_on_http_429", true)?,
    };
    if let Some(size) = endpoint.string("batch_size")? {
        let pos = endpoint.attr_pos("batch_size");
        let bytes = base2_bytes(&size).ok_or_else(|| {
            endpoint.error(pos, &format!("`{size}`: not a size"))
        })?;
        sink.max_batch = bytes;
    }
    Ok(sink)
}

fn loki_relabel(body: &Body, plan: &mut Plan) -> Result<Value, String> {
    body.check(&["forward_to", "max_cache_size"], &["rule"])?;
    body.tuning(&[], &["max_cache_size"])?;
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
    let attrs = [
        "max_age",
        "path",
        "matches",
        "labels",
        "relabel_rules",
        "forward_to",
    ];
    body.check(&attrs, &[])?;
    let matches = body.string_or("matches", "")?;
    let matches = journal_matches(&matches)
        .map_err(|e| body.error(body.block.pos, &format!("matches: {e}")))?;
    plan.journal.push(JournalSource {
        id: body.id.to_owned(),
        max_age: body.duration_or("max_age", "7h")?,
        path: body.string("path")?.filter(|p| !p.is_empty()),
        matches,
        source: source(body)?,
    });
    Ok(export(Vec::new()))
}

/// `_SYSTEMD_UNIT=a.service PRIORITY=3`: no `+` (OR), as Alloy.
fn journal_matches(text: &str) -> Result<Vec<(String, String)>, String> {
    text.split_whitespace()
        .map(|word| match word.split_once('=') {
            Some((field, value)) if !field.is_empty() => {
                Ok((field.to_owned(), value.to_owned()))
            }
            _ => Err(format!("`{word}` is not FIELD=value")),
        })
        .collect()
}

fn file(body: &Body, plan: &mut Plan) -> Result<Value, String> {
    let attrs = ["targets", "forward_to", "tail_from_end", "encoding"];
    let blocks = ["decompression", "file_watch", "file_match"];
    body.check(&attrs, &blocks)?;
    if let Some(watch) = body.block("file_watch") {
        let attrs = ["min_poll_frequency", "max_poll_frequency"];
        watch.check(&attrs, &[])?;
        // Files are read every round, not polled on their own.
        watch.tuning(&attrs, &[])?;
    }
    let mut targets = body.targets("targets")?;
    if let Some(found) = file_match_block(body)? {
        targets = Targets::FileMatch(Box::new(targets), found);
    }
    let tail = body.bool_or("tail_from_end", false)?;
    let reading = Reading {
        charset: charset(body)?,
        compression: decompression(body)?,
    };
    plan.files
        .push(Files::new(targets, tail, reading, source(body)?));
    Ok(export(Vec::new()))
}

/// The file_match block, if enabled: its ignore_older_than.
fn file_match_block(body: &Body) -> Result<Option<Option<Duration>>, String> {
    let Some(found) = body.block("file_match") else {
        return Ok(None);
    };
    found.check(&["enabled", "sync_period", "ignore_older_than"], &[])?;
    if found.duration_or("sync_period", "10s")?.is_zero() {
        let message = "sync period must be greater than 0";
        return Err(found.error(found.attr_pos("sync_period"), message));
    }
    let older = found.duration_or("ignore_older_than", "0s")?;
    let older = (!older.is_zero()).then_some(older);
    Ok(found.bool_or("enabled", false)?.then_some(older))
}

fn charset(body: &Body) -> Result<Option<Charset>, String> {
    let name = body.string_or("encoding", "")?;
    if name.is_empty() {
        return Ok(None);
    }
    let found = Charset::named(&name).ok_or_else(|| {
        let more = match cfg!(feature = "encodings") {
            true => "",
            false => " (others: feature encodings)",
        };
        let message = format!(
            "encoding `{name}`: UTF-8, UTF-16LE, UTF-16BE, ISO-8859-1{more}"
        );
        body.error(body.attr_pos("encoding"), &message)
    })?;
    Ok(Some(found))
}

fn decompression(
    body: &Body,
) -> Result<Option<(Compression, Duration)>, String> {
    let Some(block) = body.block("decompression") else {
        return Ok(None);
    };
    block.check(&["enabled", "initial_delay", "format"], &[])?;
    let format = block.required("format")?;
    let compression = match format.as_str() {
        "gz" => Compression::Gzip,
        "z" => Compression::Zlib,
        "bz2" => Compression::Bzip2,
        other => {
            let message = format!(
                "unsupported compression format: \"{other}\" - please use \
                 one of \"gz, z, bz2\""
            );
            return Err(block.error(block.attr_pos("format"), &message));
        }
    };
    let delay = block.duration_or("initial_delay", "0s")?;
    if block.value("enabled")?.is_none() {
        return Err(block.error(block.block.pos, "`enabled` is required"));
    }
    if !block.bool_or("enabled", false)? {
        return Ok(None);
    }
    built(&block, "decompression", cfg!(feature = "decompression"))?;
    Ok(Some((compression, delay)))
}

fn docker_logs(body: &Body, plan: &mut Plan) -> Result<Value, String> {
    built(body, "docker", cfg!(feature = "docker"))?;
    body.check(
        &["host", "targets", "forward_to", "labels", "relabel_rules"],
        &[],
    )?;
    docker_host(body, plan)?;
    let targets = body.targets("targets")?;
    plan.docker_logs
        .push((body.id.to_owned(), targets, source(body)?));
    Ok(export(Vec::new()))
}

fn syslog(body: &Body, plan: &mut Plan) -> Result<Value, String> {
    built(body, "syslog", cfg!(feature = "syslog"))?;
    body.check(&["relabel_rules", "forward_to"], &["listener"])?;
    let shared = source(body)?;
    for listener in body.blocks("listener") {
        plan.syslogs.push(syslog_listener(&listener, &shared)?);
    }
    Ok(export(Vec::new()))
}

// Longer than 40 lines: Alloy's attributes, one per line.
fn syslog_listener(
    listener: &Body,
    shared: &Source,
) -> Result<SyslogListener, String> {
    let attrs = [
        "address",
        "protocol",
        "idle_timeout",
        "label_structured_data",
        "labels",
        "use_incoming_timestamp",
        "use_rfc5424_message",
        "max_message_length",
        "syslog_format",
        "rfc3164_default_to_current_year",
    ];
    listener.check(&attrs, &["tls_config", "raw_format_options"])?;
    let pos = listener.block.pos;
    let one_of = |name: &str, default: &str, values: [&str; 2]| {
        let value = listener.string_or(name, default)?;
        match values.iter().position(|v| *v == value) {
            Some(index) => Ok(index == 0),
            None => Err(listener.error(pos, &format!("{name} `{value}`"))),
        }
    };
    let length = listener.value("max_message_length")?;
    let max_message_length = match length {
        Some((Value::Number(n), _)) if n >= 1.0 => n as usize,
        Some((_, pos)) => {
            return Err(listener.error(pos, "max_message_length: a number"));
        }
        None => 8192,
    };
    let tcp = one_of("protocol", "tcp", ["tcp", "udp"])?;
    let tls = listener_tls(listener)?;
    if tls.is_some() && !tcp {
        return Err(listener.error(pos, "tls_config: TCP only"));
    }
    Ok(SyslogListener {
        address: listener.required("address")?,
        tcp,
        tls,
        format: syslog_format(listener)?,
        idle_timeout: listener.duration_or("idle_timeout", "120s")?,
        label_structured_data: listener
            .bool_or("label_structured_data", false)?,
        use_incoming_timestamp: listener
            .bool_or("use_incoming_timestamp", false)?,
        use_rfc5424_message: listener.bool_or("use_rfc5424_message", false)?,
        max_message_length,
        source: Source {
            labels: listener.labels("labels")?,
            ..shared.clone()
        },
    })
}

/// `syslog_format`, with what Alloy refuses beside each.
fn syslog_format(listener: &Body) -> Result<SyslogFormat, String> {
    let pos = listener.attr_pos("syslog_format");
    let options = listener.block("raw_format_options");
    let format = match listener.string_or("syslog_format", "rfc5424")?.as_str()
    {
        "rfc5424" => SyslogFormat::Rfc5424,
        "rfc3164" => SyslogFormat::Rfc3164,
        "raw" => {
            let nul = match &options {
                Some(options) => {
                    let name = "use_null_terminator_delimiter";
                    options.check(&[name], &[])?;
                    options.bool_or(name, false)?
                }
                None => false,
            };
            SyslogFormat::Raw { nul }
        }
        other => {
            let message = format!("syslog_format `{other}`");
            return Err(listener.error(pos, &message));
        }
    };
    let SyslogFormat::Raw { .. } = format else {
        if options.is_some() {
            let message = "raw_format_options has no effect when syslog \
                format is not \"raw\"";
            return Err(listener.error(pos, message));
        }
        return Ok(format);
    };
    for name in [
        "use_rfc5424_message",
        "rfc3164_default_to_current_year",
        "use_incoming_timestamp",
    ] {
        if listener.bool_or(name, false)? {
            let message = format!(
                "\"{name}\" has no effect when syslog format is set to \"raw\""
            );
            return Err(listener.error(listener.attr_pos(name), &message));
        }
    }
    Ok(format)
}

/// A listener's `tls_config`; its client-side settings are refused.
fn listener_tls(listener: &Body) -> Result<Option<ListenerTls>, String> {
    let Some(tls) = listener.block("tls_config") else {
        return Ok(None);
    };
    built(&tls, "tls", cfg!(feature = "tls"))?;
    let attrs = [
        "ca_pem",
        "ca_file",
        "cert_pem",
        "cert_file",
        "key_pem",
        "key_file",
        "min_version",
    ];
    tls.check(&attrs, &[])?;
    let pos = tls.block.pos;
    let pem = |name| pem(&tls, name);
    let tls13_only = match tls.string_or("min_version", "TLS12")?.as_str() {
        "TLS12" => false,
        "TLS13" => true,
        other => {
            let message = format!("min_version `{other}`: TLS12 or TLS13");
            return Err(tls.error(pos, &message));
        }
    };
    let needs = |name: &str| tls.error(pos, &format!("needs {name}"));
    Ok(Some(ListenerTls {
        cert: pem("cert")?.ok_or_else(|| needs("cert_pem or cert_file"))?,
        key: pem("key")?.ok_or_else(|| needs("key_pem or key_file"))?,
        ca: pem("ca")?,
        tls13_only,
    }))
}

/// A tls_config's `<name>_pem`, or the file `<name>_file` names.
pub fn pem(tls: &Body, name: &str) -> Result<Option<String>, String> {
    let (pem, file) = (format!("{name}_pem"), format!("{name}_file"));
    let text = tls.string(&pem)?.filter(|t| !t.is_empty());
    let path = tls.string(&file)?.filter(|p| !p.is_empty());
    if text.is_some() && path.is_some() {
        let message =
            format!("at most one of {pem} and {file} must be configured");
        return Err(tls.error(tls.block.pos, &message));
    }
    if text.is_some() {
        return Ok(text);
    }
    let Some(path) = path else {
        return Ok(None);
    };
    let text = std::fs::read_to_string(&path);
    text.map(Some)
        .map_err(|e| tls.error(tls.block.pos, &format!("{path}: {e}")))
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
    body.tuning(&["timeout"], &["send_batch_size", "send_batch_max_size"])?;
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
        forwards.extend(urls.into_iter().map(|url| (signal.clone(), url)));
    }
    plan.otlp.push((address, forwards));
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
