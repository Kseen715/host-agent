//! Network devices polled over SNMP v2c, as Alloy's
//! prometheus.exporter.snmp with snmp_exporter's modules: the MIB's
//! names for the metrics and, for text, a label of the metric's name
//! with value 1. Each device is polled once a scrape interval apart from
//! the scrapes, so a slow or dead one holds up nothing: a scrape sends
//! the poll that ended since the last, stamped with its own start and
//! duration, or nothing.

mod ber;
mod transport;

use crate::remote::Writer;
use ber::{Client, Value};
use std::collections::HashMap;
use std::io;
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::{Duration, Instant};

/// A network device polled over SNMP v2c.
pub struct Device {
    pub name: String,
    pub address: String,
    pub community: String,
    pub modules: Vec<String>,
}

/// A device's index and its poll.
type Polled = (usize, Poll);

pub struct Poll {
    at_ms: i64,
    took: Duration,
    samples: io::Result<Samples>,
}

pub struct Snmp {
    names: Vec<String>,
    /// Until the first scrape starts their polls.
    devices: Vec<Device>,
    polls: Option<Receiver<Polled>>,
    /// Each device's poll not yet sent.
    latest: Vec<Option<Poll>>,
    /// One round only (--print): it waits for every device's first poll.
    wait: bool,
}

impl Snmp {
    pub fn new(devices: Vec<Device>, wait: bool) -> Result<Snmp, String> {
        let names = devices.iter().flat_map(|d| &d.modules);
        if let Some(name) = names.into_iter().find(|n| module(n).is_none()) {
            return Err(format!("no SNMP module `{name}`"));
        }
        Ok(Snmp {
            names: devices.iter().map(|d| d.name.clone()).collect(),
            latest: devices.iter().map(|_| None).collect(),
            devices,
            polls: None,
            wait,
        })
    }

    /// The device's poll that ended since the last taken; polls start
    /// with the first, every `interval`.
    pub fn take(&mut self, name: &str, interval: Duration) -> Option<Poll> {
        if self.polls.is_none() {
            let (sender, polls) = mpsc::channel();
            let devices = std::mem::take(&mut self.devices);
            if let Err(error) = start(devices, interval, sender) {
                eprintln!("SNMP pollers: {error}");
            }
            self.polls = Some(polls);
        }
        let polls = self.polls.as_ref()?;
        while self.wait && self.latest.iter().any(Option::is_none) {
            let Ok((index, polled)) = polls.recv() else {
                break;
            };
            self.latest[index] = Some(polled);
        }
        while let Ok((index, polled)) = polls.try_recv() {
            self.latest[index] = Some(polled);
        }
        let index = self.names.iter().position(|n| n == name)?;
        let polled = self.latest[index].take()?;
        if let Err(error) = &polled.samples {
            eprintln!("SNMP {name}: {error}");
        }
        Some(polled)
    }
}

impl Poll {
    /// As the current target's scrape.
    pub fn write(self, w: &mut Writer) {
        w.polled(self.at_ms, self.took);
        let samples = self.samples.iter().flat_map(|s| &s.0);
        for (metric, labels, value) in samples {
            let labels: Vec<(&str, &str)> =
                labels.iter().map(|(k, v)| (*k, v.as_str())).collect();
            w.add(metric, &labels, *value);
        }
        w.up(self.samples.is_ok());
    }
}

/// Each device on a thread of its own, polled until the part is gone.
#[cfg(not(feature = "tokio"))]
fn start(
    devices: Vec<Device>,
    interval: Duration,
    sender: Sender<Polled>,
) -> io::Result<()> {
    use transport::{Blocking, block_on};
    for (index, device) in devices.into_iter().enumerate() {
        let sender = sender.clone();
        let name = format!("snmp {}", device.name);
        std::thread::Builder::new().name(name).spawn(move || {
            loop {
                let begun = Instant::now();
                let polled = block_on(poll::<Blocking>(&device));
                if sender.send((index, polled)).is_err() {
                    return;
                }
                std::thread::sleep(interval.saturating_sub(begun.elapsed()));
            }
        })?;
    }
    Ok(())
}

/// Every device a task on one thread's runtime, polled until the part
/// is gone.
#[cfg(feature = "tokio")]
fn start(
    devices: Vec<Device>,
    interval: Duration,
    sender: Sender<Polled>,
) -> io::Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let thread = std::thread::Builder::new().name("snmp".into());
    let run = move || {
        let tasks = tokio::task::LocalSet::new();
        for (index, device) in devices.into_iter().enumerate() {
            let sender = sender.clone();
            tasks.spawn_local(async move {
                loop {
                    let begun = tokio::time::Instant::now();
                    let polled = poll::<transport::Tokio>(&device).await;
                    if sender.send((index, polled)).is_err() {
                        return;
                    }
                    tokio::time::sleep_until(begun + interval).await;
                }
            });
        }
        runtime.block_on(tasks);
    };
    thread.spawn(run).map(drop)
}

async fn poll<T: transport::Transport>(device: &Device) -> Poll {
    let at_ms = crate::time::now_ms();
    let begun = Instant::now();
    let samples = walk::<T>(device).await;
    Poll {
        at_ms,
        took: begun.elapsed(),
        samples,
    }
}

/// A device's modules, walked one after another, and snmp_exporter's
/// own numbers on them.
async fn walk<T: transport::Transport>(device: &Device) -> io::Result<Samples> {
    let mut client =
        Client::<T>::connect(&device.address, &device.community).await?;
    let mut samples = Samples::default();
    for module in device.modules.iter().filter_map(|m| module(m)) {
        scrape(&mut samples, &mut client, module).await?;
    }
    exporter_metrics(&mut samples, &client);
    Ok(samples)
}

/// The exporter's own series, under snmp_exporter's names, for this
/// poll alone: Alloy's registry is new each scrape too.
fn exporter_metrics<T>(w: &mut Samples, client: &Client<T>) {
    w.add("snmp_packets_total", &[], client.sent as f64);
    w.add("snmp_packet_retries_total", &[], client.retried as f64);
    let unexpected = client.unexpected as f64;
    w.add("snmp_unexpected_pdu_type_total", &[], unexpected);
    w.add("snmp_request_in_flight", &[], 0.0);
    let mut count = 0;
    for (index, n) in client.durations.iter().enumerate() {
        count += n;
        let le = match index {
            ber::BUCKETS => "+Inf".to_owned(),
            _ => ber::bucket_bound(index).to_string(),
        };
        let name = "snmp_packet_duration_seconds_bucket";
        w.add(name, &[("le", le)], count as f64);
    }
    let sum = client.duration_sum;
    w.add("snmp_packet_duration_seconds_sum", &[], sum);
    w.add("snmp_packet_duration_seconds_count", &[], count as f64);
}

/// One poll's series: name, labels, value.
#[derive(Default)]
struct Samples(Vec<(String, Labels, f64)>);

type Labels = Vec<(&'static str, String)>;

impl Samples {
    fn add(
        &mut self,
        name: &str,
        labels: &[(&'static str, String)],
        value: f64,
    ) {
        self.0.push((name.to_owned(), labels.to_vec(), value));
    }
}

fn module(name: &str) -> Option<&'static Module> {
    MODULES.iter().find(|m| m.name == name)
}

/// One module's walks, its metrics and snmp_exporter's numbers on them.
async fn scrape<T: transport::Transport>(
    w: &mut Samples,
    client: &mut Client<T>,
    module: &Module,
) -> io::Result<()> {
    let start = Instant::now();
    let (sent, retried) = (client.sent, client.retried);
    let mut binds = Vec::new();
    for root in module.walk {
        client.walk(root, &mut binds).await?;
    }
    let labels = [("module", module.name.to_owned())];
    let walked = start.elapsed().as_secs_f64();
    w.add("snmp_scrape_walk_duration_seconds", &labels, walked);
    let sent = (client.sent - sent) as f64;
    w.add("snmp_scrape_packets_sent", &labels, sent);
    let retries = (client.retried - retried) as f64;
    w.add("snmp_scrape_packets_retried", &labels, retries);
    w.add("snmp_scrape_pdus_returned", &labels, binds.len() as f64);
    metrics(w, module, &binds);
    let seconds = start.elapsed().as_secs_f64();
    w.add("snmp_scrape_duration_seconds", &labels, seconds);
    Ok(())
}

/// Each variable as the metric it falls under, the longest match.
fn metrics(w: &mut Samples, module: &Module, binds: &[(String, Value)]) {
    let values: HashMap<&str, &Value> = binds
        .iter()
        .map(|(oid, value)| (oid.as_str(), value))
        .collect();
    for (oid, value) in binds {
        let under = |base: &&str| {
            oid.strip_prefix(*base).is_some_and(|r| r.starts_with('.'))
        };
        let metric = module.metrics.iter().filter(|(_, base, _)| under(base));
        let Some((name, base, kind)) = metric.max_by_key(|m| m.1.len()) else {
            continue;
        };
        let mut labels = index_labels(base, &oid[base.len() + 1..], &values);
        let name = match (kind, value) {
            (Kind::Number, Value::Number(number)) => {
                w.add(name, &labels, *number);
                continue;
            }
            (Kind::Number, _) => continue,
            (Kind::IfType, _) => {
                labels.push(("ifType", if_type(value)));
                format!("{name}_info")
            }
            (Kind::Text, _) => {
                labels.push((name, text(value)));
                (*name).to_owned()
            }
            (Kind::Octet, _) => {
                labels.push((name, octets(value)));
                (*name).to_owned()
            }
            (Kind::Mac, _) => {
                labels.push((name, mac(value)));
                (*name).to_owned()
            }
        };
        w.add(&name, &labels, 1.0);
    }
}

/// A table row's labels: its index, and its lookups' values.
fn index_labels(
    base: &str,
    index: &str,
    values: &HashMap<&str, &Value>,
) -> Vec<(&'static str, String)> {
    let Some(table) = TABLES.iter().find(|t| base.starts_with(t.prefix)) else {
        return Vec::new();
    };
    let mut labels = Vec::new();
    if table.keep {
        labels.push((table.label, index.to_owned()));
    }
    for (label, column) in table.lookups {
        let value = values.get(format!("{column}.{index}").as_str());
        labels.push((*label, value.map(|v| text(v)).unwrap_or_default()));
    }
    labels
}

fn text(value: &Value) -> String {
    match value {
        Value::Number(number) => number.to_string(),
        Value::Bytes(bytes) => String::from_utf8_lossy(bytes).into_owned(),
        Value::Oid(oid) => oid.clone(),
    }
}

/// An OID's dots, or bytes in hexadecimal, as snmp_exporter shows an
/// OctetString.
fn octets(value: &Value) -> String {
    match value {
        Value::Bytes(bytes) => {
            let hex: String =
                bytes.iter().map(|b| format!("{b:02X}")).collect();
            format!("0x{hex}")
        }
        other => text(other),
    }
}

/// 48 bits as XX:XX: a shorter value (a loopback's empty one) is
/// padded with zeros, as snmp_exporter does.
fn mac(value: &Value) -> String {
    match value {
        Value::Bytes(bytes) => {
            let padding = 6usize.saturating_sub(bytes.len());
            let bytes = bytes.iter().chain(std::iter::repeat_n(&0, padding));
            let hex: Vec<String> = bytes.map(|b| format!("{b:02X}")).collect();
            hex.join(":")
        }
        other => text(other),
    }
}

/// IANA's name for an interface type, or its number.
fn if_type(value: &Value) -> String {
    let Value::Number(number) = value else {
        return text(value);
    };
    let name = (*number as usize)
        .checked_sub(1)
        .and_then(|line| IF_TYPES.lines().nth(line))
        .filter(|name| !name.is_empty());
    name.map_or_else(|| number.to_string(), str::to_owned)
}

/// ifType's names, one per line from 1 (snmp_exporter's enum_values).
const IF_TYPES: &str = include_str!("if_types.txt");

/// How a variable becomes a series: Number its value, the others a
/// label (Text as it is, Octet in hexadecimal, Mac as XX:XX, IfType by
/// name in ifType_info).
enum Kind {
    Number,
    Text,
    Octet,
    Mac,
    IfType,
}
use Kind::*;

/// The rows of a table, by the prefix of its columns: the index's label
/// (kept or not) and labels looked up in other columns of the row.
struct Table {
    prefix: &'static str,
    label: &'static str,
    keep: bool,
    lookups: &'static [(&'static str, &'static str)],
}

const IF_LOOKUPS: &[(&str, &str)] = &[
    ("ifAlias", "1.3.6.1.2.1.31.1.1.1.18"),
    ("ifDescr", "1.3.6.1.2.1.2.2.1.2"),
    ("ifName", "1.3.6.1.2.1.31.1.1.1.1"),
];

const TABLES: [Table; 4] = [
    Table {
        prefix: "1.3.6.1.2.1.1.9.1.",
        label: "sysORIndex",
        keep: true,
        lookups: &[("sysORDescr", "1.3.6.1.2.1.1.9.1.3")],
    },
    Table {
        prefix: "1.3.6.1.2.1.2.2.1.",
        label: "ifIndex",
        keep: true,
        lookups: IF_LOOKUPS,
    },
    Table {
        prefix: "1.3.6.1.2.1.31.1.1.1.",
        label: "ifIndex",
        keep: true,
        lookups: IF_LOOKUPS,
    },
    Table {
        prefix: "1.3.6.1.4.1.2021.10.1.",
        label: "laIndex",
        keep: false,
        lookups: &[("laNames", "1.3.6.1.4.1.2021.10.1.2")],
    },
];

struct Module {
    name: &'static str,
    walk: &'static [&'static str],
    metrics: &'static [(&'static str, &'static str, Kind)],
}

/// snmp_exporter's modules of these names (its snmp.yml).
const MODULES: &[Module] = &[
    Module {
        name: "system",
        walk: &["1.3.6.1.2.1.1"],
        metrics: &[
            ("sysDescr", "1.3.6.1.2.1.1.1", Text),
            ("sysObjectID", "1.3.6.1.2.1.1.2", Octet),
            ("sysUpTime", "1.3.6.1.2.1.1.3", Number),
            ("sysContact", "1.3.6.1.2.1.1.4", Text),
            ("sysName", "1.3.6.1.2.1.1.5", Text),
            ("sysLocation", "1.3.6.1.2.1.1.6", Text),
            ("sysServices", "1.3.6.1.2.1.1.7", Number),
            ("sysORLastChange", "1.3.6.1.2.1.1.8", Number),
            ("sysORIndex", "1.3.6.1.2.1.1.9.1.1", Number),
            ("sysORID", "1.3.6.1.2.1.1.9.1.2", Octet),
            ("sysORDescr", "1.3.6.1.2.1.1.9.1.3", Text),
            ("sysORUpTime", "1.3.6.1.2.1.1.9.1.4", Number),
        ],
    },
    Module {
        name: "if_mib",
        walk: &["1.3.6.1.2.1.2", "1.3.6.1.2.1.31.1.1"],
        metrics: &[
            ("ifNumber", "1.3.6.1.2.1.2.1", Number),
            ("ifIndex", "1.3.6.1.2.1.2.2.1.1", Number),
            ("ifType", "1.3.6.1.2.1.2.2.1.3", IfType),
            ("ifMtu", "1.3.6.1.2.1.2.2.1.4", Number),
            ("ifSpeed", "1.3.6.1.2.1.2.2.1.5", Number),
            ("ifPhysAddress", "1.3.6.1.2.1.2.2.1.6", Mac),
            ("ifAdminStatus", "1.3.6.1.2.1.2.2.1.7", Number),
            ("ifOperStatus", "1.3.6.1.2.1.2.2.1.8", Number),
            ("ifLastChange", "1.3.6.1.2.1.2.2.1.9", Number),
            ("ifInOctets", "1.3.6.1.2.1.2.2.1.10", Number),
            ("ifInUcastPkts", "1.3.6.1.2.1.2.2.1.11", Number),
            ("ifInNUcastPkts", "1.3.6.1.2.1.2.2.1.12", Number),
            ("ifInDiscards", "1.3.6.1.2.1.2.2.1.13", Number),
            ("ifInErrors", "1.3.6.1.2.1.2.2.1.14", Number),
            ("ifInUnknownProtos", "1.3.6.1.2.1.2.2.1.15", Number),
            ("ifOutOctets", "1.3.6.1.2.1.2.2.1.16", Number),
            ("ifOutUcastPkts", "1.3.6.1.2.1.2.2.1.17", Number),
            ("ifOutNUcastPkts", "1.3.6.1.2.1.2.2.1.18", Number),
            ("ifOutDiscards", "1.3.6.1.2.1.2.2.1.19", Number),
            ("ifOutErrors", "1.3.6.1.2.1.2.2.1.20", Number),
            ("ifOutQLen", "1.3.6.1.2.1.2.2.1.21", Number),
            ("ifSpecific", "1.3.6.1.2.1.2.2.1.22", Octet),
            ("ifInMulticastPkts", "1.3.6.1.2.1.31.1.1.1.2", Number),
            ("ifInBroadcastPkts", "1.3.6.1.2.1.31.1.1.1.3", Number),
            ("ifOutMulticastPkts", "1.3.6.1.2.1.31.1.1.1.4", Number),
            ("ifOutBroadcastPkts", "1.3.6.1.2.1.31.1.1.1.5", Number),
            ("ifHCInOctets", "1.3.6.1.2.1.31.1.1.1.6", Number),
            ("ifHCInUcastPkts", "1.3.6.1.2.1.31.1.1.1.7", Number),
            ("ifHCInMulticastPkts", "1.3.6.1.2.1.31.1.1.1.8", Number),
            ("ifHCInBroadcastPkts", "1.3.6.1.2.1.31.1.1.1.9", Number),
            ("ifHCOutOctets", "1.3.6.1.2.1.31.1.1.1.10", Number),
            ("ifHCOutUcastPkts", "1.3.6.1.2.1.31.1.1.1.11", Number),
            ("ifHCOutMulticastPkts", "1.3.6.1.2.1.31.1.1.1.12", Number),
            ("ifHCOutBroadcastPkts", "1.3.6.1.2.1.31.1.1.1.13", Number),
            ("ifLinkUpDownTrapEnable", "1.3.6.1.2.1.31.1.1.1.14", Number),
            ("ifHighSpeed", "1.3.6.1.2.1.31.1.1.1.15", Number),
            ("ifPromiscuousMode", "1.3.6.1.2.1.31.1.1.1.16", Number),
            ("ifConnectorPresent", "1.3.6.1.2.1.31.1.1.1.17", Number),
            (
                "ifCounterDiscontinuityTime",
                "1.3.6.1.2.1.31.1.1.1.19",
                Number,
            ),
        ],
    },
    Module {
        name: "ucd_la_table",
        walk: &[
            "1.3.6.1.4.1.2021.10.1.2",
            "1.3.6.1.4.1.2021.10.1.5",
            "1.3.6.1.4.1.2021.10.1.6",
        ],
        metrics: &[
            ("laNames", "1.3.6.1.4.1.2021.10.1.2", Text),
            ("laLoadInt", "1.3.6.1.4.1.2021.10.1.5", Number),
            ("laLoadFloat", "1.3.6.1.4.1.2021.10.1.6", Number),
        ],
    },
    Module {
        name: "ucd_memory",
        walk: &["1.3.6.1.4.1.2021.4"],
        metrics: &[
            ("memIndex", "1.3.6.1.4.1.2021.4.1", Number),
            ("memErrorName", "1.3.6.1.4.1.2021.4.2", Text),
            ("memTotalSwap", "1.3.6.1.4.1.2021.4.3", Number),
            ("memAvailSwap", "1.3.6.1.4.1.2021.4.4", Number),
            ("memTotalReal", "1.3.6.1.4.1.2021.4.5", Number),
            ("memAvailReal", "1.3.6.1.4.1.2021.4.6", Number),
            ("memTotalSwapTXT", "1.3.6.1.4.1.2021.4.7", Number),
            ("memAvailSwapTXT", "1.3.6.1.4.1.2021.4.8", Number),
            ("memTotalRealTXT", "1.3.6.1.4.1.2021.4.9", Number),
            ("memAvailRealTXT", "1.3.6.1.4.1.2021.4.10", Number),
            ("memTotalFree", "1.3.6.1.4.1.2021.4.11", Number),
            ("memMinimumSwap", "1.3.6.1.4.1.2021.4.12", Number),
            ("memShared", "1.3.6.1.4.1.2021.4.13", Number),
            ("memBuffer", "1.3.6.1.4.1.2021.4.14", Number),
            ("memCached", "1.3.6.1.4.1.2021.4.15", Number),
            ("memUsedSwapTXT", "1.3.6.1.4.1.2021.4.16", Number),
            ("memUsedRealTXT", "1.3.6.1.4.1.2021.4.17", Number),
            ("memTotalSwapX", "1.3.6.1.4.1.2021.4.18", Number),
            ("memAvailSwapX", "1.3.6.1.4.1.2021.4.19", Number),
            ("memTotalRealX", "1.3.6.1.4.1.2021.4.20", Number),
            ("memAvailRealX", "1.3.6.1.4.1.2021.4.21", Number),
            ("memTotalFreeX", "1.3.6.1.4.1.2021.4.22", Number),
            ("memMinimumSwapX", "1.3.6.1.4.1.2021.4.23", Number),
            ("memSharedX", "1.3.6.1.4.1.2021.4.24", Number),
            ("memBufferX", "1.3.6.1.4.1.2021.4.25", Number),
            ("memCachedX", "1.3.6.1.4.1.2021.4.26", Number),
            ("memSwapError", "1.3.6.1.4.1.2021.4.100", Number),
            ("memSwapErrorMsg", "1.3.6.1.4.1.2021.4.101", Text),
        ],
    },
    Module {
        name: "ucd_system_stats",
        walk: &["1.3.6.1.4.1.2021.11"],
        metrics: &[
            ("ssIndex", "1.3.6.1.4.1.2021.11.1", Number),
            ("ssErrorName", "1.3.6.1.4.1.2021.11.2", Text),
            ("ssSwapIn", "1.3.6.1.4.1.2021.11.3", Number),
            ("ssSwapOut", "1.3.6.1.4.1.2021.11.4", Number),
            ("ssIOSent", "1.3.6.1.4.1.2021.11.5", Number),
            ("ssIOReceive", "1.3.6.1.4.1.2021.11.6", Number),
            ("ssSysInterrupts", "1.3.6.1.4.1.2021.11.7", Number),
            ("ssSysContext", "1.3.6.1.4.1.2021.11.8", Number),
            ("ssCpuUser", "1.3.6.1.4.1.2021.11.9", Number),
            ("ssCpuSystem", "1.3.6.1.4.1.2021.11.10", Number),
            ("ssCpuIdle", "1.3.6.1.4.1.2021.11.11", Number),
            ("ssCpuRawUser", "1.3.6.1.4.1.2021.11.50", Number),
            ("ssCpuRawNice", "1.3.6.1.4.1.2021.11.51", Number),
            ("ssCpuRawSystem", "1.3.6.1.4.1.2021.11.52", Number),
            ("ssCpuRawIdle", "1.3.6.1.4.1.2021.11.53", Number),
            ("ssCpuRawWait", "1.3.6.1.4.1.2021.11.54", Number),
            ("ssCpuRawKernel", "1.3.6.1.4.1.2021.11.55", Number),
            ("ssCpuRawInterrupt", "1.3.6.1.4.1.2021.11.56", Number),
            ("ssIORawSent", "1.3.6.1.4.1.2021.11.57", Number),
            ("ssIORawReceived", "1.3.6.1.4.1.2021.11.58", Number),
            ("ssRawInterrupts", "1.3.6.1.4.1.2021.11.59", Number),
            ("ssRawContexts", "1.3.6.1.4.1.2021.11.60", Number),
            ("ssCpuRawSoftIRQ", "1.3.6.1.4.1.2021.11.61", Number),
            ("ssRawSwapIn", "1.3.6.1.4.1.2021.11.62", Number),
            ("ssRawSwapOut", "1.3.6.1.4.1.2021.11.63", Number),
            ("ssCpuRawSteal", "1.3.6.1.4.1.2021.11.64", Number),
            ("ssCpuRawGuest", "1.3.6.1.4.1.2021.11.65", Number),
            ("ssCpuRawGuestNice", "1.3.6.1.4.1.2021.11.66", Number),
            ("ssCpuNumCpus", "1.3.6.1.4.1.2021.11.67", Number),
        ],
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_dead_device_holds_up_no_round() {
        let silent = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let device = Device {
            name: "dead".into(),
            address: silent.local_addr().unwrap().to_string(),
            community: "public".into(),
            modules: vec!["if_mib".into()],
        };
        let interval = Duration::from_secs(60);
        let mut snmp = Snmp::new(vec![device], false).unwrap();
        let begun = Instant::now();
        assert!(snmp.take("dead", interval).is_none());
        assert!(begun.elapsed() < Duration::from_millis(100));
        let (index, polled) = snmp.polls.as_ref().unwrap().recv().unwrap();
        assert_eq!(index, 0);
        assert!(polled.took >= Duration::from_secs(3));
        let error = polled.samples.err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }

    /// A router's two interfaces, as if_mib walks them, and a variable
    /// past the first walk's root.
    fn interfaces() -> Vec<(&'static str, Vec<u8>)> {
        use ber::tlv;
        let int = |n: u8| tlv(0x02, &[n]);
        let mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
        vec![
            ("1.3.6.1.2.1.2.1.0", int(2)),
            ("1.3.6.1.2.1.2.2.1.1.1", int(1)),
            ("1.3.6.1.2.1.2.2.1.1.2", int(2)),
            ("1.3.6.1.2.1.2.2.1.2.1", tlv(0x04, b"lo")),
            ("1.3.6.1.2.1.2.2.1.2.2", tlv(0x04, b"eth0")),
            ("1.3.6.1.2.1.2.2.1.3.1", int(24)),
            ("1.3.6.1.2.1.2.2.1.3.2", int(6)),
            ("1.3.6.1.2.1.2.2.1.6.1", tlv(0x04, b"")),
            ("1.3.6.1.2.1.2.2.1.6.2", tlv(0x04, &mac)),
            ("1.3.6.1.2.1.2.2.1.10.2", tlv(0x41, &[0x04, 0xd2])),
            ("1.3.6.1.2.1.2.2.1.22.2", tlv(0x06, &[0])),
            ("1.3.6.1.2.1.4.1.0", int(2)),
            ("1.3.6.1.2.1.31.1.1.1.1.2", tlv(0x04, b"eth0")),
            ("1.3.6.1.2.1.31.1.1.1.6.2", tlv(0x46, &[1, 0, 0, 0, 0, 0])),
            ("1.3.6.1.2.1.31.1.1.1.18.2", tlv(0x04, b"uplink")),
        ]
    }

    #[test]
    fn walks_a_device_as_snmp_exporter() {
        let device = Device {
            name: "router".into(),
            address: ber::agent(interfaces(), 1).to_string(),
            community: "public".into(),
            modules: vec!["if_mib".into()],
        };
        let mut snmp = Snmp::new(vec![device], true).unwrap();
        let polled = snmp.take("router", Duration::from_secs(60)).unwrap();
        let mut w = Writer::text();
        polled.write(&mut w);
        let text = w.into_text();
        let lo = r#"ifDescr="lo",ifIndex="1""#;
        let eth0 =
            r#"ifAlias="uplink",ifDescr="eth0",ifIndex="2",ifName="eth0""#;
        for line in [
            "ifNumber 2".to_owned(),
            format!("ifInOctets{{{eth0}}} 1234"),
            format!("ifHCInOctets{{{eth0}}} 1099511627776"),
            format!(r#"ifType_info{{{eth0},ifType="ethernetCsmacd"}} 1"#),
            format!(r#"ifSpecific{{{eth0},ifSpecific="0.0"}} 1"#),
            format!(
                r#"ifPhysAddress{{{eth0},ifPhysAddress="52:54:00:12:34:56"}} 1"#
            ),
            format!(r#"ifType_info{{{lo},ifType="softwareLoopback"}} 1"#),
            format!(
                r#"ifPhysAddress{{{lo},ifPhysAddress="00:00:00:00:00:00"}} 1"#
            ),
            r#"snmp_scrape_pdus_returned{module="if_mib"} 14"#.to_owned(),
            r#"snmp_scrape_packets_retried{module="if_mib"} 1"#.to_owned(),
            "snmp_packets_total 4".to_owned(),
            "snmp_unexpected_pdu_type_total 3".to_owned(),
            "snmp_packet_duration_seconds_count 3".to_owned(),
            "up 1".to_owned(),
        ] {
            assert!(text.lines().any(|l| l == line), "{line}\n{text}");
        }
    }

    #[test]
    fn refuses_an_unknown_module() {
        let device = Device {
            name: "router".into(),
            address: "127.0.0.1".into(),
            community: "public".into(),
            modules: vec!["if_mib".into(), "bgp".into()],
        };
        let error = Snmp::new(vec![device], false).err().unwrap();
        assert_eq!(error, "no SNMP module `bgp`");
    }

    #[test]
    fn has_snmp_exporters_buckets() {
        let bounds: Vec<String> = (0..ber::BUCKETS)
            .map(|i| ber::bucket_bound(i).to_string())
            .collect();
        assert_eq!(bounds[0], "0.0001");
        assert_eq!(bounds[7], "0.0128");
        assert_eq!(bounds[14], "1.6384");
    }
}
