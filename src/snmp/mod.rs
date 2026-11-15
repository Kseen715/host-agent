//! Network devices polled over SNMP v2c, as Alloy's
//! prometheus.exporter.snmp with snmp_exporter's modules: job `snmp`,
//! the device's name in `instance` and `host`, the MIB's names for the
//! metrics and, for text, a label of the metric's name with value 1.
//! Polled in the round, one device after another.

mod ber;

use crate::config::Device;
use crate::parts::Part;
use crate::remote::Writer;
use ber::{Client, Value};
use std::collections::HashMap;
use std::time::Instant;

pub struct Snmp {
    devices: Vec<Device>,
}

impl Snmp {
    pub fn new(devices: Vec<Device>) -> Result<Snmp, String> {
        let names = devices.iter().flat_map(|d| &d.modules);
        if let Some(name) = names.into_iter().find(|n| module(n).is_none()) {
            return Err(format!("no SNMP module `{name}`"));
        }
        Ok(Snmp { devices })
    }
}

impl Part for Snmp {
    fn round(&mut self, w: &mut Writer, _now_ms: i64) {
        for device in &self.devices {
            let name = device.name.as_str();
            w.target("snmp", &[("instance", name), ("host", name)]);
            let scraped = Client::connect(&device.address, &device.community)
                .and_then(|mut client| {
                    let modules =
                        device.modules.iter().filter_map(|m| module(m));
                    modules
                        .into_iter()
                        .try_for_each(|m| scrape(w, &mut client, m))
                });
            if let Err(error) = &scraped {
                eprintln!("SNMP {name}: {error}");
            }
            w.up(scraped.is_ok());
        }
    }
}

fn module(name: &str) -> Option<&'static Module> {
    MODULES.iter().find(|m| m.name == name)
}

/// One module's walks, its metrics and snmp_exporter's numbers on them.
fn scrape(
    w: &mut Writer,
    client: &mut Client,
    module: &Module,
) -> std::io::Result<()> {
    let start = Instant::now();
    let (sent, retried) = (client.sent, client.retried);
    let mut binds = Vec::new();
    for root in module.walk {
        client.walk(root, &mut binds)?;
    }
    let labels = [("module", module.name)];
    let walked = start.elapsed().as_secs_f64();
    w.add("snmp_scrape_walk_duration_seconds", &labels, walked);
    w.add(
        "snmp_scrape_packets_sent",
        &labels,
        (client.sent - sent) as f64,
    );
    let retries = (client.retried - retried) as f64;
    w.add("snmp_scrape_packets_retried", &labels, retries);
    w.add("snmp_scrape_pdus_returned", &labels, binds.len() as f64);
    metrics(w, module, &binds);
    let seconds = start.elapsed().as_secs_f64();
    w.add("snmp_scrape_duration_seconds", &labels, seconds);
    Ok(())
}

/// Each variable as the metric it falls under, the longest match.
fn metrics(w: &mut Writer, module: &Module, binds: &[(String, Value)]) {
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
                add(w, name, &labels, *number);
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
        add(w, &name, &labels, 1.0);
    }
}

fn add(w: &mut Writer, name: &str, labels: &[(&str, String)], value: f64) {
    let labels: Vec<(&str, &str)> =
        labels.iter().map(|(k, v)| (*k, v.as_str())).collect();
    w.add(name, &labels, value);
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
