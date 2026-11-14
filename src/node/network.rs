//! Network devices' counters (/proc/net/dev), their sysfs attributes,
//! bonds, and the kernel's protocol counters (netstat, snmp, snmp6).

use super::{Node, absent, host_text, numbered, read};
use crate::remote::Writer;
use std::io;
use std::path::Path;

const RECEIVE: [&str; 8] = [
    "bytes",
    "packets",
    "errs",
    "drop",
    "fifo",
    "frame",
    "compressed",
    "multicast",
];
const TRANSMIT: [&str; 8] = [
    "bytes",
    "packets",
    "errs",
    "drop",
    "fifo",
    "colls",
    "carrier",
    "compressed",
];

pub fn netdev(_: &Node, w: &mut Writer) -> io::Result<()> {
    for line in host_text("/proc/net/dev")?.lines().skip(2) {
        let Some((device, counters)) = line.split_once(':') else {
            continue;
        };
        let labels = [("device", device.trim())];
        let values: Vec<f64> = counters
            .split_whitespace()
            .filter_map(|v| v.parse().ok())
            .collect();
        let names = RECEIVE.iter().map(|n| ("receive", n));
        let names = names.chain(TRANSMIT.iter().map(|n| ("transmit", n)));
        for ((way, name), value) in names.zip(values) {
            w.add(&format!("node_network_{way}_{name}_total"), &labels, value);
        }
    }
    Ok(())
}

/// Numeric attributes of /sys/class/net/<device>: decimal or `0x` hex.
const NETCLASS: [(&str, &str); 15] = [
    ("addr_assign_type", "node_network_address_assign_type"),
    ("carrier", "node_network_carrier"),
    ("carrier_changes", "node_network_carrier_changes_total"),
    ("carrier_up_count", "node_network_carrier_up_changes_total"),
    (
        "carrier_down_count",
        "node_network_carrier_down_changes_total",
    ),
    ("dev_id", "node_network_device_id"),
    ("dormant", "node_network_dormant"),
    ("flags", "node_network_flags"),
    ("ifindex", "node_network_iface_id"),
    ("iflink", "node_network_iface_link"),
    ("link_mode", "node_network_iface_link_mode"),
    ("mtu", "node_network_mtu_bytes"),
    ("name_assign_type", "node_network_name_assign_type"),
    ("netdev_group", "node_network_net_dev_group"),
    ("type", "node_network_protocol_type"),
];

pub fn netclass(_: &Node, w: &mut Writer) -> io::Result<()> {
    for (dir, device) in numbered("/sys/class/net", "") {
        if !dir.is_dir() {
            continue;
        }
        let labels = [("device", device.as_str())];
        let file = |name: &str| read(dir.join(name)).unwrap_or_default();
        let state = file("operstate");
        w.add("node_network_up", &labels, f64::from(state == "up"));
        for (name, metric) in NETCLASS {
            if let Some(value) = attribute(&dir, name) {
                w.add(metric, &labels, value);
            }
        }
        if let Some(length) = attribute(&dir, "tx_queue_len") {
            w.add("node_network_transmit_queue_length", &labels, length);
        }
        // Megabits per second; -1 (unknown) is kept, as Alloy does.
        if let Some(speed) = attribute(&dir, "speed") {
            w.add("node_network_speed_bytes", &labels, speed * 125_000.0);
        }
        let flags = attribute(&dir, "flags").unwrap_or(0.0) as u64;
        let admin = if flags & libc::IFF_UP as u64 != 0 {
            "up"
        } else {
            "down"
        };
        let (address, broadcast) = (file("address"), file("broadcast"));
        let (duplex, alias) = (file("duplex"), file("ifalias"));
        let info = [
            ("address", address.as_str()),
            ("adminstate", admin),
            ("broadcast", broadcast.as_str()),
            ("device", device.as_str()),
            ("duplex", duplex.as_str()),
            ("ifalias", alias.as_str()),
            ("operstate", state.as_str()),
        ];
        w.add("node_network_info", &info, 1.0);
    }
    Ok(())
}

fn attribute(dir: &Path, name: &str) -> Option<f64> {
    let text = read(dir.join(name))?;
    match text.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, 16).ok().map(|v| v as f64),
        None => text.parse().ok(),
    }
}

/// Bonds' enslaved interfaces, and how many of them have a link.
pub fn bonding(_: &Node, w: &mut Writer) -> io::Result<()> {
    let masters = read(crate::host::path("/sys/class/net/bonding_masters"))
        .ok_or_else(|| absent("bonding"))?;
    for master in masters.split_whitespace() {
        let dir = crate::host::path(&format!("/sys/class/net/{master}"));
        let slaves = read(dir.join("bonding/slaves")).unwrap_or_default();
        let slaves: Vec<&str> = slaves.split_whitespace().collect();
        let active = slaves
            .iter()
            .filter(|slave| {
                let mii = format!("lower_{slave}/bonding_slave/mii_status");
                read(dir.join(mii)).is_some_and(|s| s == "up")
            })
            .count();
        let labels = [("master", master)];
        w.add("node_bonding_slaves", &labels, slaves.len() as f64);
        w.add("node_bonding_active", &labels, active as f64);
    }
    Ok(())
}

pub fn netstat(node: &Node, w: &mut Writer) -> io::Result<()> {
    for file in ["/proc/net/netstat", "/proc/net/snmp"] {
        let text = host_text(file)?;
        let lines: Vec<&str> = text.lines().collect();
        for pair in lines.chunks(2) {
            let [names, values] = pair else { continue };
            let (Some((proto, names)), Some((_, values))) =
                (names.split_once(':'), values.split_once(':'))
            else {
                continue;
            };
            let fields =
                names.split_whitespace().zip(values.split_whitespace());
            for (name, value) in fields {
                add_netstat(node, w, proto, name, value);
            }
        }
    }
    let snmp6 = host_text("/proc/net/snmp6").unwrap_or_default();
    for line in snmp6.lines() {
        let mut fields = line.split_whitespace();
        let (Some(key), Some(value)) = (fields.next(), fields.next()) else {
            continue;
        };
        if let Some(six) = key.find('6') {
            add_netstat(node, w, &key[..=six], &key[six + 1..], value);
        }
    }
    Ok(())
}

fn add_netstat(
    node: &Node,
    w: &mut Writer,
    proto: &str,
    name: &str,
    value: &str,
) {
    let key = format!("{proto}_{name}");
    if node.netstat_fields.is_match(&key) {
        let value = value.parse().unwrap_or(0.0);
        w.add(&format!("node_netstat_{key}"), &[], value);
    }
}
