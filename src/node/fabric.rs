//! Fibre Channel hosts and InfiniBand ports in sysfs, as node_exporter's
//! fibrechannel and infiniband collectors give them.

use super::{Node, go_uint, invalid, sys_read, unsupported};
use crate::host;
use crate::remote::Writer;
use std::fs;
use std::io;
use std::path::Path;

const FC_INFO: [&str; 10] = [
    "speed",
    "port_state",
    "port_type",
    "port_id",
    "port_name",
    "fabric_name",
    "symbolic_name",
    "supported_classes",
    "supported_speeds",
    "dev_loss_tmo",
];

/// Attributes procfs strips the `0x` of.
const FC_HEX: [&str; 4] = ["node_name", "port_id", "port_name", "fabric_name"];

const FC_COUNTERS: [(&str, &str); 14] = [
    ("dumped_frames", "dumped_frames_total"),
    ("error_frames", "error_frames_total"),
    ("invalid_crc_count", "invalid_crc_total"),
    ("rx_frames", "rx_frames_total"),
    ("rx_words", "rx_words_total"),
    ("tx_frames", "tx_frames_total"),
    ("tx_words", "tx_words_total"),
    ("seconds_since_last_reset", "seconds_since_last_reset_total"),
    ("invalid_tx_word_count", "invalid_tx_words_total"),
    ("link_failure_count", "link_failure_total"),
    ("loss_of_sync_count", "loss_of_sync_total"),
    ("loss_of_signal_count", "loss_of_signal_total"),
    ("nos_count", "nos_total"),
    ("fcp_packet_aborts", "fcp_packet_aborts_total"),
];

pub fn fibrechannel(_: &Node, w: &mut Writer) -> io::Result<()> {
    let dir = host::path("/sys/class/fc_host");
    let mut hosts = Vec::new();
    for entry in fs::read_dir(&dir)? {
        let name = entry?.file_name().to_string_lossy().into_owned();
        let path = dir.join(&name);
        hosts.push((fc_attributes(&path, &name)?, fc_counters(&path)?));
    }
    hosts.sort_by(|a, b| a.0[0].1.cmp(&b.0[0].1));
    for (info, counters) in hosts {
        let host = info[0].1.clone();
        let labels: Vec<(&str, &str)> =
            info.iter().map(|(k, v)| (*k, v.as_str())).collect();
        w.add("node_fibrechannel_info", &labels, 1.0);
        for (metric, value) in counters {
            // All ones: the HBA does not count it.
            if value != u64::MAX {
                let metric = format!("node_fibrechannel_{metric}");
                w.add(&metric, &[("fc_host", &host)], value as f64);
            }
        }
    }
    Ok(())
}

fn fc_attributes(
    path: &Path,
    name: &str,
) -> io::Result<Vec<(&'static str, String)>> {
    let mut info = vec![("fc_host", name.to_owned())];
    for file in FC_INFO {
        let mut value = match sys_read(&path.join(file)) {
            Ok(value) => value,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        };
        if FC_HEX.contains(&file) && value.len() > 2 {
            value.drain(..2);
        }
        info.push((file, value));
    }
    Ok(info)
}

fn fc_counters(path: &Path) -> io::Result<Vec<(&'static str, u64)>> {
    let dir = path.join("statistics");
    let entries = match fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut counters = Vec::new();
    for entry in entries {
        let entry = entry?;
        let file = entry.file_name();
        let Some((_, metric)) = FC_COUNTERS.iter().find(|(f, _)| file == *f)
        else {
            continue;
        };
        if !entry.file_type()?.is_file() {
            continue;
        }
        match sys_read(&entry.path()) {
            Ok(value) => counters.push((*metric, go_uint(&value)?)),
            Err(e) if unsupported(&e) => {}
            Err(e) => return Err(e),
        }
    }
    counters.sort_by_key(|(metric, _)| {
        FC_COUNTERS.iter().position(|(_, m)| m == metric)
    });
    Ok(counters)
}

/// InfiniBand counters (`counters/`) and their names; `*_data` count
/// in 4-byte words.
const IB_COUNTERS: [(&str, &str); 22] = [
    (
        "excessive_buffer_overrun_errors",
        "excessive_buffer_overrun_errors_total",
    ),
    ("link_downed", "link_downed_total"),
    ("link_error_recovery", "link_error_recovery_total"),
    (
        "local_link_integrity_errors",
        "local_link_integrity_errors_total",
    ),
    ("multicast_rcv_packets", "multicast_packets_received_total"),
    (
        "multicast_xmit_packets",
        "multicast_packets_transmitted_total",
    ),
    (
        "port_rcv_constraint_errors",
        "port_constraint_errors_received_total",
    ),
    ("port_rcv_data", "port_data_received_bytes_total"),
    ("port_rcv_discards", "port_discards_received_total"),
    ("port_rcv_errors", "port_errors_received_total"),
    ("port_rcv_packets", "port_packets_received_total"),
    (
        "port_rcv_remote_physical_errors",
        "port_receive_remote_physical_errors_total",
    ),
    (
        "port_rcv_switch_relay_errors",
        "port_receive_switch_relay_errors_total",
    ),
    (
        "port_xmit_constraint_errors",
        "port_constraint_errors_transmitted_total",
    ),
    ("port_xmit_data", "port_data_transmitted_bytes_total"),
    ("port_xmit_discards", "port_discards_transmitted_total"),
    ("port_xmit_packets", "port_packets_transmitted_total"),
    ("port_xmit_wait", "port_transmit_wait_total"),
    ("symbol_error", "symbol_error_total"),
    ("unicast_rcv_packets", "unicast_packets_received_total"),
    ("unicast_xmit_packets", "unicast_packets_transmitted_total"),
    ("VL15_dropped", "vl15_dropped_total"),
];

/// The extended counters (`counters_ext/`), the legacy names.
const IB_EXTENDED: [(&str, &str); 8] = [
    (
        "port_multicast_rcv_packets",
        "legacy_multicast_packets_received_total",
    ),
    (
        "port_multicast_xmit_packets",
        "legacy_multicast_packets_transmitted_total",
    ),
    ("port_rcv_data_64", "legacy_data_received_bytes_total"),
    ("port_rcv_packets_64", "legacy_packets_received_total"),
    (
        "port_unicast_rcv_packets",
        "legacy_unicast_packets_received_total",
    ),
    (
        "port_unicast_xmit_packets",
        "legacy_unicast_packets_transmitted_total",
    ),
    ("port_xmit_data_64", "legacy_data_transmitted_bytes_total"),
    ("port_xmit_packets_64", "legacy_packets_transmitted_total"),
];

struct Port {
    number: String,
    state: f64,
    physical: f64,
    rate: f64,
    counters: Vec<(&'static str, f64)>,
}

pub fn infiniband(_: &Node, w: &mut Writer) -> io::Result<()> {
    let dir = host::path("/sys/class/infiniband");
    let mut devices = Vec::new();
    for entry in fs::read_dir(&dir)? {
        let name = entry?.file_name().to_string_lossy().into_owned();
        devices.push((name.clone(), ib_device(&dir.join(&name))?));
    }
    devices.sort_by(|a, b| a.0.cmp(&b.0));
    for (name, (info, ports)) in devices {
        let mut labels = vec![("device", name.as_str())];
        labels.extend(info.iter().map(|(k, v)| (*k, v.as_str())));
        w.add("node_infiniband_info", &labels, 1.0);
        for port in ports {
            let labels = [("device", name.as_str()), ("port", &port.number)];
            let gauges = [
                ("state_id", port.state),
                ("physical_state_id", port.physical),
                ("rate_bytes_per_second", port.rate),
            ];
            for (metric, value) in gauges.into_iter().chain(port.counters) {
                let metric = format!("node_infiniband_{metric}");
                w.add(&metric, &labels, value);
            }
        }
    }
    Ok(())
}

type Device = (Vec<(&'static str, String)>, Vec<Port>);

fn ib_device(path: &Path) -> io::Result<Device> {
    let mut info = vec![("firmware_version", sys_read(&path.join("fw_ver"))?)];
    for file in ["board_id", "hca_type"] {
        match sys_read(&path.join(file)) {
            Ok(value) => info.push((file, value)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    let mut ports = Vec::new();
    for entry in fs::read_dir(path.join("ports"))? {
        let number = entry?.file_name().to_string_lossy().into_owned();
        number.parse::<u32>().map_err(|_| invalid(&number))?;
        ports.push(ib_port(&path.join("ports").join(&number), number)?);
    }
    ports.sort_by_key(|p| p.number.parse::<u32>().unwrap_or(0));
    Ok((info, ports))
}

fn ib_port(path: &Path, number: String) -> io::Result<Port> {
    fs::read(path.join("link_layer"))?;
    let state = |file: &str| -> io::Result<f64> {
        let text = fs::read_to_string(path.join(file))?;
        let (id, _) = text.split_once(':').ok_or_else(|| invalid(&text))?;
        id.trim().parse::<u32>().map(f64::from).map_err(invalid)
    };
    let (state, physical) = (state("state")?, state("phys_state")?);
    let text = fs::read_to_string(path.join("rate"))?;
    let (gbits, _) = text.split_once(' ').ok_or_else(|| invalid(&text))?;
    let gbits: f32 = gbits.trim().parse().map_err(invalid)?;
    let rate = (f64::from(gbits) * 125_000_000.0) as u64 as f64;
    let mut counters = Vec::new();
    if path.join("counters").exists() {
        ib_counters(&path.join("counters"), &IB_COUNTERS, &mut counters)?;
        let extended = path.join("counters_ext");
        if extended.exists() {
            ib_counters(&extended, &IB_EXTENDED, &mut counters)?;
        }
    }
    Ok(Port {
        number,
        state,
        physical,
        rate,
        counters,
    })
}

fn ib_counters(
    dir: &Path,
    table: &[(&str, &'static str)],
    out: &mut Vec<(&'static str, f64)>,
) -> io::Result<()> {
    let mut found = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let file = entry.file_name();
        let Some(at) = table.iter().position(|(f, _)| file == *f) else {
            continue;
        };
        if !entry.file_type()?.is_file() {
            continue;
        }
        let value = match sys_read(&entry.path()) {
            Ok(value) => value,
            Err(e) if unsupported(&e) => continue,
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => continue,
            Err(e) => return Err(e),
        };
        let value = match go_uint(&value) {
            Ok(value) => value,
            Err(_) if value.contains("N/A (no PMA)") => continue,
            Err(e) => return Err(e),
        };
        let words = table[at].0.contains("_data");
        let value = if words { value.wrapping_mul(4) } else { value };
        found.push((at, value as f64));
    }
    found.sort_by_key(|(at, _)| *at);
    out.extend(found.into_iter().map(|(at, v)| (table[at].1, v)));
    Ok(())
}
