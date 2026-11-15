//! IPVS: the virtual server table's totals and each backend's
//! connections and weight, as node_exporter's ipvs collector gives them.

use super::{Node, host_text, invalid};
use crate::remote::Writer;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const TOTALS: [&str; 5] = [
    "node_ipvs_connections_total",
    "node_ipvs_incoming_packets_total",
    "node_ipvs_outgoing_packets_total",
    "node_ipvs_incoming_bytes_total",
    "node_ipvs_outgoing_bytes_total",
];

/// A backend: its labels' values in IPVS_LABELS' order, and its active
/// and inactive connections and weight.
type Backend = ([String; 6], [f64; 3]);

pub fn collect(node: &Node, w: &mut Writer) -> io::Result<()> {
    let totals = totals(&host_text("/proc/net/ip_vs_stats")?)?;
    let backends = backends(&host_text("/proc/net/ip_vs")?)?;
    for (name, value) in TOTALS.iter().zip(totals) {
        w.add(name, &[], value);
    }
    let wanted = &node.settings.ipvs_labels;
    let chosen: Vec<usize> = super::IPVS_LABELS
        .iter()
        .enumerate()
        .filter(|(_, l)| wanted.iter().any(|w| w == *l))
        .map(|(i, _)| i)
        .collect();
    let metrics = [
        "node_ipvs_backend_connections_active",
        "node_ipvs_backend_connections_inactive",
        "node_ipvs_backend_weight",
    ];
    for (key, values) in summed(&backends, &chosen) {
        let labels: Vec<(&str, &str)> = chosen
            .iter()
            .map(|&i| super::IPVS_LABELS[i])
            .zip(key)
            .collect();
        for (metric, value) in metrics.iter().zip(values) {
            w.add(metric, &labels, value);
        }
    }
    Ok(())
}

fn totals(stats: &str) -> io::Result<[f64; 5]> {
    let line = stats.split('\n').nth(2);
    let fields: Vec<&str> = line.unwrap_or("").split_whitespace().collect();
    if stats.splitn(4, '\n').count() != 4 || fields.len() != 5 {
        return Err(invalid("ip_vs_stats corrupt"));
    }
    let mut totals = [0.0; 5];
    for (total, field) in totals.iter_mut().zip(&fields) {
        *total = u64::from_str_radix(field, 16).map_err(invalid)? as f64;
    }
    Ok(totals)
}

/// Backends that differ only in labels left out, summed.
fn summed<'a>(
    backends: &'a [Backend],
    chosen: &[usize],
) -> Vec<(Vec<&'a str>, [f64; 3])> {
    let mut sums: Vec<(Vec<&str>, [f64; 3])> = Vec::new();
    for (labels, values) in backends {
        let key: Vec<&str> =
            chosen.iter().map(|&i| labels[i].as_str()).collect();
        match sums.iter_mut().find(|(k, _)| *k == key) {
            Some((_, sum)) => {
                for (s, v) in sum.iter_mut().zip(values) {
                    *s += v;
                }
            }
            None => sums.push((key, *values)),
        }
    }
    sums
}

// procfs's parseIPVSBackendStatus, line for line.
fn backends(text: &str) -> io::Result<Vec<Backend>> {
    let mut found = Vec::new();
    let (mut proto, mut mark) = (String::new(), String::new());
    let (mut local, mut local_port) = (String::new(), 0u16);
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        match fields[..] {
            [] => {}
            ["IP", ..] | ["Prot", ..] | [_, "RemoteAddress:Port", ..] => {}
            [kind @ ("TCP" | "UDP"), address, ..] => {
                proto = kind.to_owned();
                mark.clear();
                (local, local_port) = address_port(address)?;
            }
            ["FWM", value, ..] => {
                proto = "FWM".into();
                mark = value.to_owned();
                (local, local_port) = (String::new(), 0);
            }
            ["->", remote, _, weight, active, inactive, ..] => {
                let (remote, remote_port) = address_port(remote)?;
                let number = |text: &str| -> io::Result<f64> {
                    text.parse::<u64>().map(|n| n as f64).map_err(invalid)
                };
                let labels = [
                    local.clone(),
                    local_port.to_string(),
                    remote,
                    remote_port.to_string(),
                    proto.clone(),
                    mark.clone(),
                ];
                let values =
                    [number(active)?, number(inactive)?, number(weight)?];
                found.push((labels, values));
            }
            _ => {}
        }
    }
    Ok(found)
}

/// `0A000001:0050`, or `[2001:db8::1]:0050`: the address as Go prints
/// it and the port.
fn address_port(text: &str) -> io::Result<(String, u16)> {
    let address: IpAddr = match text.len() {
        13 => {
            let bits = u32::from_str_radix(&text[..8], 16).map_err(invalid)?;
            Ipv4Addr::from(bits).into()
        }
        46 => {
            let v6: Ipv6Addr = text[1..40].parse().map_err(invalid)?;
            match v6.to_ipv4_mapped() {
                Some(v4) => v4.into(),
                None => v6.into(),
            }
        }
        _ => return Err(invalid(format!("IPVS address `{text}`"))),
    };
    let port = u16::from_str_radix(&text[text.len() - 4..], 16);
    Ok((address.to_string(), port.map_err(invalid)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_backends_as_procfs() {
        let text = "IP Virtual Server version 1.2.1 (size=4096)
Prot LocalAddress:Port Scheduler Flags
  -> RemoteAddress:Port Forward Weight ActiveConn InActConn
TCP  C0A80016:0CEA wlc
  -> C0A85216:0CEA      Tunnel  100    248        2
FWM  10001000 wlc
  -> C0A8321A:0CEA      Route   0      0          1
";
        let found = backends(text).unwrap();
        assert_eq!(found[0].0[0], "192.168.0.22");
        assert_eq!(found[0].0[1], "3306");
        assert_eq!(found[0].1, [248.0, 2.0, 100.0]);
        assert_eq!(found[1].0[4..], ["FWM".to_owned(), "10001000".into()]);
        assert_eq!(found[1].0[0], "");
    }
}
