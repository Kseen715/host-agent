//! Network devices' counters (/proc/net/dev), their sysfs attributes,
//! bonds, and the kernel's protocol counters (netstat, snmp, snmp6).

use super::{Node, absent, host_text, numbered, read};
use crate::remote::Writer;
use std::ffi::CStr;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
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

pub fn netdev(node: &Node, w: &mut Writer) -> io::Result<()> {
    for line in host_text("/proc/net/dev")?.lines().skip(2) {
        let Some((device, counters)) = line.split_once(':') else {
            continue;
        };
        if node.settings.netdev.skips(device.trim()) {
            continue;
        }
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
    if node.settings.netdev_address_info {
        addresses(w)?;
    }
    Ok(())
}

/// node_network_address_info: each address of this network namespace,
/// as Go's net.Interfaces lists them.
fn addresses(w: &mut Writer) -> io::Result<()> {
    for (device, address, prefix) in interface_addresses()? {
        let netmask = prefix.to_string();
        let labels = [
            ("device", device.as_str()),
            ("address", &address.to_string()),
            ("netmask", &netmask),
            ("scope", scope(address)),
        ];
        w.add("node_network_address_info", &labels, 1.0);
    }
    Ok(())
}

/// Go's scope(): link-local, interface-local, global, or none.
fn scope(ip: IpAddr) -> &'static str {
    let link_local = match ip {
        IpAddr::V4(v4) => v4.is_link_local() || v4.octets()[..3] == [224, 0, 0],
        IpAddr::V6(v6) => {
            v6.is_unicast_link_local() || v6.segments()[0] & 0xff0f == 0xff02
        }
    };
    let global = match ip {
        IpAddr::V4(v4) => {
            !(v4.is_unspecified() || v4.is_multicast() || v4.is_broadcast())
        }
        IpAddr::V6(v6) => !(v6.is_unspecified() || v6.is_multicast()),
    };
    let interface_local =
        matches!(ip, IpAddr::V6(v6) if v6.segments()[0] & 0xff0f == 0xff01);
    if ip.is_loopback() || link_local {
        "link-local"
    } else if interface_local {
        "interface-local"
    } else if global {
        "global"
    } else {
        ""
    }
}

/// getifaddrs(3)'s IPv4 and IPv6 addresses and their prefix lengths.
fn interface_addresses() -> io::Result<Vec<(String, IpAddr, u32)>> {
    let mut list: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs fills `list`, freed below.
    if unsafe { libc::getifaddrs(&mut list) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut found = Vec::new();
    let mut entry = list;
    while !entry.is_null() {
        // SAFETY: a node of the list getifaddrs returned.
        let ifa = unsafe { &*entry };
        entry = ifa.ifa_next;
        // SAFETY: the pointers are null or point to sockaddrs.
        let addresses = unsafe { (ip(ifa.ifa_addr), ip(ifa.ifa_netmask)) };
        let (Some(address), Some(mask)) = addresses else {
            continue;
        };
        // SAFETY: a NUL-terminated interface name.
        let name = unsafe { CStr::from_ptr(ifa.ifa_name) };
        let prefix = match mask {
            IpAddr::V4(m) => u32::from(m).count_ones(),
            IpAddr::V6(m) => u128::from(m).count_ones(),
        };
        found.push((name.to_string_lossy().into_owned(), address, prefix));
    }
    // SAFETY: the list getifaddrs returned, freed once.
    unsafe { libc::freeifaddrs(list) };
    Ok(found)
}

/// A sockaddr's IP address, if it is IPv4 or IPv6.
unsafe fn ip(addr: *const libc::sockaddr) -> Option<IpAddr> {
    if addr.is_null() {
        return None;
    }
    // SAFETY: the family says which sockaddr this is.
    unsafe {
        match i32::from((*addr).sa_family) {
            libc::AF_INET => {
                let v4 = &*addr.cast::<libc::sockaddr_in>();
                let bytes = v4.sin_addr.s_addr.to_ne_bytes();
                Some(IpAddr::V4(Ipv4Addr::from(bytes)))
            }
            libc::AF_INET6 => {
                let v6 = &*addr.cast::<libc::sockaddr_in6>();
                Some(IpAddr::V6(Ipv6Addr::from(v6.sin6_addr.s6_addr)))
            }
            _ => None,
        }
    }
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

pub fn netclass(node: &Node, w: &mut Writer) -> io::Result<()> {
    let s = &node.settings;
    for (dir, device) in numbered("/sys/class/net", "") {
        if !dir.is_dir() || s.netclass_ignored.is_match(&device) {
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
        // Megabits per second; -1 (unknown) is kept unless asked not to.
        let speed = attribute(&dir, "speed");
        if let Some(speed) =
            speed.filter(|v| *v >= 0.0 || !s.netclass_invalid_speed)
        {
            w.add("node_network_speed_bytes", &labels, speed * 125_000.0);
        }
        info(&dir, &device, &state, w);
    }
    Ok(())
}

fn info(dir: &Path, device: &str, state: &str, w: &mut Writer) {
    let file = |name: &str| read(dir.join(name)).unwrap_or_default();
    let flags = attribute(dir, "flags").unwrap_or(0.0) as u64;
    let admin = match flags & libc::IFF_UP as u64 {
        0 => "down",
        _ => "up",
    };
    let (address, broadcast) = (file("address"), file("broadcast"));
    let (duplex, alias) = (file("duplex"), file("ifalias"));
    let info = [
        ("address", address.as_str()),
        ("adminstate", admin),
        ("broadcast", broadcast.as_str()),
        ("device", device),
        ("duplex", duplex.as_str()),
        ("ifalias", alias.as_str()),
        ("operstate", state),
    ];
    w.add("node_network_info", &info, 1.0);
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
    if node.settings.netstat_fields.is_match(&key) {
        let value = value.parse().unwrap_or(0.0);
        w.add(&format!("node_netstat_{key}"), &[], value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Go's scope() in node_exporter, address by address.
    #[test]
    fn scopes_addresses_as_node_exporter() {
        for (address, expected) in [
            ("127.0.0.1", "link-local"),
            ("169.254.10.1", "link-local"),
            ("224.0.0.251", "link-local"),
            ("10.0.0.1", "global"),
            ("239.1.1.1", ""),
            ("255.255.255.255", ""),
            ("0.0.0.0", ""),
            ("::1", "link-local"),
            ("fe80::1", "link-local"),
            ("ff02::1", "link-local"),
            ("ff01::1", "interface-local"),
            ("2001:db8::1", "global"),
            ("ff05::2", ""),
            ("::", ""),
        ] {
            let ip: IpAddr = address.parse().unwrap();
            assert_eq!(scope(ip), expected, "{address}");
        }
    }
}
