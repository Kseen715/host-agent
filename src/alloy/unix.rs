//! prometheus.exporter.unix: its attributes and each collector's block,
//! into crate::node's settings. Blocks of collectors this agent lacks
//! (ethtool, ntp, perf, runit, supervisord, sysctl) are accepted, as
//! Alloy accepts them, and apply to nothing: those collectors cannot
//! be enabled here.

use super::compile::{Body, Exporter, Plan};
use super::components::{internal_target, targets_value};
use super::syntax::Block;
use super::value::Value;
use crate::node::{self, Filter, Settings};
use regex_lite::Regex;

const ATTRS: [&str; 8] = [
    "rootfs_path",
    "procfs_path",
    "sysfs_path",
    "udev_data_path",
    "enable_collectors",
    "disable_collectors",
    "set_collectors",
    "include_exporter_metrics",
];

/// Each block and its attributes, as Alloy's Arguments has them.
const BLOCKS: [(&str, &[&str]); 21] = [
    ("arp", &["device_exclude", "device_include", "netlink"]),
    ("bcache", &["priority_stats"]),
    ("cpu", &["bugs_include", "guest", "info", "flags_include"]),
    ("disk", &["device_exclude", "device_include"]),
    (
        "ethtool",
        &["device_exclude", "device_include", "metrics_include"],
    ),
    (
        "filesystem",
        &["fs_types_exclude", "mount_points_exclude", "mount_timeout"],
    ),
    ("hwmon", &["chip_exclude", "chip_include"]),
    ("ipvs", &["backend_labels"]),
    (
        "ntp",
        &[
            "ip_ttl",
            "local_offset_tolerance",
            "max_distance",
            "protocol_version",
            "server",
            "server_is_local",
        ],
    ),
    (
        "netclass",
        &["ignore_invalid_speed_device", "ignored_devices"],
    ),
    (
        "netdev",
        &["address_info", "device_exclude", "device_include"],
    ),
    ("netstat", &["fields"]),
    (
        "perf",
        &[
            "cpus",
            "tracepoint",
            "disable_hardware_profilers",
            "disable_software_profilers",
            "disable_cache_profilers",
            "hardware_profilers",
            "software_profilers",
            "cache_profilers",
        ],
    ),
    ("powersupply", &["ignored_supplies"]),
    ("runit", &["service_dir"]),
    ("supervisord", &["url"]),
    ("sysctl", &["include", "include_info"]),
    (
        "systemd",
        &[
            "enable_restarts",
            "start_time",
            "task_metrics",
            "unit_exclude",
            "unit_include",
        ],
    ),
    ("tapestats", &["ignored_devices"]),
    ("textfile", &["directory"]),
    ("vmstat", &["fields"]),
];

pub fn build(body: &Body, plan: &mut Plan) -> Result<Value, String> {
    let names: Vec<&str> = BLOCKS.iter().map(|(name, _)| *name).collect();
    body.check(&ATTRS, &names)?;
    for (name, attrs) in BLOCKS {
        if let Some(block) = body.block(name) {
            block.check(attrs, &[])?;
            for attr in attrs {
                block.value(attr)?;
            }
        }
    }
    // The agent has no exporter of its own to report on.
    body.only("include_exporter_metrics", false, false)?;
    let mut settings = collectors(body)?;
    settings.sysfs = rootfs(body, plan)?;
    settings.udev_data = body.string_or("udev_data_path", "/run/udev/data")?;
    blocks(body, &mut settings)?;
    let node = Box::new(node::Node::new(settings));
    plan.exporters
        .push((body.id.to_owned(), Exporter::Unix(node)));
    Ok(targets_value(vec![internal_target(body.id, "unix")]))
}

fn collectors(body: &Body) -> Result<Settings, String> {
    let mut settings = Settings {
        enable: body.strings("enable_collectors")?,
        disable: body.strings("disable_collectors")?,
        ..Settings::default()
    };
    if body.value("set_collectors")?.is_some() {
        settings.set = Some(body.strings("set_collectors")?);
    }
    let wanted = settings.enable.iter().chain(settings.set.iter().flatten());
    if let Some(name) = wanted.into_iter().find(|n| !node::has_collector(n)) {
        let message = format!("no collector `{name}` in this agent");
        return Err(body.error(body.block.pos, &message));
    }
    Ok(settings)
}

/// The unix exporter's rootfs_path, the agent's one root for host paths;
/// the sysfs path the labels name.
fn rootfs(body: &Body, plan: &mut Plan) -> Result<String, String> {
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
    body.string_or("sysfs_path", "/sys")
}

/// Each block's settings over Alloy's defaults. One statement per
/// setting: longer than 40 lines, as the list is read whole.
fn blocks(body: &Body, s: &mut Settings) -> Result<(), String> {
    let empty = Block {
        name: String::new(),
        label: None,
        body: Vec::new(),
        pos: body.block.pos,
    };
    let block = |name: &str| body.block_or(name, &empty);
    let arp = block("arp");
    // Netlink lists the same neighbour table /proc/net/arp shows.
    arp.bool_or("netlink", false)?;
    s.arp = filter(&arp, "device")?;
    s.bcache_priority_stats =
        block("bcache").bool_or("priority_stats", false)?;
    let cpu = block("cpu");
    s.cpu.guest = cpu.bool_or("guest", false)?;
    s.cpu.flags_include = optional(&cpu, "flags_include")?;
    s.cpu.bugs_include = optional(&cpu, "bugs_include")?;
    // node_exporter turns info on for either.
    let either = s.cpu.flags_include.is_some() || s.cpu.bugs_include.is_some();
    s.cpu.info = cpu.bool_or("info", false)? || either;
    if s.cpu.info && !node::cpuinfo_known() {
        let message = "cpu info: /proc/cpuinfo of this architecture";
        return Err(cpu.error(cpu.block.pos, message));
    }
    let disk = block("disk");
    s.disk = match optional(&disk, "device_include")? {
        Some(include) => Filter {
            exclude: None,
            include: Some(include),
        },
        None => Filter {
            exclude: pattern(&disk, "device_exclude", node::DISK_EXCLUDE)?,
            include: None,
        },
    };
    let fs = block("filesystem");
    // statfs is not timed out here: a hung mount holds the round.
    fs.duration_or("mount_timeout", "5s")?;
    s.fs_mount_points =
        required(&fs, "mount_points_exclude", node::FS_MOUNT_POINTS)?;
    s.fs_types = required(&fs, "fs_types_exclude", node::FS_TYPES)?;
    s.hwmon = filter(&block("hwmon"), "chip")?;
    s.ipvs_labels = ipvs_labels(&block("ipvs"))?;
    let netclass = block("netclass");
    s.netclass_ignored = required(&netclass, "ignored_devices", "^$")?;
    s.netclass_invalid_speed =
        netclass.bool_or("ignore_invalid_speed_device", false)?;
    let netdev = block("netdev");
    s.netdev = filter(&netdev, "device")?;
    if s.netdev.include.is_some() && s.netdev.exclude.is_some() {
        let message = "device_exclude and device_include: one or the other";
        return Err(netdev.error(netdev.block.pos, message));
    }
    s.netdev_address_info = netdev.bool_or("address_info", false)?;
    s.netstat_fields =
        required(&block("netstat"), "fields", node::NETSTAT_FIELDS)?;
    s.power_supplies_ignored =
        required(&block("powersupply"), "ignored_supplies", "^$")?;
    let systemd = block("systemd");
    let anchored = |name: &str, default: &str| -> Result<Regex, String> {
        let text = systemd.string_or(name, default)?;
        compile(&systemd, &format!("^(?:{text})$"))
    };
    s.systemd.include = anchored("unit_include", ".+")?;
    s.systemd.exclude = anchored("unit_exclude", node::SYSTEMD_UNIT_EXCLUDE)?;
    s.systemd.restarts = systemd.bool_or("enable_restarts", false)?;
    s.systemd.start_time = systemd.bool_or("start_time", false)?;
    s.systemd.tasks = systemd.bool_or("task_metrics", false)?;
    s.tapes_ignored = required(&block("tapestats"), "ignored_devices", "^$")?;
    s.textfile_dir = block("textfile").string("directory")?.map(Into::into);
    s.vmstat_fields =
        required(&block("vmstat"), "fields", node::VMSTAT_FIELDS)?;
    Ok(())
}

fn compile(body: &Body, text: &str) -> Result<Regex, String> {
    Regex::new(text).map_err(|e| body.error(body.block.pos, &e.to_string()))
}

/// A pattern always applied; an empty one matches everything, as Go's.
fn required(body: &Body, name: &str, default: &str) -> Result<Regex, String> {
    compile(body, &body.string_or(name, default)?)
}

/// A pattern applied only when not empty.
fn pattern(
    body: &Body,
    name: &str,
    default: &str,
) -> Result<Option<Regex>, String> {
    let text = body.string_or(name, default)?;
    (!text.is_empty()).then(|| compile(body, &text)).transpose()
}

fn optional(body: &Body, name: &str) -> Result<Option<Regex>, String> {
    pattern(body, name, "")
}

/// `<what>_exclude` and `<what>_include`, as node_exporter's filter.
fn filter(body: &Body, what: &str) -> Result<Filter, String> {
    Ok(Filter {
        exclude: optional(body, &format!("{what}_exclude"))?,
        include: optional(body, &format!("{what}_include"))?,
    })
}

/// The backend labels asked for, in node_exporter's order; none asked
/// for, all of them.
fn ipvs_labels(body: &Body) -> Result<Vec<String>, String> {
    let asked = body.strings("backend_labels")?;
    let asked: Vec<String> =
        asked.into_iter().filter(|l| !l.is_empty()).collect();
    if let Some(unknown) = asked
        .iter()
        .find(|l| !node::IPVS_LABELS.contains(&l.as_str()))
    {
        let message = format!("unknown IPVS backend label `{unknown}`");
        return Err(body.error(body.block.pos, &message));
    }
    let all = node::IPVS_LABELS.iter().map(|l| (*l).to_owned());
    Ok(all
        .filter(|l| asked.is_empty() || asked.contains(l))
        .collect())
}
