//! Docker containers' resources under cAdvisor's names (job
//! `cadvisor`), read from their cgroups (crate::cgroup) and, for their
//! network, from /proc of their first process (on the host's network,
//! the host's interfaces, as cAdvisor reports them); and, as cAdvisor's
//! root container `/`, this host's own cgroup.

use crate::cgroup::{Cgroup, DeviceIo, Memory, Spec, find};
use crate::docker::Container;
use crate::host;
use crate::machine;
use crate::remote::Writer;
use std::fs;

/// Interfaces cAdvisor leaves out.
const IGNORED_INTERFACES: [&str; 3] = ["lo", "veth", "docker"];

/// Values cAdvisor reports without the kernel's netlink task stats,
/// always 0 for Docker's containers; kept for the same series.
const TASK_STATES: [&str; 5] = [
    "iowaiting",
    "running",
    "sleeping",
    "stopped",
    "uninterruptible",
];

pub fn collect(w: &mut Writer, containers: &[Container], now_s: f64) {
    machine::collect(w);
    let boot = machine::boot_time();
    let root = [("id", "/")];
    let cgroup = Cgroup::root();
    resources(w, &root, &cgroup, Some(1));
    spec(w, &root, &cgroup.spec(), Some(machine::memory()));
    let io = cgroup
        .io()
        .iter()
        .map(|d| device_name(&d.numbers))
        .collect();
    machine::root_filesystems(w, io);
    for name in [
        "container_start_time_seconds",
        "container_creation_time_seconds",
    ] {
        w.add(name, &root, boot);
    }
    w.add("container_health_state", &root, -1.0);
    w.add("container_last_seen", &root, now_s);

    for container in containers {
        let pid = container.details.pid;
        let Some((id, cgroup)) = Cgroup::of(pid, &container.id) else {
            continue;
        };
        let mut labels = vec![
            ("id", id.as_str()),
            ("image", container.image.as_str()),
            ("name", container.name.as_str()),
        ];
        labels.extend(container.labels.iter().map(|(k, v)| (&**k, &**v)));
        resources(w, &labels, &cgroup, Some(pid));
        spec(w, &labels, &cgroup.spec(), None);
        let started = container.details.started_ns as f64 / 1e9;
        w.add("container_start_time_seconds", &labels, started);
        w.add(
            "container_creation_time_seconds",
            &labels,
            container.created,
        );
        w.add("container_health_state", &labels, container.health);
        w.add("container_last_seen", &labels, now_s);
    }
    w.add("container_scrape_error", &[], 0.0);
}

/// One cgroup's numbers; its network's from `net_pid`'s /proc.
fn resources(
    w: &mut Writer,
    labels: &[(&str, &str)],
    cgroup: &Cgroup,
    net_pid: Option<u32>,
) {
    cpu(w, labels, cgroup);
    memory(w, labels, &cgroup.memory());
    io(w, labels, &cgroup.io());
    for (resource, what, seconds) in cgroup.pressure() {
        let name =
            format!("container_pressure_{resource}_{what}_seconds_total");
        w.add(&name, labels, seconds);
    }
    for name in [
        "container_cpu_load_average_10s",
        "container_cpu_load_d_average_10s",
    ] {
        w.add(name, labels, 0.0);
    }
    for state in TASK_STATES {
        let mut with_state = labels.to_vec();
        with_state.push(("state", state));
        w.add("container_tasks_state", &with_state, 0.0);
    }
    if let Some(pid) = net_pid {
        network(w, labels, pid);
    }
}

fn cpu(w: &mut Writer, labels: &[(&str, &str)], cgroup: &Cgroup) {
    let cpu = cgroup.cpu();
    for (which, seconds) in &cpu.usage {
        let mut with_cpu = labels.to_vec();
        with_cpu.push(("cpu", which));
        w.add("container_cpu_usage_seconds_total", &with_cpu, *seconds);
    }
    for (name, seconds) in [
        ("container_cpu_user_seconds_total", cpu.user),
        ("container_cpu_system_seconds_total", cpu.system),
    ] {
        if let Some(seconds) = seconds {
            w.add(name, labels, seconds);
        }
    }
}

/// memory.stat's fields as cAdvisor names them.
const MEMORY_STAT: [(&str, &str); 11] = [
    ("anon", "container_memory_rss"),
    ("file", "container_memory_cache"),
    ("file_mapped", "container_memory_mapped_file"),
    ("file_dirty", "container_memory_file_dirty_bytes"),
    ("file_writeback", "container_memory_file_writeback_bytes"),
    ("active_file", "container_memory_total_active_file_bytes"),
    (
        "inactive_file",
        "container_memory_total_inactive_file_bytes",
    ),
    ("pgscan", "container_memory_pgscan_total"),
    ("pgsteal", "container_memory_pgsteal_total"),
    (
        "workingset_refault_anon",
        "container_memory_workingset_refault_anon_total",
    ),
    (
        "workingset_refault_file",
        "container_memory_workingset_refault_file_total",
    ),
];

/// The working set is usage less inactive page cache, as cAdvisor counts
/// it: what the kernel cannot drop.
fn memory(w: &mut Writer, labels: &[(&str, &str)], memory: &Memory) {
    let stat = |key| find(&memory.stat, key).unwrap_or(0.0);
    w.add("container_memory_usage_bytes", labels, memory.usage);
    let working_set = (memory.usage - stat("inactive_file")).max(0.0);
    w.add("container_memory_working_set_bytes", labels, working_set);
    for (key, name) in MEMORY_STAT {
        w.add(name, labels, stat(key));
    }
    w.add("container_memory_swap", labels, memory.swap);
    w.add("container_memory_max_usage_bytes", labels, memory.peak);
    w.add("container_memory_failcnt", labels, memory.failcnt);
    w.add("container_memory_kernel_usage", labels, memory.kernel);
    let kinds = ["pgfault", "pgmajfault"].into_iter().zip(memory.faults);
    for (kind, (own, all)) in kinds {
        for (scope, count) in [("container", own), ("hierarchy", all)] {
            let mut with = labels.to_vec();
            with.extend([("failure_type", kind), ("scope", scope)]);
            w.add("container_memory_failures_total", &with, count);
        }
    }
    w.add("container_memory_events_high_total", labels, memory.high);
    w.add("container_memory_events_max_total", labels, memory.max);
    w.add("container_oom_events_total", labels, memory.oom_kills);
}

/// Devices cAdvisor does not name share one series without `device`:
/// the first one's, as a scrape keeps the first of duplicates.
fn io(w: &mut Writer, labels: &[(&str, &str)], devices: &[DeviceIo]) {
    let mut unnamed = false;
    for device in devices {
        let name = device_name(&device.numbers);
        let mut with_device = labels.to_vec();
        with_device.push(("device", &name));
        if !name.is_empty() || !std::mem::replace(&mut unnamed, true) {
            for (metric, value) in [
                ("container_fs_reads_bytes_total", device.read_bytes),
                ("container_fs_writes_bytes_total", device.write_bytes),
                ("container_fs_reads_total", device.reads),
                ("container_fs_writes_total", device.writes),
            ] {
                w.add(metric, &with_device, value);
            }
        }
        let numbers = device.numbers.as_str();
        let (major, minor) = numbers.split_once(':').unwrap_or((numbers, ""));
        for (operation, value) in &device.by_operation {
            let mut usage = with_device.clone();
            usage.extend([
                ("major", major),
                ("minor", minor),
                ("operation", operation),
            ]);
            w.add("container_blkio_device_usage_total", &usage, *value);
        }
    }
}

/// Devices cAdvisor does not name, by sysfs name.
const UNNAMED: [&str; 3] = ["loop", "ram", "sr"];

/// `/dev/sda` for `8:0`, as cAdvisor names it: whole disks, as
/// /sys/block lists them, but loop, RAM and optical drives; and any
/// device mounted on the host. Else "".
pub fn device_name(numbers: &str) -> String {
    let path = host::path(&format!("/sys/dev/block/{numbers}/uevent"));
    let uevent = fs::read_to_string(path).unwrap_or_default();
    let field = |key| uevent.lines().find_map(|l| l.strip_prefix(key));
    let Some(name) = field("DEVNAME=") else {
        return String::new();
    };
    let disk = field("DEVTYPE=") == Some("disk")
        && !UNNAMED.iter().any(|p| name.starts_with(p));
    if disk || mounted(numbers) {
        format!("/dev/{name}")
    } else {
        String::new()
    }
}

fn mounted(numbers: &str) -> bool {
    let path = host::path("/proc/1/mountinfo");
    let mounts = fs::read_to_string(path).unwrap_or_default();
    mounts.lines().any(|l| l.split(' ').nth(2) == Some(numbers))
}

/// The root's memory limits are the machine's (`machine`: memory,
/// swap); a cgroup without the memory controller has none.
fn spec(
    w: &mut Writer,
    labels: &[(&str, &str)],
    spec: &Spec,
    machine: Option<(f64, f64)>,
) {
    w.add("container_spec_cpu_period", labels, spec.period);
    if let Some(quota) = spec.quota {
        w.add("container_spec_cpu_quota", labels, quota);
    }
    w.add("container_spec_cpu_shares", labels, spec.shares);
    let limits = match machine {
        Some((memory, swap)) => {
            let reservation = spec.memory.map_or(0.0, |(_, low, _)| low);
            Some((memory, reservation, swap))
        }
        None => spec.memory,
    };
    let Some((memory, reservation, swap)) = limits else {
        return;
    };
    w.add("container_spec_memory_limit_bytes", labels, memory);
    let name = "container_spec_memory_reservation_limit_bytes";
    w.add(name, labels, reservation);
    w.add("container_spec_memory_swap_limit_bytes", labels, swap);
}

const NETWORK: [(usize, &str); 8] = [
    (0, "container_network_receive_bytes_total"),
    (1, "container_network_receive_packets_total"),
    (2, "container_network_receive_errors_total"),
    (3, "container_network_receive_packets_dropped_total"),
    (8, "container_network_transmit_bytes_total"),
    (9, "container_network_transmit_packets_total"),
    (10, "container_network_transmit_errors_total"),
    (11, "container_network_transmit_packets_dropped_total"),
];

fn network(w: &mut Writer, labels: &[(&str, &str)], pid: u32) {
    let path = host::path(&format!("/proc/{pid}/net/dev"));
    let text = fs::read_to_string(path).unwrap_or_default();
    for line in text.lines().skip(2) {
        let Some((interface, counters)) = line.split_once(':') else {
            continue;
        };
        let interface = interface.trim();
        if IGNORED_INTERFACES.iter().any(|p| interface.starts_with(p)) {
            continue;
        }
        let values: Vec<&str> = counters.split_whitespace().collect();
        let mut with_interface = labels.to_vec();
        with_interface.push(("interface", interface));
        for (index, name) in NETWORK {
            let value = values.get(index).and_then(|v| v.parse().ok());
            w.add(name, &with_interface, value.unwrap_or(0.0));
        }
    }
}
