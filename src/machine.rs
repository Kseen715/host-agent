//! What cAdvisor reports of the machine (job `cadvisor`): its CPUs,
//! memory and memory modules, and the file systems its root container
//! `/` sees, under cAdvisor's names and its rules for picking them.

use crate::host;
use crate::remote::Writer;
use std::collections::BTreeMap;
use std::fs;

pub fn collect(w: &mut Writer) {
    let text =
        |path: &str| fs::read_to_string(host::path(path)).unwrap_or_default();
    let machine_id = text("/etc/machine-id");
    let machine_id = machine_id.trim();
    let uuid = text("/sys/class/dmi/id/product_uuid");
    let uuid = Some(uuid.trim())
        .filter(|u| !u.is_empty())
        .unwrap_or(machine_id);
    let boot_id = text("/proc/sys/kernel/random/boot_id");
    let ids = [
        ("boot_id", boot_id.trim()),
        ("machine_id", machine_id),
        ("system_uuid", uuid),
    ];
    cpus(w, &ids, &text("/proc/cpuinfo"));
    let (memory, swap) = memory();
    w.add("machine_memory_bytes", &ids, memory);
    w.add("machine_swap_bytes", &ids, swap);
    dimms(w, &ids);
    w.add("machine_nvm_avg_power_budget_watts", &ids, 0.0);
    for mode in ["app_direct_mode", "memory_mode"] {
        let mut with_mode = ids.to_vec();
        with_mode.push(("mode", mode));
        w.add("machine_nvm_capacity", &with_mode, 0.0);
    }
    w.add("machine_scrape_error", &[], 0.0);
    let os = text("/etc/os-release");
    let pretty = os.lines().find_map(|l| l.strip_prefix("PRETTY_NAME="));
    let kernel = text("/proc/sys/kernel/osrelease");
    let version = [
        ("kernelVersion", kernel.trim()),
        ("osVersion", pretty.unwrap_or("").trim_matches('"')),
    ];
    w.add("cadvisor_version_info", &version, 1.0);
}

/// Logical CPUs, and distinct cores and sockets: /proc/cpuinfo's `core
/// id` and `physical id` where it has them (x86), else sysfs's
/// topology.
fn cpus(w: &mut Writer, ids: &[(&str, &str)], cpuinfo: &str) {
    let field = |key: &str| -> Vec<&str> {
        let mut values: Vec<&str> = cpuinfo
            .lines()
            .filter_map(|l| l.split_once(':'))
            .filter(|(k, _)| k.trim() == key)
            .map(|(_, v)| v.trim())
            .collect();
        values.sort_unstable();
        values.dedup();
        values
    };
    let processors = field("processor");
    let topology = |file: &str| -> usize {
        let mut values: Vec<String> = processors
            .iter()
            .filter_map(|cpu| {
                let path =
                    format!("/sys/devices/system/cpu/cpu{cpu}/topology/{file}");
                fs::read_to_string(host::path(&path)).ok()
            })
            .collect();
        values.sort_unstable();
        values.dedup();
        values.len()
    };
    let count = |key: &str, file: &str| match field(key).len() {
        0 => topology(file),
        n => n,
    };
    let cores = count("core id", "core_id");
    let sockets = count("physical id", "physical_package_id");
    w.add("machine_cpu_cores", ids, processors.len() as f64);
    w.add("machine_cpu_physical_cores", ids, cores as f64);
    w.add("machine_cpu_sockets", ids, sockets as f64);
    w.add("machine_cpu_books", ids, topology("book_id") as f64);
    w.add("machine_cpu_drawers", ids, topology("drawer_id") as f64);
}

/// Memory modules by type, as the EDAC driver lists them.
fn dimms(w: &mut Writer, ids: &[(&str, &str)]) {
    let mut types: BTreeMap<String, (f64, f64)> = BTreeMap::new();
    let controllers = host::path("/sys/devices/system/edac/mc");
    let controllers = fs::read_dir(controllers).into_iter().flatten().flatten();
    for controller in controllers {
        for dimm in fs::read_dir(controller.path()).into_iter().flatten() {
            let Ok(dimm) = dimm else { continue };
            if !dimm.file_name().to_string_lossy().starts_with("dimm") {
                continue;
            }
            let read = |file| fs::read_to_string(dimm.path().join(file));
            let (Ok(kind), Ok(size)) = (read("dimm_mem_type"), read("size"))
            else {
                continue;
            };
            let mib: f64 = size.trim().parse().unwrap_or(0.0);
            let entry = types.entry(kind.trim().to_owned()).or_default();
            entry.0 += 1.0;
            entry.1 += mib * 1024.0 * 1024.0;
        }
    }
    for (kind, (count, bytes)) in &types {
        let mut with_type = ids.to_vec();
        with_type.push(("type", kind));
        w.add("machine_dimm_count", &with_type, *count);
        w.add("machine_dimm_capacity_bytes", &with_type, *bytes);
    }
}

/// Memory and swap in bytes, as /proc/meminfo has them (in an LXC,
/// lxcfs gives the guest's).
pub fn memory() -> (f64, f64) {
    let path = host::path("/proc/meminfo");
    let meminfo = fs::read_to_string(path).unwrap_or_default();
    let kib = |key: &str| {
        let line = meminfo.lines().find(|l| l.starts_with(key));
        let value = line.and_then(|l| l.split_whitespace().nth(1));
        value.and_then(|v| v.parse::<f64>().ok()).unwrap_or(0.0) * 1024.0
    };
    (kib("MemTotal:"), kib("SwapTotal:"))
}

/// File system types cAdvisor's plugins take, besides ext* and nfs*.
const FS_TYPES: [&str; 18] = [
    "btrfs", "exfat", "f2fs", "fat", "hfs", "hfsplus", "iso9660", "jfs",
    "msdos", "ntfs", "overlay", "reiserfs", "squashfs", "tmpfs", "udf", "vfat",
    "xfs", "zfs",
];

/// /proc/diskstats fields after the name, as container_fs_* of the
/// partition: name, and scale (milliseconds to seconds).
const DISK: [(usize, &str, f64); 11] = [
    (0, "container_fs_reads_total", 1.0),
    (1, "container_fs_reads_merged_total", 1.0),
    (2, "container_fs_sector_reads_total", 1.0),
    (3, "container_fs_read_seconds_total", 0.001),
    (4, "container_fs_writes_total", 1.0),
    (5, "container_fs_writes_merged_total", 1.0),
    (6, "container_fs_sector_writes_total", 1.0),
    (7, "container_fs_write_seconds_total", 0.001),
    (8, "container_fs_io_current", 1.0),
    (9, "container_fs_io_time_seconds_total", 0.001),
    (10, "container_fs_io_time_weighted_seconds_total", 0.001),
];

/// The root container's file systems: one per mount source (a tmpfs by
/// its mount point, an overlay by its device numbers), with usage and
/// the partition's I/O counters. Devices the cgroup's I/O already
/// named (`io_devices`) keep those (one series each).
pub fn root_filesystems(w: &mut Writer, io_devices: Vec<String>) {
    let diskstats =
        fs::read_to_string(host::path("/proc/diskstats")).unwrap_or_default();
    for (source, numbers, point) in partitions() {
        let labels = [("device", source.as_str()), ("id", "/")];
        let Some(stats) = host::statvfs(&point) else {
            continue;
        };
        let block = stats.f_frsize as f64;
        let total = stats.f_blocks as f64 * block;
        let used = total - stats.f_bfree as f64 * block;
        w.add("container_fs_limit_bytes", &labels, total);
        w.add("container_fs_usage_bytes", &labels, used);
        w.add("container_fs_inodes_total", &labels, stats.f_files as f64);
        w.add("container_fs_inodes_free", &labels, stats.f_ffree as f64);
        let fields = diskstats.lines().find_map(|line| {
            let mut fields = line.split_whitespace();
            let found = format!("{}:{}", fields.next()?, fields.next()?);
            (found == numbers).then(|| fields.skip(1).collect::<Vec<_>>())
        });
        let fields = fields.unwrap_or_default();
        let named = io_devices.contains(&source);
        for (index, name, scale) in DISK {
            let from_io =
                ["container_fs_reads_total", "container_fs_writes_total"];
            if named && from_io.contains(&name) {
                continue;
            }
            let value: f64 = fields
                .get(index)
                .and_then(|v| v.parse().ok())
                .unwrap_or(0.0);
            w.add(name, &labels, value * scale);
        }
    }
}

/// Mounts of PID 1's namespace cAdvisor counts: source, `major:minor`,
/// mount point; the first mount of a source wins.
fn partitions() -> Vec<(String, String, String)> {
    let path = host::path("/proc/1/mountinfo");
    let text = fs::read_to_string(path).unwrap_or_default();
    let mut found: Vec<(String, String, String)> = Vec::new();
    for line in text.lines() {
        let Some((mount, filesystem)) = line.split_once(" - ") else {
            continue;
        };
        let mount: Vec<&str> = mount.split(' ').collect();
        let filesystem: Vec<&str> = filesystem.split(' ').collect();
        let ([_, _, numbers, _, point, ..], [kind, source, ..]) =
            (&mount[..], &filesystem[..])
        else {
            continue;
        };
        let kind = *kind;
        if !(kind.starts_with("ext")
            || kind.starts_with("nfs")
            || FS_TYPES.contains(&kind))
        {
            continue;
        }
        let point = host::unescape(point);
        let source = match kind {
            "tmpfs" => point.clone(),
            "overlay" => format!("{source}_{}", numbers.replace(':', "-")),
            _ => host::unescape(source),
        };
        if !found.iter().any(|(s, _, _)| *s == source) {
            found.push((source, (*numbers).to_owned(), point));
        }
    }
    found
}
