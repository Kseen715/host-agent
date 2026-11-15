//! The kernel's counters in /proc: CPU time, memory, load, pressure,
//! clocks, and the small ones the hosts dashboards show.

use super::{
    Node, absent, cpuinfo, hardware, host_text, number, numbered, read,
};
use crate::host;
use crate::remote::Writer;
use std::ffi::CStr;
use std::io;

/// The kernel's clock ticks per second in /proc/stat (USER_HZ).
const USER_HZ: f64 = 100.0;
const CPU_MODES: [&str; 8] = [
    "user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal",
];

pub fn stat(_: &Node, w: &mut Writer) -> io::Result<()> {
    for line in host_text("/proc/stat")?.lines() {
        let mut fields = line.split_whitespace();
        let Some(key) = fields.next() else { continue };
        let values: Vec<f64> = fields.filter_map(|v| v.parse().ok()).collect();
        let first = values.first().copied().unwrap_or(0.0);
        match key {
            "ctxt" => w.add("node_context_switches_total", &[], first),
            "processes" => w.add("node_forks_total", &[], first),
            "intr" => w.add("node_intr_total", &[], first),
            "btime" => w.add("node_boot_time_seconds", &[], first),
            "procs_running" => w.add("node_procs_running", &[], first),
            "procs_blocked" => w.add("node_procs_blocked", &[], first),
            _ => {}
        }
    }
    Ok(())
}

/// Time in each mode per CPU, its time in guests, which CPUs are
/// isolated, /proc/cpuinfo when asked for, and thermal throttling.
pub fn cpu(node: &Node, w: &mut Writer) -> io::Result<()> {
    if node.settings.cpu.info {
        cpu_info(node, w)?;
    }
    let guest = node.settings.cpu.guest;
    for line in host_text("/proc/stat")?.lines() {
        let mut fields = line.split_whitespace();
        let Some(cpu) = fields
            .next()
            .and_then(|key| key.strip_prefix("cpu"))
            .filter(|cpu| !cpu.is_empty())
        else {
            continue;
        };
        let values: Vec<f64> =
            fields.map(|v| v.parse().unwrap_or(0.0) / USER_HZ).collect();
        for (mode, value) in CPU_MODES.iter().zip(&values) {
            let labels = [("cpu", cpu), ("mode", *mode)];
            w.add("node_cpu_seconds_total", &labels, *value);
        }
        // Guest time, also counted in user and nice.
        let guests = ["user", "nice"].iter().zip(values.iter().skip(8));
        for (mode, value) in guests.filter(|_| guest) {
            let labels = [("cpu", cpu), ("mode", *mode)];
            w.add("node_cpu_guest_seconds_total", &labels, *value);
        }
    }
    for cpu in cpuinfo::isolated()? {
        w.add("node_cpu_isolated", &[("cpu", &cpu.to_string())], 1.0);
    }
    hardware::throttles(w);
    Ok(())
}

/// node_cpu_info, the frequencies when cpufreq does not run, and the
/// first CPU's flags and bugs the filters let through.
fn cpu_info(node: &Node, w: &mut Writer) -> io::Result<()> {
    let cpus = cpuinfo::read_all()?;
    for cpu in &cpus {
        let processor = cpu.processor.to_string();
        let labels = [
            ("package", cpu.package.as_str()),
            ("core", &cpu.core),
            ("cpu", &processor),
            ("vendor", &cpu.vendor),
            ("family", &cpu.family),
            ("model", &cpu.model),
            ("model_name", &cpu.model_name),
            ("microcode", &cpu.microcode),
            ("stepping", &cpu.stepping),
            ("cachesize", &cpu.cache_size),
        ];
        w.add("node_cpu_info", &labels, 1.0);
    }
    if !node.runs("cpufreq") {
        for cpu in &cpus {
            let processor = cpu.processor.to_string();
            let labels = [
                ("package", cpu.package.as_str()),
                ("core", &cpu.core),
                ("cpu", &processor),
            ];
            w.add("node_cpu_frequency_hertz", &labels, cpu.mhz * 1e6);
        }
    }
    let Some(first) = cpus.first() else {
        return Ok(());
    };
    let settings = &node.settings.cpu;
    let lists = [
        (
            &first.flags,
            &settings.flags_include,
            "node_cpu_flag_info",
            "flag",
        ),
        (
            &first.bugs,
            &settings.bugs_include,
            "node_cpu_bug_info",
            "bug",
        ),
    ];
    for (values, include, metric, label) in lists {
        let Some(include) = include else { continue };
        for value in values.iter().filter(|v| include.is_match(v)) {
            w.add(metric, &[(label, value)], 1.0);
        }
    }
    Ok(())
}

pub fn loadavg(_: &Node, w: &mut Writer) -> io::Result<()> {
    let text = host_text("/proc/loadavg")?;
    let names = ["node_load1", "node_load5", "node_load15"];
    for (name, value) in names.iter().zip(text.split_whitespace()) {
        w.add(name, &[], value.parse().unwrap_or(0.0));
    }
    Ok(())
}

/// `Active(anon):  1 kB` is node_memory_Active_anon_bytes; a line
/// without a unit keeps its name (node_memory_HugePages_Total).
pub fn meminfo(_: &Node, w: &mut Writer) -> io::Result<()> {
    for line in host_text("/proc/meminfo")?.lines() {
        let mut fields = line.split_whitespace();
        let (Some(key), Some(value)) = (fields.next(), fields.next()) else {
            continue;
        };
        let Ok(value) = value.parse::<f64>() else {
            continue;
        };
        let key = key.trim_end_matches(':').replace('(', "_").replace(')', "");
        let name = match fields.next() {
            Some("kB") => format!("node_memory_{key}_bytes"),
            _ => format!("node_memory_{key}"),
        };
        let scale = if name.ends_with("_bytes") {
            1024.0
        } else {
            1.0
        };
        w.add(&name, &[], value * scale);
    }
    Ok(())
}

pub fn vmstat(node: &Node, w: &mut Writer) -> io::Result<()> {
    for line in host_text("/proc/vmstat")?.lines() {
        let Some((key, value)) = line.split_once(' ') else {
            continue;
        };
        if node.settings.vmstat_fields.is_match(key) {
            let value = value.trim().parse().unwrap_or(0.0);
            w.add(&format!("node_vmstat_{key}"), &[], value);
        }
    }
    Ok(())
}

/// Seconds tasks waited (`some`) or all stalled (`full`) on each
/// resource.
pub fn pressure(_: &Node, w: &mut Writer) -> io::Result<()> {
    if !host::path("/proc/pressure").is_dir() {
        return Err(absent("pressure"));
    }
    for resource in ["cpu", "io", "memory", "irq"] {
        let path = host::path(&format!("/proc/pressure/{resource}"));
        let Some(text) = read(path) else {
            continue;
        };
        for line in text.lines() {
            let (kind, rest) = line.split_once(' ').unwrap_or((line, ""));
            let total = rest.split(' ').find_map(|f| f.strip_prefix("total="));
            let seconds =
                total.and_then(|t| t.parse::<f64>().ok()).unwrap_or(0.0) / 1e6;
            let what = match (resource, kind) {
                ("irq", "some") | ("cpu", "full") => continue,
                (_, "some") => "waiting",
                _ => "stalled",
            };
            let name = format!("node_pressure_{resource}_{what}_seconds_total");
            w.add(&name, &[], seconds);
        }
    }
    Ok(())
}

pub fn uname(_: &Node, w: &mut Writer) -> io::Result<()> {
    // SAFETY: uname fills the zeroed struct with NUL-terminated strings.
    let names = unsafe {
        let mut names: libc::utsname = std::mem::zeroed();
        if libc::uname(&mut names) != 0 {
            return Err(io::Error::last_os_error());
        }
        names
    };
    let text = |field: &[libc::c_char]| {
        // SAFETY: the kernel terminates each field within its array.
        unsafe { CStr::from_ptr(field.as_ptr()) }
            .to_string_lossy()
            .into_owned()
    };
    let fields = [
        ("domainname", text(&names.domainname)),
        ("machine", text(&names.machine)),
        ("nodename", text(&names.nodename)),
        ("release", text(&names.release)),
        ("sysname", text(&names.sysname)),
        ("version", text(&names.version)),
    ];
    let labels: Vec<(&str, &str)> =
        fields.iter().map(|(k, v)| (*k, v.as_str())).collect();
    w.add("node_uname_info", &labels, 1.0);
    Ok(())
}

pub fn time(_: &Node, w: &mut Writer) -> io::Result<()> {
    let ns = crate::time::now_ns();
    w.add("node_time_seconds", &[], ns as f64 / 1e9);
    if let Some((zone, offset)) = zone(ns / 1_000_000_000) {
        let labels = [("time_zone", zone.as_str())];
        w.add("node_time_zone_offset_seconds", &labels, offset);
    }
    let sources = numbered("/sys/devices/system/clocksource", "clocksource");
    for (dir, device) in sources {
        let files = [
            (
                "available_clocksource",
                "node_time_clocksource_available_info",
            ),
            ("current_clocksource", "node_time_clocksource_current_info"),
        ];
        for (file, name) in files {
            let text = read(dir.join(file)).unwrap_or_default();
            for source in text.split_whitespace() {
                let labels = [("clocksource", source), ("device", &device)];
                w.add(name, &labels, 1.0);
            }
        }
    }
    Ok(())
}

/// The local time zone's abbreviation and offset from UTC, as libc
/// knows them (TZ, /etc/localtime).
fn zone(now: i64) -> Option<(String, f64)> {
    // time_t, whose alias libc deprecates for musl's change of width.
    let now = now as _;
    // SAFETY: localtime_r fills the zeroed struct; tm_zone points into
    // libc's static zone names.
    unsafe {
        let mut tm: libc::tm = std::mem::zeroed();
        if libc::localtime_r(&now, &mut tm).is_null() || tm.tm_zone.is_null() {
            return None;
        }
        let name = CStr::from_ptr(tm.tm_zone).to_string_lossy().into_owned();
        Some((name, tm.tm_gmtoff as f64))
    }
}

pub fn filefd(_: &Node, w: &mut Writer) -> io::Result<()> {
    let text = host_text("/proc/sys/fs/file-nr")?;
    let fields: Vec<f64> = text
        .split_whitespace()
        .filter_map(|f| f.parse().ok())
        .collect();
    if let [allocated, _, maximum] = fields[..] {
        w.add("node_filefd_allocated", &[], allocated);
        w.add("node_filefd_maximum", &[], maximum);
    }
    Ok(())
}

pub fn entropy(_: &Node, w: &mut Writer) -> io::Result<()> {
    let dir = host::path("/proc/sys/kernel/random");
    if let Some(bits) = number(dir.join("entropy_avail")) {
        w.add("node_entropy_available_bits", &[], bits);
    }
    if let Some(bits) = number(dir.join("poolsize")) {
        w.add("node_entropy_pool_size_bits", &[], bits);
    }
    Ok(())
}

/// Counters of /proc/net/stat/nf_conntrack exported, summed over CPUs.
const CONNTRACK_STATS: [&str; 8] = [
    "found",
    "invalid",
    "ignore",
    "insert",
    "insert_failed",
    "drop",
    "early_drop",
    "search_restart",
];

/// Only where netfilter's conntrack is loaded.
pub fn conntrack(_: &Node, w: &mut Writer) -> io::Result<()> {
    let dir = host::path("/proc/sys/net/netfilter");
    let entries = number(dir.join("nf_conntrack_count"))
        .ok_or_else(|| absent("conntrack"))?;
    w.add("node_nf_conntrack_entries", &[], entries);
    if let Some(limit) = number(dir.join("nf_conntrack_max")) {
        w.add("node_nf_conntrack_entries_limit", &[], limit);
    }
    let text = host_text("/proc/net/stat/nf_conntrack").unwrap_or_default();
    let mut lines = text.lines();
    let header: Vec<&str> =
        lines.next().unwrap_or("").split_whitespace().collect();
    let mut sums = vec![0.0; header.len()];
    for line in lines {
        for (sum, value) in sums.iter_mut().zip(line.split_whitespace()) {
            *sum += u64::from_str_radix(value, 16).unwrap_or(0) as f64;
        }
    }
    for (name, sum) in header.iter().zip(sums) {
        if CONNTRACK_STATS.contains(name) {
            w.add(&format!("node_nf_conntrack_stat_{name}"), &[], sum);
        }
    }
    Ok(())
}
