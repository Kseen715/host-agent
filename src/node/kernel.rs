//! The kernel's tables: sockets, softirq network work, the scheduler,
//! the clock's discipline, processes, ARP; and which OS this is.

use super::{Node, host_text, number, read};
use crate::host;
use crate::remote::Writer;
use std::collections::BTreeMap;
use std::fs;
use std::io;

pub fn arp(_: &Node, w: &mut Writer) -> io::Result<()> {
    let mut devices: BTreeMap<String, f64> = BTreeMap::new();
    for line in host_text("/proc/net/arp")?.lines().skip(1) {
        if let Some(device) = line.split_whitespace().nth(5) {
            *devices.entry(device.to_owned()).or_default() += 1.0;
        }
    }
    for (device, count) in devices {
        w.add("node_arp_entries", &[("device", &device)], count);
    }
    Ok(())
}

/// os-release's fields as labels, and its version as a number.
pub fn os(_: &Node, w: &mut Writer) -> io::Result<()> {
    let text = host_text("/etc/os-release")
        .or_else(|_| host_text("/usr/lib/os-release"))?;
    let fields: BTreeMap<String, String> = text
        .lines()
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| {
            let value = value.trim().trim_matches(|c| c == '"' || c == '\'');
            (key.to_lowercase(), value.to_owned())
        })
        .collect();
    let field = |key: &str| fields.get(key).map_or("", String::as_str);
    const INFO: [&str; 12] = [
        "build_id",
        "id",
        "id_like",
        "image_id",
        "image_version",
        "name",
        "pretty_name",
        "variant",
        "variant_id",
        "version",
        "version_codename",
        "version_id",
    ];
    let labels: Vec<(&str, &str)> =
        INFO.iter().map(|key| (*key, field(key))).collect();
    w.add("node_os_info", &labels, 1.0);
    let labels = [
        ("id", field("id")),
        ("id_like", field("id_like")),
        ("name", field("name")),
    ];
    w.add(
        "node_os_version",
        &labels,
        leading_number(field("version_id")),
    );
    Ok(())
}

/// `13`, `24.04`, `3.22.1` (as 3.22): node_exporter's
/// `^[0-9]+\.?[0-9]*`, 0 if none.
pub(super) fn leading_number(text: &str) -> f64 {
    let mut end = text.bytes().take_while(u8::is_ascii_digit).count();
    if end > 0 && text[end..].starts_with('.') {
        end += 1 + text[end + 1..]
            .bytes()
            .take_while(u8::is_ascii_digit)
            .count();
    }
    text[..end].trim_end_matches('.').parse().unwrap_or(0.0)
}

/// Processes and threads by state, from each one's stat.
pub fn processes(_: &Node, w: &mut Writer) -> io::Result<()> {
    let mut pids = 0.0;
    let mut threads = 0.0;
    let mut states: BTreeMap<String, f64> = BTreeMap::new();
    let mut thread_states: BTreeMap<String, f64> = BTreeMap::new();
    let proc = host::path("/proc");
    for entry in fs::read_dir(&proc)?.flatten() {
        let name = entry.file_name();
        if !name.to_string_lossy().bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let Some((state, count)) = process_stat(&entry.path().join("stat"))
        else {
            continue;
        };
        pids += 1.0;
        threads += count;
        *states.entry(state).or_default() += 1.0;
        let tasks = fs::read_dir(entry.path().join("task"));
        for task in tasks.into_iter().flatten().flatten() {
            if let Some((state, _)) = process_stat(&task.path().join("stat")) {
                *thread_states.entry(state).or_default() += 1.0;
            }
        }
    }
    w.add("node_processes_pids", &[], pids);
    w.add("node_processes_threads", &[], threads);
    for (state, count) in &states {
        w.add("node_processes_state", &[("state", state)], *count);
    }
    for (state, count) in &thread_states {
        let labels = [("thread_state", state.as_str())];
        w.add("node_processes_threads_state", &labels, *count);
    }
    let limits = [
        ("/proc/sys/kernel/threads-max", "node_processes_max_threads"),
        ("/proc/sys/kernel/pid_max", "node_processes_max_processes"),
    ];
    for (path, name) in limits {
        if let Some(value) = number(host::path(path)) {
            w.add(name, &[], value);
        }
    }
    Ok(())
}

/// A stat file's state letter and thread count: fields 3 and 20, after
/// the command in parentheses, which may hold anything.
fn process_stat(path: &std::path::Path) -> Option<(String, f64)> {
    let text = fs::read_to_string(path).ok()?;
    let mut fields = text[text.rfind(')')? + 1..].split_whitespace();
    let state = fields.next()?.to_owned();
    let threads = fields.nth(16)?.parse().ok()?;
    Some((state, threads))
}

/// Per CPU: time running and waiting to run, and how many slices ran.
pub fn schedstat(_: &Node, w: &mut Writer) -> io::Result<()> {
    for line in host_text("/proc/schedstat")?.lines() {
        let mut fields = line.split_whitespace();
        let Some(cpu) = fields.next().and_then(|f| f.strip_prefix("cpu"))
        else {
            continue;
        };
        let values: Vec<f64> = fields.filter_map(|f| f.parse().ok()).collect();
        let [.., running, waiting, slices] = values[..] else {
            continue;
        };
        let labels = [("cpu", cpu)];
        let seconds = "node_schedstat_running_seconds_total";
        w.add(seconds, &labels, running / 1e9);
        let seconds = "node_schedstat_waiting_seconds_total";
        w.add(seconds, &labels, waiting / 1e9);
        w.add("node_schedstat_timeslices_total", &labels, slices);
    }
    Ok(())
}

pub fn selinux(_: &Node, w: &mut Writer) -> io::Result<()> {
    let Some(current) = number(host::path("/sys/fs/selinux/enforce")) else {
        w.add("node_selinux_enabled", &[], 0.0);
        return Ok(());
    };
    w.add("node_selinux_enabled", &[], 1.0);
    w.add("node_selinux_current_mode", &[], current);
    let config = read(host::path("/etc/selinux/config")).unwrap_or_default();
    let mode = config.lines().find_map(|l| l.strip_prefix("SELINUX="));
    let mode = match mode.map(str::trim) {
        Some("enforcing") => 1.0,
        Some("permissive") => 0.0,
        _ => -1.0,
    };
    w.add("node_selinux_config_mode", &[], mode);
    Ok(())
}

/// `TCP: inuse 30 orphan 3 ... mem 3927` as node_sockstat_TCP_inuse...;
/// `mem` is in pages, also given in bytes.
pub fn sockstat(_: &Node, w: &mut Writer) -> io::Result<()> {
    // SAFETY: sysconf only reads a constant.
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as f64;
    let text = host_text("/proc/net/sockstat")?;
    let six = host_text("/proc/net/sockstat6").unwrap_or_default();
    for line in text.lines().chain(six.lines()) {
        let Some((protocol, pairs)) = line.split_once(':') else {
            continue;
        };
        let words: Vec<&str> = pairs.split_whitespace().collect();
        for pair in words.chunks(2) {
            let [key, value] = pair else { continue };
            let Ok(value) = value.parse::<f64>() else {
                continue;
            };
            let name = format!("node_sockstat_{protocol}_{key}");
            w.add(&name, &[], value);
            if *key == "mem" {
                w.add(&format!("{name}_bytes"), &[], value * page);
            }
        }
    }
    Ok(())
}

/// /proc/net/softnet_stat's hexadecimal columns exported, by index;
/// column 12 (newer kernels) is the CPU, else the line's number.
const SOFTNET: [(usize, &str); 7] = [
    (0, "node_softnet_processed_total"),
    (1, "node_softnet_dropped_total"),
    (2, "node_softnet_times_squeezed_total"),
    (8, "node_softnet_cpu_collision_total"),
    (9, "node_softnet_received_rps_total"),
    (10, "node_softnet_flow_limit_count_total"),
    (11, "node_softnet_backlog_len"),
];

pub fn softnet(_: &Node, w: &mut Writer) -> io::Result<()> {
    for (line_number, line) in
        host_text("/proc/net/softnet_stat")?.lines().enumerate()
    {
        let columns: Vec<u64> = line
            .split_whitespace()
            .map(|c| u64::from_str_radix(c, 16).unwrap_or(0))
            .collect();
        let cpu = columns.get(12).map_or(line_number as u64, |c| *c);
        let cpu = cpu.to_string();
        for (column, name) in SOFTNET {
            if let Some(value) = columns.get(column) {
                w.add(name, &[("cpu", &cpu)], *value as f64);
            }
        }
    }
    Ok(())
}

/// The kernel clock's discipline, as adjtimex(2) reads it.
pub fn timex(_: &Node, w: &mut Writer) -> io::Result<()> {
    // SAFETY: modes 0 only reads into the zeroed struct.
    let (state, t) = unsafe {
        let mut t: libc::timex = std::mem::zeroed();
        let state = libc::adjtimex(&mut t);
        if state < 0 {
            return Err(io::Error::last_os_error());
        }
        (state, t)
    };
    const TIME_ERROR: i32 = 5;
    const STA_NANO: i32 = 0x2000;
    // Frequencies are parts per million, in 16.16 fixed point.
    const PPM16: f64 = 1e6 * 65536.0;
    let fine = if t.status & STA_NANO != 0 { 1e9 } else { 1e6 };
    let synced = if state == TIME_ERROR { 0.0 } else { 1.0 };
    let values = [
        ("sync_status", synced),
        ("offset_seconds", t.offset as f64 / fine),
        ("frequency_adjustment_ratio", 1.0 + t.freq as f64 / PPM16),
        ("maxerror_seconds", t.maxerror as f64 / 1e6),
        ("estimated_error_seconds", t.esterror as f64 / 1e6),
        ("status", t.status as f64),
        ("loop_time_constant", t.constant as f64),
        ("tick_seconds", t.tick as f64 / 1e6),
        ("pps_frequency_hertz", t.ppsfreq as f64 / PPM16),
        ("pps_jitter_seconds", t.jitter as f64 / fine),
        ("pps_shift_seconds", t.shift as f64),
        ("pps_stability_hertz", t.stabil as f64 / PPM16),
        ("pps_jitter_total", t.jitcnt as f64),
        ("pps_calibration_total", t.calcnt as f64),
        ("pps_error_total", t.errcnt as f64),
        ("pps_stability_exceeded_total", t.stbcnt as f64),
        ("tai_offset_seconds", t.tai as f64),
    ];
    for (name, value) in values {
        w.add(&format!("node_timex_{name}"), &[], value);
    }
    Ok(())
}

/// Bytes waiting in UDP sockets' queues, by IP version.
pub fn udp_queues(_: &Node, w: &mut Writer) -> io::Result<()> {
    let v4 = host_text("/proc/net/udp")?;
    let v6 = host_text("/proc/net/udp6").ok();
    for (ip, text) in [("v4", Some(v4)), ("v6", v6)] {
        let Some(text) = text else { continue };
        let (mut tx, mut rx) = (0, 0);
        for line in text.lines().skip(1) {
            let queues = line.split_whitespace().nth(4).unwrap_or("");
            let (t, r) = queues.split_once(':').unwrap_or(("0", "0"));
            tx += u64::from_str_radix(t, 16).unwrap_or(0);
            rx += u64::from_str_radix(r, 16).unwrap_or(0);
        }
        for (queue, bytes) in [("rx", rx), ("tx", tx)] {
            let labels = [("ip", ip), ("queue", queue)];
            w.add("node_udp_queues", &labels, bytes as f64);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_versions_as_node_exporter() {
        assert_eq!(leading_number("13"), 13.0);
        assert_eq!(leading_number("24.04"), 24.04);
        assert_eq!(leading_number("3.22.1"), 3.22);
        assert_eq!(leading_number("rolling"), 0.0);
        assert_eq!(leading_number("7."), 7.0);
    }

    #[test]
    fn reads_a_stat_with_parentheses_in_the_command() {
        let dir =
            std::env::temp_dir().join(format!("ps-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("stat");
        let fields: Vec<String> = (4..=20).map(|n| n.to_string()).collect();
        let text = format!("1 (a) b) S {}", fields.join(" "));
        fs::write(&path, text).unwrap();
        assert_eq!(process_stat(&path), Some(("S".into(), 20.0)));
        fs::remove_dir_all(dir).unwrap();
    }
}
