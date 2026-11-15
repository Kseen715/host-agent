//! Block devices beyond disks: md arrays (/proc/mdstat), bcache sets
//! and SCSI tape drives in sysfs, as procfs reads them for
//! node_exporter's mdadm, bcache and tapestats collectors.

use super::{Node, absent, host_text, invalid, sys_read};
use crate::host;
use crate::remote::Writer;
use regex_lite::Regex;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// One array of /proc/mdstat.
#[derive(Debug, Default, PartialEq)]
struct Md {
    name: String,
    state: String,
    active: i64,
    total: i64,
    failed: i64,
    spare: i64,
    blocks: i64,
    synced: i64,
}

pub fn mdadm(_: &Node, w: &mut Writer) -> io::Result<()> {
    for md in mdstat(&host_text("/proc/mdstat")?)? {
        let device = [("device", md.name.as_str())];
        w.add("node_md_disks_required", &device, md.total as f64);
        for (state, count) in [
            ("active", md.active),
            ("failed", md.failed),
            ("spare", md.spare),
        ] {
            let labels = [("device", md.name.as_str()), ("state", state)];
            w.add("node_md_disks", &labels, count as f64);
        }
        // node_exporter's state labels for mdstat's states.
        for (label, state) in [
            ("active", "active"),
            ("inactive", "inactive"),
            ("recovering", "recovering"),
            ("resync", "resyncing"),
            ("check", "checking"),
        ] {
            let labels = [("device", md.name.as_str()), ("state", label)];
            w.add("node_md_state", &labels, f64::from(md.state == state));
        }
        w.add("node_md_blocks", &device, md.blocks as f64);
        w.add("node_md_blocks_synced", &device, md.synced as f64);
    }
    Ok(())
}

// procfs's parseMDStat, line for line; longer than 40 lines to be
// compared with it whole.
fn mdstat(text: &str) -> io::Result<Vec<Md>> {
    let lines: Vec<&str> = text.split('\n').collect();
    // procfs reads the first Personalities line that lists any.
    let mut personalities = false;
    let mut arrays = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if line.trim().is_empty()
            || line.starts_with(' ')
            || line.starts_with("unused")
        {
            continue;
        }
        if !personalities {
            if let Some(list) = line.strip_prefix("Personalities : ") {
                personalities = !list.trim().is_empty();
                continue;
            }
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 3 {
            return Err(invalid(format!("mdstat: `{line}`")));
        }
        if lines.len() <= i + 3 {
            return Err(invalid(format!("mdstat: {} cut short", fields[0])));
        }
        let (active, total, size) = status(line, lines[i + 1])?;
        let sync_line = match lines[i + 2].contains("bitmap") {
            true => lines[i + 3],
            false => lines[i + 2],
        };
        let mut md = Md {
            name: fields[0].to_owned(),
            state: fields[2].to_owned(),
            active,
            total,
            failed: line.matches("(F)").count() as i64,
            spare: line.matches("(S)").count() as i64,
            blocks: size,
            synced: size,
        };
        sync(&mut md, sync_line)?;
        arrays.push(md);
    }
    Ok(arrays)
}

/// Active and required disks and size, from the status line.
fn status(device_line: &str, line: &str) -> io::Result<(i64, i64, i64)> {
    let bad = || invalid(format!("mdstat: status `{line}`"));
    let size = line.split_whitespace().next().ok_or_else(bad)?;
    let size: i64 = size.parse().map_err(|_| bad())?;
    if device_line.contains("raid0") || device_line.contains("linear") {
        let total = device_line.matches('[').count() as i64;
        return Ok((total, total, size));
    }
    if device_line.contains("inactive") {
        return Ok((0, 0, size));
    }
    let re = Regex::new(r"(\d+) blocks .*\[(\d+)/(\d+)\] \[([U_]+)\]")
        .expect("a valid pattern");
    let caps = re.captures(line).ok_or_else(bad)?;
    let total = caps[2].parse().map_err(|_| bad())?;
    let active = caps[3].parse().map_err(|_| bad())?;
    Ok((active, total, size))
}

/// The state and synced blocks while an array recovers, reshapes,
/// resyncs or is checked.
fn sync(md: &mut Md, line: &str) -> io::Result<()> {
    let state = [
        ("recovery", "recovering"),
        ("reshape", "reshaping"),
        ("check", "checking"),
        ("resync", "resyncing"),
    ];
    let Some((_, state)) = state.iter().find(|(word, _)| line.contains(word))
    else {
        return Ok(());
    };
    md.state = (*state).to_owned();
    if line.contains("PENDING") || line.contains("DELAYED") {
        md.synced = 0;
        return Ok(());
    }
    let bad = || invalid(format!("mdstat: sync `{line}`"));
    let re = Regex::new(r"\((\d+)/\d+\)").expect("a valid pattern");
    let caps = re.captures(line).ok_or_else(bad)?;
    md.synced = caps[1].parse().map_err(|_| bad())?;
    // procfs refuses a line without these, so node_exporter reports none.
    for pattern in [r"= (.+)%", r"finish=(.+)min", r"speed=(.+)[A-Z]"] {
        let re = Regex::new(pattern).expect("a valid pattern");
        let value = re.captures(line).ok_or_else(bad)?;
        value[1].trim().parse::<f64>().map_err(|_| bad())?;
    }
    Ok(())
}

/// One sysfs value of a bcache set, as procfs reads it: a missing file
/// reads 0.
struct Values<'a> {
    dir: &'a Path,
    error: Option<io::Error>,
}

impl Values<'_> {
    fn get(&mut self, sub: &str, file: &str) -> f64 {
        if self.error.is_some() {
            return 0.0;
        }
        let path = self.dir.join(sub).join(file);
        match fs::read(&path) {
            Ok(mut bytes) => {
                bytes.pop();
                match dehumanize(&bytes) {
                    Some(value) => value as f64,
                    None => {
                        self.error = Some(invalid(path.display()));
                        0.0
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => 0.0,
            Err(e) => {
                self.error = Some(e);
                0.0
            }
        }
    }
}

/// `1.5M`, bcache's sizes: a fraction counts in 1/1024ths of ten.
fn dehumanize(bytes: &[u8]) -> Option<u64> {
    let (&last, rest) = bytes.split_last()?;
    let text = std::str::from_utf8(bytes).ok()?;
    if last <= b'9' {
        return Some(text.parse::<f64>().ok()? as u64);
    }
    let rest = std::str::from_utf8(rest).ok()?;
    let mantissa = match rest.split_once('.') {
        Some((int, frac)) => {
            int.parse::<f64>().ok()? + frac.parse::<f64>().ok()? / 10.24
        }
        None => rest.parse::<f64>().ok()?,
    };
    let units = b"kMGTPEZY";
    let scale = match units.iter().position(|&u| u == last) {
        Some(i) => 2f64.powi(10 * (i as i32 + 1)),
        None => 0.0,
    };
    Some((mantissa * scale) as u64)
}

fn signed(text: &str) -> Option<f64> {
    let value = dehumanize(text.trim_start_matches('-').as_bytes())?;
    Some(if text.starts_with('-') {
        -(value as f64)
    } else {
        value as f64
    })
}

const PERIOD: [(&str, &str); 6] = [
    ("bypassed", "bypassed_bytes_total"),
    ("cache_hits", "cache_hits_total"),
    ("cache_misses", "cache_misses_total"),
    ("cache_bypass_hits", "cache_bypass_hits_total"),
    ("cache_bypass_misses", "cache_bypass_misses_total"),
    ("cache_miss_collisions", "cache_miss_collisions_total"),
];

const SET: [(&str, &str, &str); 10] = [
    ("", "average_key_size", "average_key_size_sectors"),
    ("", "btree_cache_size", "btree_cache_size_bytes"),
    ("", "cache_available_percent", "cache_available_percent"),
    ("", "congested", "congested"),
    ("", "root_usage_percent", "root_usage_percent"),
    ("", "tree_depth", "tree_depth"),
    (
        "internal",
        "active_journal_entries",
        "active_journal_entries",
    ),
    ("internal", "btree_nodes", "btree_nodes"),
    (
        "internal",
        "btree_read_average_duration_us",
        "btree_read_average_duration_seconds",
    ),
    ("internal", "cache_read_races", "cache_read_races_total"),
];

/// A bcache set's metrics, each with `uuid` and, for a device's, its
/// label.
type Metric = (&'static str, Option<(&'static str, String)>, f64);

pub fn bcache(node: &Node, w: &mut Writer) -> io::Result<()> {
    let dir = host::path("/sys/fs/bcache");
    // No sets, or no bcache: nothing to report, and no failure.
    let sets = super::entries(&dir, "");
    let sets = sets.into_iter().filter(|(_, name)| name.contains('-'));
    let priority = node.settings.bcache_priority_stats;
    let mut all = Vec::new();
    for (path, uuid) in sets {
        all.push((uuid, bcache_set(&path, priority)?));
    }
    for (uuid, metrics) in all {
        for (name, device, value) in metrics {
            let name = format!("node_bcache_{name}");
            let mut labels = vec![("uuid", uuid.as_str())];
            if let Some((label, device)) = &device {
                labels.push((label, device.as_str()));
            }
            w.add(&name, &labels, value);
        }
    }
    Ok(())
}

// procfs's GetStats and node_exporter's metrics of it, in their order.
fn bcache_set(dir: &Path, priority: bool) -> io::Result<Vec<Metric>> {
    let mut v = Values { dir, error: None };
    let mut metrics: Vec<Metric> = Vec::new();
    for (sub, file, name) in SET {
        let mut value = v.get(sub, file);
        if file == "btree_read_average_duration_us" {
            // node_exporter scales it as nanoseconds.
            value *= 1e-9;
        }
        metrics.push((name, None, value));
    }
    if let Some(error) = v.error.take() {
        return Err(error);
    }
    for (path, name) in devices(dir, "bdev") {
        let label = || Some(("backing_device", name.clone()));
        metrics.push(("dirty_data_bytes", label(), v.get(&name, "dirty_data")));
        let debug = writeback(&path.join("writeback_rate_debug"))?;
        for (key, metric) in [
            ("target", "dirty_target_bytes"),
            ("rate", "writeback_rate"),
            ("proportional", "writeback_rate_proportional_term"),
            ("integral", "writeback_rate_integral_term"),
            ("change", "writeback_change"),
        ] {
            let value = debug.iter().find(|(k, _)| *k == key);
            metrics.push((metric, label(), value.map_or(0.0, |(_, v)| *v)));
        }
        let total = format!("{name}/stats_total");
        for (file, metric) in PERIOD {
            metrics.push((metric, label(), v.get(&total, file)));
        }
        let readaheads = v.get(&total, "cache_readaheads");
        if readaheads != 0.0 {
            metrics.push(("cache_readaheads_total", label(), readaheads));
        }
    }
    if let Some(error) = v.error.take() {
        return Err(error);
    }
    for (path, name) in devices(dir, "cache") {
        let label = || Some(("cache_device", name.clone()));
        metrics.push(("io_errors", label(), v.get(&name, "io_errors")));
        let written = v.get(&name, "metadata_written");
        metrics.push(("metadata_written_bytes_total", label(), written));
        metrics.push(("written_bytes_total", label(), v.get(&name, "written")));
        if priority {
            let stats = priority_stats(&path.join("priority_stats"))?;
            let (unused, metadata) = stats;
            metrics.push(("priority_stats_unused_percent", label(), unused));
            let name = "priority_stats_metadata_percent";
            metrics.push((name, label(), metadata));
        }
    }
    match v.error {
        Some(error) => Err(error),
        None => Ok(metrics),
    }
}

/// A set's `bdevN` or `cacheN` entries.
fn devices(dir: &Path, prefix: &str) -> Vec<(PathBuf, String)> {
    super::entries(dir, prefix)
        .into_iter()
        .filter(|(_, rest)| rest.starts_with(|c: char| c.is_ascii_digit()))
        .map(|(path, rest)| (path, format!("{prefix}{rest}")))
        .collect()
}

fn writeback(path: &Path) -> io::Result<Vec<(&'static str, f64)>> {
    let text = fs::read_to_string(path)?;
    let bad = || invalid(format!("{}: unreadable", path.display()));
    let mut found = Vec::new();
    for line in text.lines() {
        let Some(last) = line.split_whitespace().last() else {
            continue;
        };
        let unsigned =
            |text: &str| dehumanize(text.as_bytes()).map(|v| v as f64);
        let (key, value) = if line.starts_with("rate:") {
            ("rate", unsigned(last.trim_end_matches("/sec")))
        } else if line.starts_with("target:") {
            ("target", unsigned(last))
        } else if line.starts_with("proportional:") {
            ("proportional", signed(last))
        } else if line.starts_with("integral:") {
            ("integral", signed(last))
        } else if line.starts_with("change:") {
            ("change", signed(last.trim_end_matches("/sec")))
        } else {
            continue;
        };
        found.push((key, value.ok_or_else(bad)?));
    }
    Ok(found)
}

fn priority_stats(path: &Path) -> io::Result<(f64, f64)> {
    let text = fs::read_to_string(path)?;
    let percent = |line: &str| -> io::Result<f64> {
        let last = line.split_whitespace().last().unwrap_or("");
        let value = last.trim_end_matches('%').parse::<u64>();
        value.map(|v| v as f64).map_err(|_| invalid(line))
    };
    let (mut unused, mut metadata) = (0.0, 0.0);
    for line in text.lines() {
        if line.starts_with("Unused:") {
            unused = percent(line)?;
        } else if line.starts_with("Metadata:") {
            metadata = percent(line)?;
        }
    }
    Ok((unused, metadata))
}

const TAPE: [(&str, &str, f64); 10] = [
    ("in_flight", "node_tape_io_now", 1.0),
    ("io_ns", "node_tape_io_time_seconds_total", 1e-9),
    ("other_cnt", "node_tape_io_others_total", 1.0),
    ("read_byte_cnt", "node_tape_read_bytes_total", 1.0),
    ("read_cnt", "node_tape_reads_completed_total", 1.0),
    ("read_ns", "node_tape_read_time_seconds_total", 1e-9),
    ("resid_cnt", "node_tape_residual_total", 1.0),
    ("write_byte_cnt", "node_tape_written_bytes_total", 1.0),
    ("write_cnt", "node_tape_writes_completed_total", 1.0),
    ("write_ns", "node_tape_write_time_seconds_total", 1e-9),
];

pub fn tapestats(node: &Node, w: &mut Writer) -> io::Result<()> {
    let dir = host::path("/sys/class/scsi_tape");
    if !dir.is_dir() {
        return Err(absent("scsi_tape"));
    }
    let tapes = super::entries(&dir, "st");
    let tapes = tapes.into_iter().filter(|(_, n)| {
        !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit())
    });
    let mut found = Vec::new();
    for (path, number) in tapes {
        let name = format!("st{number}");
        let mut counters = [0.0; TAPE.len()];
        for entry in fs::read_dir(path.join("stats"))? {
            let entry = entry?;
            let value = sys_read(&entry.path())?;
            let file = entry.file_name();
            if let Some(i) = TAPE.iter().position(|t| file == t.0) {
                counters[i] = super::go_uint(&value)? as f64;
            }
        }
        found.push((name, counters));
    }
    for (name, counters) in found {
        if node.settings.tapes_ignored.is_match(&name) {
            continue;
        }
        for ((_, metric, scale), value) in TAPE.iter().zip(counters) {
            w.add(metric, &[("device", &name)], value * scale);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const MDSTAT: &str = "Personalities : [raid1] [raid6] [raid5] [raid4]
md3 : active raid6 sda1[8] sdh1[7] sdg1[6] sdf1[11] sde1[10](S)
      5853468288 blocks super 1.2 level 6, 64k chunk, algorithm 2 [4/4] [UUUU]
      [=>...................]  recovery = 8.5% (3/5) finish=3.8min speed=1K/sec

md0 : active raid1 sdb1[1] sda1[0](F)
      248896 blocks [2/1] [U_]
      bitmap: 0/1 pages [0KB], 65536KB chunk

md1 : inactive sdc1[0](S)
      2490176 blocks super external:imsm

unused devices: <none>
";

    #[test]
    fn reads_mdstat_as_procfs() {
        let arrays = mdstat(MDSTAT).unwrap();
        assert_eq!(arrays.len(), 3);
        let md3 = &arrays[0];
        assert_eq!((md3.state.as_str(), md3.synced), ("recovering", 3));
        assert_eq!((md3.active, md3.total, md3.spare), (4, 4, 1));
        assert_eq!((arrays[1].failed, arrays[1].active), (1, 1));
        assert_eq!(arrays[1].state, "active");
        assert_eq!(
            (arrays[2].state.as_str(), arrays[2].total),
            ("inactive", 0)
        );
    }

    #[test]
    fn dehumanizes_sizes() {
        assert_eq!(dehumanize(b"512"), Some(512));
        assert_eq!(dehumanize(b"1.5k"), Some(1024 + 500));
        assert_eq!(dehumanize(b"2M"), Some(2 << 20));
        assert_eq!(signed("-1.0k"), Some(-1024.0));
    }
}
