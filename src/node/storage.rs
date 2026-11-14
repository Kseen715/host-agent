//! File systems (statvfs of each mount of PID 1's namespace) and block
//! devices' I/O counters, with what udev knows of each device.

use super::{Node, host_text};
use crate::host;
use crate::remote::Writer;
use std::collections::HashMap;
use std::io;

const SECTOR: f64 = 512.0;

pub fn filesystem(node: &Node, w: &mut Writer) -> io::Result<()> {
    let mut seen = Vec::new();
    for line in host_text("/proc/1/mounts")?.lines() {
        let fields: Vec<&str> = line.split(' ').collect();
        let [device, point, fstype, options, ..] = fields[..] else {
            continue;
        };
        let point = host::unescape(point);
        if node.fs_mount_points.is_match(&point)
            || node.fs_types.is_match(fstype)
        {
            continue;
        }
        let device = host::unescape(device);
        if seen.contains(&(device.clone(), point.clone())) {
            continue;
        }
        let labels = [
            ("device", device.as_str()),
            ("fstype", fstype),
            ("mountpoint", point.as_str()),
        ];
        let readonly = options.split(',').any(|o| o == "ro");
        filesystem_stats(w, &labels, readonly);
        seen.push((device, point));
    }
    Ok(())
}

fn filesystem_stats(w: &mut Writer, labels: &[(&str, &str)], readonly: bool) {
    let Some(stats) = host::statvfs(labels[2].1) else {
        w.add("node_filesystem_device_error", labels, 1.0);
        return;
    };
    let block = stats.f_frsize as f64;
    w.add("node_filesystem_device_error", labels, 0.0);
    w.add(
        "node_filesystem_size_bytes",
        labels,
        stats.f_blocks as f64 * block,
    );
    w.add(
        "node_filesystem_free_bytes",
        labels,
        stats.f_bfree as f64 * block,
    );
    w.add(
        "node_filesystem_avail_bytes",
        labels,
        stats.f_bavail as f64 * block,
    );
    w.add("node_filesystem_files", labels, stats.f_files as f64);
    w.add("node_filesystem_files_free", labels, stats.f_ffree as f64);
    w.add(
        "node_filesystem_readonly",
        labels,
        if readonly { 1.0 } else { 0.0 },
    );
}

/// Fields of /proc/diskstats after major, minor and name, and how each
/// is exported: name and scale (sectors to bytes, ms to seconds).
const DISK_FIELDS: [(&str, f64); 17] = [
    ("node_disk_reads_completed_total", 1.0),
    ("node_disk_reads_merged_total", 1.0),
    ("node_disk_read_bytes_total", SECTOR),
    ("node_disk_read_time_seconds_total", 0.001),
    ("node_disk_writes_completed_total", 1.0),
    ("node_disk_writes_merged_total", 1.0),
    ("node_disk_written_bytes_total", SECTOR),
    ("node_disk_write_time_seconds_total", 0.001),
    ("node_disk_io_now", 1.0),
    ("node_disk_io_time_seconds_total", 0.001),
    ("node_disk_io_time_weighted_seconds_total", 0.001),
    ("node_disk_discards_completed_total", 1.0),
    ("node_disk_discards_merged_total", 1.0),
    ("node_disk_discarded_sectors_total", 1.0),
    ("node_disk_discard_time_seconds_total", 0.001),
    ("node_disk_flush_requests_total", 1.0),
    ("node_disk_flush_requests_time_seconds_total", 0.001),
];

pub fn diskstats(node: &Node, w: &mut Writer) -> io::Result<()> {
    for line in host_text("/proc/diskstats")?.lines() {
        let mut fields = line.split_whitespace();
        let (Some(major), Some(minor), Some(device)) =
            (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        if node.disk_devices.is_match(device) {
            continue;
        }
        let labels = [("device", device)];
        for ((name, scale), value) in DISK_FIELDS.iter().zip(fields) {
            let value: f64 = value.parse().unwrap_or(0.0);
            w.add(name, &labels, value * scale);
        }
        let path = format!("/run/udev/data/b{major}:{minor}");
        let text = host_text(&path).unwrap_or_default();
        disk_info(w, device, major, minor, &udev(&text));
    }
    Ok(())
}

/// A udev database file's `E:KEY=value` properties.
fn udev(text: &str) -> HashMap<&str, &str> {
    text.lines()
        .filter_map(|line| line.strip_prefix("E:")?.split_once('='))
        .collect()
}

fn disk_info(
    w: &mut Writer,
    device: &str,
    major: &str,
    minor: &str,
    udev: &HashMap<&str, &str>,
) {
    let get = |key: &str| udev.get(key).copied().unwrap_or("");
    let info = [
        ("device", device),
        ("major", major),
        ("minor", minor),
        ("path", get("ID_PATH")),
        ("wwn", get("ID_WWN")),
        ("model", get("ID_MODEL")),
        ("serial", get("ID_SERIAL_SHORT")),
        ("revision", get("ID_REVISION")),
    ];
    w.add("node_disk_info", &info, 1.0);
    if !get("ID_FS_TYPE").is_empty() {
        let labels = [
            ("device", device),
            ("type", get("ID_FS_TYPE")),
            ("usage", get("ID_FS_USAGE")),
            ("uuid", get("ID_FS_UUID")),
            ("version", get("ID_FS_VERSION")),
        ];
        w.add("node_disk_filesystem_info", &labels, 1.0);
    }
    if !get("DM_NAME").is_empty() {
        let labels = [
            ("device", device),
            ("lv_layer", get("DM_LV_LAYER")),
            ("lv_name", get("DM_LV_NAME")),
            ("name", get("DM_NAME")),
            ("uuid", get("DM_UUID")),
            ("vg_name", get("DM_VG_NAME")),
        ];
        w.add("node_disk_device_mapper_info", &labels, 1.0);
    }
    let ata = [
        (
            "ID_ATA_ROTATION_RATE_RPM",
            "node_disk_ata_rotation_rate_rpm",
        ),
        ("ID_ATA_WRITE_CACHE", "node_disk_ata_write_cache"),
        (
            "ID_ATA_WRITE_CACHE_ENABLED",
            "node_disk_ata_write_cache_enabled",
        ),
    ];
    for (key, name) in ata {
        if let Ok(value) = get(key).parse() {
            w.add(name, &[("device", device)], value);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_udev_properties() {
        let text = "S:disk/by-id/x\nE:ID_MODEL=KINGSTON SNVS500G\nE:A=b=c\n";
        let udev = udev(text);
        assert_eq!(udev["ID_MODEL"], "KINGSTON SNVS500G");
        assert_eq!(udev["A"], "b=c");
        assert_eq!(udev.len(), 2);
    }
}
