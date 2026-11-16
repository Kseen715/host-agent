//! XFS's and Btrfs's own counters. Btrfs's devices are asked through
//! ioctls on a mount point, as node_exporter does: sysfs lacks their
//! UUIDs, usage and error counts.

use super::{Node, entries, number, read};
use crate::host;
use crate::remote::Writer;
use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;
use std::path::Path;

/// /sys/fs/xfs/<device>/stats/stats lines and the names of their
/// fields, `node_xfs_<name>_total`, in order; None: not exported.
const XFS: [(&str, &[Option<&str>]); 8] = [
    (
        "extent_alloc",
        &[
            Some("extent_allocation_extents_allocated"),
            Some("extent_allocation_blocks_allocated"),
            Some("extent_allocation_extents_freed"),
            Some("extent_allocation_blocks_freed"),
        ],
    ),
    (
        "abt",
        &[
            Some("allocation_btree_lookups"),
            Some("allocation_btree_compares"),
            Some("allocation_btree_records_inserted"),
            Some("allocation_btree_records_deleted"),
        ],
    ),
    (
        "blk_map",
        &[
            Some("block_mapping_reads"),
            Some("block_mapping_writes"),
            Some("block_mapping_unmaps"),
            Some("block_mapping_extent_list_insertions"),
            Some("block_mapping_extent_list_deletions"),
            Some("block_mapping_extent_list_lookups"),
            Some("block_mapping_extent_list_compares"),
        ],
    ),
    (
        "bmbt",
        &[
            Some("block_map_btree_lookups"),
            Some("block_map_btree_compares"),
            Some("block_map_btree_records_inserted"),
            Some("block_map_btree_records_deleted"),
        ],
    ),
    (
        "dir",
        &[
            Some("directory_operation_lookup"),
            Some("directory_operation_create"),
            Some("directory_operation_remove"),
            Some("directory_operation_getdents"),
        ],
    ),
    (
        "ig",
        &[
            Some("inode_operation_attempts"),
            Some("inode_operation_found"),
            Some("inode_operation_recycled"),
            Some("inode_operation_missed"),
            Some("inode_operation_duplicates"),
            Some("inode_operation_reclaims"),
            Some("inode_operation_attribute_changes"),
        ],
    ),
    ("rw", &[Some("write_calls"), Some("read_calls")]),
    (
        "vnodes",
        &[
            Some("vnode_active"),
            Some("vnode_allocate"),
            Some("vnode_get"),
            Some("vnode_hold"),
            Some("vnode_release"),
            Some("vnode_reclaim"),
            Some("vnode_remove"),
            None,
        ],
    ),
];

pub fn xfs(_: &Node, w: &mut Writer) -> io::Result<()> {
    xfs_in(&host::path("/sys/fs/xfs"), w);
    Ok(())
}

/// Each device's counters in `root`, /sys/fs/xfs.
fn xfs_in(root: &Path, w: &mut Writer) {
    for (dir, device) in entries(root, "") {
        let Some(text) = read(dir.join("stats/stats")) else {
            continue;
        };
        let labels = [("device", device.as_str())];
        for line in text.lines() {
            let mut fields = line.split_whitespace();
            let key = fields.next().unwrap_or("");
            let Some((_, names)) = XFS.iter().find(|(k, _)| *k == key) else {
                continue;
            };
            for (name, value) in names.iter().zip(fields) {
                if let (Some(name), Ok(value)) = (name, value.parse::<f64>()) {
                    w.add(&format!("node_xfs_{name}_total"), &labels, value);
                }
            }
        }
    }
}

const BLOCK_GROUPS: [&str; 3] = ["data", "metadata", "system"];
const DEVICE_ERRORS: [&str; 5] =
    ["write", "read", "flush", "corruption", "generation"];

pub fn btrfs(_: &Node, w: &mut Writer) -> io::Result<()> {
    btrfs_in(&host::path("/sys/fs/btrfs"), &btrfs_mounts(), w);
    Ok(())
}

/// Each file system in `root`, /sys/fs/btrfs; its devices through the
/// mount point of the same UUID in `mounts`.
fn btrfs_in(root: &Path, mounts: &[(String, String)], w: &mut Writer) {
    for (dir, uuid) in entries(root, "") {
        if !dir.join("allocation").is_dir() {
            continue;
        }
        let label = read(dir.join("label")).unwrap_or_default();
        let fs = [("label", label.as_str()), ("uuid", uuid.as_str())];
        w.add("node_btrfs_info", &fs, 1.0);
        let allocation = dir.join("allocation");
        let fs = [("uuid", uuid.as_str())];
        if let Some(bytes) = number(allocation.join("global_rsv_size")) {
            w.add("node_btrfs_global_rsv_size_bytes", &fs, bytes);
        }
        let devices = entries(&dir.join("devices"), "").len();
        for group in BLOCK_GROUPS {
            block_group(w, &allocation.join(group), group, &uuid, devices);
        }
        let mount = mounts.iter().find(|(_, fsid)| *fsid == uuid);
        if let Some((point, _)) = mount {
            btrfs_devices(w, point, &uuid);
        }
    }
}

fn block_group(
    w: &mut Writer,
    dir: &Path,
    group: &str,
    uuid: &str,
    devices: usize,
) {
    let labels = [("block_group_type", group), ("uuid", uuid)];
    if let Some(bytes) = number(dir.join("bytes_reserved")) {
        w.add("node_btrfs_reserved_bytes", &labels, bytes);
    }
    for (mode_dir, mode) in entries(dir, "") {
        let Some(total) = number(mode_dir.join("total_bytes")) else {
            continue;
        };
        let labels = [
            ("block_group_type", group),
            ("mode", mode.as_str()),
            ("uuid", uuid),
        ];
        w.add("node_btrfs_size_bytes", &labels, total);
        if let Some(used) = number(mode_dir.join("used_bytes")) {
            w.add("node_btrfs_used_bytes", &labels, used);
        }
        let ratio = allocation_ratio(&mode, devices as f64);
        w.add("node_btrfs_allocation_ratio", &labels, ratio);
    }
}

/// Bytes on disk per byte stored, by RAID profile.
fn allocation_ratio(mode: &str, devices: f64) -> f64 {
    match mode {
        "dup" | "raid1" | "raid10" => 2.0,
        "raid1c3" => 3.0,
        "raid1c4" => 4.0,
        "raid5" if devices > 1.0 => devices / (devices - 1.0),
        "raid6" if devices > 2.0 => devices / (devices - 2.0),
        _ => 1.0,
    }
}

/// Mount points of Btrfs file systems, with each one's UUID.
fn btrfs_mounts() -> Vec<(String, String)> {
    let mounts = super::host_text("/proc/1/mounts").unwrap_or_default();
    let mut found: Vec<(String, String)> = Vec::new();
    for line in mounts.lines() {
        let fields: Vec<&str> = line.split(' ').collect();
        let [_, point, "btrfs", ..] = fields[..] else {
            continue;
        };
        let point = host::unescape(point);
        let Ok(dir) = File::open(host::path(&point)) else {
            continue;
        };
        if let Some(info) = ioctl::<1024>(&dir, ioctl::FS_INFO, |_| {}) {
            let uuid = uuid_text(&info[16..32]);
            if !found.iter().any(|(_, u)| *u == uuid) {
                found.push((point, uuid));
            }
        }
    }
    found
}

fn btrfs_devices(w: &mut Writer, point: &str, uuid: &str) {
    let Ok(dir) = File::open(host::path(point)) else {
        return;
    };
    let Some(info) = ioctl::<1024>(&dir, ioctl::FS_INFO, |_| {}) else {
        return;
    };
    let max_id = u64_at(&info[..], 0);
    for devid in 1..=max_id {
        let set_id = |args: &mut [u8]| {
            args[..8].copy_from_slice(&devid.to_ne_bytes());
        };
        let Some(dev) = ioctl::<4096>(&dir, ioctl::DEV_INFO, set_id) else {
            continue;
        };
        let dev_uuid = uuid_text(&dev[8..24]);
        let (used, total) = (u64_at(&dev[..], 24), u64_at(&dev[..], 32));
        let path = &dev[3072..];
        let path = &path[..path.iter().position(|&b| b == 0).unwrap_or(0)];
        let path = String::from_utf8_lossy(path);
        let device = path.rsplit('/').next().unwrap_or("");
        let labels = [
            ("btrfs_dev_uuid", dev_uuid.as_str()),
            ("device", device),
            ("uuid", uuid),
        ];
        w.add("node_btrfs_device_size_bytes", &labels, total as f64);
        let unused = total.saturating_sub(used) as f64;
        w.add("node_btrfs_device_unused_bytes", &labels, unused);
        let set_stats = |args: &mut [u8]| {
            args[..8].copy_from_slice(&devid.to_ne_bytes());
            args[8..16].copy_from_slice(&5u64.to_ne_bytes());
        };
        let Some(stats) = ioctl::<1032>(&dir, ioctl::DEV_STATS, set_stats)
        else {
            continue;
        };
        for (index, kind) in DEVICE_ERRORS.iter().enumerate() {
            let labels = [
                ("btrfs_dev_uuid", dev_uuid.as_str()),
                ("device", device),
                ("type", kind),
                ("uuid", uuid),
            ];
            let count = u64_at(&stats[..], 24 + 8 * index) as f64;
            w.add("node_btrfs_device_errors_total", &labels, count);
        }
    }
}

mod ioctl {
    /// _IOR/_IOWR(BTRFS_IOCTL_MAGIC, nr, size) for the structs' sizes.
    const fn code(dir: u64, nr: u64, size: u64) -> u64 {
        dir << 30 | size << 16 | 0x94 << 8 | nr
    }
    pub const FS_INFO: u64 = code(2, 31, 1024);
    pub const DEV_INFO: u64 = code(3, 30, 4096);
    pub const DEV_STATS: u64 = code(3, 52, 1032);
}

/// One btrfs ioctl on `dir` with an argument struct of N bytes,
/// prepared by `set`; its result, or None if refused.
fn ioctl<const N: usize>(
    dir: &File,
    request: u64,
    set: impl FnOnce(&mut [u8]),
) -> Option<Box<[u8; N]>> {
    let mut args = Box::new([0u8; N]);
    set(&mut args[..]);
    // SAFETY: the kernel reads and writes at most N bytes, the size the
    // request encodes, of the buffer.
    let result = unsafe {
        libc::ioctl(dir.as_raw_fd(), request as _, args.as_mut_ptr())
    };
    (result == 0).then_some(args)
}

fn u64_at(bytes: &[u8], at: usize) -> u64 {
    let mut word = [0u8; 8];
    word.copy_from_slice(&bytes[at..at + 8]);
    u64::from_ne_bytes(word)
}

fn uuid_text(bytes: &[u8]) -> String {
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    let parts = [
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..],
    ];
    parts.join("-")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_btrfs_requests() {
        assert_eq!(ioctl::FS_INFO, 0x8400_941F);
        assert_eq!(ioctl::DEV_INFO, 0xD000_941E);
        assert_eq!(ioctl::DEV_STATS, 0xC408_9434);
    }

    #[test]
    fn formats_uuids() {
        let bytes: Vec<u8> = (0..16).collect();
        assert_eq!(uuid_text(&bytes), "00010203-0405-0607-0809-0a0b0c0d0e0f");
    }

    #[test]
    fn gives_profiles_ratios() {
        assert_eq!(allocation_ratio("dup", 1.0), 2.0);
        assert_eq!(allocation_ratio("raid5", 3.0), 1.5);
        assert_eq!(allocation_ratio("single", 1.0), 1.0);
    }

    fn lines(text: &str, prefix: &str) -> Vec<String> {
        let found = text.lines().filter(|l| l.starts_with(prefix));
        found.map(str::to_owned).collect()
    }

    #[test]
    fn reads_xfs_counters() {
        let root = crate::testing::scratch("xfs");
        let stats = "extent_alloc 4 7 3 5\nrw 21 32\nxs_unknown 1 2\n\
            vnodes 62578 15959 0 0 15959 15959 15959 0\n";
        super::super::sysfs(&root, &[("sda1/stats/stats", stats)]);
        let mut w = Writer::text();
        xfs_in(&root, &mut w);
        let text = w.into_text();
        let device = r#"{device="sda1"}"#;
        for line in [
            format!(
                "node_xfs_extent_allocation_extents_allocated_total{device} 4"
            ),
            format!("node_xfs_extent_allocation_blocks_freed_total{device} 5"),
            format!("node_xfs_write_calls_total{device} 21"),
            format!("node_xfs_read_calls_total{device} 32"),
            format!("node_xfs_vnode_active_total{device} 62578"),
        ] {
            assert!(text.lines().any(|l| l == line), "{line}\n{text}");
        }
        // vnodes' eighth field has no name in node_exporter.
        assert_eq!(lines(&text, "node_xfs_vnode_").len(), 7);
        assert_eq!(text.lines().count(), 4 + 2 + 7);
    }

    #[test]
    fn reads_a_btrfs_file_system() {
        let root = crate::testing::scratch("btrfs");
        let uuid = "0abb23a9-9aa5-4ef8-8c5d-2ae7e7e5d2c1";
        super::super::sysfs(
            &root.join(uuid),
            &[
                ("label", "data\n"),
                ("allocation/global_rsv_size", "16777216\n"),
                ("allocation/data/bytes_reserved", "4096\n"),
                ("allocation/data/raid5/total_bytes", "3221225472\n"),
                ("allocation/data/raid5/used_bytes", "1073741824\n"),
                ("allocation/metadata/raid1/total_bytes", "268435456\n"),
                ("devices/sda", ""),
                ("devices/sdb", ""),
                ("devices/sdc", ""),
            ],
        );
        super::super::sysfs(&root, &[("features/raid56", "0\n")]);
        let mut w = Writer::text();
        btrfs_in(&root, &[], &mut w);
        let text = w.into_text();
        let fs = format!(r#"uuid="{uuid}""#);
        let data = format!(r#"block_group_type="data",mode="raid5",{fs}"#);
        let meta = format!(r#"block_group_type="metadata",mode="raid1",{fs}"#);
        let reserved = format!(r#"block_group_type="data",{fs}"#);
        let expected = [
            format!(r#"node_btrfs_info{{label="data",{fs}}} 1"#),
            format!("node_btrfs_global_rsv_size_bytes{{{fs}}} 16777216"),
            format!("node_btrfs_reserved_bytes{{{reserved}}} 4096"),
            format!("node_btrfs_size_bytes{{{data}}} 3221225472"),
            format!("node_btrfs_used_bytes{{{data}}} 1073741824"),
            // Three devices in RAID 5: one of three bytes is parity.
            format!("node_btrfs_allocation_ratio{{{data}}} 1.5"),
            format!("node_btrfs_size_bytes{{{meta}}} 268435456"),
            format!("node_btrfs_allocation_ratio{{{meta}}} 2"),
        ];
        assert_eq!(text.lines().collect::<Vec<_>>(), expected, "{text}");
    }
}
