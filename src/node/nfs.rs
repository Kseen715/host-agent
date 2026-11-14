//! The kernel's NFS client and server counters, /proc/net/rpc/nfs and
//! nfsd: calls by protocol version and procedure, under node_exporter's
//! procedure names.

use super::{Node, host_text};
use crate::remote::Writer;
use std::collections::HashMap;
use std::io;

const V2: [&str; 18] = [
    "Null", "GetAttr", "SetAttr", "Root", "Lookup", "ReadLink", "Read",
    "WrCache", "Write", "Create", "Remove", "Rename", "Link", "SymLink",
    "MkDir", "RmDir", "ReadDir", "FsStat",
];

const V3: [&str; 22] = [
    "Null",
    "GetAttr",
    "SetAttr",
    "Lookup",
    "Access",
    "ReadLink",
    "Read",
    "Write",
    "Create",
    "MkDir",
    "SymLink",
    "MkNod",
    "Remove",
    "RmDir",
    "Rename",
    "Link",
    "ReadDir",
    "ReadDirPlus",
    "FsStat",
    "FsInfo",
    "PathConf",
    "Commit",
];

/// The client's NFSv4 procedures, in the kernel's order.
const V4_CLIENT: [&str; 59] = [
    "Null",
    "Read",
    "Write",
    "Commit",
    "Open",
    "OpenConfirm",
    "OpenNoattr",
    "OpenDowngrade",
    "Close",
    "Setattr",
    "FsInfo",
    "Renew",
    "SetClientID",
    "SetClientIDConfirm",
    "Lock",
    "Lockt",
    "Locku",
    "Access",
    "Getattr",
    "Lookup",
    "LookupRoot",
    "Remove",
    "Rename",
    "Link",
    "Symlink",
    "Create",
    "Pathconf",
    "StatFs",
    "ReadLink",
    "ReadDir",
    "ServerCaps",
    "DelegReturn",
    "GetACL",
    "SetACL",
    "FsLocations",
    "ReleaseLockowner",
    "Secinfo",
    "FsidPresent",
    "ExchangeID",
    "CreateSession",
    "DestroySession",
    "Sequence",
    "GetLeaseTime",
    "ReclaimComplete",
    "LayoutGet",
    "GetDeviceInfo",
    "LayoutCommit",
    "LayoutReturn",
    "SecinfoNoName",
    "TestStateID",
    "FreeStateID",
    "GetDeviceList",
    "BindConnToSession",
    "DestroyClientID",
    "Seek",
    "Allocate",
    "DeAllocate",
    "LayoutStats",
    "Clone",
];

/// The server's NFSv4 operations node_exporter exports, by operation
/// number (`proc4ops`).
const V4_SERVER: [(usize, &str); 33] = [
    (3, "Access"),
    (4, "Close"),
    (5, "Commit"),
    (6, "Create"),
    (7, "DelegPurge"),
    (8, "DelegReturn"),
    (9, "GetAttr"),
    (10, "GetFH"),
    (11, "Link"),
    (12, "Lock"),
    (13, "Lockt"),
    (14, "Locku"),
    (15, "Lookup"),
    (16, "LookupRoot"),
    (17, "Nverify"),
    (18, "Open"),
    (19, "OpenAttr"),
    (20, "OpenConfirm"),
    (21, "OpenDgrd"),
    (22, "PutFH"),
    (25, "Read"),
    (26, "ReadDir"),
    (27, "ReadLink"),
    (28, "Remove"),
    (29, "Rename"),
    (30, "Renew"),
    (31, "RestoreFH"),
    (32, "SaveFH"),
    (33, "SecInfo"),
    (34, "SetAttr"),
    (37, "Verify"),
    (38, "Write"),
    (39, "RelLockOwner"),
];

type Lines = HashMap<String, Vec<f64>>;

/// `key v1 v2...` lines; for `procN` and `proc4ops` the leading count
/// is dropped.
fn lines(text: &str) -> Lines {
    let mut lines = Lines::new();
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let Some(key) = fields.next() else { continue };
        let mut values: Vec<f64> =
            fields.map(|f| f.parse().unwrap_or(0.0)).collect();
        if key.starts_with("proc") && !values.is_empty() {
            values.remove(0);
        }
        lines.insert(key.to_owned(), values);
    }
    lines
}

fn value(lines: &Lines, key: &str, index: usize) -> f64 {
    lines
        .get(key)
        .and_then(|v| v.get(index))
        .copied()
        .unwrap_or(0.0)
}

pub fn client(_: &Node, w: &mut Writer) -> io::Result<()> {
    let lines = lines(&host_text("/proc/net/rpc/nfs")?);
    let net = |index| value(&lines, "net", index);
    for (index, protocol) in [(1, "udp"), (2, "tcp")] {
        let labels = [("protocol", protocol)];
        w.add("node_nfs_packets_total", &labels, net(index));
    }
    w.add("node_nfs_connections_total", &[], net(3));
    let rpc = |index| value(&lines, "rpc", index);
    w.add("node_nfs_rpcs_total", &[], rpc(0));
    w.add("node_nfs_rpc_retransmissions_total", &[], rpc(1));
    w.add("node_nfs_rpc_authentication_refreshes_total", &[], rpc(2));
    let versions: [(&str, &str, &[&str]); 3] = [
        ("proc2", "2", &V2),
        ("proc3", "3", &V3),
        ("proc4", "4", &V4_CLIENT),
    ];
    for (key, proto, names) in versions {
        for (index, method) in names.iter().enumerate() {
            let labels = [("method", *method), ("proto", proto)];
            let count = value(&lines, key, index);
            w.add("node_nfs_requests_total", &labels, count);
        }
    }
    Ok(())
}

pub fn server(_: &Node, w: &mut Writer) -> io::Result<()> {
    let lines = lines(&host_text("/proc/net/rpc/nfsd")?);
    let at = |key, index| value(&lines, key, index);
    let plain = [
        ("rc", 0, "reply_cache_hits_total"),
        ("rc", 1, "reply_cache_misses_total"),
        ("rc", 2, "reply_cache_nocache_total"),
        ("fh", 0, "file_handles_stale_total"),
        ("io", 0, "disk_bytes_read_total"),
        ("io", 1, "disk_bytes_written_total"),
        ("th", 0, "server_threads"),
        ("ra", 0, "read_ahead_cache_size_blocks"),
        ("ra", 11, "read_ahead_cache_not_found_total"),
        ("net", 3, "connections_total"),
        ("rpc", 0, "server_rpcs_total"),
    ];
    for (key, index, name) in plain {
        w.add(&format!("node_nfsd_{name}"), &[], at(key, index));
    }
    for (index, proto) in [(1, "udp"), (2, "tcp")] {
        let labels = [("proto", proto)];
        w.add("node_nfsd_packets_total", &labels, at("net", index));
    }
    for (index, error) in [(2, "fmt"), (3, "auth"), (4, "cInt")] {
        let labels = [("error", error)];
        w.add("node_nfsd_rpc_errors_total", &labels, at("rpc", index));
    }
    // The server's v2 and v3 counts leave out Null.
    let versions: [(&str, &str, &[&str]); 2] =
        [("proc2", "2", &V2), ("proc3", "3", &V3)];
    for (key, proto, names) in versions {
        for (index, method) in names.iter().enumerate().skip(1) {
            let labels = [("method", *method), ("proto", proto)];
            w.add("node_nfsd_requests_total", &labels, at(key, index));
        }
    }
    for (op, method) in V4_SERVER {
        let labels = [("method", method), ("proto", "4")];
        w.add("node_nfsd_requests_total", &labels, at("proc4ops", op));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drops_procedure_counts() {
        let lines = lines("net 1 2 3 4\nproc3 22 5 6\n");
        assert_eq!(value(&lines, "net", 3), 4.0);
        assert_eq!(value(&lines, "proc3", 1), 6.0);
        assert_eq!(value(&lines, "proc3", 9), 0.0);
    }
}
