//! The host's own metrics under node_exporter's names and labels, job
//! `node`: the collectors the homelab's dashboards and alerts read, with
//! the filters of Alloy's unix exporter (it keeps tmpfs and zram). Each
//! reports `node_scrape_collector_success` and its duration; one whose
//! source this host lacks (no NFS, no bonding) fails, as Alloy's does.

#[cfg(feature = "filesystems")]
mod filesystems;
mod hardware;
mod kernel;
mod network;
mod nfs;
mod platform;
mod storage;
mod system;
mod systemd;
mod textfile;
#[cfg(feature = "filesystems")]
mod zfs;

use crate::host;
use crate::remote::Writer;
use regex_lite::Regex;
use std::cell::RefCell;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Instant;

type Collect = fn(&Node, &mut Writer) -> io::Result<()>;

/// Alloy's unix exporter's default collectors that report something
/// on some host here, under its names.
const COLLECTORS: &[(&str, Collect)] = &[
    ("arp", kernel::arp),
    ("bonding", network::bonding),
    #[cfg(feature = "filesystems")]
    ("btrfs", filesystems::btrfs),
    ("conntrack", system::conntrack),
    ("cpu", system::cpu),
    ("cpufreq", hardware::cpufreq),
    ("diskstats", storage::diskstats),
    ("dmi", platform::dmi),
    ("edac", platform::edac),
    ("entropy", system::entropy),
    ("filefd", system::filefd),
    ("filesystem", storage::filesystem),
    ("hwmon", hardware::hwmon),
    ("loadavg", system::loadavg),
    ("meminfo", system::meminfo),
    ("netclass", network::netclass),
    ("netdev", network::netdev),
    ("netstat", network::netstat),
    ("nfs", nfs::client),
    ("nfsd", nfs::server),
    ("nvme", platform::nvme),
    ("os", kernel::os),
    ("pressure", system::pressure),
    ("processes", kernel::processes),
    ("schedstat", kernel::schedstat),
    ("selinux", kernel::selinux),
    ("sockstat", kernel::sockstat),
    ("softnet", kernel::softnet),
    ("stat", system::stat),
    ("systemd", systemd::collect),
    ("textfile", textfile::collect),
    ("thermal_zone", hardware::thermal_zone),
    ("time", system::time),
    ("timex", kernel::timex),
    ("udp_queues", kernel::udp_queues),
    ("uname", system::uname),
    ("vmstat", system::vmstat),
    #[cfg(feature = "filesystems")]
    ("xfs", filesystems::xfs),
    #[cfg(feature = "filesystems")]
    ("zfs", zfs::collect),
];

pub struct Node {
    disabled: Vec<String>,
    service_types: RefCell<systemd::ServiceTypes>,
    textfile_dir: Option<PathBuf>,
    netstat_fields: Regex,
    vmstat_fields: Regex,
    fs_mount_points: Regex,
    fs_types: Regex,
    disk_devices: Regex,
}

impl Node {
    pub fn new(disabled: Vec<String>, textfile_dir: Option<PathBuf>) -> Node {
        let regex = |text: &str| Regex::new(text).expect("a valid default");
        Node {
            disabled,
            service_types: RefCell::default(),
            textfile_dir,
            netstat_fields: regex(
                "^(.*_(InErrors|InErrs)|Ip_Forwarding|Ip(6|Ext)_(InOctets\
                 |OutOctets)|Icmp6?_(InMsgs|OutMsgs)|TcpExt_(Listen.*\
                 |Syncookies.*|TCPSynRetrans|TCPTimeouts)|Tcp_(ActiveOpens\
                 |InSegs|OutSegs|OutRsts|PassiveOpens|RetransSegs|CurrEstab)\
                 |Udp6?_(InDatagrams|OutDatagrams|NoPorts|RcvbufErrors\
                 |SndbufErrors))$",
            ),
            vmstat_fields: regex("^(oom_kill|pgpg|pswp|pg.*fault).*"),
            fs_mount_points: regex(
                "^/(dev|proc|run/credentials/.+|sys|var/lib/docker/.+\
                 |var/lib/containers/storage/.+)($|/)",
            ),
            fs_types: regex(
                "^(autofs|binfmt_misc|bpf|cgroup2?|configfs|debugfs|devpts\
                 |devtmpfs|fusectl|hugetlbfs|iso9660|mqueue|nsfs\
                 |overlay|proc|procfs|pstore|rpc_pipefs|securityfs\
                 |selinuxfs|squashfs|erofs|sysfs|tracefs)$",
            ),
            disk_devices: regex(
                "^(ram|loop|fd|(h|s|v|xv)d[a-z]|nvme\\d+n\\d+p)\\d+$",
            ),
        }
    }

    pub fn collect(&self, w: &mut Writer) {
        w.target("node", &[]);
        w.up(true);
        crate::agent::build_info(w, "node_exporter_build_info");
        for (name, collect) in COLLECTORS {
            if self.disabled.iter().any(|d| d == name) {
                continue;
            }
            let start = Instant::now();
            let ok = match collect(self, w) {
                Ok(()) => true,
                Err(error) if error.kind() == io::ErrorKind::NotFound => false,
                Err(error) => {
                    eprintln!("Collector {name}: {error}");
                    false
                }
            };
            let labels = [("collector", *name)];
            let seconds = start.elapsed().as_secs_f64();
            w.add("node_scrape_collector_duration_seconds", &labels, seconds);
            let value = if ok { 1.0 } else { 0.0 };
            w.add("node_scrape_collector_success", &labels, value);
        }
    }
}

/// The error of a collector whose source this host lacks.
fn absent(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::NotFound, what)
}

/// A host file's text (`/proc/...`), or NotFound.
fn host_text(path: &str) -> io::Result<String> {
    fs::read_to_string(host::path(path))
}

/// A file's text, trimmed.
fn read(path: impl AsRef<Path>) -> Option<String> {
    let text = fs::read_to_string(path).ok()?;
    Some(text.trim().to_owned())
}

fn number(path: impl AsRef<Path>) -> Option<f64> {
    read(path)?.parse().ok()
}

/// Entries of a host's sysfs class directory whose names start with
/// `prefix`, with what follows it: `thermal_zone3` and `3`.
fn numbered(dir: &str, prefix: &str) -> Vec<(PathBuf, String)> {
    entries(&host::path(dir), prefix)
}

/// As `numbered`, in a directory already found on the host.
fn entries(dir: &Path, prefix: &str) -> Vec<(PathBuf, String)> {
    let mut found: Vec<(PathBuf, String)> = fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name().into_string().ok()?;
            let rest = name.strip_prefix(prefix)?.to_owned();
            Some((entry.path(), rest))
        })
        .collect();
    found.sort();
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_filters_compile_and_match_alloys() {
        let node = Node::new(Vec::new(), None);
        assert!(node.netstat_fields.is_match("Tcp_CurrEstab"));
        assert!(node.netstat_fields.is_match("Udp6_InErrors"));
        assert!(!node.netstat_fields.is_match("TcpExt_TCPOFOQueue"));
        assert!(node.vmstat_fields.is_match("pgmajfault"));
        assert!(node.fs_mount_points.is_match("/var/lib/docker/overlay2/x"));
        assert!(!node.fs_mount_points.is_match("/var/lib/docker"));
        assert!(node.fs_types.is_match("overlay"));
        assert!(!node.fs_types.is_match("tmpfs"));
        assert!(node.disk_devices.is_match("nvme0n1p2"));
        assert!(!node.disk_devices.is_match("zram0"));
        assert!(!node.disk_devices.is_match("dm-0"));
    }
}
