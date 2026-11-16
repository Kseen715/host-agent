//! The host's own metrics under node_exporter's names and labels, as
//! Alloy's prometheus.exporter.unix gives them: the collectors the
//! homelab's dashboards and alerts read, with the filters of Alloy's
//! unix exporter (it keeps tmpfs and zram). Each
//! reports `node_scrape_collector_success` and its duration; one whose
//! source this host lacks (no NFS, no bonding) fails, as Alloy's does.

mod blockdev;
mod cpuinfo;
mod fabric;
#[cfg(feature = "filesystems")]
mod filesystems;
mod hardware;
mod ipvs;
mod kernel;
mod network;
mod nfs;
mod platform;
mod power;
mod storage;
mod system;
mod systemd;
mod textfile;
#[cfg(feature = "filesystems")]
mod zfs;

use crate::host;
use crate::remote::Writer;
pub use cpuinfo::known as cpuinfo_known;
use regex_lite::Regex;
use std::cell::RefCell;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Instant;

type Collect = fn(&Node, &mut Writer) -> io::Result<()>;

/// Alloy's unix exporter's Linux collectors, under its names.
const COLLECTORS: &[(&str, Collect)] = &[
    ("arp", kernel::arp),
    ("bcache", blockdev::bcache),
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
    ("fibrechannel", fabric::fibrechannel),
    ("filefd", system::filefd),
    ("filesystem", storage::filesystem),
    ("hwmon", hardware::hwmon),
    ("infiniband", fabric::infiniband),
    ("ipvs", ipvs::collect),
    ("loadavg", system::loadavg),
    ("mdadm", blockdev::mdadm),
    ("meminfo", system::meminfo),
    ("netclass", network::netclass),
    ("netdev", network::netdev),
    ("netstat", network::netstat),
    ("nfs", nfs::client),
    ("nfsd", nfs::server),
    ("nvme", platform::nvme),
    ("os", kernel::os),
    ("powersupplyclass", power::supplies),
    ("pressure", system::pressure),
    ("processes", kernel::processes),
    ("rapl", power::rapl),
    ("schedstat", kernel::schedstat),
    ("selinux", kernel::selinux),
    ("sockstat", kernel::sockstat),
    ("softnet", kernel::softnet),
    ("stat", system::stat),
    ("systemd", systemd::collect),
    ("tapestats", blockdev::tapestats),
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

/// prometheus.exporter.unix's collector settings; its filters are
/// regular expressions anchored as node_exporter anchors each.
pub struct Settings {
    pub enable: Vec<String>,
    pub disable: Vec<String>,
    /// In place of the default collectors.
    pub set: Option<Vec<String>>,
    pub textfile_dir: Option<PathBuf>,
    /// sysfs_path as configured: labels that name sysfs paths use it.
    pub sysfs: String,
    pub udev_data: String,
    pub arp: Filter,
    pub bcache_priority_stats: bool,
    pub cpu: CpuSettings,
    pub disk: Filter,
    pub fs_mount_points: Regex,
    pub fs_types: Regex,
    pub hwmon: Filter,
    /// The labels of node_ipvs_backend_*, in node_exporter's order.
    pub ipvs_labels: Vec<String>,
    pub netclass_ignored: Regex,
    pub netclass_invalid_speed: bool,
    pub netdev: Filter,
    pub netdev_address_info: bool,
    pub netstat_fields: Regex,
    pub power_supplies_ignored: Regex,
    pub systemd: SystemdSettings,
    pub tapes_ignored: Regex,
    pub vmstat_fields: Regex,
}

/// Alloy's defaults, which its configuration may change.
pub const NETSTAT_FIELDS: &str = "^(.*_(InErrors|InErrs)|Ip_Forwarding\
    |Ip(6|Ext)_(InOctets|OutOctets)|Icmp6?_(InMsgs|OutMsgs)\
    |TcpExt_(Listen.*|Syncookies.*|TCPSynRetrans|TCPTimeouts)\
    |Tcp_(ActiveOpens|InSegs|OutSegs|OutRsts|PassiveOpens|RetransSegs\
    |CurrEstab)|Udp6?_(InDatagrams|OutDatagrams|NoPorts|RcvbufErrors\
    |SndbufErrors))$";
pub const VMSTAT_FIELDS: &str = "^(oom_kill|pgpg|pswp|pg.*fault).*";
pub const FS_MOUNT_POINTS: &str =
    "^/(dev|proc|run/credentials/.+|sys|var/lib/docker/.+)($|/)";
pub const FS_TYPES: &str = "^(autofs|binfmt_misc|bpf|cgroup2?|configfs\
    |debugfs|devpts|devtmpfs|fusectl|hugetlbfs|iso9660|mqueue|nsfs|overlay\
    |proc|procfs|pstore|rpc_pipefs|securityfs|selinuxfs|squashfs|sysfs\
    |tracefs)$";
pub const DISK_EXCLUDE: &str =
    "^(ram|loop|fd|(h|s|v|xv)d[a-z]|nvme\\d+n\\d+p)\\d+$";
pub const SYSTEMD_UNIT_EXCLUDE: &str =
    ".+\\.(automount|device|mount|scope|slice)";
pub const IPVS_LABELS: [&str; 6] = [
    "local_address",
    "local_port",
    "remote_address",
    "remote_port",
    "proto",
    "local_mark",
];

/// node_exporter's device filter: a name is skipped if `exclude`
/// matches it, or `include` is given and does not.
#[derive(Default)]
pub struct Filter {
    pub exclude: Option<Regex>,
    pub include: Option<Regex>,
}

impl Filter {
    pub fn skips(&self, name: &str) -> bool {
        self.exclude.as_ref().is_some_and(|r| r.is_match(name))
            || self.include.as_ref().is_some_and(|r| !r.is_match(name))
    }
}

#[derive(Default)]
pub struct CpuSettings {
    pub guest: bool,
    pub info: bool,
    pub flags_include: Option<Regex>,
    pub bugs_include: Option<Regex>,
}

pub struct SystemdSettings {
    pub include: Regex,
    pub exclude: Regex,
    pub start_time: bool,
    pub restarts: bool,
    pub tasks: bool,
}

/// A regular expression from a default above.
pub fn regex(text: &str) -> Regex {
    Regex::new(text).expect("a valid default")
}

impl Default for Settings {
    fn default() -> Settings {
        Settings {
            enable: Vec::new(),
            disable: Vec::new(),
            set: None,
            textfile_dir: None,
            sysfs: "/sys".into(),
            udev_data: "/run/udev/data".into(),
            arp: Filter::default(),
            bcache_priority_stats: false,
            cpu: CpuSettings::default(),
            disk: Filter {
                exclude: Some(regex(DISK_EXCLUDE)),
                include: None,
            },
            fs_mount_points: regex(FS_MOUNT_POINTS),
            fs_types: regex(FS_TYPES),
            hwmon: Filter::default(),
            ipvs_labels: IPVS_LABELS.map(String::from).to_vec(),
            netclass_ignored: regex("^$"),
            netclass_invalid_speed: false,
            netdev: Filter::default(),
            netdev_address_info: false,
            netstat_fields: regex(NETSTAT_FIELDS),
            power_supplies_ignored: regex("^$"),
            systemd: SystemdSettings {
                include: regex("^(?:.+)$"),
                exclude: regex(&format!("^(?:{SYSTEMD_UNIT_EXCLUDE})$")),
                start_time: false,
                restarts: false,
                tasks: false,
            },
            tapes_ignored: regex("^$"),
            vmstat_fields: regex(VMSTAT_FIELDS),
        }
    }
}

/// Collectors Alloy runs only when asked.
const OFF_BY_DEFAULT: [&str; 2] = ["processes", "systemd"];

/// Whether this agent has the collector.
pub fn has_collector(name: &str) -> bool {
    COLLECTORS.iter().any(|(n, _)| *n == name)
}

pub struct Node {
    settings: Settings,
    service_types: RefCell<systemd::ServiceTypes>,
}

impl Node {
    pub fn new(settings: Settings) -> Node {
        Node {
            settings,
            service_types: RefCell::default(),
        }
    }

    fn runs(&self, name: &str) -> bool {
        let s = &self.settings;
        let listed = |names: &[String]| names.iter().any(|n| n == name);
        let chosen = match &s.set {
            Some(set) => listed(set),
            None => !OFF_BY_DEFAULT.contains(&name) || listed(&s.enable),
        };
        chosen && !listed(&s.disable)
    }

    pub fn collect(&self, w: &mut Writer) {
        crate::agent::build_info(w, "node_exporter_build_info");
        // node_exporter's handler counts its own failures; a round has
        // none to count.
        for cause in ["encoding", "gathering"] {
            let labels = [("cause", cause)];
            w.add("promhttp_metric_handler_errors_total", &labels, 0.0);
        }
        for (name, collect) in COLLECTORS {
            if !self.runs(name) {
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

/// A sysfs attribute, trimmed, as procfs's SysReadFile reads it.
fn sys_read(path: &Path) -> io::Result<String> {
    Ok(fs::read_to_string(path)?.trim().to_owned())
}

/// Errors procfs passes over when it reads a sysfs class's attributes:
/// the attribute is absent, or the device does not support it now.
fn unsupported(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::NotFound
            | io::ErrorKind::Unsupported
            | io::ErrorKind::InvalidInput
    ) || error.raw_os_error() == Some(libc::ENODEV)
}

fn invalid(what: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, what.to_string())
}

/// An integer as Go's ParseInt reads it with base 0: `0x1f`, `0o17`,
/// `017`, `0b1`, `1_000`.
fn go_int(text: &str) -> io::Result<i64> {
    let (negative, digits) = match text.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, text.strip_prefix('+').unwrap_or(text)),
    };
    let value = go_uint(digits)?;
    let value = i64::try_from(value).map_err(|_| invalid(text))?;
    Ok(if negative { -value } else { value })
}

fn go_uint(text: &str) -> io::Result<u64> {
    let lower = text.to_ascii_lowercase();
    let (radix, digits) = if let Some(hex) = lower.strip_prefix("0x") {
        (16, hex)
    } else if let Some(octal) = lower.strip_prefix("0o") {
        (8, octal)
    } else if let Some(binary) = lower.strip_prefix("0b") {
        (2, binary)
    } else if lower.len() > 1 && lower.starts_with('0') {
        (8, &lower[1..])
    } else {
        (10, lower.as_str())
    };
    let digits = digits.replace('_', "");
    u64::from_str_radix(&digits, radix).map_err(|_| invalid(text))
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
        let node = Node::new(Settings::default());
        assert!(node.runs("cpu") && !node.runs("systemd"));
        assert!(!node.runs("processes"));
        let s = &node.settings;
        assert!(s.netstat_fields.is_match("Tcp_CurrEstab"));
        assert!(s.netstat_fields.is_match("Udp6_InErrors"));
        assert!(!s.netstat_fields.is_match("TcpExt_TCPOFOQueue"));
        assert!(s.vmstat_fields.is_match("pgmajfault"));
        assert!(s.fs_mount_points.is_match("/var/lib/docker/overlay2/x"));
        assert!(!s.fs_mount_points.is_match("/var/lib/docker"));
        assert!(s.fs_types.is_match("overlay"));
        assert!(!s.fs_types.is_match("tmpfs"));
        assert!(s.disk.skips("nvme0n1p2"));
        assert!(!s.disk.skips("zram0"));
        assert!(!s.disk.skips("dm-0"));
        assert!(s.systemd.exclude.is_match("user.slice"));
        assert!(!s.systemd.exclude.is_match("ssh.service"));
    }
}

/// A sysfs directory for a test: each file's path under `dir` and its
/// text.
#[cfg(test)]
fn sysfs(dir: &Path, files: &[(&str, &str)]) {
    for (path, text) in files {
        let path = dir.join(path);
        fs::create_dir_all(path.parent().expect("a file in a directory"))
            .unwrap();
        fs::write(path, text).unwrap();
    }
}

/// The collectors on the Linux the tests run on, its /proc read as is:
/// what they report is checked against the kernel's own files.
#[cfg(test)]
mod host_tests {
    use super::*;

    /// Collectors whose sources every Linux has, in a VM or container.
    const EVERYWHERE: [&str; 11] = [
        "cpu", "filefd", "loadavg", "meminfo", "netdev", "netstat", "sockstat",
        "stat", "time", "uname", "vmstat",
    ];

    fn round(settings: Settings) -> String {
        let mut w = Writer::text();
        Node::new(settings).collect(&mut w);
        w.into_text()
    }

    fn set(names: &[&str]) -> Settings {
        let names = names.iter().map(|n| (*n).to_owned()).collect();
        Settings {
            set: Some(names),
            ..Settings::default()
        }
    }

    /// The value of the first series starting with `series`.
    fn value(text: &str, series: &str) -> Option<f64> {
        let line = text.lines().find(|l| l.starts_with(series))?;
        line.rsplit_once(' ')?.1.parse().ok()
    }

    fn kernel(path: &str) -> String {
        fs::read_to_string(path).unwrap()
    }

    #[test]
    fn every_linux_collector_reads_this_host() {
        let text = round(set(&EVERYWHERE));
        for name in EVERYWHERE {
            let series = format!(
                "node_scrape_collector_success{{collector=\"{name}\"}} 1"
            );
            assert!(text.contains(&series), "{name} failed:\n{text}");
        }
        let total = kernel("/proc/meminfo");
        let total = total.lines().find_map(|l| l.strip_prefix("MemTotal:"));
        let kib: f64 = total
            .unwrap()
            .trim()
            .trim_end_matches(" kB")
            .parse()
            .unwrap();
        let reported = value(&text, "node_memory_MemTotal_bytes ");
        assert_eq!(reported, Some(kib * 1024.0));
        let boot = value(&text, "node_boot_time_seconds ");
        assert_eq!(boot, Some(host::boot_time()));
        let release = kernel("/proc/sys/kernel/osrelease");
        let release = format!("release=\"{}\"", release.trim());
        let uname = text.lines().find(|l| l.starts_with("node_uname_info"));
        assert!(uname.unwrap().contains(&release), "{uname:?}");
        let idle = "node_cpu_seconds_total{cpu=\"0\",mode=\"idle\"} ";
        assert!(value(&text, idle).unwrap() > 0.0);
        let lo = "node_network_receive_bytes_total{device=\"lo\"} ";
        assert!(value(&text, lo).is_some());
        let now = crate::time::now_ms() as f64 / 1e3;
        let clock = value(&text, "node_time_seconds ").unwrap();
        assert!((clock - now).abs() < 60.0, "{clock} vs {now}");
        assert!(value(&text, "node_load1 ").unwrap() >= 0.0);
    }

    /// Only the fields Alloy's defaults let through.
    #[test]
    fn netstat_and_vmstat_keep_their_default_fields() {
        let text = round(set(&["netstat", "vmstat"]));
        assert!(text.contains("node_netstat_Tcp_CurrEstab "));
        assert!(!text.contains("node_netstat_TcpExt_TCPOFOQueue "));
        assert!(text.contains("node_vmstat_pgfault "));
        assert!(!text.contains("node_vmstat_nr_free_pages "));
    }

    #[test]
    fn filters_devices_and_collectors() {
        let mut settings = set(&["netdev", "loadavg"]);
        settings.netdev.include = Some(regex("^lo$"));
        settings.disable = vec!["loadavg".into()];
        let text = round(settings);
        let devices: Vec<&str> = text
            .lines()
            .filter(|l| l.starts_with("node_network_receive_bytes_total"))
            .collect();
        assert_eq!(devices.len(), 1, "{devices:?}");
        assert!(devices[0].contains("device=\"lo\""));
        assert!(!text.contains("collector=\"loadavg\""));
        let text = round(Settings {
            enable: vec!["processes".into()],
            ..Settings::default()
        });
        assert!(text.contains("collector=\"processes\"} 1"));
        assert!(!text.contains("collector=\"systemd\""));
        assert!(text.contains("node_exporter_build_info{"));
    }

    /// What only a setting turns on: /proc/cpuinfo's CPUs, the flags
    /// let through, and the addresses of the interfaces.
    #[test]
    fn reports_cpu_info_and_addresses_when_asked() {
        let mut settings = set(&["cpu", "netdev"]);
        settings.cpu.info = true;
        settings.cpu.flags_include = Some(regex("^(fpu|sse2)$"));
        settings.netdev_address_info = true;
        let text = round(settings);
        let count = |prefix: &str| {
            text.lines().filter(|l| l.starts_with(prefix)).count()
        };
        let cpuinfo = kernel("/proc/cpuinfo");
        let processors = cpuinfo.lines().filter(|l| l.starts_with("processor"));
        let processors = processors.count();
        assert_eq!(count("node_cpu_info{"), processors);
        // Without cpufreq, the frequencies are cpuinfo's.
        assert_eq!(count("node_cpu_frequency_hertz{"), processors);
        #[cfg(target_arch = "x86_64")]
        assert_eq!(count("node_cpu_flag_info{"), 2, "{text}");
        let lo = concat!(
            r#"node_network_address_info{address="127.0.0.1","#,
            r#"device="lo",netmask="8",scope="link-local"} 1"#
        );
        assert!(text.lines().any(|l| l == lo), "{text}");
    }

    /// Each collector, its source on this host or not, says once
    /// whether it succeeded.
    #[test]
    fn every_collector_reports_success_once() {
        let names: Vec<&str> = COLLECTORS.iter().map(|(n, _)| *n).collect();
        let text = round(set(&names));
        for name in names {
            let series = format!(
                "node_scrape_collector_success{{collector=\"{name}\"}}"
            );
            assert_eq!(text.matches(&series).count(), 1, "{name}");
        }
    }
}
