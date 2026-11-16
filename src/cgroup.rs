//! A cgroup's numbers in v2's terms, as cAdvisor reads them: from v2's
//! single tree, or from v1's tree per controller (Docker on cgroup v1,
//! as on Unraid 6).

use crate::host;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// v1 counts CPU time in USER_HZ ticks, 100 a second.
const TICKS: f64 = 100.0;
/// v1's limits from here up mean none (i64::MAX rounded down to a
/// page): cAdvisor reports them as 0.
const UNLIMITED: f64 = 4.6e18;
/// v1's memory.stat totals (the cgroup with its children) by v2's
/// names.
const V1_MEMORY_STAT: [(&str, &str); 7] = [
    ("total_rss", "anon"),
    ("total_cache", "file"),
    ("total_mapped_file", "file_mapped"),
    ("total_dirty", "file_dirty"),
    ("total_writeback", "file_writeback"),
    ("total_active_file", "active_file"),
    ("total_inactive_file", "inactive_file"),
];
const PRESSURE: [&str; 3] = ["cpu", "io", "memory"];

pub enum Cgroup {
    V2(PathBuf),
    /// Each controller's directory.
    V1(Vec<(String, PathBuf)>),
}

pub struct Cpu {
    /// Seconds used by cAdvisor's `cpu` label: v2 gives the `total`, v1
    /// each CPU's.
    pub usage: Vec<(String, f64)>,
    pub user: Option<f64>,
    pub system: Option<f64>,
}

#[derive(Default)]
pub struct Memory {
    pub usage: f64,
    /// memory.stat by v2's names.
    pub stat: Vec<(String, f64)>,
    pub swap: f64,
    pub peak: f64,
    pub failcnt: f64,
    pub kernel: f64,
    /// `pgfault` and `pgmajfault`: the cgroup's own, and with its
    /// children.
    pub faults: [(f64, f64); 2],
    pub high: f64,
    pub max: f64,
    pub oom_kills: f64,
}

pub struct DeviceIo {
    /// `major:minor`.
    pub numbers: String,
    pub read_bytes: f64,
    pub write_bytes: f64,
    pub reads: f64,
    pub writes: f64,
    /// Bytes by blkio's operation names.
    pub by_operation: Vec<(String, f64)>,
}

/// The limits, cAdvisor's `spec`; none set is 0.
pub struct Spec {
    pub period: f64,
    pub quota: Option<f64>,
    pub shares: f64,
    /// Limit, reservation, swap limit; None without the memory
    /// controller.
    pub memory: Option<(f64, f64, f64)>,
}

fn unified() -> bool {
    host::path("/sys/fs/cgroup/cgroup.controllers").exists()
}

impl Cgroup {
    /// The host's root cgroup, cAdvisor's container `/`.
    pub fn root() -> Cgroup {
        if unified() {
            return Cgroup::V2(host::path("/sys/fs/cgroup"));
        }
        Cgroup::V1(v1_dirs(&read(host::path("/proc/1/cgroup")), true))
    }

    /// Every cgroup under the root but itself, by path (cAdvisor's
    /// `id`), parents first: those of the memory controller on v1.
    pub fn all() -> Vec<(String, Cgroup)> {
        let root = Cgroup::root();
        let mut paths = Vec::new();
        below(&root.file("memory", ""), "", &mut paths);
        paths
            .into_iter()
            .map(|path| {
                let under = |dir: &PathBuf| dir.join(&path[1..]);
                let cgroup = match &root {
                    Cgroup::V2(dir) => Cgroup::V2(under(dir)),
                    Cgroup::V1(dirs) => Cgroup::V1(
                        dirs.iter()
                            .map(|(c, d)| (c.clone(), under(d)))
                            .collect(),
                    ),
                };
                (path, cgroup)
            })
            .collect()
    }

    /// When the cgroup was made, as cAdvisor's raw handler takes it: its
    /// directory's modification time, in seconds.
    pub fn created(&self) -> f64 {
        let meta = fs::metadata(self.file("memory", ""));
        meta.map_or(0.0, |m| m.mtime() as f64)
    }

    /// The process's cgroup path (cAdvisor's `id`) and its cgroup. A
    /// path without the container's id is another process: Docker runs
    /// in another PID namespace (Docker Desktop), or the PID was reused.
    pub fn of(pid: u32, container: &str) -> Option<(String, Cgroup)> {
        let text = read(host::path(&format!("/proc/{pid}/cgroup")));
        let (path, cgroup) = if unified() {
            let path = text.lines().find_map(|l| l.strip_prefix("0::"))?;
            let dir = host::path(&format!("/sys/fs/cgroup{path}"));
            (path, Cgroup::V2(dir))
        } else {
            let memory = text.lines().find_map(|line| {
                let [_, controllers, path] = fields(line)?;
                controllers
                    .split(',')
                    .any(|c| c == "memory")
                    .then_some(path)
            })?;
            (memory, Cgroup::V1(v1_dirs(&text, false)))
        };
        let found =
            path.contains(container) && cgroup.file("memory", "").is_dir();
        found.then(|| (path.to_owned(), cgroup))
    }

    fn file(&self, controller: &str, name: &str) -> PathBuf {
        match self {
            Cgroup::V2(dir) => dir.join(name),
            Cgroup::V1(dirs) => dirs
                .iter()
                .find(|(c, _)| c == controller)
                .map_or_else(PathBuf::new, |(_, dir)| dir.join(name)),
        }
    }

    pub fn cpu(&self) -> Cpu {
        if let Cgroup::V2(_) = self {
            let stat = stat(self.file("cpu", "cpu.stat"));
            let seconds = |key| find(&stat, key).map(|usec| usec / 1e6);
            let usage = seconds("usage_usec").map(|s| ("total".into(), s));
            return Cpu {
                usage: usage.into_iter().collect(),
                user: seconds("user_usec"),
                system: seconds("system_usec"),
            };
        }
        let per_cpu = read(self.file("cpuacct", "cpuacct.usage_percpu"));
        let usage = per_cpu.split_whitespace().enumerate();
        let usage = usage.filter_map(|(cpu, ns)| {
            Some((format!("cpu{cpu:02}"), ns.parse::<f64>().ok()? / 1e9))
        });
        let stat = stat(self.file("cpuacct", "cpuacct.stat"));
        let seconds = |key| find(&stat, key).map(|ticks| ticks / TICKS);
        Cpu {
            usage: usage.collect(),
            user: seconds("user"),
            system: seconds("system"),
        }
    }

    /// Without the memory controller (not delegated, as in an LXC that
    /// does not enable it), zeros, as cAdvisor reports.
    pub fn memory(&self) -> Memory {
        let memory = match self {
            Cgroup::V2(_) => self.memory_v2(),
            Cgroup::V1(_) => self.memory_v1(),
        };
        memory.unwrap_or_default()
    }

    /// The host's root cgroup has no memory.current: anon + file stands
    /// in, as runc does.
    fn memory_v2(&self) -> Option<Memory> {
        let file = |name| self.file("memory", name);
        let stat = stat(file("memory.stat"));
        let usage = value(file("memory.current"))
            .or_else(|| Some(find(&stat, "anon")? + find(&stat, "file")?))?;
        let faults = ["pgfault", "pgmajfault"].map(|kind| {
            let count = find(&stat, kind).unwrap_or(0.0);
            (count, count)
        });
        let events = self::stat(file("memory.events"));
        let event = |key| find(&events, key).unwrap_or(0.0);
        Some(Memory {
            usage,
            swap: value(file("memory.swap.current")).unwrap_or(0.0),
            peak: value(file("memory.peak")).unwrap_or(0.0),
            failcnt: 0.0,
            kernel: 0.0,
            faults,
            high: event("high"),
            max: event("max"),
            oom_kills: event("oom_kill"),
            stat,
        })
    }

    /// v1 counts swap with memory (memsw). Its faults are the cgroup's
    /// own in both scopes, as cAdvisor reports them (the root's
    /// total_pgfault is larger).
    fn memory_v1(&self) -> Option<Memory> {
        let file = |name| self.file("memory", name);
        let number = |name| value(file(name)).unwrap_or(0.0);
        let usage = value(file("memory.usage_in_bytes"))?;
        let own = stat(file("memory.stat"));
        let count = |key| find(&own, key).unwrap_or(0.0);
        let renamed = V1_MEMORY_STAT
            .iter()
            .filter_map(|(v1, v2)| Some(((*v2).to_owned(), find(&own, v1)?)));
        let with_swap = value(file("memory.memsw.usage_in_bytes"));
        let oom = stat(file("memory.oom_control"));
        Some(Memory {
            usage,
            stat: renamed.collect(),
            swap: with_swap.map_or(0.0, |all| all - usage),
            peak: number("memory.max_usage_in_bytes"),
            failcnt: number("memory.failcnt"),
            kernel: number("memory.kmem.usage_in_bytes"),
            faults: ["pgfault", "pgmajfault"].map(|k| (count(k), count(k))),
            high: 0.0,
            max: 0.0,
            oom_kills: find(&oom, "oom_kill").unwrap_or(0.0),
        })
    }

    pub fn io(&self) -> Vec<DeviceIo> {
        match self {
            Cgroup::V2(_) => self.io_v2(),
            Cgroup::V1(_) => self.io_v1(),
        }
    }

    /// io.stat: `8:0 rbytes=1 wbytes=2 rios=3 wios=4 ...` per device.
    fn io_v2(&self) -> Vec<DeviceIo> {
        let text = read(self.file("io", "io.stat"));
        let devices = text.lines().filter_map(|line| {
            let mut fields = line.split_whitespace();
            let numbers = fields.next()?.to_owned();
            let pairs: Vec<(&str, f64)> = fields
                .filter_map(|f| f.split_once('='))
                .filter_map(|(key, v)| Some((key, v.parse().ok()?)))
                .collect();
            let get = |key| pairs.iter().find(|(k, _)| *k == key);
            let get = |key| get(key).map_or(0.0, |(_, v)| *v);
            Some(DeviceIo {
                numbers,
                read_bytes: get("rbytes"),
                write_bytes: get("wbytes"),
                reads: get("rios"),
                writes: get("wios"),
                by_operation: vec![
                    ("Read".into(), get("rbytes")),
                    ("Write".into(), get("wbytes")),
                ],
            })
        });
        devices.collect()
    }

    fn io_v1(&self) -> Vec<DeviceIo> {
        let file = |name| self.file("blkio", name);
        let bytes = blkio(file("blkio.throttle.io_service_bytes"));
        let counts = blkio(file("blkio.throttle.io_serviced"));
        let get = |list: &[(String, f64)], operation: &str| {
            let found = list.iter().find(|(o, _)| o == operation);
            found.map_or(0.0, |(_, v)| *v)
        };
        let devices = bytes.into_iter().map(|(numbers, by_operation)| {
            let count = counts.iter().find(|(n, _)| *n == numbers);
            let count = count.map_or(&[][..], |(_, list)| list);
            DeviceIo {
                read_bytes: get(&by_operation, "Read"),
                write_bytes: get(&by_operation, "Write"),
                reads: get(count, "Read"),
                writes: get(count, "Write"),
                numbers,
                by_operation,
            }
        });
        devices.collect()
    }

    /// Seconds the cgroup's tasks waited (`some`) or all stalled
    /// (`full`), by resource; v1 has none, which cAdvisor reports as 0.
    pub fn pressure(&self) -> Vec<(&'static str, &'static str, f64)> {
        let mut found = Vec::new();
        for resource in PRESSURE {
            if let Cgroup::V1(_) = self {
                found.extend([(resource, "waiting", 0.0)]);
                found.extend([(resource, "stalled", 0.0)]);
                continue;
            }
            let name = format!("{resource}.pressure");
            for line in read(self.file(resource, &name)).lines() {
                let (kind, rest) = line.split_once(' ').unwrap_or((line, ""));
                let what = if kind == "some" { "waiting" } else { "stalled" };
                let total =
                    rest.split(' ').find_map(|f| f.strip_prefix("total="));
                let usec = total.and_then(|t| t.parse().ok()).unwrap_or(0.0);
                found.push((resource, what, usec / 1e6));
            }
        }
        found
    }

    pub fn spec(&self) -> Spec {
        match self {
            Cgroup::V2(_) => self.spec_v2(),
            Cgroup::V1(_) => self.spec_v1(),
        }
    }

    /// Shares from v2's weight, as runc converts them.
    fn spec_v2(&self) -> Spec {
        let max = read(self.file("cpu", "cpu.max"));
        let mut max = max.split_whitespace();
        let (quota, period) = (max.next(), max.next());
        let weight = value(self.file("cpu", "cpu.weight")).unwrap_or(0.0);
        let shares = match weight as u64 {
            0 => 0,
            weight => 2 + ((weight - 1) * 262_142) / 9_999,
        };
        let memory = |name| value(self.file("memory", name));
        let limits = memory("memory.max").map(|max| {
            let low = memory("memory.low").unwrap_or(0.0);
            (max, low, memory("memory.swap.max").unwrap_or(0.0))
        });
        Spec {
            period: period.and_then(|p| p.parse().ok()).unwrap_or(0.0),
            quota: quota.and_then(|q| q.parse().ok()),
            shares: shares as f64,
            memory: limits,
        }
    }

    /// A quota of -1 is none.
    fn spec_v1(&self) -> Spec {
        let number = |controller, name| {
            let found = value(self.file(controller, name));
            found.filter(|v| *v < UNLIMITED).unwrap_or(0.0)
        };
        let quota = value(self.file("cpu", "cpu.cfs_quota_us"));
        let limit = self.file("memory", "memory.limit_in_bytes");
        let limits = limit.exists().then(|| {
            let memory = |name| number("memory", name);
            (
                memory("memory.limit_in_bytes"),
                memory("memory.soft_limit_in_bytes"),
                memory("memory.memsw.limit_in_bytes"),
            )
        });
        Spec {
            period: number("cpu", "cpu.cfs_period_us"),
            quota: quota.filter(|q| *q > 0.0),
            shares: number("cpu", "cpu.shares"),
            memory: limits,
        }
    }
}

/// `hierarchy:controllers:path`.
fn fields(line: &str) -> Option<[&str; 3]> {
    let mut fields = line.splitn(3, ':');
    Some([fields.next()?, fields.next()?, fields.next()?])
}

/// Each v1 controller's directory, from /proc/<pid>/cgroup: each
/// hierarchy is mounted under its controllers' names (`cpu,cpuacct`).
/// `root`: the hierarchies' roots instead of the process's cgroups.
fn below(dir: &Path, path: &str, found: &mut Vec<String>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    let mut children: Vec<_> = entries
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    children.sort();
    for child in children {
        let path = format!("{path}/{child}");
        found.push(path.clone());
        below(&dir.join(&child), &path, found);
    }
}

fn v1_dirs(text: &str, root: bool) -> Vec<(String, PathBuf)> {
    let mut dirs = Vec::new();
    for [_, controllers, path] in text.lines().filter_map(fields) {
        if controllers.is_empty() || controllers.starts_with("name=") {
            continue;
        }
        let path = if root { "" } else { path };
        let dir = host::path(&format!("/sys/fs/cgroup/{controllers}{path}"));
        let names = controllers.split(',');
        dirs.extend(names.map(|name| (name.to_owned(), dir.clone())));
    }
    dirs
}

/// blkio's `major:minor Operation value` lines, by device in file order.
fn blkio(path: PathBuf) -> Vec<(String, Vec<(String, f64)>)> {
    let mut devices: Vec<(String, Vec<(String, f64)>)> = Vec::new();
    for line in read(path).lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let [numbers, operation, value] = fields[..] else {
            continue;
        };
        let entry = (operation.to_owned(), value.parse().unwrap_or(0.0));
        match devices.iter_mut().find(|(n, _)| n == numbers) {
            Some((_, operations)) => operations.push(entry),
            None => devices.push((numbers.to_owned(), vec![entry])),
        }
    }
    devices
}

fn read(path: PathBuf) -> String {
    fs::read_to_string(path).unwrap_or_default()
}

/// `key value` lines, as cpu.stat and memory.stat are.
fn stat(path: PathBuf) -> Vec<(String, f64)> {
    let text = read(path);
    let pairs = text.lines().filter_map(|line| {
        let (key, value) = line.split_once(' ')?;
        Some((key.to_owned(), value.trim().parse().ok()?))
    });
    pairs.collect()
}

pub fn find(pairs: &[(String, f64)], key: &str) -> Option<f64> {
    pairs.iter().find(|(k, _)| k == key).map(|(_, v)| *v)
}

/// A one-value file; `max` (no limit) is 0, as cAdvisor reports it.
fn value(path: PathBuf) -> Option<f64> {
    match read(path).trim() {
        "max" => Some(0.0),
        value => value.parse().ok(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_v1_hierarchies() {
        let text = "13:name=elogind:/docker/a\n3:cpuacct:/docker/a\n\
                    2:cpu,cpuacct:/docker/a\n0::/";
        let dirs = v1_dirs(text, false);
        let names: Vec<&str> = dirs.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, ["cpuacct", "cpu", "cpuacct"]);
        assert!(dirs[1].1.ends_with("cpu,cpuacct/docker/a"));
        assert!(v1_dirs(text, true)[0].1.ends_with("cgroup/cpuacct"));
    }

    #[test]
    fn groups_blkio_by_device() {
        let dir =
            std::env::temp_dir().join(format!("blkio-{}", std::process::id()));
        fs::write(&dir, "9:2 Read 5\n9:2 Write 6\n7:2 Read 1\nTotal 12\n")
            .unwrap();
        let devices = blkio(dir.clone());
        assert_eq!(devices.len(), 2);
        assert_eq!(devices[0].1, [("Read".into(), 5.0), ("Write".into(), 6.0)]);
        fs::remove_file(dir).unwrap();
    }

    fn write_all(dir: &Path, files: &[(&str, &str)]) {
        fs::create_dir_all(dir).unwrap();
        for (name, text) in files {
            fs::write(dir.join(name), text).unwrap();
        }
    }

    /// A container's cgroup v2 directory, as the kernel writes it.
    #[test]
    fn reads_a_v2_cgroup() {
        let dir = crate::testing::scratch("cgroup-v2");
        write_all(
            &dir,
            &[
                (
                    "cpu.stat",
                    "usage_usec 2500000\nuser_usec 2000000\n\
                    system_usec 500000\n",
                ),
                ("memory.current", "1048576\n"),
                (
                    "memory.stat",
                    "anon 4096\nfile 8192\npgfault 7\n\
                    pgmajfault 2\n",
                ),
                (
                    "memory.events",
                    "low 0\nhigh 3\nmax 4\noom 1\n\
                    oom_kill 1\n",
                ),
                ("memory.swap.current", "0\n"),
                ("memory.peak", "2097152\n"),
                ("memory.max", "max\n"),
                ("memory.low", "65536\n"),
                (
                    "io.stat",
                    "8:0 rbytes=10 wbytes=20 rios=1 wios=2 \
                    dbytes=0 dios=0\n259:0 rbytes=5\n",
                ),
                ("cpu.max", "50000 100000\n"),
                ("cpu.weight", "10000\n"),
                (
                    "cpu.pressure",
                    "some avg10=0.00 avg60=0.00 \
                    avg300=0.00 total=1500000\n\
                    full avg10=0.00 avg60=0.00 avg300=0.00 total=500000\n",
                ),
            ],
        );
        let cgroup = Cgroup::V2(dir.clone());
        let cpu = cgroup.cpu();
        assert_eq!(cpu.usage, [("total".to_owned(), 2.5)]);
        assert_eq!((cpu.user, cpu.system), (Some(2.0), Some(0.5)));
        let memory = cgroup.memory();
        assert_eq!((memory.usage, memory.peak), (1_048_576.0, 2_097_152.0));
        assert_eq!(memory.faults, [(7.0, 7.0), (2.0, 2.0)]);
        assert_eq!(
            (memory.high, memory.max, memory.oom_kills),
            (3.0, 4.0, 1.0)
        );
        let io = cgroup.io();
        assert_eq!(io.len(), 2);
        assert_eq!(io[0].numbers, "8:0");
        let counts = (
            io[0].read_bytes,
            io[0].write_bytes,
            io[0].reads,
            io[0].writes,
        );
        assert_eq!(counts, (10.0, 20.0, 1.0, 2.0));
        assert_eq!((io[1].read_bytes, io[1].writes), (5.0, 0.0));
        let pressure = cgroup.pressure();
        assert!(pressure.contains(&("cpu", "waiting", 1.5)));
        assert!(pressure.contains(&("cpu", "stalled", 0.5)));
        let spec = cgroup.spec();
        assert_eq!((spec.quota, spec.period), (Some(50_000.0), 100_000.0));
        // runc's top weight is v1's top shares.
        assert_eq!(spec.shares, 262_144.0);
        assert_eq!(spec.memory, Some((0.0, 65_536.0, 0.0)));
    }

    /// The host's root cgroup has no memory.current: anon + file.
    #[test]
    fn a_v2_root_counts_anon_and_file() {
        let dir = crate::testing::scratch("cgroup-v2-root");
        write_all(&dir, &[("memory.stat", "anon 4096\nfile 8192\n")]);
        let cgroup = Cgroup::V2(dir);
        assert_eq!(cgroup.memory().usage, 12_288.0);
        let spec = cgroup.spec();
        assert_eq!((spec.quota, spec.shares, spec.memory), (None, 0.0, None));
        assert!(cgroup.io().is_empty());
    }

    /// Docker's directories on cgroup v1, one per controller.
    #[test]
    fn reads_v1_controllers() {
        let root = crate::testing::scratch("cgroup-v1");
        let (cpu, memory, blkio) =
            (root.join("cpu"), root.join("memory"), root.join("blkio"));
        write_all(
            &cpu,
            &[
                ("cpuacct.usage_percpu", "1000000000 500000000\n"),
                ("cpuacct.stat", "user 150\nsystem 50\n"),
                ("cpu.cfs_quota_us", "-1\n"),
                ("cpu.cfs_period_us", "100000\n"),
                ("cpu.shares", "512\n"),
            ],
        );
        write_all(
            &memory,
            &[
                ("memory.usage_in_bytes", "1000\n"),
                ("memory.memsw.usage_in_bytes", "1500\n"),
                (
                    "memory.stat",
                    "rss 1\npgfault 9\npgmajfault 1\n\
                    total_rss 600\ntotal_cache 300\n",
                ),
                ("memory.max_usage_in_bytes", "2000\n"),
                ("memory.failcnt", "3\n"),
                (
                    "memory.oom_control",
                    "oom_kill_disable 0\n\
                    under_oom 0\noom_kill 2\n",
                ),
                ("memory.limit_in_bytes", "9223372036854771712\n"),
                ("memory.soft_limit_in_bytes", "4096\n"),
            ],
        );
        write_all(
            &blkio,
            &[
                (
                    "blkio.throttle.io_service_bytes",
                    "8:0 Read 100\n8:0 Write 200\n8:0 Total 300\nTotal 300\n",
                ),
                (
                    "blkio.throttle.io_serviced",
                    "8:0 Read 1\n8:0 Write 2\nTotal 3\n",
                ),
            ],
        );
        let dirs = [
            ("cpu", &cpu),
            ("cpuacct", &cpu),
            ("memory", &memory),
            ("blkio", &blkio),
        ];
        let cgroup = Cgroup::V1(
            dirs.iter()
                .map(|(c, d)| ((*c).to_owned(), (*d).clone()))
                .collect(),
        );
        let usage = cgroup.cpu();
        assert_eq!(
            usage.usage,
            [("cpu00".to_owned(), 1.0), ("cpu01".to_owned(), 0.5)]
        );
        assert_eq!((usage.user, usage.system), (Some(1.5), Some(0.5)));
        let m = cgroup.memory();
        assert_eq!(
            (m.usage, m.swap, m.peak, m.failcnt),
            (1000.0, 500.0, 2000.0, 3.0)
        );
        assert_eq!(m.oom_kills, 2.0);
        assert_eq!(m.faults, [(9.0, 9.0), (1.0, 1.0)]);
        assert_eq!(find(&m.stat, "anon"), Some(600.0));
        assert_eq!(find(&m.stat, "file"), Some(300.0));
        let io = cgroup.io();
        let counts = (
            io[0].read_bytes,
            io[0].write_bytes,
            io[0].reads,
            io[0].writes,
        );
        assert_eq!(counts, (100.0, 200.0, 1.0, 2.0));
        assert!(cgroup.pressure().iter().all(|(_, _, v)| *v == 0.0));
        let spec = cgroup.spec();
        assert_eq!(
            (spec.quota, spec.period, spec.shares),
            (None, 100_000.0, 512.0)
        );
        // v1's "no limit" is i64::MAX rounded to a page: 0, as cAdvisor.
        assert_eq!(spec.memory, Some((0.0, 4096.0, 0.0)));
    }

    /// Without the memory controller, zeros, as cAdvisor reports.
    #[test]
    fn no_memory_controller_is_zeros() {
        let cgroup = Cgroup::V1(Vec::new());
        assert_eq!(cgroup.memory().usage, 0.0);
        assert!(cgroup.spec().memory.is_none());
        assert!(cgroup.cpu().usage.is_empty());
    }

    #[test]
    fn lists_cgroups_below_a_root_parents_first() {
        let dir = crate::testing::scratch("cgroup-below");
        fs::create_dir_all(dir.join("system.slice/docker-1.scope")).unwrap();
        fs::create_dir_all(dir.join("init.scope")).unwrap();
        fs::write(dir.join("cgroup.procs"), "").unwrap();
        let mut found = Vec::new();
        below(&dir, "", &mut found);
        assert_eq!(
            found,
            [
                "/init.scope",
                "/system.slice",
                "/system.slice/docker-1.scope"
            ]
        );
    }
}
