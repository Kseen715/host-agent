//! OpenZFS's kstats: the ARC and the other module-wide statistics,
//! each pool's state and each dataset's counters.

use super::{Node, absent, entries, host_text, read};
use crate::host;
use crate::remote::Writer;
use std::io;

/// Files in /proc/spl/kstat/zfs and their names' prefixes.
const KSTATS: [(&str, &str); 11] = [
    ("abdstats", "abd"),
    ("arcstats", "arc"),
    ("dbufstats", "dbuf"),
    ("dmu_tx", "dmu_tx"),
    ("dnodestats", "dnode"),
    ("fm", "fm"),
    ("vdev_cache_stats", "vdev_cache"),
    ("vdev_mirror_stats", "vdev_mirror"),
    ("xuio_stats", "xuio"),
    ("zfetchstats", "zfetch"),
    ("zil", "zil"),
];

const POOL_STATES: [&str; 7] = [
    "online",
    "degraded",
    "faulted",
    "offline",
    "removed",
    "unavail",
    "suspended",
];

/// kstat's type of a text value; the rest are numbers.
const KSTAT_STRING: &str = "7";

pub fn collect(_: &Node, w: &mut Writer) -> io::Result<()> {
    if !host::path("/proc/spl/kstat/zfs/arcstats").is_file() {
        return Err(absent("zfs"));
    }
    for (file, prefix) in KSTATS {
        let path = format!("/proc/spl/kstat/zfs/{file}");
        let text = host_text(&path).unwrap_or_default();
        for (name, _, value) in kstat(&text) {
            if let Ok(value) = value.parse() {
                let name =
                    format!("node_zfs_{prefix}_{name}").replace('-', "_");
                w.add(&name, &[], value);
            }
        }
    }
    pools(w);
    Ok(())
}

/// A kstat file's `name type data` lines, after its two header lines.
fn kstat(text: &str) -> impl Iterator<Item = (&str, &str, &str)> {
    text.lines().skip(2).filter_map(|line| {
        let (name, rest) = line.trim_start().split_once(char::is_whitespace)?;
        let rest = rest.trim_start();
        let (kind, value) = rest.split_once(char::is_whitespace)?;
        Some((name, kind, value.trim()))
    })
}

/// Each pool's directory: `state`, and an `objset-0x...` per dataset.
fn pools(w: &mut Writer) {
    let dir = host::path("/proc/spl/kstat/zfs");
    for (pool_dir, pool) in entries(&dir, "") {
        let Some(state) = read(pool_dir.join("state")) else {
            continue;
        };
        let state = state.to_lowercase();
        for name in POOL_STATES {
            let labels = [("state", name), ("zpool", pool.as_str())];
            let value = if state == name { 1.0 } else { 0.0 };
            w.add("node_zfs_zpool_state", &labels, value);
        }
        for (objset, _) in entries(&pool_dir, "objset-") {
            dataset(w, &pool, &read(objset).unwrap_or_default());
        }
    }
}

fn dataset(w: &mut Writer, pool: &str, text: &str) {
    let lines: Vec<_> = kstat(text).collect();
    let Some((_, _, name)) =
        lines.iter().find(|(key, _, _)| *key == "dataset_name")
    else {
        return;
    };
    let labels = [("dataset", *name), ("zpool", pool)];
    for (key, kind, value) in &lines {
        if *kind == KSTAT_STRING {
            continue;
        }
        if let Ok(value) = value.parse() {
            let metric = format!("node_zfs_zpool_dataset_{key}");
            w.add(&metric, &labels, value);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_a_dataset_with_spaces_in_its_name() {
        let text = "41 1 0x01 7 2160 5214787391 74985931356512\n\
            name                            type data\n\
            dataset_name                    7    nvme/a b\n\
            writes                          4    12\n";
        let lines: Vec<_> = kstat(text).collect();
        assert_eq!(lines[0], ("dataset_name", "7", "nvme/a b"));
        assert_eq!(lines[1], ("writes", "4", "12"));
    }
}
