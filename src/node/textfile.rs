//! `*.prom` files that jobs on this host write (backups, Proxmox
//! guests, NVMe links, memory modules), passed on as the node's own.

use super::Node;
use crate::exposition;
use crate::remote::Writer;
use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;

pub fn collect(node: &Node, w: &mut Writer) -> io::Result<()> {
    let Some(dir) = &node.settings.textfile_dir else {
        return Ok(());
    };
    let mut paths: Vec<_> = fs::read_dir(dir)?
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|e| e == "prom"))
        .collect();
    paths.sort();
    let mut error = false;
    for path in paths {
        let (Ok(text), Ok(meta)) =
            (fs::read_to_string(&path), fs::metadata(&path))
        else {
            error = true;
            continue;
        };
        exposition::parse(&text, |name, labels, value| {
            let labels: Vec<(&str, &str)> =
                labels.iter().map(|(k, v)| (*k, v.as_ref())).collect();
            w.add(name, &labels, value);
        });
        let file = path.to_string_lossy();
        w.add(
            "node_textfile_mtime_seconds",
            &[("file", &file)],
            meta.mtime() as f64,
        );
    }
    w.add(
        "node_textfile_scrape_error",
        &[],
        if error { 1.0 } else { 0.0 },
    );
    Ok(())
}
