//! What the firmware and the drivers say about the machine: its DMI
//! names, its memory controllers' error counts, its NVMe controllers.

use super::{Node, absent, entries, number, numbered, read};
use crate::host;
use crate::remote::Writer;
use std::io;
use std::path::Path;

/// node_exporter's labels and the /sys/class/dmi/id files they come
/// from. Serials and the UUID are readable by root only, as this agent
/// runs.
const DMI: [(&str, &str); 20] = [
    ("bios_date", "bios_date"),
    ("bios_release", "bios_release"),
    ("bios_vendor", "bios_vendor"),
    ("bios_version", "bios_version"),
    ("board_asset_tag", "board_asset_tag"),
    ("board_name", "board_name"),
    ("board_serial", "board_serial"),
    ("board_vendor", "board_vendor"),
    ("board_version", "board_version"),
    ("chassis_asset_tag", "chassis_asset_tag"),
    ("chassis_serial", "chassis_serial"),
    ("chassis_vendor", "chassis_vendor"),
    ("chassis_version", "chassis_version"),
    ("product_family", "product_family"),
    ("product_name", "product_name"),
    ("product_serial", "product_serial"),
    ("product_sku", "product_sku"),
    ("product_uuid", "product_uuid"),
    ("product_version", "product_version"),
    ("system_vendor", "sys_vendor"),
];

pub fn dmi(_: &Node, w: &mut Writer) -> io::Result<()> {
    let dir = host::path("/sys/class/dmi/id");
    if !dir.is_dir() {
        return Err(absent("dmi"));
    }
    let values: Vec<(&str, String)> = DMI
        .iter()
        .map(|(label, file)| (*label, read(dir.join(file)).unwrap_or_default()))
        .collect();
    let labels: Vec<(&str, &str)> =
        values.iter().map(|(k, v)| (*k, v.as_str())).collect();
    if labels.iter().any(|(_, v)| !v.is_empty()) {
        w.add("node_dmi_info", &labels, 1.0);
    }
    Ok(())
}

/// Memory controllers' corrected and uncorrected errors, in total and
/// per chip-select row; `unknown` counts those without a row.
pub fn edac(_: &Node, w: &mut Writer) -> io::Result<()> {
    let base = "/sys/devices/system/edac/mc";
    for (dir, controller) in numbered(base, "mc") {
        let mc = [("controller", controller.as_str())];
        let totals = [
            ("ce_count", "node_edac_correctable_errors_total"),
            ("ue_count", "node_edac_uncorrectable_errors_total"),
        ];
        for (file, name) in totals {
            w.add(name, &mc, number(dir.join(file)).unwrap_or(0.0));
        }
        let unknown = [
            (
                "ce_noinfo_count",
                "node_edac_csrow_correctable_errors_total",
            ),
            (
                "ue_noinfo_count",
                "node_edac_csrow_uncorrectable_errors_total",
            ),
        ];
        let labels =
            [("controller", controller.as_str()), ("csrow", "unknown")];
        for (file, name) in unknown {
            w.add(name, &labels, number(dir.join(file)).unwrap_or(0.0));
        }
        rows(w, &dir, &controller);
    }
    Ok(())
}

fn rows(w: &mut Writer, controller_dir: &Path, controller: &str) {
    for (row_dir, row) in entries(controller_dir, "csrow") {
        let labels = [("controller", controller), ("csrow", row.as_str())];
        let counts = [
            ("ce_count", "node_edac_csrow_correctable_errors_total"),
            ("ue_count", "node_edac_csrow_uncorrectable_errors_total"),
        ];
        for (file, name) in counts {
            let value = number(row_dir.join(file)).unwrap_or(0.0);
            w.add(name, &labels, value);
        }
    }
}

pub fn nvme(_: &Node, w: &mut Writer) -> io::Result<()> {
    if !host::path("/sys/class/nvme").is_dir() {
        return Err(absent("nvme"));
    }
    for (dir, number) in numbered("/sys/class/nvme", "nvme") {
        let device = format!("nvme{number}");
        let file = |name: &str| read(dir.join(name)).unwrap_or_default();
        let labels = [
            ("device", device.clone()),
            ("firmware_revision", file("firmware_rev")),
            ("model", file("model")),
            ("serial", file("serial")),
            ("state", file("state")),
        ];
        let labels: Vec<(&str, &str)> =
            labels.iter().map(|(k, v)| (*k, v.as_str())).collect();
        w.add("node_nvme_info", &labels, 1.0);
    }
    Ok(())
}
