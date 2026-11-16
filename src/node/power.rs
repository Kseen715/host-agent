//! Power: RAPL energy counters (/sys/class/powercap) and power supplies
//! (/sys/class/power_supply), as node_exporter's rapl and
//! powersupplyclass collectors give them.

use super::{Node, absent, go_int, invalid, sys_read, unsupported};
use crate::host;
use crate::remote::Writer;
use std::collections::HashMap;
use std::fs;
use std::io;

/// Each zone's energy, `node_rapl_<zone>_joules_total`: a zone named
/// `package-0` is `package` at index 0; zones of the same name without
/// an index are counted in turn.
pub fn rapl(node: &Node, w: &mut Writer) -> io::Result<()> {
    let dir = host::path("/sys/class/powercap");
    let entries = super::entries(&dir, "");
    if entries.is_empty() && !dir.is_dir() {
        return Err(absent("powercap"));
    }
    let mut used: HashMap<String, i64> = HashMap::new();
    let mut zones = Vec::new();
    for (path, entry) in entries {
        let Ok(name) = fs::read_to_string(path.join("name")) else {
            continue;
        };
        let name = name.trim();
        let (index, name) = match name.split('-').collect::<Vec<_>>()[..] {
            [base, index] if index.parse::<i64>().is_ok() => {
                (index.parse().unwrap_or(0), base.to_owned())
            }
            _ => (used.get(name).copied().unwrap_or(0), name.to_owned()),
        };
        let range = sys_read(&path.join("max_energy_range_uj"));
        range.map_err(no_access)?.parse::<u64>().map_err(invalid)?;
        used.insert(name.clone(), index + 1);
        let label = format!("{}/class/powercap/{entry}", node.settings.sysfs);
        zones.push((path, name, index, label));
    }
    let mut energies = Vec::new();
    for (path, name, index, label) in zones {
        let energy = sys_read(&path.join("energy_uj")).map_err(no_access)?;
        let energy = energy.parse::<u64>().map_err(invalid)?;
        energies.push((name, index, label, energy as f64 / 1e6));
    }
    for (name, index, path, joules) in energies {
        let metric = format!("node_rapl_{}_joules_total", sanitize(&name));
        let labels = [("index", index.to_string()), ("path", path)];
        let labels = labels.each_ref().map(|(k, v)| (*k, v.as_str()));
        w.add(&metric, &labels, joules);
    }
    Ok(())
}

/// Root only since Linux 5.10: node_exporter has no data then.
fn no_access(error: io::Error) -> io::Error {
    match error.kind() {
        io::ErrorKind::PermissionDenied => absent("powercap"),
        _ => error,
    }
}

/// node_exporter's SanitizeMetricName: runs of other characters, with
/// underscores around them, become one underscore.
fn sanitize(name: &str) -> String {
    let mut out = String::new();
    let mut pending = false;
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() {
            if pending {
                while out.ends_with('_') {
                    out.pop();
                }
                out.push('_');
                pending = false;
            }
            out.push(ch);
        } else if ch == '_' {
            out.push(ch);
        } else {
            pending = true;
        }
    }
    if pending {
        while out.ends_with('_') {
            out.pop();
        }
        out.push('_');
    }
    out
}

/// Attributes reported as they are, in micro-units (as SI), and in
/// tenths of a degree.
const AS_IS: [(&str, &str); 10] = [
    ("authentic", "authentic"),
    ("calibrate", "calibrate"),
    ("capacity", "capacity"),
    ("capacity_alert_max", "capacity_alert_max"),
    ("capacity_alert_min", "capacity_alert_min"),
    ("cycle_count", "cyclecount"),
    ("online", "online"),
    ("present", "present"),
    ("time_to_empty_now", "time_to_empty_seconds"),
    ("time_to_full_now", "time_to_full_seconds"),
];

const MICRO: [(&str, &str); 31] = [
    ("current_boot", "current_boot"),
    ("current_max", "current_max"),
    ("current_now", "current_ampere"),
    ("energy_empty", "energy_empty"),
    ("energy_empty_design", "energy_empty_design"),
    ("energy_full", "energy_full"),
    ("energy_full_design", "energy_full_design"),
    ("energy_now", "energy_watthour"),
    ("voltage_boot", "voltage_boot"),
    ("voltage_max", "voltage_max"),
    ("voltage_max_design", "voltage_max_design"),
    ("voltage_min", "voltage_min"),
    ("voltage_min_design", "voltage_min_design"),
    ("voltage_now", "voltage_volt"),
    ("voltage_ocv", "voltage_ocv"),
    ("charge_control_limit", "charge_control_limit"),
    ("charge_control_limit_max", "charge_control_limit_max"),
    ("charge_counter", "charge_counter"),
    ("charge_empty", "charge_empty"),
    ("charge_empty_design", "charge_empty_design"),
    ("charge_full", "charge_full"),
    ("charge_full_design", "charge_full_design"),
    ("charge_now", "charge_ampere"),
    ("charge_term_current", "charge_term_current"),
    ("constant_charge_current", "constant_charge_current"),
    ("constant_charge_current_max", "constant_charge_current_max"),
    ("constant_charge_voltage", "constant_charge_voltage"),
    ("constant_charge_voltage_max", "constant_charge_voltage_max"),
    ("precharge_current", "precharge_current"),
    ("input_current_limit", "input_current_limit"),
    ("power_now", "power_watt"),
];

const TENTHS: [(&str, &str); 8] = [
    ("temp", "temp_celsius"),
    ("temp_alert_max", "temp_alert_max_celsius"),
    ("temp_alert_min", "temp_alert_min_celsius"),
    ("temp_ambient", "temp_ambient_celsius"),
    ("temp_ambient_max", "temp_ambient_max_celsius"),
    ("temp_ambient_min", "temp_ambient_min_celsius"),
    ("temp_max", "temp_max_celsius"),
    ("temp_min", "temp_min_celsius"),
];

/// Attributes that are text: labels of node_power_supply_info.
const TEXT: [&str; 11] = [
    "capacity_level",
    "charge_type",
    "health",
    "manufacturer",
    "model_name",
    "serial_number",
    "status",
    "technology",
    "type",
    "usb_type",
    "scope",
];

/// Attributes procfs parses as numbers without reporting them.
const UNREPORTED: [&str; 6] = [
    "charge_avg",
    "current_avg",
    "energy_avg",
    "power_avg",
    "time_to_empty_avg",
    "voltage_avg",
];

type Supply = (String, HashMap<String, String>);

pub fn supplies(node: &Node, w: &mut Writer) -> io::Result<()> {
    let dir = host::path("/sys/class/power_supply");
    let names = fs::read_dir(&dir)?;
    let mut found: Vec<Supply> = Vec::new();
    for entry in names {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        found.push((name, attributes(&entry.path())?));
    }
    found.retain(|(name, _)| {
        !node.settings.power_supplies_ignored.is_match(name)
    });
    found.sort_by(|a, b| a.0.cmp(&b.0));
    for (name, values) in &found {
        supply(w, name, values)?;
    }
    Ok(())
}

fn supply(
    w: &mut Writer,
    name: &str,
    values: &HashMap<String, String>,
) -> io::Result<()> {
    let labels = [("power_supply", name)];
    let tables = [(&AS_IS[..], 1.0), (&MICRO[..], 1e6), (&TENTHS[..], 10.0)];
    for (table, divisor) in tables {
        for (file, metric) in table {
            if let Some(value) = values.get(*file) {
                let metric = format!("node_power_supply_{metric}");
                w.add(&metric, &labels, go_int(value)? as f64 / divisor);
            }
        }
    }
    let mut info = vec![("power_supply", name)];
    for file in TEXT {
        if let Some(value) = values.get(file) {
            info.push((file, value.as_str()));
        }
    }
    w.add("node_power_supply_info", &info, 1.0);
    Ok(())
}

/// A supply's regular files' values, numbers checked as procfs does.
fn attributes(dir: &std::path::Path) -> io::Result<HashMap<String, String>> {
    let mut values = HashMap::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let value = match sys_read(&entry.path()) {
            Ok(value) => value,
            Err(e) if unsupported(&e) => continue,
            Err(e) => return Err(e),
        };
        let file = entry.file_name().to_string_lossy().into_owned();
        let numeric = AS_IS.iter().chain(&MICRO).chain(&TENTHS);
        let numeric = numeric.map(|(f, _)| *f).chain(UNREPORTED);
        if numeric.clone().any(|f| f == file) {
            go_int(&value)?;
        }
        values.insert(file, value);
    }
    Ok(values)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitizes_names_as_node_exporter() {
        assert_eq!(sanitize("package"), "package");
        assert_eq!(sanitize("dram:x"), "dram_x");
        assert_eq!(sanitize("a_-_b"), "a_b");
        assert_eq!(sanitize("psys-"), "psys_");
    }

    /// A laptop's battery: numbers scaled as node_exporter scales them,
    /// text in the info series.
    #[test]
    fn reads_a_power_supply() {
        let dir = crate::testing::scratch("power-supply").join("BAT0");
        super::super::sysfs(
            &dir,
            &[
                ("capacity", "87\n"),
                ("cycle_count", "123\n"),
                ("voltage_now", "12500000\n"),
                ("energy_full", "0x2faf080\n"),
                ("temp", "305\n"),
                ("status", "Discharging\n"),
                ("manufacturer", "ACME\n"),
                ("type", "Battery\n"),
            ],
        );
        let values = attributes(&dir).unwrap();
        let mut w = Writer::text();
        supply(&mut w, "BAT0", &values).unwrap();
        let text = w.into_text();
        for wanted in [
            "node_power_supply_capacity{power_supply=\"BAT0\"} 87",
            "node_power_supply_cyclecount{power_supply=\"BAT0\"} 123",
            "node_power_supply_voltage_volt{power_supply=\"BAT0\"} 12.5",
            "node_power_supply_energy_full{power_supply=\"BAT0\"} 50",
            "node_power_supply_temp_celsius{power_supply=\"BAT0\"} 30.5",
            "manufacturer=\"ACME\"",
            "status=\"Discharging\"",
        ] {
            assert!(text.contains(wanted), "{wanted} not in\n{text}");
        }
        fs::write(dir.join("capacity"), "full\n").unwrap();
        assert!(attributes(&dir).is_err(), "a number that is not one");
    }
}
