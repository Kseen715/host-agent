//! Sensors and clocks in sysfs: hwmon chips, thermal zones, cooling
//! devices, CPU frequencies and thermal throttling. Names and labels are
//! node_exporter's to the letter: the fan curves and dashboards select
//! chips by them (`platform_nct6775_656`).

use super::{Node, number, numbered, read};
use crate::remote::Writer;
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

const SENSOR_TYPES: [&str; 13] = [
    "vrm",
    "beep_enable",
    "update_interval",
    "in",
    "cpu",
    "fan",
    "pwm",
    "temp",
    "curr",
    "power",
    "energy",
    "humidity",
    "intrusion",
];

/// The CPUs' frequencies: the hardware's (`cpuinfo_*`, root only) and
/// the governor's (`scaling_*`), and which governor runs.
pub fn cpufreq(_: &Node, w: &mut Writer) -> io::Result<()> {
    let files = [
        ("cpuinfo_cur_freq", "node_cpu_frequency_hertz"),
        ("cpuinfo_min_freq", "node_cpu_frequency_min_hertz"),
        ("cpuinfo_max_freq", "node_cpu_frequency_max_hertz"),
        ("scaling_cur_freq", "node_cpu_scaling_frequency_hertz"),
        ("scaling_min_freq", "node_cpu_scaling_frequency_min_hertz"),
        ("scaling_max_freq", "node_cpu_scaling_frequency_max_hertz"),
    ];
    for (dir, cpu) in cpus() {
        let freq = dir.join("cpufreq");
        for (file, name) in files {
            if let Some(khz) = number(freq.join(file)) {
                w.add(name, &[("cpu", &cpu)], khz * 1000.0);
            }
        }
        let current = read(freq.join("scaling_governor")).unwrap_or_default();
        let available = read(freq.join("scaling_available_governors"));
        for governor in available.unwrap_or_default().split_whitespace() {
            let labels = [("cpu", cpu.as_str()), ("governor", governor)];
            let value = if governor == current { 1.0 } else { 0.0 };
            w.add("node_cpu_scaling_governor", &labels, value);
        }
    }
    Ok(())
}

/// `cpuN` directories, with N.
fn cpus() -> impl Iterator<Item = (PathBuf, String)> {
    let all = numbered("/sys/devices/system/cpu", "cpu");
    all.into_iter().filter(|(_, cpu)| {
        !cpu.is_empty() && cpu.bytes().all(|b| b.is_ascii_digit())
    })
}

/// Thermal throttling per core and per package: a package's cores
/// share its counter.
pub fn throttles(w: &mut Writer) {
    let mut seen = Vec::new();
    for (dir, _) in cpus() {
        let topology = dir.join("topology");
        let throttle = dir.join("thermal_throttle");
        let (Some(package), Some(core)) = (
            read(topology.join("physical_package_id")),
            read(topology.join("core_id")),
        ) else {
            continue;
        };
        let core_key = format!("{package}:{core}");
        if !seen.contains(&core_key) {
            if let Some(count) = number(throttle.join("core_throttle_count")) {
                let labels =
                    [("core", core.as_str()), ("package", package.as_str())];
                w.add("node_cpu_core_throttles_total", &labels, count);
            }
            seen.push(core_key);
        }
        if !seen.contains(&package) {
            let file = throttle.join("package_throttle_count");
            if let Some(count) = number(file) {
                let labels = [("package", package.as_str())];
                w.add("node_cpu_package_throttles_total", &labels, count);
            }
            seen.push(package);
        }
    }
}

pub fn thermal_zone(_: &Node, w: &mut Writer) -> io::Result<()> {
    for (dir, zone) in numbered("/sys/class/thermal", "thermal_zone") {
        let (Some(kind), Some(temp)) =
            (read(dir.join("type")), number(dir.join("temp")))
        else {
            continue;
        };
        let labels = [("type", kind.as_str()), ("zone", zone.as_str())];
        w.add("node_thermal_zone_temp", &labels, temp / 1000.0);
    }
    for (dir, name) in numbered("/sys/class/thermal", "cooling_device") {
        let kind = read(dir.join("type")).unwrap_or_default();
        let labels = [("name", name.as_str()), ("type", kind.as_str())];
        if let Some(state) = number(dir.join("cur_state")) {
            w.add("node_cooling_device_cur_state", &labels, state);
        }
        if let Some(state) = number(dir.join("max_state")) {
            w.add("node_cooling_device_max_state", &labels, state);
        }
    }
    Ok(())
}

pub fn hwmon(_: &Node, w: &mut Writer) -> io::Result<()> {
    for (dir, _) in numbered("/sys/class/hwmon", "hwmon") {
        let Some(chip) = chip_name(&dir) else {
            continue;
        };
        let mut sensors = BTreeMap::new();
        sensor_files(&dir, &mut sensors);
        sensor_files(&dir.join("device"), &mut sensors);
        if let Some(name) = read(dir.join("name")).map(|n| clean(&n)) {
            let labels =
                [("chip", chip.as_str()), ("chip_name", name.as_str())];
            w.add("node_hwmon_chip_names", &labels, 1.0);
        }
        for (sensor, elements) in &sensors {
            sensor_metrics(w, &chip, sensor, elements);
        }
    }
    Ok(())
}

type Elements = BTreeMap<String, String>;

/// `temp1_crit_alarm` is sensor `temp1`, element `crit_alarm`; a sensor
/// without a number is number 0.
fn sensor_files(dir: &Path, sensors: &mut BTreeMap<String, Elements>) {
    for entry in fs::read_dir(dir).into_iter().flatten().flatten() {
        let Ok(file) = entry.file_name().into_string() else {
            continue;
        };
        let Some((kind, number, element)) = explode(&file) else {
            continue;
        };
        if !SENSOR_TYPES.contains(&kind) || !entry.path().is_file() {
            continue;
        }
        let Some(value) = read(entry.path()) else {
            continue;
        };
        let sensor = format!("{kind}{number}");
        sensors
            .entry(sensor)
            .or_default()
            .insert(element.to_owned(), value);
    }
}

/// node_exporter's `^([^0-9]+)([0-9]*)?(_(.+))?$` on a file name.
fn explode(file: &str) -> Option<(&str, u32, &str)> {
    let digits = file
        .find(|c: char| c.is_ascii_digit())
        .unwrap_or(file.len());
    let kind = &file[..digits];
    let rest = &file[digits..];
    let number_len = rest.bytes().take_while(u8::is_ascii_digit).count();
    let number = rest[..number_len].parse().unwrap_or(0);
    let element = match &rest[number_len..] {
        "" => "",
        tail => tail.strip_prefix('_').filter(|e| !e.is_empty())?,
    };
    (!kind.is_empty()).then_some((kind, number, element))
}

fn sensor_metrics(
    w: &mut Writer,
    chip: &str,
    sensor: &str,
    elements: &Elements,
) {
    let labels = [("chip", chip), ("sensor", sensor)];
    if let Some(label) = elements.get("label") {
        let with_label = [
            ("chip", chip),
            ("sensor", sensor),
            ("label", label.as_str()),
        ];
        w.add("node_hwmon_sensor_label", &with_label, 1.0);
    }
    let kind = explode(sensor).map_or(sensor, |(kind, _, _)| kind);
    let plain = |w: &mut Writer, name: &str, scale: f64| {
        let value = elements.get("").or_else(|| elements.get("input"));
        if let Some(value) = value.and_then(|v| v.parse::<f64>().ok()) {
            w.add(name, &labels, value * scale);
        }
    };
    match kind {
        "beep_enable" => return plain(w, "node_hwmon_beep_enabled", 1.0),
        "vrm" => return plain(w, "node_hwmon_voltage_regulator_version", 1.0),
        "update_interval" => {
            return plain(w, "node_hwmon_update_interval_seconds", 0.001);
        }
        _ => {}
    }
    for (element, value) in elements {
        let Ok(value) = value.parse::<f64>() else {
            continue;
        };
        if element == "label" {
            continue;
        }
        let mut name = format!("node_hwmon_{kind}");
        if element == "input" {
            if elements.contains_key("") {
                name.push_str("_input");
            }
        } else if !element.is_empty() {
            name.push('_');
            name.push_str(element);
        }
        let (suffix, scale) = unit(kind, element);
        w.add(&format!("{name}{suffix}"), &labels, value * scale);
    }
}

/// The unit node_exporter gives an element: alarms and faults have none.
fn unit(kind: &str, element: &str) -> (&'static str, f64) {
    match (kind, element) {
        (_, "fault" | "alarm") => ("", 1.0),
        (_, "beep") => ("_enabled", 1.0),
        ("in" | "cpu", _) => ("_volts", 0.001),
        ("temp", e) if e != "type" => ("_celsius", 0.001),
        ("curr", _) => ("_amps", 0.001),
        ("power", _) => ("_watt", 1e-6),
        ("energy", _) => ("_joule_total", 1e-6),
        ("fan", "input" | "min" | "max" | "target") => ("_rpm", 1.0),
        _ => ("", 1.0),
    }
}

/// The chip's stable name: its device's bus and address
/// (`platform_coretemp_0`), else its driver's name, else `hwmonN`.
fn chip_name(dir: &Path) -> Option<String> {
    if let Ok(device) = fs::canonicalize(dir.join("device")) {
        let name = device.file_name().map(|n| clean(&n.to_string_lossy()));
        let parent = device.parent().and_then(Path::file_name);
        let bus = parent.map(|p| clean(&p.to_string_lossy()));
        match (bus, name) {
            (Some(bus), Some(name)) if !bus.is_empty() && !name.is_empty() => {
                return Some(format!("{bus}_{name}"));
            }
            (_, Some(name)) if !name.is_empty() => return Some(name),
            _ => {}
        }
    }
    if let Some(name) = read(dir.join("name")).map(|n| clean(&n)) {
        if !name.is_empty() {
            return Some(name);
        }
    }
    let real = fs::canonicalize(dir).ok()?;
    let name = clean(&real.file_name()?.to_string_lossy());
    (!name.is_empty()).then_some(name)
}

/// Lowercase, `[^a-z0-9:_]` to `_`, trimmed of `_`.
fn clean(name: &str) -> String {
    let lower = name.to_lowercase();
    let replaced: String = lower
        .chars()
        .map(|c| match c {
            'a'..='z' | '0'..='9' | ':' | '_' => c,
            _ => '_',
        })
        .collect();
    replaced.trim_matches('_').to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_sensor_files() {
        assert_eq!(
            explode("temp1_crit_alarm"),
            Some(("temp", 1, "crit_alarm"))
        );
        assert_eq!(explode("pwm2"), Some(("pwm", 2, "")));
        assert_eq!(
            explode("update_interval"),
            Some(("update_interval", 0, ""))
        );
        assert_eq!(explode("temp1x"), None);
        assert_eq!(explode("1abc"), None);
    }

    #[test]
    fn cleans_chip_names() {
        assert_eq!(clean("coretemp.0"), "coretemp_0");
        assert_eq!(clean("0000:00:18.3"), "0000:00:18_3");
        assert_eq!(clean("_Pwm-Fan_"), "pwm_fan");
    }

    #[test]
    fn gives_units() {
        assert_eq!(unit("temp", "crit_alarm"), ("_celsius", 0.001));
        assert_eq!(unit("fan", "alarm"), ("", 1.0));
        assert_eq!(unit("fan", "pulses"), ("", 1.0));
        assert_eq!(unit("in", "max"), ("_volts", 0.001));
    }
}
