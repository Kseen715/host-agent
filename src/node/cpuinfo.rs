//! /proc/cpuinfo as procfs reads it on x86 and ARM, for the cpu
//! collector's `info`; and the isolated CPUs.

use super::{host_text, invalid};
use crate::host;
use std::fs;
use std::io;

#[derive(Clone, Default)]
pub struct Cpu {
    pub processor: u32,
    pub vendor: String,
    pub family: String,
    pub model: String,
    pub model_name: String,
    pub stepping: String,
    pub microcode: String,
    pub mhz: f64,
    pub cache_size: String,
    pub package: String,
    pub core: String,
    pub flags: Vec<String>,
    pub bugs: Vec<String>,
}

/// Whether this architecture's /proc/cpuinfo can be read here.
pub fn known() -> bool {
    cfg!(any(
        target_arch = "x86",
        target_arch = "x86_64",
        target_arch = "arm",
        target_arch = "aarch64"
    ))
}

pub fn read_all() -> io::Result<Vec<Cpu>> {
    let text = host_text("/proc/cpuinfo")?;
    if cfg!(any(target_arch = "arm", target_arch = "aarch64")) {
        arm(&text)
    } else {
        x86(&text)
    }
}

/// `key: value` lines; the key trimmed, the value as it is.
fn fields(text: &str) -> impl Iterator<Item = (&str, &str)> {
    text.lines().filter(|l| l.contains(':')).map(|line| {
        let (key, value) = line.split_once(": ").unwrap_or((line, ""));
        (key.trim(), value)
    })
}

fn number(value: &str) -> io::Result<u32> {
    let value = super::go_uint(value)?;
    u32::try_from(value).map_err(invalid)
}

/// The first line that is not blank, refused unless it is `<key>: `
/// with one of `keys`.
fn first_line<'a>(text: &'a str, keys: &[&str]) -> io::Result<&'a str> {
    let first = text.lines().find(|l| !l.trim().is_empty()).unwrap_or("");
    match keys.iter().any(|k| first.starts_with(k)) && first.contains(':') {
        true => Ok(first),
        false => Err(invalid(format!("cpuinfo: `{first}`"))),
    }
}

fn x86(text: &str) -> io::Result<Vec<Cpu>> {
    first_line(text, &["processor"])?;
    let mut cpus: Vec<Cpu> = Vec::new();
    for (key, value) in fields(text) {
        if key == "processor" {
            cpus.push(Cpu {
                processor: number(value)?,
                ..Cpu::default()
            });
            continue;
        }
        if let Some(cpu) = cpus.last_mut() {
            x86_field(cpu, key, value)?;
        }
    }
    Ok(cpus)
}

fn x86_field(cpu: &mut Cpu, key: &str, value: &str) -> io::Result<()> {
    let text = value.to_owned();
    match key {
        "vendor" | "vendor_id" => cpu.vendor = text,
        "cpu family" => cpu.family = text,
        "model" => cpu.model = text,
        "model name" => cpu.model_name = text,
        "stepping" => cpu.stepping = text,
        "microcode" => cpu.microcode = text,
        "cpu MHz" => cpu.mhz = value.parse().map_err(invalid)?,
        "cache size" => cpu.cache_size = text,
        "physical id" => cpu.package = text,
        "core id" => cpu.core = text,
        "flags" => cpu.flags = words(value),
        "bugs" => cpu.bugs = words(value),
        "siblings" | "cpu cores" | "cpuid level" | "clflush size"
        | "cache_alignment" => {
            number(value)?;
        }
        "bogomips" => {
            value.parse::<f64>().map_err(invalid)?;
        }
        _ => {}
    }
    Ok(())
}

fn words(value: &str) -> Vec<String> {
    value.split_whitespace().map(str::to_owned).collect()
}

fn arm(text: &str) -> io::Result<Vec<Cpu>> {
    let first = first_line(text, &["processor", "Processor"])?;
    // Old kernels: one `Processor: <model>` line for every CPU.
    let common = match first.split_once(": ") {
        Some((key, model)) if key.trim() == "Processor" => Cpu {
            model_name: model.to_owned(),
            ..Cpu::default()
        },
        _ => Cpu::default(),
    };
    let mut cpus: Vec<Cpu> = Vec::new();
    let mut features = Vec::new();
    for (key, value) in fields(text) {
        match key {
            "processor" => cpus.push(Cpu {
                processor: number(value)?,
                ..common.clone()
            }),
            "BogoMIPS" => {
                if cpus.is_empty() {
                    cpus.push(common.clone());
                }
                value.parse::<f64>().map_err(invalid)?;
            }
            "Features" => features = words(value),
            "model name" => {
                if let Some(cpu) = cpus.last_mut() {
                    cpu.model_name = value.to_owned();
                }
            }
            _ => {}
        }
    }
    for cpu in &mut cpus {
        cpu.flags = features.clone();
    }
    Ok(cpus)
}

/// The CPUs `/sys/devices/system/cpu/isolated` lists: `1-3,5`.
pub fn isolated() -> io::Result<Vec<u32>> {
    let path = host::path("/sys/devices/system/cpu/isolated");
    let text = match fs::read_to_string(path) {
        Ok(text) => text.trim().to_owned(),
        Err(e) if e.kind() == io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e),
    };
    let mut cpus = Vec::new();
    for part in text.split(',').filter(|p| !p.is_empty()) {
        let (from, to) = part.split_once('-').unwrap_or((part, part));
        let (from, to): (u32, u32) = (
            from.trim().parse().map_err(invalid)?,
            to.trim().parse().map_err(invalid)?,
        );
        cpus.extend(from..=to);
    }
    Ok(cpus)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_x86_and_arm() {
        let text = "processor\t: 0\nvendor_id\t: GenuineIntel\n\
            cpu MHz\t\t: 800.000\nphysical id\t: 0\ncore id\t\t: 1\n\
            flags\t\t: fpu vme\nbugs\t\t: spectre_v1\n\n\
            processor\t: 1\nvendor_id\t: GenuineIntel\n";
        let cpus = x86(text).unwrap();
        assert_eq!(cpus.len(), 2);
        assert_eq!((cpus[0].mhz, cpus[0].core.as_str()), (800.0, "1"));
        assert_eq!(cpus[0].flags, ["fpu", "vme"]);
        assert_eq!(cpus[1].processor, 1);
        let text = "processor\t: 0\nBogoMIPS\t: 48.00\n\
            Features\t: fp asimd\n\nprocessor\t: 1\nBogoMIPS\t: 48.00\n";
        let cpus = arm(text).unwrap();
        assert_eq!(cpus.len(), 2);
        assert_eq!(cpus[1].flags, ["fp", "asimd"]);
    }
}
