//! Units' states, timers' last runs, sockets' connections and systemd
//! itself, from systemctl: as root it talks to systemd's private
//! socket, so a guest without D-Bus answers too.

use super::{Node, absent, kernel::leading_number};
use crate::host;
use crate::json::Json;
use crate::remote::Writer;
use std::collections::HashMap;
use std::io;
use std::process::Command;

const STATES: [&str; 5] =
    ["activating", "active", "deactivating", "inactive", "failed"];
/// A socket's properties and their names.
const SOCKET: [(&str, &str); 3] = [
    (
        "NAccepted",
        "node_systemd_socket_accepted_connections_total",
    ),
    ("NConnections", "node_systemd_socket_current_connections"),
    ("NRefused", "node_systemd_socket_refused_connections_total"),
];

struct Unit {
    name: String,
    load: String,
    active: String,
}

/// Services' `Type`, kept between rounds: asking costs about 3 ms a
/// unit, and it changes only with the unit file.
pub type ServiceTypes = HashMap<String, String>;

pub fn collect(node: &Node, w: &mut Writer) -> io::Result<()> {
    if !host::path("/run/systemd/system").is_dir() {
        return Err(absent("systemd"));
    }
    systemd(w)?;
    let units = list_units()?;
    // Counted before the filter, as node_exporter does.
    for state in STATES {
        let count = units.iter().filter(|u| u.active == state).count();
        w.add("node_systemd_units", &[("state", state)], count as f64);
    }
    let filter = &node.settings.systemd;
    let units: Vec<&Unit> = units
        .iter()
        .filter(|u| u.load == "loaded")
        .filter(|u| filter.include.is_match(&u.name))
        .filter(|u| !filter.exclude.is_match(&u.name))
        .collect();
    states(node, w, &units)?;
    services(node, w, &units)?;
    if filter.start_time {
        start_times(w, &units)?;
    }
    sockets(w, &units)?;
    timers(w, &units)
}

/// Each unit's state, with its service's or mount's `Type`.
fn states(node: &Node, w: &mut Writer, units: &[&Unit]) -> io::Result<()> {
    let mut types = node.service_types.borrow_mut();
    let typed = units.iter().map(|u| u.name.as_str());
    let typed =
        typed.filter(|n| n.ends_with(".service") || n.ends_with(".mount"));
    let unknown: Vec<&str> =
        typed.filter(|name| !types.contains_key(*name)).collect();
    for (id, properties) in show(&unknown, "Type")? {
        let kind = properties.get("Type").cloned().unwrap_or_default();
        types.insert(id, kind);
    }
    for unit in units {
        let kind = types.get(&unit.name).map_or("", String::as_str);
        for state in STATES {
            let labels = [
                ("name", unit.name.as_str()),
                ("state", state),
                ("type", kind),
            ];
            let value = f64::from(unit.active == state);
            w.add("node_systemd_unit_state", &labels, value);
        }
    }
    Ok(())
}

/// Services' restarts and tasks, when asked for; a property systemd
/// leaves unset (`[not set]`, `infinity`) is left out.
fn services(node: &Node, w: &mut Writer, units: &[&Unit]) -> io::Result<()> {
    let settings = &node.settings.systemd;
    let mut wanted = Vec::new();
    if settings.restarts {
        wanted.push(("NRestarts", "node_systemd_service_restart_total"));
    }
    if settings.tasks {
        wanted.push(("TasksCurrent", "node_systemd_unit_tasks_current"));
        wanted.push(("TasksMax", "node_systemd_unit_tasks_max"));
    }
    if wanted.is_empty() {
        return Ok(());
    }
    let names: Vec<&str> = units
        .iter()
        .map(|u| u.name.as_str())
        .filter(|name| name.ends_with(".service"))
        .collect();
    let properties: Vec<&str> = wanted.iter().map(|(p, _)| *p).collect();
    for (id, values) in show(&names, &properties.join(","))? {
        for (property, metric) in &wanted {
            let value = values.get(*property).and_then(|v| v.parse().ok());
            if let Some(value) = value.filter(|v: &u64| *v != u64::MAX) {
                w.add(metric, &[("name", &id)], value as f64);
            }
        }
    }
    Ok(())
}

/// When each active unit entered that state; 0 for the others.
fn start_times(w: &mut Writer, units: &[&Unit]) -> io::Result<()> {
    let active: Vec<&str> = units
        .iter()
        .filter(|u| u.active == "active")
        .map(|u| u.name.as_str())
        .collect();
    let mut started: HashMap<String, f64> = HashMap::new();
    // Unix seconds: show prints timestamps for people otherwise.
    for (id, values) in show_with(&active, "ActiveEnterTimestamp", true)? {
        let at = values.get("ActiveEnterTimestamp");
        let at = at.and_then(|v| v.strip_prefix('@')?.parse().ok());
        if let Some(at) = at {
            started.insert(id, at);
        }
    }
    for unit in units {
        let at = match unit.active.as_str() {
            "active" => match started.get(&unit.name) {
                Some(at) => *at,
                None => continue,
            },
            _ => 0.0,
        };
        let labels = [("name", unit.name.as_str())];
        w.add("node_systemd_unit_start_time_seconds", &labels, at);
    }
    Ok(())
}

/// systemd's version, and whether it has finished starting with no
/// unit failed.
fn systemd(w: &mut Writer) -> io::Result<()> {
    let text = systemctl(&["--version"])?;
    let first = text.lines().next().unwrap_or("");
    let version = first
        .split_once('(')
        .and_then(|(_, rest)| rest.strip_suffix(')'))
        .unwrap_or(first.split_whitespace().nth(1).unwrap_or(""));
    let value = leading_number(version);
    w.add("node_systemd_version", &[("version", version)], value);
    // Exits non-zero when not running; its answer is still the state.
    let state = Command::new("systemctl")
        .arg("is-system-running")
        .output()?;
    let running = String::from_utf8_lossy(&state.stdout).trim() == "running";
    w.add("node_systemd_system_running", &[], f64::from(running));
    Ok(())
}

fn sockets(w: &mut Writer, units: &[&Unit]) -> io::Result<()> {
    let sockets: Vec<&str> = units
        .iter()
        .map(|u| u.name.as_str())
        .filter(|name| name.ends_with(".socket"))
        .collect();
    for (id, properties) in show(&sockets, "NAccepted,NConnections,NRefused")? {
        for (property, name) in SOCKET {
            let value = properties.get(property).and_then(|v| v.parse().ok());
            w.add(name, &[("name", &id)], value.unwrap_or(0.0));
        }
    }
    Ok(())
}

/// When each timer the filter lets through last fired: list-timers'
/// JSON gives it in microseconds, as node_exporter reports it.
fn timers(w: &mut Writer, units: &[&Unit]) -> io::Result<()> {
    let text = systemctl(&["list-timers", "--all", "--output=json"])?;
    let json = Json::parse(&text).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "list-timers: not JSON")
    })?;
    for timer in json.arr() {
        let Some(unit) = timer.get("unit").and_then(Json::str) else {
            continue;
        };
        if !units.iter().any(|u| u.name == unit) {
            continue;
        }
        let last = timer.get("last").and_then(Json::num).unwrap_or(0.0);
        let name = "node_systemd_timer_last_trigger_seconds";
        w.add(name, &[("name", unit)], last / 1e6);
    }
    Ok(())
}

fn systemctl(args: &[&str]) -> io::Result<String> {
    let output = Command::new("systemctl").args(args).output()?;
    if !output.status.success() {
        let error = String::from_utf8_lossy(&output.stderr);
        return Err(io::Error::other(format!("systemctl: {}", error.trim())));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// `UNIT LOAD ACTIVE SUB DESCRIPTION` lines.
fn list_units() -> io::Result<Vec<Unit>> {
    let text = systemctl(&[
        "list-units",
        "--all",
        "--plain",
        "--no-legend",
        "--no-pager",
        "--full",
    ])?;
    let mut units = Vec::new();
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        if let (Some(name), Some(load), Some(active)) =
            (fields.next(), fields.next(), fields.next())
        {
            units.push(Unit {
                name: name.to_owned(),
                load: load.to_owned(),
                active: active.to_owned(),
            });
        }
    }
    Ok(units)
}

type Properties = Vec<(String, HashMap<String, String>)>;

/// `properties` of `units`, by unit, in one call.
fn show(units: &[&str], properties: &str) -> io::Result<Properties> {
    show_with(units, properties, false)
}

/// As `show`; `unix`, timestamps as `@<seconds>`.
fn show_with(
    units: &[&str],
    properties: &str,
    unix: bool,
) -> io::Result<Properties> {
    if units.is_empty() {
        return Ok(Vec::new());
    }
    let property = format!("--property=Id,{properties}");
    let mut args = vec!["show", property.as_str()];
    if unix {
        args.push("--timestamp=unix");
    }
    args.push("--");
    args.extend(units);
    let text = systemctl(&args)?;
    let mut found = Vec::new();
    for block in text.split("\n\n") {
        let mut values: HashMap<String, String> = block
            .lines()
            .filter_map(|line| line.split_once('='))
            .map(|(key, value)| (key.to_owned(), value.to_owned()))
            .collect();
        if let Some(id) = values.remove("Id") {
            found.push((id, values));
        }
    }
    Ok(found)
}
