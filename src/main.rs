//! host-agent: pushes a host's metrics to Prometheus (remote write) and
//! its logs to Loki, the subset of Grafana Alloy that the homelab
//! repository's configuration used, in a few MiB.
//!
//! Usage: `host-agent [--print] [CONFIG]`. `--print` writes one round
//! of metrics to stdout in the text format and sends nothing.

// A build without some parts leaves their shared helpers unused; the
// full build is the one linted for dead code.
#![cfg_attr(
    not(all(
        feature = "docker",
        feature = "journal-files",
        feature = "minecraft",
        feature = "otlp",
        feature = "relabel",
        feature = "snmp",
        feature = "syslog"
    )),
    allow(dead_code, unused_imports, unused_mut)
)]

mod agent;
#[cfg(feature = "docker")]
mod cgroup;
mod config;
#[cfg(feature = "docker")]
mod containers;
#[cfg(feature = "docker")]
mod docker;
mod exposition;
mod files;
mod glob;
mod host;
mod http;
#[cfg(feature = "journal")]
mod journal;
mod json;
mod levels;
mod loki;
#[cfg(feature = "docker")]
mod machine;
mod node;
#[cfg(feature = "otlp")]
mod otlp;
mod parts;
mod process;
#[cfg(feature = "relabel")]
mod relabel;
mod remote;
mod scrape;
#[cfg(feature = "snmp")]
mod snmp;
mod spool;
mod state;
#[cfg(feature = "syslog")]
mod syslog;
mod time;

use std::process::ExitCode;

const DEFAULT_CONFIG: &str = "/etc/host-agent/config";
/// The configuration's text, in place of the file: a container from
/// `scratch` gets it this way where no file can be put on the host.
const CONFIG_VARIABLE: &str = "HOST_AGENT_CONFIG";

fn main() -> ExitCode {
    let mut print = false;
    let mut path = String::from(DEFAULT_CONFIG);
    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "--print" => print = true,
            _ => path = arg,
        }
    }
    let agent = load(&path).and_then(|c| agent::Agent::new(c, print));
    let mut agent = match agent {
        Ok(agent) => agent,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::FAILURE;
        }
    };
    if print {
        agent.round();
        return ExitCode::SUCCESS;
    }
    // SIGHUP: the configuration again. A bad one keeps the running agent,
    // which reports alloy_config_last_load_successful 0, as Alloy does.
    while let agent::Ended::Reload = agent.run() {
        match load(&path).and_then(|c| agent::Agent::new(c, false)) {
            Ok(new) => {
                eprintln!("Configuration reloaded");
                agent = new;
            }
            Err(error) => {
                eprintln!("Reload: {error}");
                agent.config_failed();
            }
        }
    }
    ExitCode::SUCCESS
}

/// The configuration from HOST_AGENT_CONFIG, else from the file.
fn load(path: &str) -> Result<config::Config, String> {
    let text = match std::env::var(CONFIG_VARIABLE) {
        Ok(text) => text,
        Err(_) => std::fs::read_to_string(path)
            .map_err(|error| format!("{path}: {error}"))?,
    };
    config::Config::parse(&text)
}
