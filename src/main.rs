//! host-agent: pushes a host's metrics to Prometheus (remote write) and
//! its logs to Loki, the subset of Grafana Alloy that the homelab
//! repository's configuration used, in a few MiB.
//!
//! Usage: `host-agent [--print] [CONFIG]`. `--print` writes one round
//! of metrics to stdout in the text format and sends nothing.

mod agent;
mod cgroup;
mod config;
mod containers;
mod docker;
mod exposition;
mod files;
mod glob;
mod host;
mod http;
mod journal;
mod json;
mod levels;
mod loki;
mod machine;
mod node;
mod process;
mod remote;
mod scrape;
mod spool;
mod state;
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
    let text = match std::env::var(CONFIG_VARIABLE) {
        Ok(text) => Ok(text),
        Err(_) => std::fs::read_to_string(&path)
            .map_err(|error| format!("{path}: {error}")),
    };
    let agent = text
        .and_then(|text| config::Config::parse(&text))
        .and_then(|config| agent::Agent::new(config, print));
    let mut agent = match agent {
        Ok(agent) => agent,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::FAILURE;
        }
    };
    if print {
        agent.round();
    } else {
        agent.run();
    }
    ExitCode::SUCCESS
}
