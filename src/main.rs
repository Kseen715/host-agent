//! host-agent: pushes a host's metrics to Prometheus (remote write) and
//! its logs to Loki, reading Grafana Alloy's configuration: the
//! components it has, in a few MiB.
//!
//! Usage: `host-agent [run] [--print] [--server.http.listen-addr=ADDR]
//! [--storage.path=DIR] [CONFIG]`, CONFIG a file or a directory of
//! `*.alloy` files. `--print` writes one round of metrics to stdout in
//! the text format and sends nothing.

// A build without some parts leaves their shared helpers unused; the
// full build is the one linted for dead code.
#![cfg_attr(
    not(all(
        feature = "docker",
        feature = "journal-files",
        feature = "otlp",
        feature = "server",
        feature = "snmp",
        feature = "syslog"
    )),
    allow(dead_code, unused_imports, unused_mut)
)]

mod agent;
mod alloy;
#[cfg(feature = "docker")]
mod cgroup;
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
mod logs;
mod loki;
#[cfg(feature = "docker")]
mod machine;
mod node;
#[cfg(feature = "otlp")]
mod otlp;
mod parts;
mod process;
mod relabel;
mod remote;
mod scrape;
#[cfg(feature = "server")]
mod server;
#[cfg(feature = "snmp")]
mod snmp;
mod spool;
mod stages;
mod state;
#[cfg(feature = "syslog")]
mod syslog;
mod tap;
mod targets;
mod template;
mod time;

use std::process::ExitCode;

const DEFAULT_CONFIG: &str = "/etc/host-agent/config.alloy";
/// The configuration's text, in place of the file: a container from
/// `scratch` gets it this way where no file can be put on the host.
const CONFIG_VARIABLE: &str = "HOST_AGENT_CONFIG";

fn main() -> ExitCode {
    let (options, path) = match arguments() {
        Ok(parsed) => parsed,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::FAILURE;
        }
    };
    let agent = load(&path).and_then(|c| agent::Agent::new(&c, &options));
    let mut agent = match agent {
        Ok(agent) => agent,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::FAILURE;
        }
    };
    if options.print {
        agent.round();
        return ExitCode::SUCCESS;
    }
    // SIGHUP: the configuration again. A bad one keeps the running agent,
    // which reports alloy_config_last_load_successful 0, as Alloy does.
    while let agent::Ended::Reload = agent.run() {
        match load(&path).and_then(|c| agent::Agent::new(&c, &options)) {
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

/// Alloy's `run` command line: the flags this agent uses; others are
/// named and passed over.
fn arguments() -> Result<(agent::Options, String), String> {
    let mut options = agent::Options {
        // Alloy's defaults.
        listen: String::from("127.0.0.1:12345"),
        storage: std::path::PathBuf::from("/var/lib/host-agent"),
        print: false,
    };
    let mut path = String::from(DEFAULT_CONFIG);
    let mut args = std::env::args().skip(1).peekable();
    if args.peek().is_some_and(|a| a == "run") {
        args.next();
    }
    while let Some(arg) = args.next() {
        let (flag, value) = match arg.split_once('=') {
            Some((flag, value)) => (flag.to_owned(), Some(value.to_owned())),
            None => (arg.clone(), None),
        };
        let mut value = || value.clone().or_else(|| args.next());
        match flag.as_str() {
            "--print" => options.print = true,
            "--server.http.listen-addr" => {
                options.listen = value().ok_or("listen-addr: no address")?
            }
            "--storage.path" => {
                options.storage = value().ok_or("storage.path: no path")?.into()
            }
            f if f.starts_with("--") => eprintln!("{f}: not used here"),
            _ => path = arg,
        }
    }
    Ok((options, path))
}

/// The configuration from HOST_AGENT_CONFIG, else from `path`.
fn load(path: &str) -> Result<Vec<alloy::syntax::Stmt>, String> {
    match std::env::var(CONFIG_VARIABLE) {
        Ok(text) => alloy::parse(&text),
        Err(_) => alloy::read(path),
    }
}
