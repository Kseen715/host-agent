//! The configuration file: one setting per line, `key value`; repeated
//! keys add to a list; `#` starts a comment line. Written by Ansible
//! (role observability_agent in the homelab repository).
//!
//! ```text
//! host mc-01
//! metrics_url http://10.18.18.81:9090/api/v1/write
//! logs_url http://10.18.18.81:3100/loki/api/v1/push
//! interval 15
//! textfile_dir /var/lib/alloy/textfile
//! log_targets_dir /var/lib/alloy/logs.d
//! log syslog /var/log/messages
//! state_dir /var/lib/host-agent
//! spool_max_mb 256
//! root /host/root
//! disable diskstats
//! scrape mc-router 127.0.0.1:9101
//! minecraft classic crafty 25565 26565
//! server_port 25565 classic
//! journal_max_age 12h
//! journal_drop ^info: guest-ping called
//! snmp keenetic 10.18.18.1 public system,if_mib
//! syslog 514
//! metric_relabel drop source_labels=__name__ regex=go_.*
//! log_relabel labeldrop regex=filename
//! otlp 127.0.0.1:4318
//! otlp_forward logs http://10.18.18.81:3100/otlp/v1/logs
//! syslog_device keenetic 10.18.18.1
//! ```

use crate::files::Target;
use crate::scrape::ServerPort;
use regex_lite::Regex;
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

pub struct Scrape {
    pub job: String,
    pub address: String,
}

/// A Minecraft server's metrics plugin, inside the Compose service's
/// container, which publishes no port for it: reached at the
/// container's address if the container exposes the server's port.
pub struct Minecraft {
    pub server: String,
    pub service: String,
    pub port: u16,
    pub metrics_port: u16,
}

/// A network device polled over SNMP v2c.
pub struct Device {
    pub name: String,
    pub address: String,
    pub community: String,
    pub modules: Vec<String>,
}

pub struct Config {
    pub host: String,
    pub metrics_url: String,
    pub logs_url: String,
    pub interval: Duration,
    pub textfile_dir: Option<PathBuf>,
    pub log_targets_dir: Option<PathBuf>,
    /// `log <job> <path>`: a log file (or pattern) and its job.
    pub logs: Vec<Target>,
    pub state_dir: PathBuf,
    /// Metrics kept on disk while Prometheus is away; 0: none kept.
    pub spool_max_mb: u64,
    /// In a container: where the host's root is mounted (crate::host).
    pub root: Option<PathBuf>,
    pub disabled: Vec<String>,
    pub scrapes: Vec<Scrape>,
    pub minecraft: Vec<Minecraft>,
    pub server_ports: Vec<ServerPort>,
    pub journal_max_age: String,
    pub journal_drops: Vec<Regex>,
    /// `snmp <name> <address> <community> <module,...>`: a device polled.
    pub snmp: Vec<Device>,
    /// `metric_relabel <rule>`, `log_relabel <rule>` (crate::relabel).
    pub metric_relabel: Vec<String>,
    pub log_relabel: Vec<String>,
    /// `otlp <address>`: OTLP/HTTP received there (crate::otlp)...
    pub otlp: Option<String>,
    /// ...and `otlp_forward <signal> <url>`: where each signal goes.
    pub otlp_forwards: Vec<(String, String)>,
    /// `syslog <port>`: network devices' syslog received there.
    pub syslog_port: Option<u16>,
    /// `syslog_device <name> <address>`: a device whose lines are kept.
    pub syslog_devices: Vec<(String, IpAddr)>,
}

impl Config {
    pub fn parse(text: &str) -> Result<Config, String> {
        let mut config = Config {
            host: String::new(),
            metrics_url: String::new(),
            logs_url: String::new(),
            interval: Duration::from_secs(15),
            textfile_dir: None,
            log_targets_dir: None,
            logs: Vec::new(),
            state_dir: PathBuf::from("/var/lib/host-agent"),
            spool_max_mb: 256,
            root: None,
            disabled: Vec::new(),
            scrapes: Vec::new(),
            minecraft: Vec::new(),
            server_ports: Vec::new(),
            journal_max_age: String::from("12h"),
            journal_drops: Vec::new(),
            snmp: Vec::new(),
            metric_relabel: Vec::new(),
            log_relabel: Vec::new(),
            otlp: None,
            otlp_forwards: Vec::new(),
            syslog_port: None,
            syslog_devices: Vec::new(),
        };
        for (number, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (key, value) = line.split_once(' ').unwrap_or((line, ""));
            config
                .set(key, value.trim())
                .map_err(|error| format!("line {}: {error}", number + 1))?;
        }
        for (key, value) in [
            ("host", &config.host),
            ("metrics_url", &config.metrics_url),
            ("logs_url", &config.logs_url),
        ] {
            if value.is_empty() {
                return Err(format!("{key} is not set"));
            }
        }
        Ok(config)
    }

    fn set(&mut self, key: &str, value: &str) -> Result<(), String> {
        let words: Vec<&str> = value.split_whitespace().collect();
        match (key, &words[..]) {
            ("host", [host]) => self.host = (*host).into(),
            ("metrics_url", [url]) => self.metrics_url = (*url).into(),
            ("logs_url", [url]) => self.logs_url = (*url).into(),
            ("interval", [seconds]) => {
                let seconds =
                    seconds.parse().map_err(|_| "interval is seconds")?;
                self.interval = Duration::from_secs(seconds);
            }
            ("textfile_dir", [dir]) => self.textfile_dir = Some(dir.into()),
            ("log_targets_dir", [dir]) => {
                self.log_targets_dir = Some(dir.into())
            }
            ("log", [job, path]) => self.logs.push(Target {
                path: (*path).into(),
                exclude: None,
                labels: vec![("job".into(), (*job).into())],
            }),
            ("state_dir", [dir]) => self.state_dir = dir.into(),
            ("spool_max_mb", [mb]) => {
                self.spool_max_mb =
                    mb.parse().map_err(|_| "spool_max_mb is a number")?;
            }
            ("root", [dir]) => self.root = Some(dir.into()),
            ("disable", [collector]) => self.disabled.push((*collector).into()),
            ("scrape", [job, address]) => self.scrapes.push(Scrape {
                job: (*job).into(),
                address: (*address).into(),
            }),
            ("minecraft", [server, service, port, metrics_port]) => {
                let number = |p: &str| {
                    p.parse().map_err(|_| format!("{p} is not a port"))
                };
                self.minecraft.push(Minecraft {
                    server: (*server).into(),
                    service: (*service).into(),
                    port: number(port)?,
                    metrics_port: number(metrics_port)?,
                });
            }
            ("server_port", [port, name]) => {
                self.server_ports.push(ServerPort {
                    port: (*port).into(),
                    name: (*name).into(),
                })
            }
            ("journal_max_age", [age]) => self.journal_max_age = (*age).into(),
            ("journal_drop", _) if !value.is_empty() => {
                let regex = Regex::new(value).map_err(|e| e.to_string())?;
                self.journal_drops.push(regex);
            }
            ("snmp", [name, address, community, modules]) => {
                self.snmp.push(Device {
                    name: (*name).into(),
                    address: (*address).into(),
                    community: (*community).into(),
                    modules: modules.split(',').map(str::to_owned).collect(),
                })
            }
            ("metric_relabel", _) => self.metric_relabel.push(value.into()),
            ("log_relabel", _) => self.log_relabel.push(value.into()),
            ("otlp", [address]) => self.otlp = Some((*address).into()),
            ("otlp_forward", [signal, url]) => {
                self.otlp_forwards.push(((*signal).into(), (*url).into()))
            }
            ("syslog", [port]) => {
                let port = port.parse().map_err(|_| "syslog is a port")?;
                self.syslog_port = Some(port);
            }
            ("syslog_device", [name, address]) => {
                let address =
                    address.parse().map_err(|_| "not an IP address")?;
                self.syslog_devices.push(((*name).into(), address));
            }
            _ => return Err(format!("cannot read `{key} {value}`")),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn reads_the_documented_example() {
        let text = include_str!("config.rs")
            .lines()
            .skip_while(|l| !l.starts_with("//! ```text"))
            .skip(1)
            .take_while(|l| !l.starts_with("//! ```"))
            .map(|l| l.trim_start_matches("//! "))
            .collect::<Vec<_>>()
            .join("\n");
        let config = Config::parse(&text).unwrap();
        assert_eq!(config.host, "mc-01");
        assert_eq!(config.minecraft[0].metrics_port, 26565);
        assert!(config.journal_drops[0].is_match("info: guest-ping called"));
        assert_eq!(config.disabled, ["diskstats"]);
        assert_eq!(config.logs[0].path, "/var/log/messages");
        assert_eq!(config.root.as_deref(), Some(Path::new("/host/root")));
    }

    #[test]
    fn refuses_unknown_lines() {
        let error = Config::parse("host h\nfrobnicate 1\n").err().unwrap();
        assert_eq!(error, "line 2: cannot read `frobnicate 1`");
    }
}
