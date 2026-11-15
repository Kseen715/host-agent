//! The agent's optional parts, each behind a cargo feature: what a part
//! adds to each round of metrics, and the log sources it reads. A
//! configuration that asks for a part this build lacks is refused.

use crate::config::Config;
use crate::loki::Loki;
use crate::remote::Writer;
use crate::state::Positions;
use std::os::fd::RawFd;

pub trait Part {
    /// Adds its metrics to a round.
    fn round(&mut self, _w: &mut Writer, _now_ms: i64) {}
    /// Once a round, after the metrics: opens or closes log sources.
    fn follow(&mut self, _loki: &mut Loki, _positions: &mut Positions) {}
    /// Before each wait: restarts what has stopped.
    fn prepare(&mut self, _positions: &Positions) {}
    /// What to wait on for lines.
    fn fds(&self) -> Vec<RawFd> {
        Vec::new()
    }
    /// Whether its sources wait while Loki cannot take lines.
    fn feeds_loki(&self) -> bool {
        true
    }
    /// The `index`th of `fds` is ready.
    fn read(&mut self, _index: usize, _loki: &mut Loki, _p: &mut Positions) {}
}

pub fn build(
    config: &mut Config,
    print: bool,
) -> Result<Vec<Box<dyn Part>>, String> {
    refuse_missing(config)?;
    let mut parts: Vec<Box<dyn Part>> = Vec::new();
    #[cfg(feature = "journal")]
    if !print {
        let drops = std::mem::take(&mut config.journal_drops);
        let age = &config.journal_max_age;
        let journal = crate::journal::Journal::new(age, drops);
        if let Some(journal) = journal {
            parts.push(Box::new(journal));
        }
    }
    #[cfg(feature = "docker")]
    {
        let minecraft = std::mem::take(&mut config.minecraft);
        if let Some(docker) = crate::docker::Docker::new(minecraft) {
            parts.push(Box::new(docker));
        }
    }
    #[cfg(feature = "snmp")]
    if !config.snmp.is_empty() {
        let devices = std::mem::take(&mut config.snmp);
        parts.push(Box::new(crate::snmp::Snmp::new(devices)?));
    }
    #[cfg(feature = "otlp")]
    if let (Some(address), false) = (&config.otlp, print) {
        let otlp = crate::otlp::Otlp::bind(address, &config.otlp_forwards)?;
        parts.push(Box::new(otlp));
    }
    #[cfg(feature = "syslog")]
    if let (Some(port), false) = (config.syslog_port, print) {
        let devices = std::mem::take(&mut config.syslog_devices);
        let syslog = crate::syslog::Syslog::bind(port, devices)
            .map_err(|e| format!("syslog on port {port}: {e}"))?;
        parts.push(Box::new(syslog));
    }
    let _ = (config, print);
    Ok(parts)
}

/// Settings whose part this build was made without.
fn refuse_missing(config: &Config) -> Result<(), String> {
    let wanted = [
        ("minecraft", !config.minecraft.is_empty()),
        ("syslog", config.syslog_port.is_some()),
        ("snmp", !config.snmp.is_empty()),
        ("otlp", config.otlp.is_some()),
        (
            "relabel",
            !config.metric_relabel.is_empty() || !config.log_relabel.is_empty(),
        ),
    ];
    let built = [
        ("minecraft", cfg!(feature = "minecraft")),
        ("syslog", cfg!(feature = "syslog")),
        ("snmp", cfg!(feature = "snmp")),
        ("otlp", cfg!(feature = "otlp")),
        ("relabel", cfg!(feature = "relabel")),
    ];
    for ((feature, used), (_, present)) in wanted.iter().zip(built) {
        if *used && !present {
            return Err(format!("built without feature `{feature}`"));
        }
    }
    Ok(())
}
