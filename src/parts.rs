//! Sources and receivers the agent waits on, each behind a cargo
//! feature: the configuration's compiler refuses a component whose part
//! this build was made without.

use crate::alloy::Plan;
use crate::logs::Logs;
use crate::state::Positions;
use std::os::fd::RawFd;

pub trait Part {
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
    fn read(&mut self, _index: usize, _logs: &mut Logs, _p: &mut Positions) {}
}

/// The journal, syslog listeners and OTLP receiver the plan has;
/// --print has none.
pub fn build(plan: &mut Plan) -> Result<Vec<Box<dyn Part>>, String> {
    let mut parts: Vec<Box<dyn Part>> = Vec::new();
    if plan.print {
        return Ok(parts);
    }
    #[cfg(feature = "journal")]
    for (id, max_age, source) in std::mem::take(&mut plan.journal) {
        match crate::journal::Journal::new(id, max_age, source) {
            Some(journal) => parts.push(Box::new(journal)),
            None => eprintln!("Journal: this host has none"),
        }
    }
    #[cfg(feature = "syslog")]
    for listener in std::mem::take(&mut plan.syslogs) {
        let address = listener.address.clone();
        let syslog = crate::syslog::Syslog::bind(listener)
            .map_err(|e| format!("syslog on {address}: {e}"))?;
        parts.push(Box::new(syslog));
    }
    #[cfg(feature = "otlp")]
    for (address, forwards) in std::mem::take(&mut plan.otlp) {
        let otlp = crate::otlp::Otlp::bind(&address, &forwards)?;
        parts.push(Box::new(otlp));
    }
    Ok(parts)
}
