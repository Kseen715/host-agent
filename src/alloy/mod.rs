//! Alloy's configuration (config.alloy), read as Alloy reads it: the
//! components this agent has, in Alloy's syntax, so one file serves
//! both.

mod client;
mod compile;
mod components;
mod process;
mod snmp;
mod stdlib;
pub mod syntax;
mod unix;
mod value;

#[cfg(feature = "tls")]
pub use compile::ListenerTls;
pub use compile::{
    Exporter, JournalSource, Plan, ScrapeJob, SyslogFormat, SyslogListener,
    compile,
};
pub use components::INTERNAL;

use std::fs;
use std::path::Path;

/// The configuration at `path`: a file, or every `*.alloy` file in a
/// directory, as Alloy takes it.
pub fn read(path: &str) -> Result<Vec<syntax::Stmt>, String> {
    let error = |e: std::io::Error| format!("{path}: {e}");
    if !Path::new(path).is_dir() {
        let text = fs::read_to_string(path).map_err(error)?;
        return syntax::parse(&text).map_err(|e| format!("{path}:{e}"));
    }
    let mut files: Vec<_> = fs::read_dir(path)
        .map_err(error)?
        .flatten()
        .map(|entry| entry.path())
        .filter(|p| p.extension().is_some_and(|e| e == "alloy"))
        .collect();
    files.sort();
    let mut stmts = Vec::new();
    for file in files {
        let name = file.display().to_string();
        let text =
            fs::read_to_string(&file).map_err(|e| format!("{name}: {e}"))?;
        stmts.extend(syntax::parse(&text).map_err(|e| format!("{name}:{e}"))?);
    }
    Ok(stmts)
}

/// A configuration's text, read: HOST_AGENT_CONFIG's.
pub fn parse(text: &str) -> Result<Vec<syntax::Stmt>, String> {
    syntax::parse(text)
}
