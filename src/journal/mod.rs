//! loki.source.journal: the systemd journal, read through journalctl,
//! or from the files with feature `journal-files`.

#[cfg(feature = "journal-files")]
mod files;
#[cfg(not(feature = "journal-files"))]
mod journalctl;

#[cfg(feature = "journal-files")]
pub use files::Journal;
#[cfg(not(feature = "journal-files"))]
pub use journalctl::Journal;

use crate::logs::{Logs, Source};

/// The journal's words for its priorities 0 to 7.
const PRIORITIES: [&str; 8] = [
    "emerg", "alert", "crit", "err", "warning", "notice", "info", "debug",
];

/// An entry's time and its fields, `NAME` and value.
#[derive(Default)]
pub struct Fields<'a> {
    pub realtime_us: Option<i64>,
    pub pairs: Vec<(&'a [u8], &'a [u8])>,
}

/// An entry as Alloy's loki.source.journal gives it: MESSAGE the line,
/// every field a label `__journal_<name>` for the source's rules, and
/// `__journal_priority_keyword` the priority's word.
pub fn deliver(source: &Source, entry: &Fields, logs: &mut Logs) {
    let mut message = None;
    let mut labels = Vec::with_capacity(entry.pairs.len() + 1);
    for &(name, value) in &entry.pairs {
        let value = String::from_utf8_lossy(value).into_owned();
        match name {
            b"MESSAGE" => message = Some(value.clone()),
            b"PRIORITY" => {
                let word =
                    value.parse().ok().and_then(|p: usize| PRIORITIES.get(p));
                let word = word.map_or(value.clone(), |w| (*w).to_owned());
                labels.push(("__journal_priority_keyword".into(), word));
            }
            _ => {}
        }
        let name = String::from_utf8_lossy(name).to_lowercase();
        labels.push((format!("__journal_{name}"), value));
    }
    let Some(message) = message else {
        return;
    };
    let ns = entry
        .realtime_us
        .map_or_else(crate::time::now_ns, |us| us * 1000);
    source.emit(logs, labels, ns, &message);
}
