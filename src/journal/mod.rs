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

use crate::alloy::JournalSource;
use crate::logs::Logs;

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

/// An entry as Alloy's loki.source.journal gives it, if its `matches`
/// pass: MESSAGE the line, every field a label `__journal_<name>` for
/// the source's rules, and `__journal_priority_keyword` the priority's
/// word.
pub fn deliver(config: &JournalSource, entry: &Fields, logs: &mut Logs) {
    if !passes(&config.matches, entry) {
        return;
    }
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
    config.source.emit(logs, labels, ns, &message);
}

/// For each field the matches name, the entry has one of its values.
fn passes(matches: &[(String, String)], entry: &Fields) -> bool {
    let has = |field: &str, value: &str| {
        let pair = (field.as_bytes(), value.as_bytes());
        entry.pairs.contains(&pair)
    };
    matches.iter().all(|(field, _)| {
        let mut values = matches.iter().filter(|(f, _)| f == field);
        values.any(|(_, value)| has(field, value))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matches(list: &[(&str, &str)]) -> Vec<(String, String)> {
        list.iter()
            .map(|(f, v)| (f.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn matches_as_sd_journal() {
        let entry = Fields {
            realtime_us: None,
            pairs: vec![(b"_SYSTEMD_UNIT", b"a.service"), (b"PRIORITY", b"3")],
        };
        assert!(passes(&[], &entry));
        let unit = "_SYSTEMD_UNIT";
        let either = matches(&[(unit, "b.service"), (unit, "a.service")]);
        assert!(passes(&either, &entry));
        let both = matches(&[(unit, "a.service"), ("PRIORITY", "4")]);
        assert!(!passes(&both, &entry));
    }
}
