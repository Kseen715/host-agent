//! The systemd journal to Loki as Alloy's loki.source.journal sends it:
//! job `journal`, `unit`, `level` in the journal's words. Read through
//! journalctl, or from the files with feature `journal-files`.

#[cfg(feature = "journal-files")]
mod files;
#[cfg(not(feature = "journal-files"))]
mod journalctl;

#[cfg(feature = "journal-files")]
pub use files::Journal;
#[cfg(not(feature = "journal-files"))]
pub use journalctl::Journal;

use crate::levels::PRIORITIES;
use crate::loki::Loki;
use regex_lite::Regex;

/// The fields of an entry that are sent.
#[derive(Default)]
pub struct Fields<'a> {
    pub realtime_us: Option<i64>,
    pub message: Option<&'a [u8]>,
    pub priority: Option<&'a [u8]>,
    pub unit: Option<&'a [u8]>,
}

/// An entry to Loki as Alloy's loki.source.journal sends it, unless a
/// drop expression matches its message.
pub fn deliver(drops: &[Regex], entry: &Fields, loki: &mut Loki) {
    let Some(message) = entry.message else {
        return;
    };
    let message = String::from_utf8_lossy(message);
    if drops.iter().any(|drop| drop.is_match(&message)) {
        return;
    }
    let number = |field: Option<&[u8]>| -> Option<i64> {
        std::str::from_utf8(field?).ok()?.parse().ok()
    };
    let ns = entry.realtime_us.unwrap_or(0) * 1000;
    let level = number(entry.priority)
        .and_then(|p| PRIORITIES.get(usize::try_from(p).ok()?));
    let unit = entry.unit.map(String::from_utf8_lossy);
    let labels = [
        ("job", "journal"),
        ("unit", unit.as_deref().unwrap_or("")),
        ("level", level.copied().unwrap_or("")),
    ];
    loki.add(&labels, ns, &message);
}
