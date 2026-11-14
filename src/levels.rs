//! Container output and log files have no structured severity: the
//! first level word in a line becomes its level, in the journal's words
//! (lowercase, warning, crit), so one level is one label value. A klog
//! line (cAdvisor, Kubernetes tools) states it in its header letter
//! instead, and its text may say "Error" at info.

/// Words as Alloy's `(?i)\b(debug|info|warn|error|...)` found them, no
/// word boundary after: "warning" and "information" count.
const WORDS: [(&str, &str); 7] = [
    ("debug", "debug"),
    ("info", "info"),
    ("warn", "warning"),
    ("error", "error"),
    ("fatal", "crit"),
    ("critical", "crit"),
    ("panic", "crit"),
];

/// The journal's words for its priorities 0 to 7.
pub const PRIORITIES: [&str; 8] = [
    "emerg", "alert", "crit", "err", "warning", "notice", "info", "debug",
];

pub fn level(line: &str) -> Option<&'static str> {
    klog(line.as_bytes()).or_else(|| first_word(line.as_bytes()))
}

fn first_word(bytes: &[u8]) -> Option<&'static str> {
    for at in 0..bytes.len() {
        if at > 0 && is_word(bytes[at - 1]) {
            continue;
        }
        let rest = &bytes[at..];
        for (word, level) in WORDS {
            let head = rest.get(..word.len());
            if head.is_some_and(|h| h.eq_ignore_ascii_case(word.as_bytes())) {
                return Some(level);
            }
        }
    }
    None
}

/// `I1018 00:08:41.675830 ...`: level letter, month and day, time.
fn klog(bytes: &[u8]) -> Option<&'static str> {
    let level = match bytes.first()? {
        b'I' => "info",
        b'W' => "warning",
        b'E' => "error",
        b'F' => "crit",
        _ => return None,
    };
    let shape = b"0000 00:00:00.";
    let head = bytes.get(1..1 + shape.len())?;
    let fits = head.iter().zip(shape).all(|(&b, &s)| {
        if s == b'0' {
            b.is_ascii_digit()
        } else {
            b == s
        }
    });
    let rest = &bytes[1 + shape.len()..];
    let digits = rest.iter().take_while(|b| b.is_ascii_digit()).count();
    (fits && digits > 0 && rest.get(digits) == Some(&b' ')).then_some(level)
}

/// Go's regexp `\b`: ASCII word characters only.
fn is_word(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_the_first_level_word() {
        assert_eq!(level("[12:00] WARNING: low disk"), Some("warning"));
        assert_eq!(level("Information: error later"), Some("info"));
        assert_eq!(level("terror is not a level"), None);
        assert_eq!(level("x_error has a word before it"), None);
        assert_eq!(level("PANIC now"), Some("crit"));
        assert_eq!(level("plain line"), None);
    }

    #[test]
    fn klog_headers_win() {
        let line = "I1018 00:08:41.675830 1 x.go:1] Error was retried";
        assert_eq!(level(line), Some("info"));
        assert_eq!(level("E1018 00:08:41.6 1 boom"), Some("error"));
        assert_eq!(level("Info1018 nope"), Some("info"));
    }
}
