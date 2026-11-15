//! Syslog messages: RFC 5424, and RFC 3164 with as much of its loose
//! header as there is, read into what Alloy's labels hold.

use crate::time;

/// RFC 5424's words for the severities 0 to 7, as Alloy's labels have
/// them.
const SEVERITIES: [&str; 8] = [
    "emergency",
    "alert",
    "critical",
    "error",
    "warning",
    "notice",
    "informational",
    "debug",
];

const FACILITIES: [&str; 24] = [
    "kern",
    "user",
    "mail",
    "daemon",
    "auth",
    "syslog",
    "lpr",
    "news",
    "uucp",
    "cron",
    "authpriv",
    "ftp",
    "ntp",
    "security",
    "console",
    "solaris-cron",
    "local0",
    "local1",
    "local2",
    "local3",
    "local4",
    "local5",
    "local6",
    "local7",
];

#[derive(Default)]
pub struct Message<'a> {
    pub severity: &'static str,
    pub facility: &'static str,
    pub hostname: &'a str,
    pub app: &'a str,
    pub pid: &'a str,
    pub msg_id: &'a str,
    /// Structured data: each element's id, and its parameters.
    pub data: Vec<(&'a str, Vec<(&'a str, String)>)>,
    /// The time the message says it was sent, in nanoseconds.
    pub ns: Option<i64>,
    pub text: &'a str,
}

/// `<PRI>`: the severity and the facility, and what follows.
fn priority(raw: &str) -> Option<(&'static str, &'static str, &str)> {
    let (priority, rest) = raw.strip_prefix('<')?.split_once('>')?;
    let priority: u8 = priority.parse().ok().filter(|p| *p < 192)?;
    let facility = FACILITIES.get(usize::from(priority >> 3))?;
    Some((SEVERITIES[usize::from(priority & 7)], facility, rest))
}

/// `<PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD [MSG]`, `-` for
/// a field left out.
pub fn rfc5424(raw: &str) -> Option<Message<'_>> {
    let (severity, facility, rest) = priority(raw)?;
    let mut rest = rest.strip_prefix("1 ")?;
    let mut field = || {
        let (value, after) = rest.split_once(' ').unwrap_or((rest, ""));
        rest = after;
        Some(value).filter(|v| *v != "-").unwrap_or("")
    };
    let stamp = field();
    let (hostname, app, pid, msg_id) = (field(), field(), field(), field());
    let (data, text) = structured_data(rest)?;
    let text = text.strip_prefix(' ').unwrap_or(text);
    Some(Message {
        severity,
        facility,
        hostname,
        app,
        pid,
        msg_id,
        data,
        ns: time::parse_rfc3339(stamp),
        text: text.strip_prefix('\u{feff}').unwrap_or(text),
    })
}

type Element<'a> = (&'a str, Vec<(&'a str, String)>);

/// `-` or `[id name="value" ...]...`, and the rest; `\"`, `\\` and
/// `\]` in values stand for the character.
fn structured_data(text: &str) -> Option<(Vec<Element<'_>>, &str)> {
    if let Some(rest) = text.strip_prefix('-') {
        return Some((Vec::new(), rest));
    }
    let mut elements = Vec::new();
    let mut rest = text;
    while let Some(after) = rest.strip_prefix('[') {
        let end = after.find([' ', ']'])?;
        let (id, mut params) = (&after[..end], Vec::new());
        rest = &after[end..];
        while let Some(param) = rest.strip_prefix(' ') {
            let (name, value) = param.split_once("=\"")?;
            let (value, after) = quoted(value)?;
            params.push((name, value));
            rest = after;
        }
        rest = rest.strip_prefix(']')?;
        elements.push((id, params));
    }
    Some((elements, rest))
}

/// A value up to its closing quote, unescaped, and what follows.
fn quoted(text: &str) -> Option<(String, &str)> {
    let mut value = String::new();
    let mut chars = text.char_indices();
    while let Some((at, c)) = chars.next() {
        match c {
            '"' => return Some((value, &text[at + 1..])),
            '\\' => {
                let (_, next) = chars.next()?;
                if !matches!(next, '"' | '\\' | ']') {
                    value.push('\\');
                }
                value.push(next);
            }
            c => value.push(c),
        }
    }
    None
}

/// `<PRI>` and as much of RFC 3164's header as there is: a timestamp,
/// the sender's name, `tag[pid]:`.
pub fn rfc3164(raw: &str) -> Option<Message<'_>> {
    let (severity, facility, rest) = priority(raw)?;
    let (ns, rest) = timestamp(rest);
    let (host, after_host) = rest.split_once(' ').unwrap_or(("", rest));
    let (hostname, (app, pid, text)) = match tag(rest) {
        Some(tagged) => ("", tagged),
        None => (host, tag(after_host).unwrap_or(("", "", rest))),
    };
    let text = if app.is_empty() { rest } else { text };
    Some(Message {
        severity,
        facility,
        hostname: if app.is_empty() { "" } else { hostname },
        app,
        pid,
        ns,
        text,
        ..Message::default()
    })
}

/// A BSD timestamp (`Nov  5 02:36:24 `, this year's, as UTC: it says
/// neither) or an RFC 3339 one, and `rest` after it.
fn timestamp(rest: &str) -> (Option<i64>, &str) {
    let b = rest.as_bytes();
    let bsd = b.len() > 16
        && [(3, b' '), (6, b' '), (9, b':'), (12, b':'), (15, b' ')]
            .iter()
            .all(|&(at, byte)| b[at] == byte);
    if bsd {
        let ns = time::parse_layout("Jan _2 15:04:05", &rest[..15], None);
        return (ns, &rest[16..]);
    }
    let rfc3339 =
        b.len() > 5 && b[..4].iter().all(u8::is_ascii_digit) && b[4] == b'-';
    match rest.split_once(' ') {
        Some((stamp, after)) if rfc3339 => (time::parse_rfc3339(stamp), after),
        _ => (None, rest),
    }
}

/// `tag[pid]: text` as the tag, the pid and the text; None if `rest`
/// does not start with one.
fn tag(rest: &str) -> Option<(&str, &str, &str)> {
    let (head, text) = rest.split_once(':')?;
    if head.is_empty() || head.contains(' ') {
        return None;
    }
    let (app, pid) = head.split_once('[').unwrap_or((head, ""));
    let pid = pid.trim_end_matches(']');
    Some((app, pid, text.strip_prefix(' ').unwrap_or(text)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fields(raw: &str) -> (&'static str, &str, &str) {
        let m = rfc3164(raw).unwrap();
        (m.severity, m.app, m.text)
    }

    #[test]
    fn reads_bsd_syslog() {
        assert_eq!(
            fields("<30>Nov 15 02:36:24 ndhcps: sending ACK. "),
            ("informational", "ndhcps", "sending ACK. ")
        );
        assert_eq!(
            fields("<27>Nov  5 02:36:24 keenetic ndm: Core::Syslog: x"),
            ("error", "ndm", "Core::Syslog: x")
        );
        assert_eq!(
            fields("<12>2026-11-15T02:36:24Z dropbear[42]: login"),
            ("warning", "dropbear", "login")
        );
        assert_eq!(fields("<14>just text"), ("informational", "", "just text"));
        let m = rfc3164("<27>Nov  5 02:36:24 keenetic ndm[7]: x").unwrap();
        assert_eq!(
            (m.hostname, m.pid, m.facility),
            ("keenetic", "7", "daemon")
        );
        assert!(m.ns.is_some());
        assert!(rfc3164("no priority").is_none());
    }

    #[test]
    fn reads_rfc5424() {
        let raw = "<165>1 2003-10-11T22:14:15.003Z mymachine.example.com \
                   evntslog - ID47 [exampleSDID@32473 iut=\"3\" \
                   eventSource=\"Appl\\\"ication\"][x@1] \u{feff}An event";
        let m = rfc5424(raw).unwrap();
        assert_eq!((m.severity, m.facility), ("notice", "local4"));
        assert_eq!(
            (m.hostname, m.app, m.pid),
            ("mymachine.example.com", "evntslog", "")
        );
        assert_eq!((m.msg_id, m.text), ("ID47", "An event"));
        assert_eq!(m.ns, Some(1_065_910_455_003_000_000));
        assert_eq!(m.data[0].0, "exampleSDID@32473");
        assert_eq!(m.data[0].1[1], ("eventSource", "Appl\"ication".into()));
        assert_eq!(m.data[1], ("x@1", Vec::new()));
        let bare = rfc5424("<14>1 - - - - - -").unwrap();
        assert_eq!((bare.app, bare.text, bare.ns), ("", "", None));
        assert!(rfc5424("<14>Nov 15 02:36:24 x: y").is_none());
    }
}
