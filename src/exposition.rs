//! Prometheus's text exposition format, read: exporters' scrapes and
//! the textfile directory's `*.prom` files, each sample with its own
//! timestamp if it has one, for a scrape that honors them.

use std::borrow::Cow;

pub type Labels<'a> = Vec<(&'a str, Cow<'a, str>)>;

/// Calls `sample` with each sample's name, labels, value and timestamp
/// in milliseconds; lines that cannot be read are skipped.
pub fn parse(
    text: &str,
    mut sample: impl FnMut(&str, &Labels, f64, Option<i64>),
) {
    for line in text.lines() {
        let line = line.trim_start();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((name, labels, value, at)) = parse_line(line) {
            sample(name, &labels, value, at);
        }
    }
}

type Sample<'a> = (&'a str, Labels<'a>, f64, Option<i64>);

fn parse_line(line: &str) -> Option<Sample<'_>> {
    let end = line.find(['{', ' ', '\t']).unwrap_or(line.len());
    let (name, mut rest) = line.split_at(end);
    let mut labels = Vec::new();
    if let Some(inside) = rest.strip_prefix('{') {
        rest = parse_labels(inside, &mut labels)?;
    }
    let mut words = rest.split_whitespace();
    let value = parse_value(words.next()?)?;
    let at = words.next().and_then(|ms| ms.parse().ok());
    Some((name, labels, value, at))
}

/// Reads `key="value",...}` into `labels`; returns what follows `}`.
fn parse_labels<'a>(
    mut rest: &'a str,
    labels: &mut Labels<'a>,
) -> Option<&'a str> {
    loop {
        rest = rest.trim_start_matches([' ', ',']);
        if let Some(after) = rest.strip_prefix('}') {
            return Some(after);
        }
        let (key, after) = rest.split_once('=')?;
        let after = after.trim_start().strip_prefix('"')?;
        let (value, after) = quoted(after)?;
        labels.push((key.trim(), value));
        rest = after;
    }
}

/// A label value up to its closing quote, unescaped.
fn quoted(text: &str) -> Option<(Cow<'_, str>, &str)> {
    let bytes = text.as_bytes();
    let mut i = 0;
    let mut escaped = false;
    while i < bytes.len() && bytes[i] != b'"' {
        escaped |= bytes[i] == b'\\';
        i += if bytes[i] == b'\\' { 2 } else { 1 };
    }
    let (raw, rest) = (text.get(..i)?, text.get(i + 1..)?);
    if !escaped {
        return Some((Cow::Borrowed(raw), rest));
    }
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some(other) => out.push(other),
            None => {}
        }
    }
    Some((Cow::Owned(out), rest))
}

fn parse_value(text: &str) -> Option<f64> {
    match text {
        "+Inf" => Some(f64::INFINITY),
        "-Inf" => Some(f64::NEG_INFINITY),
        "NaN" => Some(f64::NAN),
        _ => text.parse().ok(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn collect(text: &str) -> Vec<String> {
        let mut out = Vec::new();
        parse(text, |name, labels, value, at| {
            let pairs: Vec<String> =
                labels.iter().map(|(k, v)| format!("{k}={v}")).collect();
            let at = at.map(|ms| format!("@{ms}")).unwrap_or_default();
            out.push(format!("{name}|{}|{value}{at}", pairs.join(",")));
        });
        out
    }

    #[test]
    fn reads_samples() {
        let text = "# HELP up x\n# TYPE up gauge\nup 1\n\
            a_total{x=\"1\",y=\"q\\\"uo\\\\te\\n\"} 2.5 1700000000000\n\
            b{} +Inf\n  c{z=\"a,b}\",} -3e2\nbroken{x=\"1\" 5\n";
        assert_eq!(
            collect(text),
            [
                "up||1",
                "a_total|x=1,y=q\"uo\\te\n|2.5@1700000000000",
                "b||inf",
                "c|z=a,b}|-300",
            ]
        );
    }
}
