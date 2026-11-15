//! loki.process: stages that read a line into an extracted map (its
//! labels to begin with), then set its labels, line or time from it, or
//! drop it: Promtail's pipeline, as Alloy's `stage.*` blocks give it.

use crate::json::Json;
use crate::logs::Entry;
use crate::relabel::Labels;
use crate::template::Template;
use crate::time;
use regex_lite::Regex;
use std::time::Duration;

pub enum Stage {
    Regex(Regex, Option<String>),
    Template(String, Template),
    /// The expression, the source (else the line), the replacement.
    Replace(Regex, Option<String>, Template),
    /// A label and the extracted value it is set from.
    Labels(Vec<(String, String)>),
    StaticLabels(Labels),
    LabelDrop(Vec<String>),
    LabelKeep(Vec<String>),
    Drop(Drop),
    /// Values to extract and the paths or keys they are read from.
    Json(Option<String>, Vec<(String, String)>),
    Logfmt(Option<String>, Vec<(String, String)>),
    /// The source and the formats tried in turn.
    Timestamp(String, Vec<String>),
    Output(String),
    Match(Selector, Action),
}

pub enum Action {
    Drop,
    Keep(Vec<Stage>),
}

/// Drops a line that meets every condition given.
#[derive(Default)]
pub struct Drop {
    pub source: Option<String>,
    pub regex: Option<Regex>,
    pub value: Option<String>,
    pub older_than: Option<Duration>,
    pub longer_than: Option<usize>,
}

/// Runs the stages; false if one drops the line.
pub fn run(stages: &[Stage], entry: &mut Entry) -> bool {
    let mut extracted = entry.labels.clone();
    run_with(stages, entry, &mut extracted)
}

fn run_with(stages: &[Stage], entry: &mut Entry, x: &mut Labels) -> bool {
    stages.iter().all(|stage| stage.apply(entry, x))
}

impl Stage {
    /// Whether the entry goes on.
    fn apply(&self, entry: &mut Entry, x: &mut Labels) -> bool {
        match self {
            Stage::Drop(drop) => !drop.matches(entry, x),
            Stage::Match(selector, action) if selector.matches(entry) => {
                match action {
                    Action::Drop => false,
                    Action::Keep(stages) => run_with(stages, entry, x),
                }
            }
            Stage::Match(..) => true,
            _ => {
                self.extract(entry, x);
                self.shape(entry, x);
                true
            }
        }
    }

    /// The stages that set extracted values.
    fn extract(&self, entry: &mut Entry, x: &mut Labels) {
        match self {
            Stage::Regex(regex, source) => {
                if let Some(input) = input(source, entry, x) {
                    extract(regex, &input, x);
                }
            }
            Stage::Template(source, template) => {
                let rendered = template.render(&|name: &str| match name {
                    "Value" => get(x, source).map(str::to_owned),
                    "Entry" => Some(entry.line.clone()),
                    _ => get(x, name).map(str::to_owned),
                });
                if let Ok(text) = rendered {
                    set(x, source, text);
                }
            }
            Stage::Replace(regex, source, with) => {
                replace(regex, source, with, entry, x)
            }
            Stage::Json(source, fields) => {
                if let Some(input) = input(source, entry, x) {
                    json(&input, fields, x);
                }
            }
            Stage::Logfmt(source, fields) => {
                if let Some(input) = input(source, entry, x) {
                    logfmt(&input, fields, x);
                }
            }
            _ => {}
        }
    }

    /// The stages that change the entry's labels, time or line.
    fn shape(&self, entry: &mut Entry, x: &Labels) {
        match self {
            Stage::Labels(values) => {
                for (label, from) in values {
                    if let Some(value) = get(x, from) {
                        set(&mut entry.labels, label, value.to_owned());
                    }
                }
            }
            Stage::StaticLabels(values) => {
                for (label, value) in values {
                    set(&mut entry.labels, label, value.clone());
                }
            }
            Stage::LabelDrop(names) => {
                entry.labels.retain(|(k, _)| !names.contains(k))
            }
            Stage::LabelKeep(names) => {
                entry.labels.retain(|(k, _)| names.contains(k))
            }
            Stage::Timestamp(source, formats) => {
                let value = get(x, source);
                let parsed = value
                    .and_then(|v| formats.iter().find_map(|f| timestamp(f, v)));
                if let Some(ns) = parsed {
                    entry.ns = ns;
                }
            }
            Stage::Output(source) => {
                if let Some(value) = get(x, source) {
                    entry.line = value.to_owned();
                }
            }
            _ => {}
        }
    }
}

/// What a stage reads: an extracted value, or without a source the
/// line; None if the value is not there.
fn input(source: &Option<String>, entry: &Entry, x: &Labels) -> Option<String> {
    match source {
        Some(name) => get(x, name).map(str::to_owned),
        None => Some(entry.line.clone()),
    }
}

fn extract(regex: &Regex, input: &str, x: &mut Labels) {
    let Some(captures) = regex.captures(input) else {
        return;
    };
    for name in regex.capture_names().flatten() {
        let value = captures.name(name).map_or("", |m| m.as_str());
        set(x, name, value.to_owned());
    }
}

/// Each captured group in its source replaced by the template, given
/// the group's text as `.Value`.
fn replace(
    regex: &Regex,
    source: &Option<String>,
    with: &Template,
    entry: &mut Entry,
    x: &mut Labels,
) {
    let Some(text) = input(source, entry, x) else {
        return;
    };
    let mut out = String::new();
    let mut last = 0;
    for captures in regex.captures_iter(&text) {
        let groups = (1..captures.len()).filter_map(|i| captures.get(i));
        for group in groups.collect::<Vec<_>>() {
            if group.start() < last {
                continue;
            }
            out.push_str(&text[last..group.start()]);
            let fields = |name: &str| match name {
                "Value" => Some(group.as_str().to_owned()),
                _ => get(x, name).map(str::to_owned),
            };
            out.push_str(&with.render(&fields).unwrap_or_default());
            last = group.end();
        }
    }
    if last == 0 {
        return;
    }
    extract(regex, &text, x);
    out.push_str(&text[last..]);
    match source {
        Some(name) => set(x, name, out),
        None => entry.line = out,
    }
}

impl Drop {
    fn matches(&self, entry: &Entry, x: &Labels) -> bool {
        if let Some(age) = self.older_than {
            let age = age.as_nanos() as i64;
            if entry.ns >= time::now_ns() - age {
                return false;
            }
        }
        if self.longer_than.is_some_and(|n| entry.line.len() <= n) {
            return false;
        }
        let value = match &self.source {
            Some(name) => match get(x, name) {
                Some(value) => value,
                None => return false,
            },
            None => entry.line.as_str(),
        };
        self.regex.as_ref().is_none_or(|r| r.is_match(value))
            && self.value.as_ref().is_none_or(|v| v == value)
    }
}

/// Values at JMESPath's simplest paths: `a.b`, `a[0]`; objects and
/// arrays are not extracted.
fn json(input: &str, fields: &[(String, String)], x: &mut Labels) {
    let Some(json) = Json::parse(input) else {
        return;
    };
    for (name, path) in fields {
        let path = if path.is_empty() { name } else { path };
        let mut at = Some(&json);
        for step in path.split('.') {
            let (key, index) = match step.split_once('[') {
                Some((key, i)) => {
                    (key, i.trim_end_matches(']').parse::<usize>().ok())
                }
                None => (step, None),
            };
            at = at.and_then(
                |j| if key.is_empty() { Some(j) } else { j.get(key) },
            );
            if let Some(index) = index {
                at = at.and_then(|j| j.arr().get(index));
            }
        }
        let value = match at {
            Some(Json::Str(s)) => s.clone(),
            Some(Json::Num(n)) => n.to_string(),
            Some(Json::Bool(b)) => b.to_string(),
            _ => continue,
        };
        set(x, name, value);
    }
}

/// `key=value key="quoted value"` pairs.
fn logfmt(input: &str, fields: &[(String, String)], x: &mut Labels) {
    let mut pairs = Vec::new();
    let mut rest = input.trim_start();
    while !rest.is_empty() {
        let end = rest.find([' ', '=']).unwrap_or(rest.len());
        let key = &rest[..end];
        rest = &rest[end..];
        let mut value = String::new();
        if let Some(after) = rest.strip_prefix('=') {
            (value, rest) = logfmt_value(after);
        }
        pairs.push((key, value));
        rest = rest.trim_start();
    }
    for (name, key) in fields {
        let key = if key.is_empty() { name } else { key };
        if let Some((_, value)) = pairs.iter().find(|(k, _)| k == key) {
            set(x, name, value.clone());
        }
    }
}

fn logfmt_value(text: &str) -> (String, &str) {
    let Some(quoted) = text.strip_prefix('"') else {
        let end = text.find(' ').unwrap_or(text.len());
        return (text[..end].to_owned(), &text[end..]);
    };
    let mut value = String::new();
    let mut chars = quoted.char_indices();
    while let Some((at, c)) = chars.next() {
        match c {
            '"' => return (value, &quoted[at + 1..]),
            '\\' => value.extend(chars.next().map(|(_, c)| c)),
            c => value.push(c),
        }
    }
    (value, "")
}

fn timestamp(format: &str, value: &str) -> Option<i64> {
    let number = |scale: i64| value.parse::<i64>().ok().map(|n| n * scale);
    match format {
        "Unix" => value.parse::<f64>().ok().map(|s| (s * 1e9) as i64),
        "UnixMs" => number(1_000_000),
        "UnixUs" => number(1_000),
        "UnixNs" => number(1),
        layout => time::parse_layout(time::named_layout(layout), value),
    }
}

fn get<'a>(labels: &'a Labels, name: &str) -> Option<&'a str> {
    let found = labels.iter().find(|(k, _)| k == name);
    found.map(|(_, v)| v.as_str())
}

fn set(labels: &mut Labels, name: &str, value: String) {
    match labels.iter_mut().find(|(k, _)| k == name) {
        Some((_, old)) => *old = value,
        None => labels.push((name.to_owned(), value)),
    }
}

/// A LogQL stream selector and line filters, as stage.match takes
/// them: `{app="a", level=~"err|crit"} |= "timeout" !~ "retry"`.
pub struct Selector {
    labels: Vec<(String, Test)>,
    lines: Vec<Test>,
}

enum Test {
    Equal(String, bool),
    Regex(Regex, bool),
    Contains(String, bool),
}

impl Test {
    fn passes(&self, value: &str) -> bool {
        match self {
            Test::Equal(want, yes) => (value == want) == *yes,
            Test::Regex(regex, yes) => regex.is_match(value) == *yes,
            Test::Contains(part, yes) => value.contains(part.as_str()) == *yes,
        }
    }
}

impl Selector {
    pub fn parse(text: &str) -> Result<Selector, String> {
        let mut scan = Scan(text.trim());
        scan.expect("{")?;
        let mut labels = Vec::new();
        while !scan.eat("}") {
            let name = scan.name();
            let op = scan.op(&["=~", "!~", "!=", "="])?;
            let value = scan.string()?;
            labels.push((name, test(op, value, false)?));
            scan.eat(",");
        }
        let mut lines = Vec::new();
        while !scan.0.trim().is_empty() {
            let op = scan.op(&["|=", "!=", "|~", "!~"])?;
            lines.push(test(op, scan.string()?, true)?);
        }
        Ok(Selector { labels, lines })
    }

    fn matches(&self, entry: &Entry) -> bool {
        self.labels.iter().all(|(name, test)| {
            test.passes(get(&entry.labels, name).unwrap_or(""))
        }) && self.lines.iter().all(|test| test.passes(&entry.line))
    }
}

fn test(op: &str, value: String, line: bool) -> Result<Test, String> {
    let yes = op.starts_with(['=', '|']);
    if op.ends_with('~') {
        let anchored = if line {
            value
        } else {
            format!("^(?:{value})$")
        };
        let regex = Regex::new(&anchored).map_err(|e| e.to_string())?;
        return Ok(Test::Regex(regex, yes));
    }
    Ok(if line {
        Test::Contains(value, yes)
    } else {
        Test::Equal(value, yes)
    })
}

struct Scan<'a>(&'a str);

impl Scan<'_> {
    fn eat(&mut self, token: &str) -> bool {
        self.0 = self.0.trim_start();
        let rest = self.0.strip_prefix(token);
        rest.map(|rest| self.0 = rest).is_some()
    }

    fn expect(&mut self, token: &str) -> Result<(), String> {
        self.eat(token)
            .then_some(())
            .ok_or(format!("expected `{token}`"))
    }

    fn name(&mut self) -> String {
        self.0 = self.0.trim_start();
        let end = self.0.find(|c: char| !(c.is_alphanumeric() || c == '_'));
        let (name, rest) = self.0.split_at(end.unwrap_or(self.0.len()));
        self.0 = rest;
        name.to_owned()
    }

    fn op(&mut self, ops: &[&'static str]) -> Result<&'static str, String> {
        let op = ops.iter().find(|op| self.eat(op));
        op.copied().ok_or(format!("expected one of {ops:?}"))
    }

    fn string(&mut self) -> Result<String, String> {
        self.0 = self.0.trim_start();
        if let Some(raw) = self.0.strip_prefix('`') {
            let end = raw.find('`').ok_or("unclosed string")?;
            self.0 = &raw[end + 1..];
            return Ok(raw[..end].to_owned());
        }
        if !self.0.starts_with('"') {
            return Err("expected a string".into());
        }
        let (value, rest) = logfmt_value(self.0);
        self.0 = rest;
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(line: &str) -> Entry {
        Entry {
            labels: vec![("job".into(), "docker".into())],
            ns: 0,
            line: line.into(),
        }
    }

    fn levels() -> Vec<Stage> {
        let regex = |r: &str| Regex::new(r).unwrap();
        let template = |t: &str| Template::parse(t).unwrap();
        let level = Some("level".to_owned());
        vec![
            Stage::Regex(
                regex(r"(?i)\b(?P<level>debug|info|warn|error)"),
                None,
            ),
            Stage::Template("level".into(), template("{{ ToLower .Value }}")),
            Stage::Replace(regex("^(w|warn)$"), level, template("warning")),
            Stage::Labels(vec![("level".into(), "level".into())]),
        ]
    }

    #[test]
    fn sets_a_level_label() {
        let mut warned = entry("[12:00] WARN: low disk");
        assert!(run(&levels(), &mut warned));
        assert_eq!(get(&warned.labels, "level"), Some("warning"));
        let mut plain = entry("plain line");
        assert!(run(&levels(), &mut plain));
        assert_eq!(get(&plain.labels, "level"), None);
    }

    #[test]
    fn drops_matches_and_parses() {
        let drop = Stage::Drop(Drop {
            regex: Some(Regex::new("^info: guest-ping").unwrap()),
            ..Drop::default()
        });
        assert!(!run(&[drop], &mut entry("info: guest-ping called")));

        let selector = Selector::parse(r#"{job=~"dock.*"} |= "boom""#);
        let stage = Stage::Match(selector.unwrap(), Action::Drop);
        assert!(!run(std::slice::from_ref(&stage), &mut entry("a boom")));
        assert!(run(&[stage], &mut entry("quiet")));

        let mut parsed = entry(r#"{"a":{"b":[1,"x"]}}"#);
        let fields = vec![("v".into(), "a.b[1]".into())];
        let stages = [
            Stage::Json(None, fields),
            Stage::Output("v".into()),
            Stage::Logfmt(None, vec![("t".into(), String::new())]),
        ];
        assert!(run(&stages, &mut parsed));
        assert_eq!(parsed.line, "x");
        let mut timed = entry(r#"t="1970-01-01T00:00:01Z" msg=hi"#);
        let stages = [
            Stage::Logfmt(None, vec![("t".into(), String::new())]),
            Stage::Timestamp("t".into(), vec!["RFC3339".into()]),
        ];
        assert!(run(&stages, &mut timed));
        assert_eq!(timed.ns, 1_000_000_000);
    }
}
