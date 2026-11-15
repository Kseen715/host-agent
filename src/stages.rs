//! loki.process: stages that read a line into an extracted map (its
//! labels to begin with), then set its labels, line or time from it, or
//! drop it: Promtail's pipeline, as Alloy's `stage.*` blocks give it.

use crate::json::Json;
use crate::logs::Entry;
use crate::relabel::Labels;
use crate::template::Template;
use crate::time;
use crate::zone::Zone;
use regex_lite::Regex;
use std::cell::RefCell;
use std::collections::HashMap;
use std::time::Duration;

/// Streams whose last time stage.timestamp keeps for `fudge`, as
/// Promtail's cache holds them.
const FUDGED_STREAMS: usize = 10_000;

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
    Json(JsonStage),
    /// Values to extract and the keys they are read from.
    Logfmt(Option<String>, Vec<(String, String)>),
    Timestamp(Timestamp),
    Output(String),
    Match(Selector, Action),
}

pub enum Action {
    Drop,
    Keep(Vec<Stage>),
}

/// stage.timestamp: the source, the formats tried in turn, the zone of
/// a time without one; with `fudge`, a line whose time cannot be read
/// gets its stream's last one plus 1 ns.
pub struct Timestamp {
    pub source: String,
    pub formats: Vec<String>,
    pub zone: Option<Zone>,
    pub fudge: bool,
    pub last: RefCell<HashMap<String, i64>>,
}

impl Timestamp {
    fn apply(&self, entry: &mut Entry, x: &Labels) {
        let value = get(x, &self.source);
        let parsed = value.and_then(|v| {
            let zone = self.zone.as_ref();
            self.formats.iter().find_map(|f| timestamp(f, v, zone))
        });
        if parsed.is_none() && !self.fudge {
            return;
        }
        let mut last = self.last.borrow_mut();
        let stream = format!("{:?}", entry.labels);
        let ns = match parsed {
            Some(ns) => ns,
            None => match last.get(&stream) {
                Some(ns) => ns + 1,
                None => return,
            },
        };
        entry.ns = ns;
        if last.len() >= FUDGED_STREAMS && !last.contains_key(&stream) {
            last.clear();
        }
        last.insert(stream, ns);
    }
}

/// stage.json: values read from the line (or `source`) as JSON.
#[derive(Default)]
pub struct JsonStage {
    pub source: Option<String>,
    /// Each value to extract and the path it is read from.
    pub fields: Vec<(String, Vec<Step>)>,
    /// Top-level keys extracted under their own names.
    pub keys: Option<Regex>,
    /// A line that is not a JSON object is dropped.
    pub drop_malformed: bool,
}

/// A step of a JMESPath made of fields and indexes: `a."b-c"[0][-1]`.
pub enum Step {
    Field(String),
    Index(i64),
}

/// The paths stage.json can follow; anything else JMESPath has is
/// refused, not read another way.
pub fn json_path(text: &str) -> Result<Vec<Step>, String> {
    let refuse = || format!("`{text}`: only fields and indexes");
    let mut steps = Vec::new();
    let mut rest = text;
    while !rest.is_empty() {
        if let Some(inside) = rest.strip_prefix('[') {
            let (index, after) = inside.split_once(']').ok_or_else(refuse)?;
            steps.push(Step::Index(index.parse().map_err(|_| refuse())?));
            rest = after;
        } else {
            if !steps.is_empty() {
                rest = rest.strip_prefix('.').ok_or_else(refuse)?;
            }
            let (field, after) = json_field(rest).ok_or_else(refuse)?;
            steps.push(Step::Field(field));
            rest = after;
        }
    }
    if steps.is_empty() {
        return Err(refuse());
    }
    Ok(steps)
}

/// An identifier, or a quoted one, and what follows it.
fn json_field(text: &str) -> Option<(String, &str)> {
    if let Some(quoted) = text.strip_prefix('"') {
        let end = quoted.find('"')?;
        let name = &quoted[..end];
        return (!name.contains('\\'))
            .then(|| (name.to_owned(), &quoted[end + 1..]));
    }
    let end = text
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .unwrap_or(text.len());
    let name = &text[..end];
    let starts =
        name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_');
    starts.then(|| (name.to_owned(), &text[end..]))
}

impl JsonStage {
    /// Whether the entry goes on.
    fn apply(&self, entry: &Entry, x: &mut Labels) -> bool {
        let Some(input) = input(&self.source, entry, x) else {
            return true;
        };
        let json = Json::parse(&input).filter(|j| matches!(j, Json::Obj(_)));
        let Some(json) = json else {
            return !self.drop_malformed;
        };
        for (name, path) in &self.fields {
            if let Some(value) = follow(&json, path).and_then(json_value) {
                set(x, name, value);
            }
        }
        if let Some(keys) = &self.keys {
            for (key, value) in json.obj() {
                if let Some(value) =
                    keys.is_match(key).then(|| json_value(value)).flatten()
                {
                    set(x, key, value);
                }
            }
        }
        true
    }
}

fn follow<'a>(json: &'a Json, path: &[Step]) -> Option<&'a Json> {
    path.iter().try_fold(json, |at, step| match step {
        Step::Field(name) => at.get(name),
        Step::Index(i) => {
            let items = at.arr();
            let i = if *i < 0 { items.len() as i64 + i } else { *i };
            items.get(usize::try_from(i).ok()?)
        }
    })
}

/// A value as Alloy extracts it: objects and arrays as JSON text.
fn json_value(json: &Json) -> Option<String> {
    match json {
        Json::Null => None,
        Json::Str(s) => Some(s.clone()),
        Json::Num(n) => Some(n.to_string()),
        Json::Bool(b) => Some(b.to_string()),
        other => Some(other.go_text()),
    }
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
            Stage::Json(json) => json.apply(entry, x),
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
            Stage::Timestamp(stage) => stage.apply(entry, x),
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

fn timestamp(format: &str, value: &str, zone: Option<&Zone>) -> Option<i64> {
    let number = |scale: i64| value.parse::<i64>().ok().map(|n| n * scale);
    match format {
        "Unix" => value.parse::<f64>().ok().map(|s| (s * 1e9) as i64),
        "UnixMs" => number(1_000_000),
        "UnixUs" => number(1_000),
        "UnixNs" => number(1),
        layout => time::parse_layout(time::named_layout(layout), value, zone),
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
    fn reads_json_as_alloy() {
        assert!(json_path(r#"a."b-c"[0][-1]"#).is_ok());
        for refused in ["a | b", "a[*]", "keys(@)", "a..b", "", "1a"] {
            assert!(json_path(refused).is_err(), "{refused}");
        }
        let stage = |drop_malformed| {
            Stage::Json(JsonStage {
                fields: vec![("o".into(), json_path("o").unwrap())],
                keys: Some(Regex::new("^n").unwrap()),
                drop_malformed,
                ..JsonStage::default()
            })
        };
        let mut parsed = entry(r#"{"o":{"z":"<",  "a":[1e21,2]},"n":1}"#);
        let x = &mut parsed.labels.clone();
        assert!(stage(false).apply(&mut parsed, x));
        assert_eq!(get(x, "o"), Some(r#"{"a":[1e+21,2],"z":"\u003c"}"#));
        assert_eq!(get(x, "n"), Some("1"));
        assert!(run(&[stage(false)], &mut entry("[1]")));
        assert!(!run(&[stage(true)], &mut entry("not json")));
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
    }

    #[test]
    fn parses_json_and_logfmt() {
        let mut parsed = entry(r#"{"a":{"b":[1,"x"]}}"#);
        let json = JsonStage {
            fields: vec![("v".into(), json_path("a.b[-1]").unwrap())],
            ..JsonStage::default()
        };
        let stages = [
            Stage::Json(json),
            Stage::Output("v".into()),
            Stage::Logfmt(None, vec![("t".into(), String::new())]),
        ];
        assert!(run(&stages, &mut parsed));
        assert_eq!(parsed.line, "x");
    }

    #[test]
    fn reads_timestamps() {
        let stages = [
            Stage::Logfmt(None, vec![("t".into(), String::new())]),
            Stage::Timestamp(Timestamp {
                source: "t".into(),
                formats: vec!["2006-01-02 15:04:05".into()],
                zone: None,
                fudge: true,
                last: RefCell::default(),
            }),
        ];
        let mut timed = entry(r#"t="1970-01-01 00:00:01" msg=hi"#);
        assert!(run(&stages, &mut timed));
        assert_eq!(timed.ns, 1_000_000_000);
        let mut unreadable = entry("t=never");
        assert!(run(&stages, &mut unreadable));
        assert_eq!(unreadable.ns, 1_000_000_001);
    }
}
