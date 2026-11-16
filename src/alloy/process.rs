//! loki.process's `stage.*` blocks, built into crate::stages.

use super::compile::Body;
use crate::stages::{
    Action, Drop, JsonStage, Selector, Stage, Timestamp, json_path,
};
use crate::template::Template;
use crate::zone::Zone;
use regex_lite::Regex;

pub const STAGES: [&str; 13] = [
    "stage.regex",
    "stage.template",
    "stage.replace",
    "stage.labels",
    "stage.static_labels",
    "stage.label_drop",
    "stage.label_keep",
    "stage.drop",
    "stage.json",
    "stage.logfmt",
    "stage.timestamp",
    "stage.output",
    "stage.match",
];

pub fn stages(body: &Body) -> Result<Vec<Stage>, String> {
    body.children().map(|child| stage(&child)).collect()
}

// One arm per stage: longer than 40 lines, as a table is read whole.
fn stage(body: &Body) -> Result<Stage, String> {
    let pos = body.block.pos;
    let fail = |e: String| body.error(pos, &e);
    let regex = |name: &str| -> Result<Regex, String> {
        Regex::new(&body.required(name)?).map_err(|e| fail(e.to_string()))
    };
    let template = |text: &str| Template::parse(text).map_err(fail);
    Ok(match body.name() {
        "stage.regex" => {
            body.check(&["expression", "source"], &[])?;
            Stage::Regex(regex("expression")?, body.string("source")?)
        }
        "stage.template" => {
            body.check(&["source", "template"], &[])?;
            let text = template(&body.required("template")?)?;
            Stage::Template(body.required("source")?, text)
        }
        "stage.replace" => {
            body.check(&["expression", "source", "replace"], &[])?;
            let with = template(&body.string_or("replace", "")?)?;
            Stage::Replace(regex("expression")?, body.string("source")?, with)
        }
        "stage.labels" | "stage.static_labels" => labels(body)?,
        "stage.label_drop" | "stage.label_keep" => {
            body.check(&["values"], &[])?;
            let names = body.strings("values")?;
            match body.name() {
                "stage.label_drop" => Stage::LabelDrop(names),
                _ => Stage::LabelKeep(names),
            }
        }
        "stage.drop" => drop(body)?,
        "stage.json" | "stage.logfmt" => parse(body)?,
        "stage.timestamp" => timestamp(body)?,
        "stage.output" => {
            body.check(&["source"], &[])?;
            Stage::Output(body.required("source")?)
        }
        "stage.match" => matched(body)?,
        other => return Err(fail(format!("`{other}` is not a stage here"))),
    })
}

fn labels(body: &Body) -> Result<Stage, String> {
    body.check(&["values"], &[])?;
    let values = body.labels("values")?;
    if body.name() == "stage.static_labels" {
        return Ok(Stage::StaticLabels(values));
    }
    let from = |(label, from): (String, String)| {
        let from = if from.is_empty() { label.clone() } else { from };
        (label, from)
    };
    Ok(Stage::Labels(values.into_iter().map(from).collect()))
}

// Longer than 40 lines: Alloy's attributes, one per line.
fn drop(body: &Body) -> Result<Stage, String> {
    let attrs = [
        "source",
        "separator",
        "expression",
        "value",
        "older_than",
        "longer_than",
        "drop_counter_reason",
    ];
    body.check(&attrs, &[])?;
    // As in stage.match; `separator` joins several sources, refused below.
    body.string("drop_counter_reason")?;
    body.string("separator")?;
    let pos = body.block.pos;
    let source = body.string("source")?;
    if source.as_ref().is_some_and(|s| s.contains(',')) {
        return Err(body.error(pos, "one `source` only"));
    }
    let regex = body.string("expression")?;
    let regex = regex.map(|r| Regex::new(&r)).transpose();
    let older_than = match body.value("older_than")? {
        Some(_) => Some(body.duration_or("older_than", "")?),
        None => None,
    };
    let longer_than = body.string("longer_than")?;
    let longer_than = longer_than.map(|text| {
        bytes(&text).ok_or_else(|| body.error(pos, "longer_than: a size"))
    });
    let drop = Drop {
        regex: regex.map_err(|e| body.error(pos, &e.to_string()))?,
        value: body.string("value")?,
        older_than,
        longer_than: longer_than.transpose()?,
        source,
    };
    let conditions = [
        drop.source.is_some(),
        drop.regex.is_some(),
        drop.older_than.is_some(),
        drop.longer_than.is_some(),
    ];
    if !conditions.contains(&true) {
        return Err(body.error(pos, "drops nothing: no condition"));
    }
    Ok(Stage::Drop(drop))
}

/// `8KB` as bytes, kilobytes being 1024 as Alloy reads them.
fn bytes(text: &str) -> Option<usize> {
    let split = text
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(text.len());
    let number: usize = text[..split].parse().ok()?;
    let scale = match text[split..].trim() {
        "" | "B" => 1,
        "KB" | "KiB" => 1 << 10,
        "MB" | "MiB" => 1 << 20,
        "GB" | "GiB" => 1 << 30,
        _ => return None,
    };
    Some(number * scale)
}

fn parse(body: &Body) -> Result<Stage, String> {
    if body.name() == "stage.logfmt" {
        body.check(&["mapping", "source"], &[])?;
        let mapping = body.labels("mapping")?;
        return Ok(Stage::Logfmt(body.string("source")?, mapping));
    }
    body.check(&["expressions", "regex", "source", "drop_malformed"], &[])?;
    let pos = body.block.pos;
    let mut fields = Vec::new();
    for (name, path) in body.labels("expressions")? {
        let path = if path.is_empty() { name.clone() } else { path };
        let steps = json_path(&path).map_err(|e| body.error(pos, &e))?;
        fields.push((name, steps));
    }
    let keys = body.string("regex")?.filter(|r| !r.is_empty());
    let keys = keys.map(|r| Regex::new(&r));
    let keys = keys
        .transpose()
        .map_err(|e| body.error(pos, &e.to_string()))?;
    if fields.is_empty() && keys.is_none() {
        return Err(body.error(pos, "needs `expressions` or `regex`"));
    }
    Ok(Stage::Json(JsonStage {
        source: body.string("source")?,
        fields,
        keys,
        drop_malformed: body.bool_or("drop_malformed", false)?,
    }))
}

fn timestamp(body: &Body) -> Result<Stage, String> {
    let attrs = [
        "source",
        "format",
        "fallback_formats",
        "location",
        "action_on_failure",
    ];
    body.check(&attrs, &[])?;
    let pos = body.block.pos;
    let zone = match body.string("location")? {
        Some(name) => Some(Zone::load(&name).map_err(|e| body.error(pos, &e))?),
        None => None,
    };
    let fudge = match body.string_or("action_on_failure", "fudge")?.as_str() {
        "fudge" => true,
        "skip" => false,
        other => {
            let message = format!("action_on_failure `{other}`");
            return Err(body.error(pos, &message));
        }
    };
    let mut formats = vec![body.required("format")?];
    formats.extend(body.strings("fallback_formats")?);
    Ok(Stage::Timestamp(Timestamp {
        source: body.required("source")?,
        formats,
        zone,
        fudge,
        last: Default::default(),
    }))
}

fn matched(body: &Body) -> Result<Stage, String> {
    let attrs = ["selector", "action", "pipeline_name", "drop_counter_reason"];
    body.check(&attrs, &STAGES)?;
    // Names in Alloy's own metrics of dropped lines, which this agent
    // does not keep.
    body.string("pipeline_name")?;
    body.string("drop_counter_reason")?;
    let pos = body.block.pos;
    let selector = Selector::parse(&body.required("selector")?)
        .map_err(|e| body.error(pos, &format!("selector: {e}")))?;
    let action = match body.string_or("action", "keep")?.as_str() {
        "keep" => Action::Keep(stages(body)?),
        "drop" => Action::Drop,
        other => {
            return Err(body.error(pos, &format!("action `{other}`")));
        }
    };
    Ok(Stage::Match(selector, action))
}

#[cfg(test)]
mod tests {
    use super::super::compile::compile;
    use super::super::syntax::parse;
    use super::bytes;
    use crate::logs::{Entry, Kind};
    use crate::stages::{self, Stage};

    /// The stages of a loki.process with `body`, as the agent runs them.
    fn pipeline(body: &str) -> Result<Vec<Stage>, String> {
        let text = format!(
            r#"loki.write "w" {{ endpoint {{ url = "http://l/" }} }}
            loki.process "p" {{
                {body}
                forward_to = [loki.write.w.receiver]
            }}"#
        );
        let mut plan = compile(&parse(&text).unwrap(), true)?;
        let found =
            plan.logs.nodes.iter_mut().find_map(
                |node| match std::mem::replace(&mut node.kind, Kind::Write(0)) {
                    Kind::Process(stages) => Some(stages),
                    _ => None,
                },
            );
        Ok(found.expect("a loki.process node"))
    }

    fn entry(job: &str, line: &str) -> Entry {
        Entry {
            labels: vec![("job".into(), job.into())],
            ns: 1,
            line: line.into(),
        }
    }

    fn label<'a>(entry: &'a Entry, name: &str) -> Option<&'a str> {
        let found = entry.labels.iter().find(|(k, _)| k == name);
        found.map(|(_, v)| v.as_str())
    }

    /// A container's JSON line: its level a label, its time the
    /// entry's, its message the line; debug lines dropped.
    #[test]
    fn shapes_json_lines() {
        let stages = pipeline(
            r#"stage.json {
                expressions = {"level" = "", "msg" = "message", "ts" = "time"}
            }
            stage.timestamp {
                source = "ts"
                format = "RFC3339Nano"
            }
            stage.labels { values = {"level" = ""} }
            stage.static_labels { values = {"site" = "home"} }
            stage.template {
                source = "msg"
                template = "{{ ToUpper .msg }}"
            }
            stage.output { source = "msg" }
            stage.match {
                selector = "{level=\"debug\"}"
                action = "drop"
            }
            stage.label_drop { values = ["job"] }"#,
        )
        .unwrap();
        let mut info = entry(
            "docker",
            concat!(
                r#"{"level":"info","message":"started","#,
                r#""time":"2026-11-15T10:00:00.5Z"}"#
            ),
        );
        assert!(stages::run(&stages, &mut info));
        assert_eq!(info.line, "STARTED");
        assert_eq!(label(&info, "level"), Some("info"));
        assert_eq!(label(&info, "site"), Some("home"));
        assert_eq!(label(&info, "job"), None);
        let at = crate::time::parse_rfc3339("2026-11-15T10:00:00.5Z");
        assert_eq!(Some(info.ns), at);
        let mut debug = entry("docker", r#"{"level":"debug","message":"x"}"#);
        assert!(!stages::run(&stages, &mut debug));
    }

    /// logfmt, a secret masked, healthy requests and long lines dropped,
    /// and a nested pipeline for one job's errors.
    #[test]
    fn filters_and_rewrites_logfmt_lines() {
        let stages = pipeline(
            r#"stage.logfmt { mapping = {"status" = "", "who" = "user"} }
            stage.replace {
                expression = "password=(\\S+)"
                replace = "***"
            }
            stage.drop {
                source = "status"
                value = "200"
            }
            stage.drop { longer_than = "1KB" }
            stage.match {
                selector = "{job=\"app\"} |= \"error\""
                stage.regex { expression = "code=(?P<code>\\d+)" }
                stage.labels { values = {"code" = "", "who" = ""} }
            }
            stage.label_keep { values = ["job", "code", "who"] }"#,
        )
        .unwrap();
        let line = "status=500 user=ann password=hunter2 error code=42";
        let mut failed = entry("app", line);
        assert!(stages::run(&stages, &mut failed));
        assert_eq!(
            failed.line,
            "status=500 user=ann password=*** error code=42"
        );
        assert_eq!(label(&failed, "code"), Some("42"));
        assert_eq!(label(&failed, "who"), Some("ann"));
        let mut other = entry("web", line);
        assert!(stages::run(&stages, &mut other));
        assert_eq!(label(&other, "code"), None);
        assert!(!stages::run(&stages, &mut entry("app", "status=200 ok")));
        let long = format!("status=500 {}", "x".repeat(1025));
        assert!(!stages::run(&stages, &mut entry("app", &long)));
    }

    #[test]
    fn refuses_stages_it_cannot_run() {
        let cases = [
            ("stage.metrics { }", "stage.metrics"),
            ("stage.drop { }", "drops nothing"),
            (r#"stage.drop { source = "a,b" }"#, "one `source` only"),
            (r#"stage.drop { longer_than = "1XB" }"#, "a size"),
            (r#"stage.drop { expression = "(" }"#, "closing"),
            (r#"stage.json { source = "x" }"#, "needs `expressions`"),
            (
                r#"stage.json { expressions = {"a" = "[["} }"#,
                "only fields and indexes",
            ),
            (
                r#"stage.timestamp {
                    source = "t"
                    format = "RFC3339"
                    action_on_failure = "explode"
                }"#,
                "action_on_failure `explode`",
            ),
            (
                r#"stage.timestamp {
                    source = "t"
                    format = "RFC3339"
                    location = "Nowhere/Never"
                }"#,
                "Nowhere/Never",
            ),
            (
                r#"stage.match {
                    selector = "{a=\"b\"}"
                    action = "maybe"
                }"#,
                "action `maybe`",
            ),
            (r#"stage.match { selector = "a" }"#, "selector"),
            (r#"stage.template { source = "a" }"#, "template"),
        ];
        for (body, wanted) in cases {
            let error = pipeline(body).err().unwrap_or_default();
            assert!(error.contains(wanted), "{body}: {error}");
        }
    }

    #[test]
    fn reads_sizes_as_alloy_does() {
        assert_eq!(bytes("10"), Some(10));
        assert_eq!(bytes("8KB"), Some(8 << 10));
        assert_eq!(bytes("2 MiB"), Some(2 << 20));
        assert_eq!(bytes("1GB"), Some(1 << 30));
        assert_eq!(bytes("1TB"), None);
        assert_eq!(bytes("KB"), None);
    }
}
