//! loki.process's `stage.*` blocks, built into crate::stages.

use super::compile::Body;
use crate::stages::{Action, Drop, Selector, Stage, Timestamp};
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
    let (fields, json) = match body.name() {
        "stage.json" => ("expressions", true),
        _ => ("mapping", false),
    };
    body.check(&[fields, "source", "drop_malformed"], &[])?;
    let source = body.string("source")?;
    let fields = body.labels(fields)?;
    Ok(if json {
        Stage::Json(source, fields)
    } else {
        Stage::Logfmt(source, fields)
    })
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
