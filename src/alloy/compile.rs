//! From the syntax tree to what the agent runs: each component is
//! evaluated after those it refers to, its exports given to the ones
//! after it, and built into the metrics and logs graphs, the scrapes
//! and the sources (super::components). A component, attribute or
//! block this agent does not have is refused, not ignored.

use super::syntax::{Block, Expr, Kind, Pos, Stmt};
use super::value::{self, Capsule, Value};
use crate::files::Files;
use crate::logs::{Logs, Source};
use crate::relabel::{Labels, Rule, Settings};
use crate::remote::Metrics;
use crate::targets::Targets;
use std::collections::HashMap;
use std::path::PathBuf;
use std::rc::Rc;
use std::time::Duration;

/// Top-level blocks that configure Alloy itself: accepted, not used.
const IGNORED: [&str; 3] = ["logging", "livedebugging", "tracing"];

/// A prometheus.scrape component.
pub struct ScrapeJob {
    pub targets: Targets,
    pub to: Rc<[usize]>,
    pub interval: Duration,
    pub job: String,
    pub honor_labels: bool,
    pub metrics_path: String,
    pub scheme: String,
    pub params: Labels,
}

/// An exporter scraped in process, by its component's id.
pub enum Exporter {
    Unix(Box<crate::node::Node>),
    /// prometheus.exporter.self: the agent's own metrics.
    Agent,
    #[cfg(feature = "docker")]
    Cadvisor,
    #[cfg(feature = "snmp")]
    Snmp(crate::snmp::Snmp),
}

/// otelcol.* components, for the receiver to find where each signal
/// ends up.
pub enum Otel {
    /// Each signal's next components.
    Pass(Vec<(String, Vec<usize>)>),
    /// Each signal's URL.
    Export(Vec<(String, String)>),
}

/// A loki.source.syslog `listener`, with its component's source.
pub struct SyslogListener {
    pub address: String,
    pub tcp: bool,
    pub rfc5424: bool,
    pub idle_timeout: Duration,
    pub label_structured_data: bool,
    pub use_incoming_timestamp: bool,
    pub use_rfc5424_message: bool,
    pub max_message_length: usize,
    pub source: Source,
}

#[derive(Default)]
pub struct Plan {
    pub metrics: Metrics,
    pub logs: Logs,
    pub scrapes: Vec<ScrapeJob>,
    pub exporters: Vec<(String, Exporter)>,
    /// prometheus.exporter.unix's rootfs_path (crate::host).
    pub root: Option<PathBuf>,
    /// Each loki.source.journal: its id, max_age and source.
    pub journal: Vec<(String, Duration, Source)>,
    pub files: Vec<Files>,
    /// Each loki.source.docker: its id, targets and source.
    pub docker_logs: Vec<(String, Targets, Source)>,
    /// Whether a component reads Docker.
    pub docker: bool,
    pub syslogs: Vec<SyslogListener>,
    /// Each otelcol.receiver.otlp's address and each signal's URLs.
    pub otlp: Vec<(String, Vec<(String, String)>)>,
    pub otel: Vec<Otel>,
    /// --print: one round to stdout.
    pub print: bool,
}

pub fn compile(stmts: &[Stmt], print: bool) -> Result<Plan, String> {
    let components = components(stmts)?;
    let order = order(&components)?;
    let mut plan = Plan {
        print,
        ..Plan::default()
    };
    let mut exports: HashMap<String, Value> = HashMap::new();
    for index in order {
        let (id, block) = &components[index];
        let export = {
            let resolve = |name: &str| exports.get(name).cloned();
            let body = Body {
                block,
                id,
                resolve: &resolve,
            };
            super::components::build(&body, &mut plan)?
        };
        exports.insert(id.clone(), export);
    }
    Ok(plan)
}

/// Each component's id (`prometheus.scrape.node`) and block.
fn components(stmts: &[Stmt]) -> Result<Vec<(String, &Block)>, String> {
    let mut found: Vec<(String, &Block)> = Vec::new();
    for stmt in stmts {
        let block = match stmt {
            Stmt::Block(block) => block,
            Stmt::Attr { name, pos, .. } => {
                return Err(format!("{pos}: `{name}` outside a block"));
            }
        };
        if IGNORED.contains(&block.name.as_str()) {
            continue;
        }
        let Some(label) = &block.label else {
            let pos = block.pos;
            return Err(format!("{pos}: {} needs a label", block.name));
        };
        let id = format!("{}.{label}", block.name);
        if found.iter().any(|(other, _)| *other == id) {
            return Err(format!("{}: {id} is declared twice", block.pos));
        }
        found.push((id, block));
    }
    Ok(found)
}

/// The components in an order where each comes after those it refers
/// to, in the file's order where that leaves a choice.
fn order(components: &[(String, &Block)]) -> Result<Vec<usize>, String> {
    let needs: Vec<Vec<usize>> = components
        .iter()
        .map(|(_, block)| {
            let mut paths = Vec::new();
            references(&block.body, &mut paths);
            let named = |(index, (id, _)): (usize, &(String, &Block))| {
                let refers = paths.iter().any(|p| {
                    p == id
                        || p.strip_prefix(id.as_str())
                            .is_some_and(|r| r.starts_with('.'))
                });
                refers.then_some(index)
            };
            components.iter().enumerate().filter_map(named).collect()
        })
        .collect();
    let mut order = Vec::new();
    while order.len() < components.len() {
        let ready = (0..components.len()).find(|i| {
            !order.contains(i) && needs[*i].iter().all(|n| order.contains(n))
        });
        let Some(ready) = ready else {
            let stuck = (0..components.len()).filter(|i| !order.contains(i));
            let ids: Vec<&str> =
                stuck.map(|i| components[i].0.as_str()).collect();
            return Err(format!("a cycle among {}", ids.join(", ")));
        };
        order.push(ready);
    }
    Ok(order)
}

/// Every dotted name the body's expressions use.
fn references(body: &[Stmt], paths: &mut Vec<String>) {
    for stmt in body {
        match stmt {
            Stmt::Attr { value, .. } => expr_references(value, paths),
            Stmt::Block(block) => references(&block.body, paths),
        }
    }
}

fn expr_references(expr: &Expr, paths: &mut Vec<String>) {
    if let Some(path) = value::path(expr) {
        paths.push(path);
        return;
    }
    match &expr.kind {
        Kind::Array(items) => {
            items.iter().for_each(|e| expr_references(e, paths))
        }
        Kind::Object(fields) => {
            fields.iter().for_each(|(_, e)| expr_references(e, paths))
        }
        Kind::Access(inner, _) | Kind::Unary(_, inner) => {
            expr_references(inner, paths)
        }
        Kind::Index(a, b) | Kind::Binary(_, a, b) => {
            expr_references(a, paths);
            expr_references(b, paths);
        }
        Kind::Call(_, args) => {
            args.iter().for_each(|e| expr_references(e, paths))
        }
        _ => {}
    }
}

/// A block's body, read with the exports of the components before it.
pub struct Body<'a> {
    pub block: &'a Block,
    /// The component's id, for errors.
    pub id: &'a str,
    resolve: value::Resolve<'a>,
}

impl<'a> Body<'a> {
    pub fn name(&self) -> &str {
        &self.block.name
    }

    pub fn label(&self) -> &str {
        self.block.label.as_deref().unwrap_or("")
    }

    pub fn error(&self, pos: Pos, message: &str) -> String {
        format!("{pos}: {}: {message}", self.id)
    }

    /// Refuses attributes and blocks not listed, and any twice.
    pub fn check(&self, attrs: &[&str], blocks: &[&str]) -> Result<(), String> {
        let mut seen = Vec::new();
        for stmt in &self.block.body {
            let (name, pos, listed) = match stmt {
                Stmt::Attr { name, pos, .. } => {
                    if seen.contains(&name) {
                        return Err(
                            self.error(*pos, &format!("`{name}` twice"))
                        );
                    }
                    seen.push(name);
                    (name, *pos, attrs.contains(&name.as_str()))
                }
                Stmt::Block(b) => {
                    (&b.name, b.pos, blocks.contains(&b.name.as_str()))
                }
            };
            if !listed {
                let message = format!("`{name}` is not supported here");
                return Err(self.error(pos, &message));
            }
        }
        Ok(())
    }

    fn attr(&self, name: &str) -> Option<(&'a Expr, Pos)> {
        self.block.body.iter().find_map(|stmt| match stmt {
            Stmt::Attr {
                name: n,
                value,
                pos,
            } if n == name => Some((value, *pos)),
            _ => None,
        })
    }

    pub fn value(&self, name: &str) -> Result<Option<(Value, Pos)>, String> {
        let Some((expr, pos)) = self.attr(name) else {
            return Ok(None);
        };
        let value = value::eval(expr, self.resolve)
            .map_err(|e| format!("{e} (in {})", self.id))?;
        Ok(Some((value, pos)))
    }

    pub fn string(&self, name: &str) -> Result<Option<String>, String> {
        match self.value(name)? {
            None => Ok(None),
            Some((Value::String(s), _)) => Ok(Some(s)),
            Some((other, pos)) => {
                Err(self.wrong(pos, name, "a string", &other))
            }
        }
    }

    pub fn string_or(
        &self,
        name: &str,
        default: &str,
    ) -> Result<String, String> {
        Ok(self.string(name)?.unwrap_or_else(|| default.to_owned()))
    }

    pub fn required(&self, name: &str) -> Result<String, String> {
        let missing =
            || self.error(self.block.pos, &format!("`{name}` is required"));
        self.string(name)?.ok_or_else(missing)
    }

    pub fn bool_or(&self, name: &str, default: bool) -> Result<bool, String> {
        match self.value(name)? {
            None => Ok(default),
            Some((Value::Bool(b), _)) => Ok(b),
            Some((other, pos)) => Err(self.wrong(pos, name, "a bool", &other)),
        }
    }

    pub fn duration_or(
        &self,
        name: &str,
        default: &str,
    ) -> Result<Duration, String> {
        let text = self.string_or(name, default)?;
        let pos = self.attr(name).map_or(self.block.pos, |a| a.1);
        crate::time::parse_duration(&text).ok_or_else(|| {
            self.error(pos, &format!("`{text}` is not a duration"))
        })
    }

    pub fn strings(&self, name: &str) -> Result<Vec<String>, String> {
        let Some((value, pos)) = self.value(name)? else {
            return Ok(Vec::new());
        };
        let Value::Array(items) = value else {
            return Err(self.wrong(pos, name, "a list of strings", &value));
        };
        let strings = items.into_iter().map(|item| match item {
            Value::String(s) => Ok(s),
            other => Err(self.wrong(pos, name, "a list of strings", &other)),
        });
        strings.collect()
    }

    /// An object of strings, such as `labels`.
    pub fn labels(&self, name: &str) -> Result<Labels, String> {
        match self.value(name)? {
            None => Ok(Vec::new()),
            Some((value, pos)) => object_strings(value)
                .map_err(|kind| self.error(pos, &format!("`{name}`: {kind}"))),
        }
    }

    pub fn targets(&self, name: &str) -> Result<Targets, String> {
        let missing =
            self.error(self.block.pos, &format!("`{name}` is required"));
        let (value, pos) = self.value(name)?.ok_or(missing)?;
        targets_of(value)
            .map_err(|e| self.error(pos, &format!("`{name}`: {e}")))
    }

    /// The rules an attribute refers to (`relabel_rules`).
    pub fn rules_attr(
        &self,
        name: &str,
    ) -> Result<Option<Rc<Vec<Rule>>>, String> {
        match self.value(name)? {
            None => Ok(None),
            Some((Value::Capsule(Capsule::Rules(rules)), _)) => Ok(Some(rules)),
            Some((other, pos)) => Err(self.wrong(pos, name, "rules", &other)),
        }
    }

    /// The graph nodes a `forward_to` list names, of one kind.
    pub fn receivers(
        &self,
        name: &str,
        node: fn(&Capsule) -> Option<usize>,
    ) -> Result<Rc<[usize]>, String> {
        let Some((value, pos)) = self.value(name)? else {
            return Ok(Rc::from([]));
        };
        let Value::Array(items) = value else {
            return Err(self.wrong(pos, name, "a list of receivers", &value));
        };
        let nodes = items.iter().map(|item| match item {
            Value::Capsule(capsule) => node(capsule),
            _ => None,
        });
        let nodes: Option<Vec<usize>> = nodes.collect();
        let wrong =
            || self.error(pos, &format!("`{name}` names the wrong kind"));
        Ok(Rc::from(nodes.ok_or_else(wrong)?))
    }

    pub fn blocks(&self, name: &'a str) -> impl Iterator<Item = Body<'a>> + '_ {
        self.block.body.iter().filter_map(move |stmt| match stmt {
            Stmt::Block(block) if block.name == name => Some(Body {
                block,
                id: self.id,
                resolve: self.resolve,
            }),
            _ => None,
        })
    }

    /// Every block inside, in order.
    pub fn children(&self) -> impl Iterator<Item = Body<'a>> + '_ {
        self.block.body.iter().filter_map(move |stmt| match stmt {
            Stmt::Block(block) => Some(Body {
                block,
                id: self.id,
                resolve: self.resolve,
            }),
            Stmt::Attr { .. } => None,
        })
    }

    pub fn block(&self, name: &'a str) -> Option<Body<'a>> {
        self.blocks(name).next()
    }

    /// The `rule` blocks, as relabel rules.
    pub fn rules(&self) -> Result<Vec<Rule>, String> {
        let mut rules = Vec::new();
        for rule in self.blocks("rule") {
            rule.check(
                &[
                    "action",
                    "source_labels",
                    "separator",
                    "regex",
                    "target_label",
                    "replacement",
                ],
                &[],
            )?;
            let defaults = Settings::default();
            let settings = Settings {
                action: rule.string_or("action", &defaults.action)?,
                sources: rule.strings("source_labels")?,
                separator: rule.string_or("separator", &defaults.separator)?,
                regex: rule.string_or("regex", &defaults.regex)?,
                target: rule.string_or("target_label", "")?,
                replacement: rule
                    .string_or("replacement", &defaults.replacement)?,
            };
            rules.push(
                Rule::new(settings)
                    .map_err(|e| rule.error(rule.block.pos, &e))?,
            );
        }
        Ok(rules)
    }

    fn wrong(&self, pos: Pos, name: &str, want: &str, got: &Value) -> String {
        self.error(
            pos,
            &format!("`{name}` should be {want}, not {}", got.kind()),
        )
    }
}

fn object_strings(value: Value) -> Result<Labels, String> {
    let Value::Object(fields) = value else {
        return Err(format!("expected an object, not {}", value.kind()));
    };
    let pairs = fields.into_iter().map(|(key, value)| match value {
        Value::String(s) => Ok((key, s)),
        other => {
            Err(format!("`{key}` should be a string, not {}", other.kind()))
        }
    });
    pairs.collect()
}

/// Targets from a value: a component's that may change, or a list of
/// objects of strings.
pub fn targets_of(value: Value) -> Result<Targets, String> {
    match value {
        Value::Capsule(Capsule::Targets(targets)) => Ok(targets),
        Value::Array(items) => {
            let targets: Result<Vec<Labels>, String> =
                items.into_iter().map(object_strings).collect();
            Ok(Targets::Static(targets?))
        }
        other => Err(format!("expected targets, not {}", other.kind())),
    }
}

/// An export of named values.
pub fn export(fields: Vec<(&str, Value)>) -> Value {
    Value::Object(fields.into_iter().map(|(k, v)| (k.to_owned(), v)).collect())
}

#[cfg(test)]
mod tests {
    use super::super::syntax::parse;
    use super::*;

    #[test]
    fn orders_by_reference_and_refuses_cycles() {
        let text = r#"
            b "x" { y = a.x.out }
            a "x" { }
        "#;
        let stmts = parse(text).unwrap();
        let found = components(&stmts).unwrap();
        assert_eq!(order(&found).unwrap(), [1, 0]);
        let cycle =
            parse(r#"a "x" { y = b.x.o } b "x" { y = a.x.o }"#).unwrap();
        let error = order(&components(&cycle).unwrap()).unwrap_err();
        assert!(error.contains("cycle"), "{error}");
        let twice = parse(r#"a "x" { } a "x" { }"#).unwrap();
        assert!(components(&twice).unwrap_err().contains("twice"));
    }
}
