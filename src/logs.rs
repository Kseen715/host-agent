//! Log lines on their way: from a source (journal, files, Docker,
//! syslog) through loki.relabel and loki.process to loki.write, as the
//! configuration's `forward_to` lists connect them.

use crate::loki::{Flushed, Loki};
use crate::relabel::{self, Labels, Rule};
use crate::stages::{self, Stage};
use std::rc::Rc;
use std::time::Instant;

#[derive(Clone)]
pub struct Entry {
    pub labels: Labels,
    pub ns: i64,
    pub line: String,
}

pub enum Kind {
    Relabel(Rc<Vec<Rule>>),
    /// A loki.relabel: its rules, results cached.
    Cached(Rc<Vec<Rule>>, relabel::Cache),
    Process(Vec<Stage>),
    /// A loki.write: its index in `sinks`.
    Write(usize),
}

pub struct Node {
    pub kind: Kind,
    pub to: Rc<[usize]>,
}

#[derive(Default)]
pub struct Logs {
    pub nodes: Vec<Node>,
    pub sinks: Vec<Loki>,
}

impl Logs {
    pub fn send(&mut self, to: &[usize], entry: Entry) {
        let Some((last, rest)) = to.split_last() else {
            return;
        };
        for node in rest {
            self.at(*node, entry.clone());
        }
        self.at(*last, entry);
    }

    fn at(&mut self, node: usize, mut entry: Entry) {
        let kept = match &mut self.nodes[node].kind {
            Kind::Write(sink) => {
                let Entry { labels, ns, line } = &entry;
                return self.sinks[*sink].add(labels, *ns, line);
            }
            Kind::Relabel(rules) => relabel::apply(rules, &mut entry.labels),
            Kind::Cached(rules, cache) => {
                let labels = std::mem::take(&mut entry.labels);
                cache
                    .apply(rules, labels)
                    .map(|l| entry.labels = l)
                    .is_some()
            }
            Kind::Process(stages) => stages::run(stages, &mut entry),
        };
        if kept {
            let to = Rc::clone(&self.nodes[node].to);
            self.send(&to, entry);
        }
    }

    /// No more lines now: a batch is full or waits for a retry.
    pub fn blocked(&self, now: Instant) -> bool {
        self.sinks.iter().any(|s| s.blocked(now))
    }

    pub fn due_at(&self) -> Option<Instant> {
        self.sinks.iter().filter_map(Loki::due_at).min()
    }

    /// Done only when every batch is.
    pub fn flush(&mut self) -> Flushed {
        let mut all = Flushed::Done;
        for sink in &mut self.sinks {
            if let Flushed::Kept = sink.flush() {
                all = Flushed::Kept;
            }
        }
        all
    }
}

/// What a source does with its lines: its `labels`, its
/// `relabel_rules`, then the labels starting `__` go, as Alloy's
/// sources do.
#[derive(Clone, Default)]
pub struct Source {
    pub labels: Labels,
    pub rules: Option<Rc<Vec<Rule>>>,
    pub to: Rc<[usize]>,
}

impl Source {
    /// A line with the labels the source found for it.
    pub fn emit(&self, logs: &mut Logs, found: Labels, ns: i64, line: &str) {
        if let Some(labels) = self.labels_for(found) {
            self.send(logs, labels, ns, line);
        }
    }

    /// The labels a line goes with, None if the rules drop it: for a
    /// source whose lines share them, made once.
    pub fn labels_for(&self, found: Labels) -> Option<Labels> {
        let mut labels = self.labels.clone();
        for (name, value) in found {
            match labels.iter_mut().find(|(k, _)| *k == name) {
                Some((_, old)) => *old = value,
                None => labels.push((name, value)),
            }
        }
        if let Some(rules) = &self.rules {
            if !relabel::apply(rules, &mut labels) {
                return None;
            }
        }
        labels.retain(|(k, _)| !k.starts_with("__"));
        Some(labels)
    }

    pub fn send(&self, logs: &mut Logs, labels: Labels, ns: i64, line: &str) {
        let line = line.to_owned();
        logs.send(&self.to, Entry { labels, ns, line });
    }
}
