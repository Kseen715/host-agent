//! Prometheus's relabel rules (relabel_config), for series before they
//! are sent (`metric_relabel`, as a scrape's metric_relabel_configs)
//! and for log lines' labels (`log_relabel`, as loki.relabel). A rule
//! is a line: the action, then `key=value` settings, `regex=` last as
//! it may hold spaces:
//!
//! ```text
//! metric_relabel drop source_labels=__name__ regex=go_.*
//! metric_relabel labelmap regex=__meta_(.+)
//! log_relabel labeldrop regex=filename
//! ```

use regex_lite::Regex;

#[derive(Clone, Copy, PartialEq)]
enum Action {
    Replace,
    Keep,
    Drop,
    LabelMap,
    LabelKeep,
    LabelDrop,
    Lowercase,
    Uppercase,
}

pub struct Rule {
    action: Action,
    sources: Vec<String>,
    separator: String,
    regex: Regex,
    target: String,
    replacement: String,
}

/// A label set as a rule sees it.
pub type Labels = Vec<(String, String)>;

impl Rule {
    /// A rule from the words after its key; `regex=` takes the rest.
    pub fn parse(value: &str) -> Result<Rule, String> {
        let (settings, regex) = match value.split_once(" regex=") {
            Some((settings, regex)) => (settings, regex),
            None => (value, "(.*)"),
        };
        let mut words = settings.split_whitespace();
        let action = match words.next().unwrap_or_default() {
            "replace" => Action::Replace,
            "keep" => Action::Keep,
            "drop" => Action::Drop,
            "labelmap" => Action::LabelMap,
            "labelkeep" => Action::LabelKeep,
            "labeldrop" => Action::LabelDrop,
            "lowercase" => Action::Lowercase,
            "uppercase" => Action::Uppercase,
            other => return Err(format!("no relabel action `{other}`")),
        };
        let regex = Regex::new(&format!("^(?:{regex})$"))
            .map_err(|e| format!("regex: {e}"))?;
        let mut rule = Rule {
            action,
            sources: Vec::new(),
            separator: ";".into(),
            regex,
            target: String::new(),
            replacement: "$1".into(),
        };
        for word in words {
            rule.set(word)?;
        }
        Ok(rule)
    }

    fn set(&mut self, word: &str) -> Result<(), String> {
        let (key, value) = word.split_once('=').unwrap_or((word, ""));
        match key {
            "source_labels" => {
                self.sources = value.split(',').map(str::to_owned).collect();
            }
            "separator" => self.separator = value.into(),
            "target_label" => self.target = value.into(),
            "replacement" => self.replacement = value.into(),
            _ => return Err(format!("cannot read `{word}`")),
        }
        Ok(())
    }

    /// Applies the rule; false if the series or line is dropped.
    fn apply(&self, labels: &mut Labels) -> bool {
        let get = |name: &str| {
            let found = labels.iter().find(|(k, _)| k == name);
            found.map_or("", |(_, v)| v.as_str())
        };
        let value: Vec<&str> = self.sources.iter().map(|s| get(s)).collect();
        let value = value.join(&self.separator);
        match self.action {
            Action::Keep => return self.regex.is_match(&value),
            Action::Drop => return !self.regex.is_match(&value),
            Action::Replace => {
                if let Some(captures) = self.regex.captures(&value) {
                    let mut target = String::new();
                    captures.expand(&self.target, &mut target);
                    let mut new = String::new();
                    captures.expand(&self.replacement, &mut new);
                    set(labels, &target, new);
                }
            }
            Action::Lowercase => {
                set(labels, &self.target, value.to_lowercase())
            }
            Action::Uppercase => {
                set(labels, &self.target, value.to_uppercase())
            }
            Action::LabelMap => {
                let mut mapped = Vec::new();
                for (name, value) in labels.iter() {
                    if let Some(captures) = self.regex.captures(name) {
                        let mut new = String::new();
                        captures.expand(&self.replacement, &mut new);
                        mapped.push((new, value.clone()));
                    }
                }
                for (name, value) in mapped {
                    set(labels, &name, value);
                }
            }
            Action::LabelKeep => labels.retain(|(k, _)| self.regex.is_match(k)),
            Action::LabelDrop => {
                labels.retain(|(k, _)| !self.regex.is_match(k))
            }
        }
        true
    }
}

/// Applies the rules in order; false if one drops the series or line.
pub fn apply(rules: &[Rule], labels: &mut Labels) -> bool {
    rules.iter().all(|rule| rule.apply(labels))
}

/// Sets a label; an empty value removes it, as Prometheus does.
fn set(labels: &mut Labels, name: &str, value: String) {
    labels.retain(|(k, _)| k != name);
    if !name.is_empty() && !value.is_empty() {
        labels.push((name.to_owned(), value));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn labels(pairs: &[(&str, &str)]) -> Labels {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn applies_like_prometheus() {
        let rules = [
            "drop source_labels=__name__ regex=go_.*",
            "replace source_labels=instance target_label=node \
             regex=(.*):\\d+",
            "labeldrop regex=job",
            "uppercase source_labels=node target_label=NODE",
        ]
        .map(|rule| Rule::parse(rule).unwrap());
        let mut kept = labels(&[
            ("__name__", "up"),
            ("instance", "mc-01:9100"),
            ("job", "node"),
        ]);
        assert!(apply(&rules, &mut kept));
        kept.sort();
        assert_eq!(
            kept,
            labels(&[
                ("NODE", "MC-01"),
                ("__name__", "up"),
                ("instance", "mc-01:9100"),
                ("node", "mc-01"),
            ])
        );
        let mut dropped = labels(&[("__name__", "go_goroutines")]);
        assert!(!apply(&rules, &mut dropped));

        let keep = Rule::parse("keep source_labels=a,b regex=x;y").unwrap();
        assert!(apply(&[keep], &mut labels(&[("a", "x"), ("b", "y")])));
        let map = Rule::parse("labelmap regex=__meta_(.+)").unwrap();
        let mut mapped = labels(&[("__meta_zone", "home")]);
        assert!(apply(&[map], &mut mapped));
        assert!(mapped.contains(&("zone".into(), "home".into())));
        assert!(Rule::parse("hashmod").is_err());
    }
}
