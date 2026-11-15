//! Prometheus's relabel rules (relabel_config), as Alloy's `rule`
//! blocks give them: for targets (discovery.relabel), series
//! (prometheus.relabel) and log lines' labels (loki.relabel and the
//! sources' relabel_rules).

use regex_lite::Regex;
use std::collections::hash_map::DefaultHasher;
use std::collections::{BTreeMap, HashMap};
use std::hash::{Hash, Hasher};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, PartialEq)]
enum Action {
    Replace,
    Keep,
    Drop,
    KeepEqual,
    DropEqual,
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

/// A rule's settings, Alloy's defaults where not given.
pub struct Settings {
    pub action: String,
    pub sources: Vec<String>,
    pub separator: String,
    pub regex: String,
    pub target: String,
    pub replacement: String,
}

impl Default for Settings {
    fn default() -> Settings {
        Settings {
            action: "replace".into(),
            sources: Vec::new(),
            separator: ";".into(),
            regex: "(.*)".into(),
            target: String::new(),
            replacement: "$1".into(),
        }
    }
}

impl Rule {
    pub fn new(settings: Settings) -> Result<Rule, String> {
        let action = match settings.action.to_lowercase().as_str() {
            "replace" => Action::Replace,
            "keep" => Action::Keep,
            "drop" => Action::Drop,
            "keepequal" => Action::KeepEqual,
            "dropequal" => Action::DropEqual,
            "labelmap" => Action::LabelMap,
            "labelkeep" => Action::LabelKeep,
            "labeldrop" => Action::LabelDrop,
            "lowercase" => Action::Lowercase,
            "uppercase" => Action::Uppercase,
            other => {
                return Err(format!("relabel action `{other}` unsupported"));
            }
        };
        let regex = Regex::new(&format!("^(?:{})$", settings.regex))
            .map_err(|e| format!("regex: {e}"))?;
        let needs_target = matches!(
            action,
            Action::Replace
                | Action::KeepEqual
                | Action::DropEqual
                | Action::Lowercase
                | Action::Uppercase
        );
        if needs_target && settings.target.is_empty() {
            return Err(format!("`{}` needs target_label", settings.action));
        }
        Ok(Rule {
            action,
            sources: settings.sources,
            separator: settings.separator,
            regex,
            target: settings.target,
            replacement: settings.replacement,
        })
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
            Action::KeepEqual => return get(&self.target) == value,
            Action::DropEqual => return get(&self.target) != value,
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

/// A relabel component's results by the labels' hash, as Alloy keeps
/// them: past `max` entries the least recently used goes; with a TTL
/// instead, a scan every quarter of it drops entries unused that long.
pub struct Cache {
    max: usize,
    ttl: Option<Duration>,
    entries: HashMap<u64, Cached>,
    /// Hashes by when they were last used, oldest first.
    by_use: BTreeMap<u64, u64>,
    tick: u64,
    scanned: Instant,
}

struct Cached {
    original: Labels,
    /// None: dropped.
    result: Option<Labels>,
    tick: u64,
    used: Instant,
}

impl Cache {
    pub fn new(max: usize, ttl: Option<Duration>) -> Cache {
        Cache {
            max,
            ttl,
            entries: HashMap::new(),
            by_use: BTreeMap::new(),
            tick: 0,
            scanned: Instant::now(),
        }
    }

    /// `labels` relabeled by `rules`, None when dropped.
    pub fn apply(&mut self, rules: &[Rule], labels: Labels) -> Option<Labels> {
        self.scan();
        let mut hasher = DefaultHasher::new();
        labels.hash(&mut hasher);
        let hash = hasher.finish();
        self.tick += 1;
        if let Some(found) = self.entries.get_mut(&hash) {
            // A different set with the same hash is relabeled anew.
            if found.original == labels {
                self.by_use.remove(&found.tick);
                self.by_use.insert(self.tick, hash);
                (found.tick, found.used) = (self.tick, Instant::now());
                return found.result.clone();
            }
            self.by_use.remove(&found.tick);
        }
        let mut result = labels.clone();
        let result = apply(rules, &mut result).then_some(result);
        let entry = Cached {
            original: labels,
            result: result.clone(),
            tick: self.tick,
            used: Instant::now(),
        };
        self.entries.insert(hash, entry);
        self.by_use.insert(self.tick, hash);
        if self.ttl.is_none() && self.entries.len() > self.max {
            if let Some((_, oldest)) = self.by_use.pop_first() {
                self.entries.remove(&oldest);
            }
        }
        result
    }

    fn scan(&mut self) {
        let Some(ttl) = self.ttl else { return };
        if self.scanned.elapsed() < ttl / 4 {
            return;
        }
        self.scanned = Instant::now();
        let by_use = &mut self.by_use;
        self.entries.retain(|_, entry| {
            let keep = entry.used.elapsed() < ttl;
            if !keep {
                by_use.remove(&entry.tick);
            }
            keep
        });
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

    fn rule(action: &str, sources: &str, target: &str, regex: &str) -> Rule {
        let mut settings = Settings {
            action: action.into(),
            sources: sources.split(',').map(str::to_owned).collect(),
            target: target.into(),
            ..Settings::default()
        };
        settings.sources.retain(|s| !s.is_empty());
        if !regex.is_empty() {
            settings.regex = regex.into();
        }
        Rule::new(settings).unwrap()
    }

    #[test]
    fn caches_results() {
        let rules = [rule("drop", "a", "", "x")];
        let mut cache = Cache::new(2, None);
        assert!(cache.apply(&rules, labels(&[("a", "x")])).is_none());
        let kept = cache.apply(&rules, labels(&[("a", "y")]));
        assert_eq!(kept, Some(labels(&[("a", "y")])));
        assert!(cache.apply(&rules, labels(&[("a", "x")])).is_none());
        cache.apply(&rules, labels(&[("a", "z")]));
        assert_eq!(cache.entries.len(), 2);
        // `y` was the least recently used.
        let found: Vec<&Labels> =
            cache.entries.values().map(|e| &e.original).collect();
        assert!(!found.contains(&&labels(&[("a", "y")])));
        let mut aged = Cache::new(0, Some(Duration::ZERO));
        aged.apply(&rules, labels(&[("a", "y")]));
        aged.apply(&rules, labels(&[("a", "z")]));
        assert_eq!(aged.entries.len(), 1, "the scan dropped `y`");
    }

    #[test]
    fn applies_like_prometheus() {
        let rules = [
            rule("drop", "__name__", "", "go_.*"),
            rule("replace", "instance", "node", "(.*):\\d+"),
            rule("labeldrop", "", "", "job"),
            rule("uppercase", "node", "NODE", ""),
        ];
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

        let keep = rule("keep", "a,b", "", "x;y");
        assert!(apply(&[keep], &mut labels(&[("a", "x"), ("b", "y")])));
        let map = rule("labelmap", "", "", "__meta_(.+)");
        let mut mapped = labels(&[("__meta_zone", "home")]);
        assert!(apply(&[map], &mut mapped));
        assert!(mapped.contains(&("zone".into(), "home".into())));
        let equal = rule("keepequal", "a", "b", "");
        assert!(apply(&[equal], &mut labels(&[("a", "1"), ("b", "1")])));
        let settings = Settings {
            action: "hashmod".into(),
            ..Settings::default()
        };
        assert!(Rule::new(settings).is_err());
    }
}
