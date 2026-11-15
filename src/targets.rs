//! Targets: label sets that say what to scrape or read, as Alloy's
//! discovery components export them. Docker's containers and file_sd
//! files change while the agent runs, so targets are resolved anew
//! each time they are used.

use crate::glob;
use crate::host;
use crate::json::Json;
use crate::relabel::{self, Labels, Rule};
use std::cell::RefCell;
use std::fs;
use std::rc::Rc;
use std::time::{Duration, Instant, SystemTime};

#[derive(Clone)]
pub enum Targets {
    Static(Vec<Labels>),
    /// discovery.docker's: crate::docker::targets, made each round.
    Docker,
    /// discovery.file's: the file_sd files these patterns match.
    Files(Vec<String>),
    /// discovery.relabel's output.
    Relabel(Box<Targets>, Rc<Vec<Rule>>),
    Concat(Vec<Targets>),
    /// array.combine_maps's: the left joined with the right on these
    /// labels; the bool keeps the left ones that do not join.
    Combine(Box<[Targets; 2]>, Vec<String>, bool),
    /// local.file_match's: a target per file its `__path__` matches,
    /// less those modified longer ago than the duration.
    FileMatch(Box<Targets>, Option<Duration>),
    /// Its targets resolved again only once the duration has passed:
    /// discovery's refresh_interval, file_match's sync_period.
    Cached(Box<Targets>, Duration, Rc<RefCell<Option<Resolved>>>),
}

/// Targets as last resolved, and when.
type Resolved = (Instant, Vec<Labels>);

/// `inner`, resolved at most once every `every`.
pub fn cached(inner: Targets, every: Duration) -> Targets {
    Targets::Cached(Box::new(inner), every, Rc::default())
}

impl Targets {
    /// The targets now; `docker`: discovery.docker's.
    pub fn resolve(&self, docker: &[Labels]) -> Vec<Labels> {
        match self {
            Targets::Static(targets) => targets.clone(),
            Targets::Docker => docker.to_vec(),
            Targets::Files(patterns) => file_sd(patterns),
            Targets::Relabel(inner, rules) => inner
                .resolve(docker)
                .into_iter()
                .filter_map(|mut t| relabel::apply(rules, &mut t).then_some(t))
                .collect(),
            Targets::Concat(parts) => {
                parts.iter().flat_map(|p| p.resolve(docker)).collect()
            }
            Targets::Combine(sides, on, keep) => {
                let [left, right] = sides.as_ref();
                let (left, right) =
                    (left.resolve(docker), right.resolve(docker));
                combine(&left, &right, on, *keep, String::eq)
            }
            Targets::FileMatch(inner, older) => inner
                .resolve(docker)
                .iter()
                .flat_map(|target| file_match(target, *older))
                .collect(),
            Targets::Cached(inner, every, kept) => {
                let mut kept = kept.borrow_mut();
                match kept.as_ref() {
                    Some((at, targets)) if at.elapsed() < *every => {
                        targets.clone()
                    }
                    _ => {
                        let targets = inner.resolve(docker);
                        *kept = Some((Instant::now(), targets.clone()));
                        targets
                    }
                }
            }
        }
    }
}

/// array.combine_maps: each left map with each right one that has the
/// same values under every key in `on`, merged (the right's win). With
/// `keep`, a left map is also kept as is once for each right one it
/// does not join, as Alloy's loop does.
pub fn combine<T: Clone>(
    left: &[Vec<(String, T)>],
    right: &[Vec<(String, T)>],
    on: &[String],
    keep: bool,
    same: impl Fn(&T, &T) -> bool,
) -> Vec<Vec<(String, T)>> {
    fn get<'a, T>(map: &'a [(String, T)], key: &str) -> Option<&'a T> {
        map.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }
    let joins = |l: &[(String, T)], r: &[(String, T)]| {
        on.iter().all(|key| match (get(l, key), get(r, key)) {
            (Some(a), Some(b)) => same(a, b),
            _ => false,
        })
    };
    let mut out = Vec::new();
    for l in left {
        for r in right {
            if joins(l, r) {
                let mut merged: Vec<_> = l
                    .iter()
                    .filter(|(k, _)| get(r, k).is_none())
                    .cloned()
                    .collect();
                merged.extend(r.iter().cloned());
                out.push(merged);
            } else if keep {
                out.push(l.clone());
            }
        }
    }
    out
}

fn file_match(target: &Labels, older: Option<Duration>) -> Vec<Labels> {
    let recent = |meta: &fs::Metadata| match (older, meta.modified()) {
        (Some(older), Ok(at)) => {
            SystemTime::now().duration_since(at).unwrap_or_default() <= older
        }
        _ => true,
    };
    let files = paths(target).into_iter().filter(|path| {
        let meta = fs::metadata(host::path(path));
        meta.is_ok_and(|meta| meta.is_file() && recent(&meta))
    });
    files
        .map(|path| {
            let mut found = target.clone();
            found.retain(|(k, _)| k != "__path__");
            found.push(("__path__".into(), path));
            found
        })
        .collect()
}

/// The paths a target's `__path__` names or matches (a glob), less
/// those its `__path_exclude__` matches.
pub fn paths(target: &Labels) -> Vec<String> {
    let path = get(target, "__path__");
    let exclude = get(target, "__path_exclude__");
    let paths = if glob::is_pattern(path) {
        glob::expand(path)
    } else {
        vec![path.to_owned()]
    };
    let excluded = |p: &str| !exclude.is_empty() && glob::matches(exclude, p);
    paths
        .into_iter()
        .filter(|p| !p.is_empty() && !excluded(p))
        .collect()
}

/// Prometheus's file_sd in JSON: a target per entry of each group's
/// `targets`, as `__address__`, with the group's labels and
/// `__meta_filepath`.
fn file_sd(patterns: &[String]) -> Vec<Labels> {
    let mut targets = Vec::new();
    for pattern in patterns {
        let paths = if glob::is_pattern(pattern) {
            glob::expand(pattern)
        } else {
            vec![pattern.clone()]
        };
        for path in paths {
            let text = fs::read_to_string(host::path(&path));
            let Some(json) = text.ok().as_deref().and_then(Json::parse) else {
                eprintln!("Targets: {path} is not file_sd JSON");
                continue;
            };
            for group in json.arr() {
                targets.extend(group_targets(group, &path));
            }
        }
    }
    targets
}

fn group_targets(group: &Json, path: &str) -> Vec<Labels> {
    let labels = group.get("labels").map(Json::obj).unwrap_or_default();
    let mut common: Labels = labels
        .iter()
        .filter_map(|(k, v)| Some((k.clone(), v.str()?.to_owned())))
        .collect();
    common.push(("__meta_filepath".into(), path.to_owned()));
    let addresses = group.get("targets").map(Json::arr).unwrap_or_default();
    let addresses = addresses.iter().filter_map(Json::str);
    addresses
        .map(|address| {
            let mut target = common.clone();
            target.push(("__address__".into(), address.to_owned()));
            target
        })
        .collect()
}

/// A label's value, or "".
pub fn get<'a>(labels: &'a Labels, name: &str) -> &'a str {
    let found = labels.iter().find(|(k, _)| k == name);
    found.map_or("", |(_, v)| v.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relabel::Settings;

    #[test]
    fn reads_file_sd_and_relabels() {
        let dir = std::env::temp_dir()
            .join(format!("ha-targets-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let groups = r#"[{"targets":["a:1","b:2"],"labels":{"job":"x"}}]"#;
        fs::write(dir.join("t.json"), groups).unwrap();
        let rule = Rule::new(Settings {
            action: "drop".into(),
            sources: vec!["__address__".into()],
            regex: "b:.*".into(),
            ..Settings::default()
        })
        .unwrap();
        let files = Targets::Files(vec![format!("{}/*.json", dir.display())]);
        let targets = Targets::Relabel(Box::new(files), Rc::new(vec![rule]));
        let found = targets.resolve(&[]);
        assert_eq!(found.len(), 1);
        assert_eq!(get(&found[0], "__address__"), "a:1");
        assert_eq!(get(&found[0], "job"), "x");
        assert!(get(&found[0], "__meta_filepath").ends_with("t.json"));
        let pattern = format!("{}/*.json", dir.display());
        let target = vec![("__path__".to_owned(), pattern)];
        let matched = Targets::FileMatch(
            Box::new(Targets::Static(vec![target])),
            Some(Duration::from_secs(60)),
        );
        let found = matched.resolve(&[]);
        assert_eq!(found.len(), 1);
        assert!(get(&found[0], "__path__").ends_with("/t.json"));
        let kept = cached(matched, Duration::from_secs(60));
        assert_eq!(kept.resolve(&[]).len(), 1);
        fs::write(dir.join("u.json"), groups).unwrap();
        assert_eq!(kept.resolve(&[]).len(), 1, "resolved again too soon");
        fs::remove_dir_all(dir).unwrap();
    }
}
