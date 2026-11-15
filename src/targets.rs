//! Targets: label sets that say what to scrape or read, as Alloy's
//! discovery components export them. Docker's containers and file_sd
//! files change while the agent runs, so targets are resolved anew
//! each time they are used.

use crate::glob;
use crate::host;
use crate::json::Json;
use crate::relabel::{self, Labels, Rule};
use std::fs;
use std::rc::Rc;
use std::time::{Duration, SystemTime};

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
    /// local.file_match's: a target per file its `__path__` matches,
    /// less those modified longer ago than the duration.
    FileMatch(Box<Targets>, Option<Duration>),
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
            Targets::FileMatch(inner, older) => inner
                .resolve(docker)
                .iter()
                .flat_map(|target| file_match(target, *older))
                .collect(),
        }
    }
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
        fs::remove_dir_all(dir).unwrap();
    }
}
