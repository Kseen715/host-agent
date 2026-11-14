//! Path patterns as Alloy's local.file_match takes them (doublestar):
//! `*` and `?` within one path component, `[abc]`, `[a-z]`, `[!a]`,
//! and `**` for any number of components.

use crate::host;
use std::fs;

/// Directories deeper than this below a `**` are not searched.
const MAX_DEPTH: usize = 16;

pub fn is_pattern(path: &str) -> bool {
    path.contains(['*', '?', '['])
}

/// The host's files that `pattern` (an absolute path) matches, sorted.
pub fn expand(pattern: &str) -> Vec<String> {
    let pattern = parts(pattern);
    let fixed = pattern.iter().take_while(|p| !is_pattern(p)).count();
    let base = format!("/{}", pattern[..fixed].join("/"));
    let rest = &pattern[fixed..];
    let depth = if rest.contains(&"**") {
        MAX_DEPTH
    } else {
        rest.len()
    };
    let mut found = Vec::new();
    walk(&base, depth, &mut |path| {
        if matches_parts(rest, &parts(&path[base.len()..])) {
            found.push(path.to_owned());
        }
    });
    found.sort();
    found
}

fn walk(dir: &str, depth: usize, visit: &mut impl FnMut(&str)) {
    if depth == 0 {
        return;
    }
    let Ok(entries) = fs::read_dir(host::path(dir)) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let path =
            format!("{}/{}", dir.trim_end_matches('/'), name.to_string_lossy());
        match entry.file_type() {
            Ok(kind) if kind.is_dir() => walk(&path, depth - 1, visit),
            Ok(_) => visit(&path),
            Err(_) => {}
        }
    }
}

/// Whether `path` matches `pattern`, both absolute.
pub fn matches(pattern: &str, path: &str) -> bool {
    matches_parts(&parts(pattern), &parts(path))
}

/// A path's components.
fn parts(path: &str) -> Vec<&str> {
    path.split('/').filter(|p| !p.is_empty()).collect()
}

fn matches_parts(pattern: &[&str], path: &[&str]) -> bool {
    match (pattern.first(), path.first()) {
        (None, _) => path.is_empty(),
        (Some(&"**"), _) => {
            matches_parts(&pattern[1..], path)
                || (!path.is_empty() && matches_parts(pattern, &path[1..]))
        }
        (Some(part), Some(name)) => {
            component(part.as_bytes(), name.as_bytes())
                && matches_parts(&pattern[1..], &path[1..])
        }
        (Some(_), None) => false,
    }
}

/// One path component against its pattern.
fn component(pattern: &[u8], name: &[u8]) -> bool {
    match (pattern.first(), name.first()) {
        (None, _) => name.is_empty(),
        (Some(b'*'), _) => {
            component(&pattern[1..], name)
                || (!name.is_empty() && component(pattern, &name[1..]))
        }
        (Some(b'?'), Some(_)) => component(&pattern[1..], &name[1..]),
        (Some(b'['), Some(&byte)) => match class(&pattern[1..], byte) {
            Some((true, rest)) => component(rest, &name[1..]),
            Some((false, _)) => false,
            None => byte == b'[' && component(&pattern[1..], &name[1..]),
        },
        (Some(b'\\'), Some(&byte)) if pattern.len() > 1 => {
            pattern[1] == byte && component(&pattern[2..], &name[1..])
        }
        (Some(&expected), Some(&byte)) => {
            expected == byte && component(&pattern[1..], &name[1..])
        }
        (Some(_), None) => false,
    }
}

/// A `[...]` class after its `[`: whether `byte` is in it, and the
/// pattern after its `]`; None if it is not closed.
fn class(pattern: &[u8], byte: u8) -> Option<(bool, &[u8])> {
    let negated = matches!(pattern.first(), Some(b'!' | b'^'));
    let body = &pattern[usize::from(negated)..];
    let end = 1 + body.get(1..)?.iter().position(|&b| b == b']')?;
    let set = &body[..end];
    let mut found = false;
    let mut i = 0;
    while i < set.len() {
        if i + 2 < set.len() && set[i + 1] == b'-' {
            found |= (set[i]..=set[i + 2]).contains(&byte);
            i += 3;
        } else {
            found |= set[i] == byte;
            i += 1;
        }
    }
    Some((found != negated, &body[end + 1..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_like_doublestar() {
        assert!(matches("/var/log/*.log", "/var/log/a.log"));
        assert!(!matches("/var/log/*.log", "/var/log/x/a.log"));
        assert!(matches("/var/log/**/*.log", "/var/log/a.log"));
        assert!(matches("/var/log/**/*.log", "/var/log/x/y/a.log"));
        assert!(matches(
            "/srv/s?/logs/latest.log",
            "/srv/s1/logs/latest.log"
        ));
        assert!(matches("/a/[a-c]x", "/a/bx"));
        assert!(!matches("/a/[!a-c]x", "/a/bx"));
        assert!(matches("/a/[]]x", "/a/]x"));
        assert!(matches("/a/\\*", "/a/*"));
        assert!(!matches("/a/\\*", "/a/b"));
        assert!(!matches("/a/*", "/a"));
    }

    #[test]
    fn expands_in_directories() {
        let dir =
            std::env::temp_dir().join(format!("glob-{}", std::process::id()));
        for sub in ["s1/logs", "s2/logs", "s2/old"] {
            fs::create_dir_all(dir.join(sub)).unwrap();
        }
        for file in ["s1/logs/latest.log", "s2/logs/latest.log", "s2/old/a.log"]
        {
            fs::write(dir.join(file), "").unwrap();
        }
        let root = dir.display();
        let found = expand(&format!("{root}/*/logs/*.log"));
        assert_eq!(found.len(), 2);
        assert!(found[0].ends_with("s1/logs/latest.log"));
        assert_eq!(expand(&format!("{root}/**/*.log")).len(), 3);
        fs::remove_dir_all(dir).unwrap();
    }
}
