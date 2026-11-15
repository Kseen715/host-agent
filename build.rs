//! The build's labels on `*_build_info`, as Go programs give theirs:
//! the branch and revision (git, or HOST_AGENT_REVISION where the
//! sources come without it), the compiler and the features built.

use std::env;
use std::process::Command;

fn main() {
    let revision = env::var("HOST_AGENT_REVISION")
        .ok()
        .or_else(|| git(&["rev-parse", "--short=7", "HEAD"]));
    let branch = git(&["rev-parse", "--abbrev-ref", "HEAD"]);
    let rustc = env::var("RUSTC").unwrap_or_else(|_| "rustc".into());
    let version = Command::new(rustc).arg("--version").output().ok();
    let version = version
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .and_then(|text| text.split_whitespace().nth(1).map(str::to_owned));
    let mut features: Vec<String> = env::vars()
        .filter_map(|(key, _)| {
            let name = key.strip_prefix("CARGO_FEATURE_")?;
            let name = name.to_lowercase().replace('_', "-");
            Some(name).filter(|n| n != "default")
        })
        .collect();
    features.sort();
    let values = [
        (
            "BUILD_REVISION",
            revision.unwrap_or_else(|| "unknown".into()),
        ),
        ("BUILD_BRANCH", branch.unwrap_or_else(|| "HEAD".into())),
        ("BUILD_RUST", format!("rust{}", version.unwrap_or_default())),
        ("BUILD_TAGS", features.join(",")),
    ];
    for (key, value) in values {
        println!("cargo:rustc-env={key}={value}");
    }
    println!("cargo:rerun-if-env-changed=HOST_AGENT_REVISION");
    // A commit moves HEAD, or the branch it points at.
    for path in ["HEAD", "refs/heads"] {
        if let Some(path) = git(&["rev-parse", "--git-path", path]) {
            println!("cargo:rerun-if-changed={path}");
        }
    }
}

fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    let text = String::from_utf8(out.stdout).ok()?;
    Some(text.trim().to_owned())
        .filter(|t| out.status.success() && !t.is_empty())
}
