// SPDX-License-Identifier: MIT
use std::process::Command;

fn main() {
    let version = compute_version();
    println!("cargo:rustc-env=ATPROXY_VERSION={version}");
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs/heads/");
}

fn compute_version() -> String {
    let tag = git_nearest_tag();
    let hash = git_short_hash().unwrap_or_else(|| "dev".into());
    format!("{tag}+{hash}")
}

fn git_nearest_tag() -> String {
    let out = Command::new("git")
        .args(["describe", "--tags", "--abbrev=0", "--match", "v*"])
        .output()
        .ok();
    match out {
        Some(o) if o.status.success() => {
            let raw = String::from_utf8_lossy(&o.stdout).trim().to_string();
            raw.trim_start_matches('v').to_string()
        }
        _ => "0.0.0".into(),
    }
}

fn git_short_hash() -> Option<String> {
    let out = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() { None } else { Some(s) }
}
