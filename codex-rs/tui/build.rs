use std::env;
use std::process::Command;

const TAG_PREFIX: &str = "rust-v";
const ALPHA_DELIMITER: &str = "-alpha.";
const TAG_DESCRIBE_ARGS: [&str; 5] = ["describe", "--tags", "--match", "rust-v*", "--abbrev=0"];
const TAG_LIST_ARGS: [&str; 4] = [
    "for-each-ref",
    "refs/tags/rust-v*",
    "--sort=-v:refname",
    "--format=%(refname:strip=2)",
];

fn main() {
    let display_version = env::var("CODEX_DISPLAY_VERSION")
        .ok()
        .filter(|version| !version.trim().is_empty())
        .or_else(resolve_display_version_from_git)
        .unwrap_or_else(fallback_display_version);

    println!("cargo:rustc-env=CODEX_DISPLAY_VERSION={display_version}");
    println!("cargo:rerun-if-env-changed=CODEX_DISPLAY_VERSION");
    println!("cargo:rerun-if-changed=build.rs");
}

fn resolve_display_version_from_git() -> Option<String> {
    if let Ok(output) = Command::new("git").args(TAG_DESCRIBE_ARGS).output()
        && output.status.success()
        && let Ok(stdout) = std::str::from_utf8(&output.stdout)
        && let Some(version) = stdout
            .lines()
            .next()
            .map(str::trim)
            .and_then(normalize_tag_for_display)
    {
        return Some(version);
    }

    let output = Command::new("git").args(TAG_LIST_ARGS).output().ok()?;
    if !output.status.success() {
        return None;
    }

    std::str::from_utf8(&output.stdout)
        .ok()?
        .lines()
        .map(str::trim)
        .find_map(normalize_tag_for_display)
}

fn normalize_tag_for_display(tag: &str) -> Option<String> {
    let version = tag.strip_prefix(TAG_PREFIX)?;
    if !is_supported_semver_tag(version) {
        return None;
    }
    Some(format!("v{version}"))
}

fn is_supported_semver_tag(version: &str) -> bool {
    if version.starts_with("0.0.") {
        return false;
    }

    if let Some((base, alpha_counter)) = version.split_once(ALPHA_DELIMITER) {
        return is_plain_semver(base) && is_numeric(alpha_counter);
    }

    is_plain_semver(version)
}

fn is_plain_semver(version: &str) -> bool {
    let mut parts = version.split('.');
    let (Some(major), Some(minor), Some(patch), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };

    [major, minor, patch].into_iter().all(is_numeric)
}

fn is_numeric(part: &str) -> bool {
    !part.is_empty() && part.chars().all(|character| character.is_ascii_digit())
}

fn fallback_display_version() -> String {
    env::var("CARGO_PKG_VERSION")
        .ok()
        .filter(|version| !version.trim().is_empty())
        .map(|version| format!("v{version}"))
        .unwrap_or_else(|| "v0.0.0".to_string())
}
