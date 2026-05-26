// SPDX-License-Identifier: MIT
use std::process::Command;
use tracing::{debug, error, info};

/// Resolve an Android package name to its numeric UID.
///
/// Runs `pm list packages -U` on the device and parses the output, which
/// has lines in the format:
///
/// ```text
/// package:com.example.app uid:10188
/// ```
///
/// Returns `None` if the command fails or the package is not found.
pub fn resolve_uid(package: &str) -> Option<u32> {
    info!(package, "resolving package name to UID");

    let output = match Command::new("pm").args(["list", "packages", "-U"]).output() {
        Ok(o) => o,
        Err(e) => {
            error!(package, error = %e, "failed to execute `pm list packages -U`");
            return None;
        }
    };

    if !output.status.success() {
        error!(
            package,
            exit_code = output.status.code().unwrap_or(-1),
            "`pm list packages -U` exited with error"
        );
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_uid_from_output(package, &stdout)
}

/// Parse a UID from `pm list packages -U` output for a given package name.
fn parse_uid_from_output(package: &str, stdout: &str) -> Option<u32> {
    for line in stdout.lines() {
        // Format: package:com.example.app uid:10188
        // Parse the package field exactly to avoid substring false matches
        // (e.g. "com.example.app" must not match "com.example.app.debug").
        let Some(rest) = line.strip_prefix("package:") else {
            continue;
        };
        let Some(space) = rest.find(' ') else {
            continue;
        };
        let pkg_name = &rest[..space];
        if pkg_name != package {
            continue;
        }
        if let Some(uid_part) = rest[space + 1..].strip_prefix("uid:")
            && let Ok(uid) = uid_part.trim().parse::<u32>()
        {
            debug!(package, uid, "resolved package to UID");
            return Some(uid);
        }
    }

    error!(package, "package not found in `pm list packages -U` output");
    None
}

/// Resolve a target string into a list of UIDs.
///
/// The target can be:
/// - A package name (contains a `.`) → resolved via `pm list packages -U`
/// - A single numeric UID (e.g. `10188`)
/// - Multiple comma-separated UIDs (e.g. `10188,10200,10300`)
///
/// Returns `None` if any part fails to resolve.
pub fn resolve_target(target: &str) -> Option<Vec<u32>> {
    // If it contains a dot, treat as a package name.
    if target.contains('.') {
        let uid = resolve_uid(target)?;
        Some(vec![uid])
    } else if target.contains(',') {
        // Comma-separated UIDs.
        let mut uids = Vec::new();
        for part in target.split(',') {
            let trimmed = part.trim();
            if trimmed.is_empty() {
                error!("empty UID in comma-separated list");
                return None;
            }
            match trimmed.parse::<u32>() {
                Ok(uid) => uids.push(uid),
                Err(e) => {
                    error!(part = trimmed, error = %e, "invalid UID in comma-separated list");
                    return None;
                }
            }
        }
        if uids.is_empty() {
            error!("no valid UIDs in target");
            return None;
        }
        Some(uids)
    } else {
        // Single numeric UID.
        match target.parse::<u32>() {
            Ok(uid) => Some(vec![uid]),
            Err(e) => {
                error!(target, error = %e, "target is not a valid UID or package name");
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_uid_exact_match() {
        let out = "package:com.example.app uid:10188\npackage:com.other.app uid:10200\n";
        assert_eq!(parse_uid_from_output("com.example.app", out), Some(10188));
        assert_eq!(parse_uid_from_output("com.other.app", out), Some(10200));
    }

    #[test]
    fn test_parse_uid_no_substring_false_positive() {
        let out = "package:com.example.app uid:10188\npackage:com.example.app.debug uid:10200\n";
        assert_eq!(parse_uid_from_output("com.example.app", out), Some(10188));
        assert_eq!(
            parse_uid_from_output("com.example.app.debug", out),
            Some(10200)
        );
    }

    #[test]
    fn test_parse_uid_not_found() {
        let out = "package:com.example.app uid:10188\n";
        assert_eq!(parse_uid_from_output("com.nonexistent", out), None);
    }

    #[test]
    fn test_parse_uid_partial_name_no_match() {
        let out = "package:com.example.app uid:10188\npackage:com.other.app uid:10200\n";
        assert_eq!(parse_uid_from_output("com.app", out), None);
        assert_eq!(parse_uid_from_output("com.other", out), None);
    }

    #[test]
    fn test_resolve_target_single_uid() {
        assert_eq!(resolve_target("10188"), Some(vec![10188]));
    }

    #[test]
    fn test_resolve_target_comma_uids() {
        assert_eq!(
            resolve_target("10188,10200,10300"),
            Some(vec![10188, 10200, 10300])
        );
    }

    #[test]
    fn test_resolve_target_comma_uids_with_spaces() {
        assert_eq!(
            resolve_target("10188, 10200 , 10300"),
            Some(vec![10188, 10200, 10300])
        );
    }

    #[test]
    fn test_resolve_target_bad_uid() {
        assert_eq!(resolve_target("abc"), None);
    }

    #[test]
    fn test_resolve_target_bad_comma_mixed() {
        assert_eq!(resolve_target("10188,abc,10300"), None);
    }

    #[test]
    fn test_resolve_target_empty_comma_part() {
        assert_eq!(resolve_target("10188,,10300"), None);
    }

    // Package name resolution requires `pm` binary (Android), tested via
    // parse_uid_from_output above. resolve_target with dots calls resolve_uid
    // which invokes `pm` (not testable outside Android).
}
