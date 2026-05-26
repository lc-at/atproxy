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

    for line in stdout.lines() {
        // Format: package:com.example.app uid:10188
        if !line.contains(package) {
            continue;
        }
        if let Some(uid_part) = line.split("uid:").nth(1)
            && let Ok(uid) = uid_part.trim().parse::<u32>()
        {
            debug!(package, uid, "resolved package to UID");
            return Some(uid);
        }
    }

    error!(package, "package not found in `pm list packages -U` output");
    None
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_parse_pm_output_line() {
        let line = "package:com.example.app uid:10188";
        let uid_part = line.split("uid:").nth(1).unwrap().trim();
        assert_eq!(uid_part.parse::<u32>().unwrap(), 10188);
    }

    #[test]
    fn test_parse_pm_output_wrong_package() {
        let line = "package:com.other.app uid:10200";
        let uid_part = line.split("uid:").nth(1).unwrap().trim();
        assert_eq!(uid_part.parse::<u32>().unwrap(), 10200);
    }
}
