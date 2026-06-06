// SPDX-License-Identifier: MIT
//! iptables rule management for per-UID OUTPUT REDIRECT.
//!
//! Applies and cleans up `nat/OUTPUT` rules that redirect TCP connections
//! from a specific UID to the local transparent-proxy listener, while
//! exempting loopback and direct-to-proxy traffic.
//!
//! **IPv6 note:** `ip6tables -t nat` requires kernel ≥3.7 with
//! `CONFIG_IP6_NF_NAT` enabled. Many Android kernels lack this module.
//! [`apply()`] returns `false` if the rules could not be applied, allowing
//! the caller to warn the user.

use std::process::Command;
use tracing::{debug, error, info, warn};

/// Manages iptables rules for a single UID.
pub struct Iptables {
    pub uid: u32,
    pub ipv6: bool,
}

impl Iptables {
    fn cmd_name(&self) -> &'static str {
        if self.ipv6 { "ip6tables" } else { "iptables" }
    }

    /// Execute an iptables command. Returns `true` on success.
    fn run(&self, args: &[&str]) -> bool {
        let cmd = self.cmd_name();
        debug!(command = cmd, args = ?args, "executing iptables command");
        let status = Command::new(cmd)
            .args(args)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        match status {
            Ok(s) if s.success() => true,
            Ok(s) => {
                warn!(
                    command = cmd,
                    exit_code = s.code().unwrap_or(-1),
                    "iptables command failed"
                );
                false
            }
            Err(e) => {
                error!(command = cmd, error = %e, "iptables exec failed");
                false
            }
        }
    }

    /// Apply iptables rules: REDIRECT the UID's TCP traffic to `listen_port`,
    /// with RETURN exemptions for loopback and direct-to-proxy connections.
    ///
    /// `proxy_ip` should be the stringified form of the upstream proxy's IP
    /// (IPv4 or IPv6). The direct-to-proxy RETURN rule is only installed when
    /// the address family matches this iptables instance (v4 ip vs iptables,
    /// v6 ip vs ip6tables); cross-family entries are silently skipped — the
    /// REDIRECT rule still applies, and the worst case is a brief redirect
    /// loop that the OS rejects at connect time.
    ///
    /// Returns `true` if the main REDIRECT rule was applied successfully,
    /// `false` otherwise (e.g. ip6tables nat table not available).
    pub fn apply(&self, listen_port: u16, proxy_ip: &str, proxy_port: u16) -> bool {
        let uid_s = self.uid.to_string();
        let port_s = listen_port.to_string();
        let lo = if self.ipv6 { "::1/128" } else { "127.0.0.0/8" };

        // Main REDIRECT rule, this is the critical one.
        if !self.run(&[
            "-t",
            "nat",
            "-I",
            "OUTPUT",
            "1",
            "-p",
            "tcp",
            "-m",
            "owner",
            "--uid-owner",
            &uid_s,
            "-j",
            "REDIRECT",
            "--to-port",
            &port_s,
        ]) {
            if self.ipv6 {
                warn!(
                    uid = self.uid,
                    "ip6tables nat table not available, \
                     kernel may lack CONFIG_IP6_NF_NAT. \
                     IPv6 traffic will NOT be proxied."
                );
            }
            return false;
        }

        // Exempt direct-to-proxy connections (avoid redirect loop), but only
        // when the proxy address family matches this iptables instance.
        // Trying to add `-d ::1` to iptables (v4) or `-d 1.2.3.4` to
        // ip6tables would either fail silently or install a useless rule.
        if let Some(proxy_str) = self.family_matched_proxy(proxy_ip) {
            let pp = proxy_port.to_string();
            self.run(&[
                "-t",
                "nat",
                "-I",
                "OUTPUT",
                "1",
                "-p",
                "tcp",
                "-m",
                "owner",
                "--uid-owner",
                &uid_s,
                "-d",
                proxy_str,
                "--dport",
                &pp,
                "-j",
                "RETURN",
            ]);
        }

        // Exempt loopback connections.
        self.run(&[
            "-t",
            "nat",
            "-I",
            "OUTPUT",
            "1",
            "-p",
            "tcp",
            "-m",
            "owner",
            "--uid-owner",
            &uid_s,
            "-d",
            lo,
            "-j",
            "RETURN",
        ]);

        info!(
            uid = self.uid,
            listen_port,
            ipv6 = self.ipv6,
            "iptables rules applied"
        );
        true
    }

    /// Return the proxy IP string for the `-d` argument iff its address family
    /// matches this iptables instance. Empty / unspecified IPs are filtered
    /// out as before.
    fn family_matched_proxy<'a>(&self, proxy_ip: &'a str) -> Option<&'a str> {
        if proxy_ip.is_empty() || proxy_ip == "0.0.0.0" || proxy_ip == "::" {
            return None;
        }
        let parsed: std::net::IpAddr = proxy_ip.parse().ok()?;
        let family_matches = match (self.ipv6, parsed) {
            (false, std::net::IpAddr::V4(_)) | (true, std::net::IpAddr::V6(_)) => true,
            _ => false,
        };
        if family_matches {
            Some(proxy_ip)
        } else {
            None
        }
    }

    /// Remove all iptables rules matching this UID from the nat OUTPUT chain.
    pub fn cleanup(&self) {
        let cmd = self.cmd_name();

        let Ok(output) = Command::new(cmd)
            .args(["-t", "nat", "-S", "OUTPUT"])
            .output()
        else {
            return;
        };

        let rules = String::from_utf8_lossy(&output.stdout);
        let mut removed = 0u32;

        for line in rules.lines() {
            // Token-level match: `--uid-owner 1000` must not accidentally
            // match a rule for UID 10000 / 21000 (which the previous
            // `line.contains(&uid_s)` substring check did).
            if !rule_matches_uid(line, self.uid) {
                continue;
            }
            let delete_rule = line.replace("-A ", "-D ");
            let mut args: Vec<&str> = vec!["-t", "nat"];
            args.extend(delete_rule.split_whitespace());
            debug!(command = cmd, args = ?args, "removing iptables rule");
            let status = Command::new(cmd)
                .args(&args)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
            if status.is_ok_and(|s| s.success()) {
                removed += 1;
            } else {
                warn!(
                    command = cmd,
                    rule = delete_rule.as_str(),
                    "failed to remove iptables rule"
                );
            }
        }

        if removed > 0 {
            info!(
                uid = self.uid,
                removed,
                ipv6 = self.ipv6,
                "cleaned iptables rules"
            );
        }
    }
}

/// Return `true` iff `line` is an iptables rule whose `--uid-owner` argument
/// equals `uid` exactly. Token-based to avoid substring false positives
/// (e.g. UID `1000` previously matched against `--uid-owner 10000`).
fn rule_matches_uid(line: &str, uid: u32) -> bool {
    let uid_s = uid.to_string();
    let mut iter = line.split_whitespace();
    while let Some(tok) = iter.next() {
        if tok == "--uid-owner" {
            if let Some(val) = iter.next() {
                if val == uid_s {
                    return true;
                }
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_matches_uid_exact() {
        assert!(rule_matches_uid(
            "-A OUTPUT -p tcp -m owner --uid-owner 1000 -j REDIRECT --to-port 5280",
            1000
        ));
    }

    #[test]
    fn test_rule_matches_uid_no_substring_false_positive() {
        // Regression: the old `line.contains(&uid_s)` matched any rule whose
        // text mentioned the UID digits anywhere. UID 1000 must NOT match
        // rules for 10000, 11000, 21000, 10001, etc.
        assert!(!rule_matches_uid(
            "-A OUTPUT -p tcp -m owner --uid-owner 10000 -j REDIRECT --to-port 5280",
            1000
        ));
        assert!(!rule_matches_uid(
            "-A OUTPUT -p tcp -m owner --uid-owner 21000 -j REDIRECT --to-port 5280",
            1000
        ));
        assert!(!rule_matches_uid(
            "-A OUTPUT -p tcp -m owner --uid-owner 10001 -j REDIRECT --to-port 5280",
            1000
        ));
    }

    #[test]
    fn test_rule_matches_uid_no_owner_flag() {
        // Rules without --uid-owner should not match.
        assert!(!rule_matches_uid(
            "-A OUTPUT -p tcp -j REDIRECT --to-port 5280",
            1000
        ));
    }

    #[test]
    fn test_rule_matches_uid_with_other_numbers_present() {
        // UID 1000 should match even when the rule contains other numbers
        // like --to-port 5280, and should NOT match a rule with port 1000
        // but a different uid-owner.
        assert!(rule_matches_uid(
            "-A OUTPUT -p tcp -m owner --uid-owner 1000 -j REDIRECT --to-port 5280",
            1000
        ));
        assert!(!rule_matches_uid(
            "-A OUTPUT -p tcp -m owner --uid-owner 9999 -j REDIRECT --to-port 1000",
            1000
        ));
    }

    // ---------- family_matched_proxy ----------

    #[test]
    fn test_family_matched_proxy_v4_to_iptables() {
        let ip4 = Iptables { uid: 1000, ipv6: false };
        assert_eq!(ip4.family_matched_proxy("1.2.3.4"), Some("1.2.3.4"));
        assert_eq!(ip4.family_matched_proxy("127.0.0.1"), Some("127.0.0.1"));
    }

    #[test]
    fn test_family_matched_proxy_v6_to_ip6tables() {
        let ip6 = Iptables { uid: 1000, ipv6: true };
        assert_eq!(ip6.family_matched_proxy("::1"), Some("::1"));
        assert_eq!(
            ip6.family_matched_proxy("2001:db8::1"),
            Some("2001:db8::1")
        );
    }

    #[test]
    fn test_family_matched_proxy_cross_family_rejected() {
        // IPv4 proxy must NOT be passed to ip6tables...
        let ip6 = Iptables { uid: 1000, ipv6: true };
        assert_eq!(ip6.family_matched_proxy("1.2.3.4"), None);
        assert_eq!(ip6.family_matched_proxy("127.0.0.1"), None);
        // ...and IPv6 proxy must NOT be passed to iptables.
        let ip4 = Iptables { uid: 1000, ipv6: false };
        assert_eq!(ip4.family_matched_proxy("::1"), None);
        assert_eq!(ip4.family_matched_proxy("2001:db8::1"), None);
    }

    #[test]
    fn test_family_matched_proxy_empty_or_unspecified() {
        let ip4 = Iptables { uid: 1000, ipv6: false };
        assert_eq!(ip4.family_matched_proxy(""), None);
        assert_eq!(ip4.family_matched_proxy("0.0.0.0"), None);
        let ip6 = Iptables { uid: 1000, ipv6: true };
        assert_eq!(ip6.family_matched_proxy(""), None);
        assert_eq!(ip6.family_matched_proxy("::"), None);
    }

    #[test]
    fn test_family_matched_proxy_invalid() {
        let ip4 = Iptables { uid: 1000, ipv6: false };
        assert_eq!(ip4.family_matched_proxy("garbage"), None);
        assert_eq!(ip4.family_matched_proxy("999.999.999.999"), None);
    }
}
