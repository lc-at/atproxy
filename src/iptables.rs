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

        // Exempt direct-to-proxy connections (avoid redirect loop).
        if !proxy_ip.is_empty() && proxy_ip != "0.0.0.0" && proxy_ip != "::" {
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
                proxy_ip,
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

    /// Remove all iptables rules matching this UID from the nat OUTPUT chain.
    pub fn cleanup(&self) {
        let cmd = self.cmd_name();
        let uid_s = self.uid.to_string();

        let Ok(output) = Command::new(cmd)
            .args(["-t", "nat", "-S", "OUTPUT"])
            .output()
        else {
            return;
        };

        let rules = String::from_utf8_lossy(&output.stdout);
        let mut removed = 0u32;

        for line in rules.lines() {
            if !line.contains(&uid_s) || !line.contains("--uid-owner") {
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
