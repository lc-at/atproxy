// SPDX-License-Identifier: MIT
use std::process::Command;

pub struct Iptables {
    pub uid: u32,
    pub ipv6: bool,
    pub verbose: bool,
}

impl Iptables {
    fn cmd_name(&self) -> &'static str {
        if self.ipv6 { "ip6tables" } else { "iptables" }
    }

    fn run(&self, args: &[&str]) -> bool {
        let cmd = self.cmd_name();
        if self.verbose {
            eprint!("{cmd}");
            for a in args {
                eprint!(" {a}");
            }
            eprintln!();
        }
        let status = Command::new(cmd)
            .args(args)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        match status {
            Ok(s) if s.success() => true,
            Ok(s) => {
                if !self.verbose {
                    eprintln!("iptables error (exit {})", s.code().unwrap_or(-1));
                }
                false
            }
            Err(e) => {
                eprintln!("iptables exec failed: {e}");
                false
            }
        }
    }

    pub fn apply(&self, listen_port: u16, proxy_ip: &str, proxy_port: u16) {
        let uid_s = self.uid.to_string();
        let port_s = listen_port.to_string();
        let lo = if self.ipv6 { "::1/128" } else { "127.0.0.0/8" };

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
            "-j",
            "REDIRECT",
            "--to-port",
            &port_s,
        ]);

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

        eprintln!("iptables applied (uid={} → :{})", self.uid, listen_port);
    }

    pub fn cleanup(&self) {
        let cmd = self.cmd_name();
        let uid_s = self.uid.to_string();

        let output = match Command::new(cmd)
            .args(["-t", "nat", "-S", "OUTPUT"])
            .output()
        {
            Ok(o) => o,
            Err(_) => return,
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
            let status = Command::new(cmd)
                .args(&args)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
            if status.map_or(false, |s| s.success()) {
                removed += 1;
            }
        }

        if removed > 0 {
            eprintln!("Cleaned {removed} rule(s) for uid={} ({cmd})", self.uid);
        }
    }
}
