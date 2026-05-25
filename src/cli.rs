// SPDX-License-Identifier: MIT
use clap::Parser;

#[derive(Parser)]
#[command(name = "atproxy", version = env!("ATPROXY_VERSION"), about = "Per-app transparent TCP proxy")]
pub struct Cli {
    /// Target UID to intercept (hint: use `pm list packages -U`)
    pub uid: Option<u32>,

    /// Upstream HTTP proxy address (host:port)
    pub proxy: Option<String>,

    /// Listen port for redirected connections
    #[arg(short, long, default_value = "5280")]
    pub port: u16,

    /// Verbose per-connection logging
    #[arg(short, long)]
    pub verbose: bool,

    /// Also add ip6tables rules
    #[arg(short = '6', long)]
    pub ipv6: bool,

    /// Remove stale iptables rules for UID and exit
    #[arg(long)]
    pub clean: bool,
}
