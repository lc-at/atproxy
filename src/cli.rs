// SPDX-License-Identifier: MIT
use clap::Parser;

/// Per-app transparent TCP proxy for Android → upstream HTTP CONNECT proxy.
///
/// Intercepts TCP connections from a specific Android UID or package name and
/// tunnels them through an upstream HTTP CONNECT proxy using iptables OUTPUT
/// REDIRECT rules and `SO_ORIGINAL_DST` recovery.
#[derive(Parser)]
#[command(name = "atproxy", version = env!("ATPROXY_VERSION"), about = "Per-app transparent TCP proxy")]
pub struct Cli {
    /// Target to redirect (can be: package name, comma-separated UIDs)
    #[arg(value_name = "TARGET")]
    pub target: Option<String>,

    /// Upstream HTTP proxy address (host:port).
    #[arg(value_name = "PROXY")]
    pub proxy: Option<String>,

    /// Listen port for redirected connections.
    #[arg(short, long, default_value = "5280")]
    pub port: u16,

    /// Verbose per-connection logging (sets log level to debug).
    #[arg(short, long)]
    pub verbose: bool,

    /// Also add ip6tables rules.
    #[arg(short = '6', long)]
    pub ipv6: bool,

    /// Remove stale iptables rules for resolved UIDs and exit.
    #[arg(long)]
    pub clean: bool,
}
