// SPDX-License-Identifier: MIT
use clap::Parser;

/// Per-app transparent TCP proxy for Android → upstream HTTP CONNECT proxy.
///
/// Intercepts TCP connections from a specific Android UID (or package) and
/// tunnels them through an upstream HTTP CONNECT proxy using iptables OUTPUT
/// REDIRECT rules and SO_ORIGINAL_DST recovery.
#[derive(Parser)]
#[command(name = "atproxy", version = env!("ATPROXY_VERSION"), about = "Per-app transparent TCP proxy")]
pub struct Cli {
    /// Target UID to intercept (hint: use `pm list packages -U`).
    ///
    /// Mutually exclusive with `--filter`.
    #[arg(conflicts_with = "filter")]
    pub uid: Option<u32>,

    /// Upstream HTTP proxy address (host:port).
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

    /// Remove stale iptables rules for UID and exit.
    #[arg(long)]
    pub clean: bool,

    /// Android package name to intercept (e.g. `com.example.app`).
    ///
    /// Resolves to a UID at startup via `pm list packages -U`.
    /// Mutually exclusive with the positional UID argument.
    #[arg(short, long, conflicts_with = "uid")]
    pub filter: Option<String>,
}
