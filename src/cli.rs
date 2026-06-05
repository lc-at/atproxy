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

    /// Upstream HTTP proxy address (IPv4:port).
    ///
    /// Must be an IPv4 literal (e.g. `1.2.3.4:8080`). DNS hostnames are not
    /// resolved — on Android the system resolver is unreliable under musl,
    /// so atproxy requires the IP explicitly. If your proxy only has a
    /// hostname, add an entry to `/etc/hosts` on the device first.
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

    /// Destination IPv4 addresses or CIDR ranges to exclude from the upstream
    /// proxy. Connections whose `SO_ORIGINAL_DST` matches an entry bypass the
    /// proxy and are relayed directly to the destination.
    ///
    /// May be specified multiple times and/or as a comma-separated list.
    /// Examples: `--exclude 10.0.0.0/8`, `--exclude 1.1.1.1,8.8.8.8`.
    #[arg(long, value_name = "IP[/MASK]", value_delimiter = ',')]
    pub exclude: Vec<String>,
}
