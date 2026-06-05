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
    ///
    /// Host may be an IPv4 address or a DNS hostname. Hostnames are resolved
    /// at startup via the system resolver and the first A record is used.
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

    /// DNS server(s) to use for resolving the upstream proxy hostname.
    ///
    /// Only used as a fallback when the system resolver (`getaddrinfo`)
    /// fails or returns no IPv4 results — necessary on Android where musl's
    /// libc has no path to the system's NetD daemon and `/etc/resolv.conf`
    /// typically doesn't exist.
    ///
    /// May be specified multiple times and/or as a comma-separated list.
    /// Defaults: read from `/etc/resolv.conf` if present, else
    /// `1.1.1.1,8.8.8.8,1.0.0.1,8.8.4.4`.
    #[arg(long, value_name = "IP", value_delimiter = ',')]
    pub dns: Vec<String>,
}
