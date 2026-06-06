// SPDX-License-Identifier: MIT
//! atproxy
//!
//! Intercepts TCP connections from specific Android UIDs (or a package) and
//! tunnels them through an upstream HTTP CONNECT proxy using iptables OUTPUT
//! REDIRECT rules and `SO_ORIGINAL_DST` recovery.
//!
//! Destinations matching `--exclude` entries bypass the upstream proxy and
//! are relayed directly.

mod cli;
mod exclude;
mod iptables;
mod relay;
mod resolve;
mod stats;

use std::sync::Arc;

use clap::Parser;
use tokio::net::TcpListener;
use tokio::signal::unix::{SignalKind, signal};
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use cli::Cli;
use exclude::ExcludeList;
use iptables::Iptables;
use relay::parse_host_port;
use stats::Stats;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    // Initialize structured logging with timestamps and module paths.
    // Use RUST_LOG env var to override; default is info (or debug with -v).
    let default_level = if std::env::args_os().any(|a| a == "-v" || a == "--verbose") {
        "atproxy=debug"
    } else {
        "atproxy=info"
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_level)),
        )
        .with_target(true)
        .compact()
        .init();

    let cli = Cli::try_parse().unwrap_or_else(|e| {
        // If no args were given at all, show help instead of an error.
        if std::env::args_os().len() <= 1 {
            let mut cmd = <Cli as clap::CommandFactory>::command();
            cmd.print_help().unwrap();
            std::process::exit(0);
        }
        // For genuine usage errors, show clap's formatted error.
        e.exit();
    });

    // Resolve UIDs and proxy from positional args.
    let Some((uids, proxy_str)) = resolve_args(&cli) else {
        <Cli as clap::CommandFactory>::command()
            .print_help()
            .unwrap();
        std::process::exit(1);
    };

    if cli.clean {
        for &uid in &uids {
            let ip4 = Iptables { uid, ipv6: false };
            let ip6 = Iptables { uid, ipv6: true };
            ip4.cleanup();
            if cli.ipv6 {
                ip6.cleanup();
            }
        }
        return;
    }

    let Some((proxy_host, proxy_port)) = parse_host_port(&proxy_str) else {
        error!("bad proxy address: expected IP:port (e.g. 1.2.3.4:8080 or [::1]:8080)");
        std::process::exit(1);
    };

    // Parse the exclude list early so a bad value fails fast.
    let excludes = match ExcludeList::from_strs(cli.exclude.iter().map(String::as_str)) {
        Ok(l) => Arc::new(l),
        Err(e) => {
            error!(error = %e, "invalid --exclude entry");
            std::process::exit(1);
        }
    };

    // Proxy address must be an IPv4 or IPv6 literal. DNS hostnames are not
    // accepted — on Android+musl the system resolver is unreliable (often
    // only consults /etc/hosts) and silently resolving to a stale/wrong IP
    // is worse than failing fast. Users who need a hostname should add it
    // to /etc/hosts or pass the IP directly.
    //
    // parse_host_port strips the brackets from `[::1]:8080` so we can parse
    // the host as a plain IpAddr.
    let proxy_ip: std::net::IpAddr = match proxy_host.trim_start_matches('[').trim_end_matches(']').parse() {
        Ok(ip) => ip,
        Err(_) => {
            error!(
                proxy_host,
                "proxy must be an IPv4 or IPv6 literal, not a hostname (got {:?}); \
                 DNS resolution is intentionally disabled — pass the IP directly",
                proxy_host,
            );
            std::process::exit(1);
        }
    };
    let proxy_addr = std::net::SocketAddr::new(proxy_ip, proxy_port);

    let proxy_ip_str = proxy_addr.ip().to_string();
    let proxy_port_u16 = proxy_addr.port();

    if !nix::unistd::geteuid().is_root() {
        error!("root required. Run with su or sudo.");
        std::process::exit(1);
    }

    let stats = Arc::new(Stats::new());

    for &uid in &uids {
        let ip4 = Iptables { uid, ipv6: false };
        if !ip4.apply(cli.port, &proxy_ip_str, proxy_port_u16) {
            error!(uid, "failed to apply iptables rules for UID");
            std::process::exit(1);
        }
        if cli.ipv6 {
            let ip6 = Iptables { uid, ipv6: true };
            if !ip6.apply(cli.port, &proxy_ip_str, proxy_port_u16) {
                warn!(
                    uid,
                    "IPv6 rules not applied, \
                     kernel may lack CONFIG_IP6_NF_NAT. \
                     Only IPv4 traffic will be proxied for this UID."
                );
            }
        }
    }

    let mut sigterm = signal(SignalKind::terminate()).expect("sigterm handler");
    let mut sigint = signal(SignalKind::interrupt()).expect("sigint handler");

    // Bind a dual-stack IPv6 socket. On Linux this accepts both v4 and v6
    // connections by default (IPV6_V6ONLY=0), which is exactly what we need:
    // iptables-redirected v4 traffic and ip6tables-redirected v6 traffic
    // both arrive on the same port.
    //
    // If the kernel refuses dual-stack (uncommon), fall back to IPv4-only —
    // IPv6 traffic will then simply not be proxied.
    let listener = match TcpListener::bind(format!("[::]:{}", cli.port)).await {
        Ok(l) => l,
        Err(e) => {
            warn!(
                error = %e,
                port = cli.port,
                "failed to bind IPv6 dual-stack listener; falling back to IPv4-only"
            );
            TcpListener::bind(format!("0.0.0.0:{}", cli.port))
                .await
                .expect("bind failed")
        }
    };

    info!(
        listen_port = cli.port,
        uids = ?uids,
        proxy_host = proxy_host.as_str(),
        proxy_ip = proxy_ip_str.as_str(),
        proxy_port = proxy_port_u16,
        excluded = excludes.len(),
        "listening for redirected connections"
    );

    let proxy_addr_v4 = proxy_addr;

    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                match accept_result {
                    Ok((client, _peer)) => {
                        let stats = stats.clone();
                        let excludes = excludes.clone();
                        let proxy = proxy_addr_v4;
                        tokio::spawn(relay::handle(client, proxy, stats, excludes));
                    }
                    Err(e) => {
                        error!(error = %e, "accept error");
                    }
                }
            }
            _ = sigterm.recv() => break,
            _ = sigint.recv() => break,
        }
    }

    info!("shutting down");
    info!(
        total = stats.total(),
        active = stats.active(),
        failed = stats.failed(),
        bytes_up_kb = stats.bytes_up_kb(),
        bytes_down_kb = stats.bytes_down_kb(),
        "final stats"
    );

    info!("cleaning iptables rules");
    for &uid in &uids {
        let ip4 = Iptables { uid, ipv6: false };
        let ip6 = Iptables { uid, ipv6: true };
        ip4.cleanup();
        if cli.ipv6 {
            ip6.cleanup();
        }
    }
}

/// Resolve UIDs and proxy address from CLI arguments.
///
/// The TARGET positional auto-detects its type:
/// - Package name (contains `.`) → resolved via `pm list packages -U`
/// - Single UID (e.g. `10188`)
/// - Comma-separated UIDs (e.g. `10188,10200`)
///
/// Returns `None` if required arguments are missing or resolution fails.
fn resolve_args(cli: &Cli) -> Option<(Vec<u32>, String)> {
    let target = cli.target.as_ref()?;
    let proxy = cli.proxy.as_ref()?;
    let uids = resolve::resolve_target(target)?;
    Some((uids, proxy.clone()))
}
