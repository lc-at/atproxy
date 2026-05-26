// SPDX-License-Identifier: MIT
//! atproxy — Per-app transparent TCP proxy for Android.
//!
//! Intercepts TCP connections from specific Android UIDs (or a package) and
//! tunnels them through an upstream HTTP CONNECT proxy using iptables OUTPUT
//! REDIRECT rules and `SO_ORIGINAL_DST` recovery.

mod cli;
mod iptables;
mod relay;
mod resolve;
mod stats;

use std::sync::Arc;

use clap::Parser;
use tokio::net::TcpListener;
use tokio::signal::unix::{SignalKind, signal};
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use cli::Cli;
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
    let (uids, proxy_str) = match resolve_args(&cli) {
        Some(v) => v,
        None => {
            <Cli as clap::CommandFactory>::command()
                .print_help()
                .unwrap();
            std::process::exit(1);
        }
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

    let (proxy_host, proxy_port) = match parse_host_port(&proxy_str) {
        Some(v) => v,
        None => {
            error!("bad proxy address: expected host:port");
            std::process::exit(1);
        }
    };

    let proxy_addr: std::net::SocketAddr =
        match tokio::net::lookup_host(format!("{proxy_host}:{proxy_port}")).await {
            Ok(mut addrs) => addrs.next().unwrap_or_else(|| {
                error!("no addresses resolved for proxy");
                std::process::exit(1);
            }),
            Err(e) => {
                error!(proxy_host, proxy_port, error = %e, "cannot resolve proxy address");
                std::process::exit(1);
            }
        };

    let proxy_ip_str = match proxy_addr {
        std::net::SocketAddr::V4(a) => a.ip().to_string(),
        std::net::SocketAddr::V6(a) => a.ip().to_string(),
    };
    let proxy_port_u16 = proxy_addr.port();

    if !nix::unistd::geteuid().is_root() {
        error!("root required. Run with su or sudo.");
        std::process::exit(1);
    }

    let stats = Arc::new(Stats::new());

    for &uid in &uids {
        let ip4 = Iptables { uid, ipv6: false };
        ip4.apply(cli.port, &proxy_ip_str, proxy_port_u16);
        if cli.ipv6 {
            let ip6 = Iptables { uid, ipv6: true };
            ip6.apply(cli.port, &proxy_ip_str, proxy_port_u16);
        }
    }

    let mut sigterm = signal(SignalKind::terminate()).expect("sigterm handler");
    let mut sigint = signal(SignalKind::interrupt()).expect("sigint handler");

    let listener = TcpListener::bind(format!("0.0.0.0:{}", cli.port))
        .await
        .expect("bind failed");

    info!(
        listen_port = cli.port,
        uids = ?uids,
        proxy_ip = proxy_ip_str.as_str(),
        proxy_port = proxy_port_u16,
        "listening for redirected connections"
    );

    let proxy_addr_v4 = match proxy_addr {
        std::net::SocketAddr::V4(a) => a,
        _ => {
            error!("only IPv4 proxy addresses supported for CONNECT");
            std::process::exit(1);
        }
    };

    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                match accept_result {
                    Ok((client, _peer)) => {
                        let stats = stats.clone();
                        let proxy = proxy_addr_v4;
                        tokio::spawn(relay::handle(client, proxy, stats));
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
