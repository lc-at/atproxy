// SPDX-License-Identifier: MIT
mod cli;
mod iptables;
mod relay;
mod stats;

use std::sync::Arc;

use clap::Parser;
use tokio::net::TcpListener;
use tokio::signal::unix::{SignalKind, signal};

use cli::Cli;
use iptables::Iptables;
use relay::parse_host_port;
use stats::Stats;

#[tokio::main(flavor = "current_thread")]
async fn main() {
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

    if cli.clean {
        let uid = match cli.uid {
            Some(u) => u,
            None => {
                eprintln!("Error: --clean requires a UID argument");
                std::process::exit(1);
            }
        };

        let ip4 = Iptables {
            uid,
            ipv6: false,
            verbose: cli.verbose,
        };

        let ip6 = Iptables {
            uid,
            ipv6: true,
            verbose: cli.verbose,
        };

        ip4.cleanup();
        if cli.ipv6 {
            ip6.cleanup();
        }

        return;
    }

    let uid = match cli.uid {
        Some(u) => u,
        None => {
            <Cli as clap::CommandFactory>::command()
                .print_help()
                .unwrap();
            std::process::exit(1);
        }
    };

    let proxy_str = match cli.proxy {
        Some(ref s) => s,
        None => {
            <Cli as clap::CommandFactory>::command()
                .print_help()
                .unwrap();
            std::process::exit(1);
        }
    };

    let (proxy_host, proxy_port) = match parse_host_port(proxy_str) {
        Some(v) => v,
        None => {
            eprintln!("Error: bad proxy address: expected host:port");
            std::process::exit(1);
        }
    };

    let proxy_addr: std::net::SocketAddr =
        match tokio::net::lookup_host(format!("{proxy_host}:{proxy_port}")).await {
            Ok(mut addrs) => addrs.next().unwrap_or_else(|| {
                eprintln!("Error: no addresses for proxy");
                std::process::exit(1);
            }),
            Err(e) => {
                eprintln!("Error: cannot resolve proxy address: {e}");
                std::process::exit(1);
            }
        };

    let proxy_ip_str = match proxy_addr {
        std::net::SocketAddr::V4(a) => a.ip().to_string(),
        std::net::SocketAddr::V6(a) => a.ip().to_string(),
    };
    let proxy_port_u16 = proxy_addr.port();

    if !nix::unistd::geteuid().is_root() {
        eprintln!("Error: root required. Run with su or sudo.");
        std::process::exit(1);
    }

    let stats = Arc::new(Stats::new());

    let ip4 = Iptables {
        uid,
        ipv6: false,
        verbose: cli.verbose,
    };
    let ip6 = Iptables {
        uid,
        ipv6: true,
        verbose: cli.verbose,
    };
    ip4.apply(cli.port, &proxy_ip_str, proxy_port_u16);
    if cli.ipv6 {
        ip6.apply(cli.port, &proxy_ip_str, proxy_port_u16);
    }

    let mut sigterm = signal(SignalKind::terminate()).expect("sigterm handler");
    let mut sigint = signal(SignalKind::interrupt()).expect("sigint handler");

    let listener = TcpListener::bind(format!("0.0.0.0:{}", cli.port))
        .await
        .expect("bind failed");

    eprintln!(
        "Listening :{} → {}:{}",
        cli.port, proxy_ip_str, proxy_port_u16
    );

    let proxy_addr_v4 = match proxy_addr {
        std::net::SocketAddr::V4(a) => a,
        _ => {
            eprintln!("Error: only IPv4 proxy addresses supported for CONNECT");
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
                        let verbose = cli.verbose;
                        tokio::spawn(relay::handle(client, proxy, stats, verbose));
                    }
                    Err(e) => {
                        eprintln!("accept error: {e}");
                    }
                }
            }
            _ = sigterm.recv() => break,
            _ = sigint.recv() => break,
        }
    }

    eprintln!("\nShutting down…");
    eprintln!("Stats: {stats}");

    eprintln!("Cleaning iptables…");
    let ip4 = Iptables {
        uid,
        ipv6: false,
        verbose: cli.verbose,
    };
    let ip6 = Iptables {
        uid,
        ipv6: true,
        verbose: cli.verbose,
    };
    ip4.cleanup();
    if cli.ipv6 {
        ip6.cleanup();
    }
}
