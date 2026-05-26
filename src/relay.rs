// SPDX-License-Identifier: MIT
//! TCP relay logic: transparent proxy via HTTP CONNECT handshake.
//!
//! Recovers the original destination via `SO_ORIGINAL_DST`, establishes an
//! HTTP CONNECT tunnel through the upstream proxy, then performs bidirectional
//! relay between client and proxy.

use std::net::SocketAddrV4;
use std::os::unix::io::AsRawFd;
use std::sync::Arc;

use nix::sys::socket::{getsockopt, sockopt::OriginalDst};
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

use crate::stats::Stats;

/// Recover the original destination address from a redirected socket.
pub fn get_original_dst(sock: &TcpStream) -> Option<SocketAddrV4> {
    use std::net::Ipv4Addr;
    let addr = getsockopt(sock, OriginalDst).ok()?;
    let ip = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
    let port = u16::from_be(addr.sin_port);
    Some(SocketAddrV4::new(ip, port))
}

/// Set TCP keepalive parameters on a socket.
pub fn set_keepalive(sock: &TcpStream) {
    let fd = sock.as_raw_fd();
    unsafe {
        let v: libc::c_int = 1;
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_KEEPALIVE,
            &v as *const _ as *const _,
            std::mem::size_of::<libc::c_int>() as _,
        );
        let idle: libc::c_int = 30;
        let intvl: libc::c_int = 10;
        let cnt: libc::c_int = 3;
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_KEEPIDLE,
            &idle as *const _ as *const _,
            std::mem::size_of::<libc::c_int>() as _,
        );
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_KEEPINTVL,
            &intvl as *const _ as *const _,
            std::mem::size_of::<libc::c_int>() as _,
        );
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_KEEPCNT,
            &cnt as *const _ as *const _,
            std::mem::size_of::<libc::c_int>() as _,
        );
    }
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    for i in 0..buf.len().saturating_sub(3) {
        if buf[i..].starts_with(b"\r\n\r\n") {
            return Some(i + 4);
        }
    }
    None
}

/// Perform the HTTP CONNECT handshake with the upstream proxy.
async fn connect_handshake(proxy: &mut TcpStream, target: SocketAddrV4) -> io::Result<Vec<u8>> {
    let req = format!(
        "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n\r\n",
        target.ip(),
        target.port(),
        target.ip(),
        target.port(),
    );
    proxy.write_all(req.as_bytes()).await?;

    let mut buf = vec![0u8; 4096];
    let mut total = 0;

    loop {
        if total >= buf.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "CONNECT response too large",
            ));
        }
        let n = proxy.read(&mut buf[total..]).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "proxy EOF during CONNECT",
            ));
        }
        total += n;

        if let Some(hdr_end) = find_header_end(&buf[..total]) {
            let header = std::str::from_utf8(&buf[..hdr_end])
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "non-UTF8 response"))?;

            if !header.contains(" 200 ") {
                warn!(
                    target_ip = %target.ip(),
                    target_port = target.port(),
                    response = header.lines().next().unwrap_or(""),
                    "proxy rejected CONNECT"
                );
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "proxy rejected CONNECT",
                ));
            }

            return Ok(buf[hdr_end..total].to_vec());
        }
    }
}

/// Handle a single client connection: recover original destination, establish
/// CONNECT tunnel, and relay data bidirectionally.
pub async fn handle(client: TcpStream, proxy_addr: SocketAddrV4, stats: Arc<Stats>) {
    stats.conn_open();
    let ok = relay_inner(client, proxy_addr, &stats).await.is_ok();
    stats.conn_close(ok);
}

async fn relay_inner(client: TcpStream, proxy_addr: SocketAddrV4, stats: &Stats) -> io::Result<()> {
    let orig_dst = get_original_dst(&client)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "SO_ORIGINAL_DST failed"))?;

    debug!(
        ip = %orig_dst.ip(),
        port = orig_dst.port(),
        "original destination recovered"
    );

    relay_to_dst(client, proxy_addr, stats, orig_dst).await
}

/// Relay a client connection through the upstream proxy to the given destination.
///
/// Performs the CONNECT handshake with the upstream proxy and then relays
/// data bidirectionally. Separated from [`relay_inner`] so the relay logic
/// can be tested without `SO_ORIGINAL_DST`.
pub(crate) async fn relay_to_dst(
    client: TcpStream,
    proxy_addr: SocketAddrV4,
    stats: &Stats,
    orig_dst: SocketAddrV4,
) -> io::Result<()> {
    client.set_nodelay(true)?;
    set_keepalive(&client);

    let mut proxy = TcpStream::connect(proxy_addr).await?;
    proxy.set_nodelay(true)?;
    set_keepalive(&proxy);

    let early_data = connect_handshake(&mut proxy, orig_dst).await?;

    info!(
        ip = %orig_dst.ip(),
        port = orig_dst.port(),
        "tunnel established"
    );

    let (mut cr, mut cw) = io::split(client);
    let (mut pr, mut pw) = io::split(proxy);

    if !early_data.is_empty() {
        cw.write_all(&early_data).await?;
    }

    let up = async {
        let result = io::copy(&mut cr, &mut pw).await;
        let _ = pw.shutdown().await;
        result
    };

    let down = async {
        let result = io::copy(&mut pr, &mut cw).await;
        let _ = cw.shutdown().await;
        result
    };

    let (up_result, down_result) = tokio::join!(up, down);

    if let Ok(n) = &up_result {
        stats.add_up(*n);
    }
    if let Ok(n) = &down_result {
        stats.add_down(*n);
    }

    Ok(())
}

/// Parse a `host:port` string into its components.
pub fn parse_host_port(s: &str) -> Option<(String, u16)> {
    let colon = s.rfind(':')?;
    let host = s[..colon].to_string();
    let port: u16 = s[colon + 1..].parse().ok()?;
    if host.is_empty() || port == 0 {
        return None;
    }
    Some((host, port))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use tokio::net::TcpListener;
    use tokio::task::JoinHandle;

    // ── Test helpers ──────────────────────────────────────────────

    /// Echo server: reads from client, writes the same bytes back.
    async fn start_echo_server() -> (SocketAddr, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            loop {
                if let Ok((sock, _)) = listener.accept().await {
                    tokio::spawn(async move {
                        let (mut r, mut w) = io::split(sock);
                        let _ = io::copy(&mut r, &mut w).await;
                    });
                }
            }
        });
        (addr, handle)
    }

    /// CONNECT proxy: parses CONNECT requests, connects to origin, relays.
    async fn start_connect_proxy() -> (SocketAddr, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            loop {
                if let Ok((client, _)) = listener.accept().await {
                    tokio::spawn(async move {
                        let _ = test_proxy_session(client).await;
                    });
                }
            }
        });
        (addr, handle)
    }

    /// A server that rejects CONNECT with 403.
    async fn start_reject_proxy() -> (SocketAddr, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            loop {
                if let Ok((mut client, _)) = listener.accept().await {
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 4096];
                        let _ = client.read(&mut buf).await;
                        let _ = client
                            .write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n")
                            .await;
                    });
                }
            }
        });
        (addr, handle)
    }

    /// Chunked server: reads trigger, sends CHUNK1:CHUNK2:CHUNK3 with delays.
    async fn start_chunked_server() -> (SocketAddr, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            loop {
                if let Ok((mut sock, _)) = listener.accept().await {
                    tokio::spawn(async move {
                        let mut drain = [0u8; 256];
                        let _ = sock.read(&mut drain).await;
                        let _ = sock.write_all(b"CHUNK1:").await;
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                        let _ = sock.write_all(b"CHUNK2:").await;
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                        let _ = sock.write_all(b"CHUNK3").await;
                    });
                }
            }
        });
        (addr, handle)
    }

    async fn test_proxy_session(mut client: TcpStream) -> std::io::Result<()> {
        let mut buf = vec![0u8; 4096];
        let mut total = 0;
        loop {
            if total >= buf.len() {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "too large"));
            }
            let n = client.read(&mut buf[total..]).await?;
            if n == 0 {
                return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "eof"));
            }
            total += n;
            if total >= 4 && &buf[total - 4..total] == b"\r\n\r\n" {
                break;
            }
        }

        let req = String::from_utf8_lossy(&buf[..total]);
        let target = req
            .lines()
            .next()
            .and_then(|l| l.strip_prefix("CONNECT "))
            .and_then(|l| l.split_once(' '))
            .map(|(t, _)| t)
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "bad CONNECT"))?;

        let (host, port_s) = target
            .rsplit_once(':')
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "bad target"))?;
        let port: u16 = port_s
            .parse()
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "bad port"))?;

        let origin = TcpStream::connect((host, port)).await?;
        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;

        let (mut cr, mut cw) = io::split(client);
        let (mut or_, mut ow) = io::split(origin);
        let up = async {
            let r = io::copy(&mut cr, &mut ow).await;
            let _ = ow.shutdown().await;
            r
        };
        let down = async {
            let r = io::copy(&mut or_, &mut cw).await;
            let _ = cw.shutdown().await;
            r
        };
        let _ = tokio::join!(up, down);
        Ok(())
    }

    /// Create a connected TCP pair: returns (client_end, test_end).
    async fn tcp_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client_end = TcpStream::connect(addr).await.unwrap();
        let (test_end, _) = listener.accept().await.unwrap();
        (client_end, test_end)
    }

    fn addr_v4(addr: SocketAddr) -> SocketAddrV4 {
        match addr {
            SocketAddr::V4(a) => a,
            _ => panic!("expected IPv4"),
        }
    }

    // ── Unit tests ────────────────────────────────────────────────

    #[test]
    fn test_parse_host_port() {
        assert_eq!(
            parse_host_port("192.168.1.1:8080"),
            Some(("192.168.1.1".into(), 8080))
        );
        assert_eq!(parse_host_port("bad"), None);
        assert_eq!(parse_host_port(":8080"), None);
    }

    #[test]
    fn test_find_header_end() {
        let hdr = b"HTTP/1.1 200 OK\r\n\r\n";
        assert_eq!(find_header_end(hdr), Some(hdr.len()));
        let with_body = b"HTTP/1.1 200 OK\r\n\r\ndata";
        assert_eq!(find_header_end(with_body), Some(19));
        assert_eq!(find_header_end(b"partial"), None);
    }

    // ── CONNECT handshake tests ───────────────────────────────────

    #[tokio::test]
    async fn test_connect_handshake_success() {
        let (echo_addr, echo_h) = start_echo_server().await;
        let (proxy_addr, proxy_h) = start_connect_proxy().await;

        let mut proxy_conn = TcpStream::connect(proxy_addr).await.unwrap();
        let target = SocketAddrV4::new(Ipv4Addr::LOCALHOST, echo_addr.port());
        let early = connect_handshake(&mut proxy_conn, target).await.unwrap();
        assert!(early.is_empty(), "no early data expected");

        proxy_conn.write_all(b"HANDSHAKE_OK").await.unwrap();
        let mut buf = vec![0u8; 64];
        let n = proxy_conn.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"HANDSHAKE_OK");

        drop(proxy_conn);
        echo_h.abort();
        proxy_h.abort();
    }

    #[tokio::test]
    async fn test_connect_handshake_rejected() {
        let (echo_addr, echo_h) = start_echo_server().await;
        let (proxy_addr, proxy_h) = start_reject_proxy().await;

        let mut proxy_conn = TcpStream::connect(proxy_addr).await.unwrap();
        let target = SocketAddrV4::new(Ipv4Addr::LOCALHOST, echo_addr.port());
        let result = connect_handshake(&mut proxy_conn, target).await;
        assert!(result.is_err(), "expected handshake to fail on 403");

        echo_h.abort();
        proxy_h.abort();
    }

    // ── Full relay pipeline tests (relay_to_dst) ──────────────────

    #[tokio::test]
    async fn test_relay_echo() {
        let stats = Arc::new(Stats::new());
        let (echo_addr, echo_h) = start_echo_server().await;
        let (proxy_addr, proxy_h) = start_connect_proxy().await;

        let (client, mut tester) = tcp_pair().await;
        let proxy_v4 = addr_v4(proxy_addr);
        let dst_v4 = SocketAddrV4::new(Ipv4Addr::LOCALHOST, echo_addr.port());

        let relay_h = tokio::spawn({
            let stats = stats.clone();
            async move { relay_to_dst(client, proxy_v4, &stats, dst_v4).await }
        });

        tester.write_all(b"RELAY_ECHO_TEST").await.unwrap();
        tester.shutdown().await.unwrap();

        let mut response = Vec::new();
        tester.read_to_end(&mut response).await.unwrap();
        assert!(response.starts_with(b"RELAY_ECHO_TEST"), "echo mismatch");

        relay_h.await.unwrap().unwrap();

        echo_h.abort();
        proxy_h.abort();
    }

    #[tokio::test]
    async fn test_relay_large_payload() {
        let stats = Arc::new(Stats::new());
        let (echo_addr, echo_h) = start_echo_server().await;
        let (proxy_addr, proxy_h) = start_connect_proxy().await;

        let (client, mut tester) = tcp_pair().await;
        let proxy_v4 = addr_v4(proxy_addr);
        let dst_v4 = SocketAddrV4::new(Ipv4Addr::LOCALHOST, echo_addr.port());

        let payload = vec![0xAB_u8; 512 * 1024];
        let expected = payload.clone();

        let relay_h = tokio::spawn({
            let stats = stats.clone();
            async move { relay_to_dst(client, proxy_v4, &stats, dst_v4).await }
        });

        tester.write_all(&payload).await.unwrap();
        tester.shutdown().await.unwrap();

        let mut response = Vec::new();
        tester.read_to_end(&mut response).await.unwrap();
        assert_eq!(response.len(), expected.len(), "size mismatch");
        assert_eq!(response, expected, "content mismatch");

        relay_h.await.unwrap().unwrap();
        echo_h.abort();
        proxy_h.abort();
    }

    #[tokio::test]
    async fn test_relay_concurrent() {
        let stats = Arc::new(Stats::new());
        let (echo_addr, echo_h) = start_echo_server().await;
        let (proxy_addr, proxy_h) = start_connect_proxy().await;

        let proxy_v4 = addr_v4(proxy_addr);
        let dst_v4 = SocketAddrV4::new(Ipv4Addr::LOCALHOST, echo_addr.port());

        let mut handles = Vec::new();
        for i in 0..5 {
            let (client, mut tester) = tcp_pair().await;
            let msg = format!("CONN{i}_HELLO");

            let h = tokio::spawn({
                let stats = stats.clone();
                async move { relay_to_dst(client, proxy_v4, &stats, dst_v4).await }
            });

            tester.write_all(msg.as_bytes()).await.unwrap();
            tester.shutdown().await.unwrap();
            let mut response = Vec::new();
            tester.read_to_end(&mut response).await.unwrap();
            assert!(response.starts_with(msg.as_bytes()), "conn {i} echo mismatch");

            handles.push(h);
        }

        for h in handles {
            h.await.unwrap().unwrap();
        }

        echo_h.abort();
        proxy_h.abort();
    }

    #[tokio::test]
    async fn test_relay_chunked() {
        let stats = Arc::new(Stats::new());
        let (chunked_addr, chunked_h) = start_chunked_server().await;
        let (proxy_addr, proxy_h) = start_connect_proxy().await;

        let (client, mut tester) = tcp_pair().await;
        let proxy_v4 = addr_v4(proxy_addr);
        let dst_v4 = SocketAddrV4::new(Ipv4Addr::LOCALHOST, chunked_addr.port());

        let relay_h = tokio::spawn({
            let stats = stats.clone();
            async move { relay_to_dst(client, proxy_v4, &stats, dst_v4).await }
        });

        tester.write_all(b"TRIGGER\n").await.unwrap();

        let mut response = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            tester.read_to_end(&mut response),
        )
        .await
        .unwrap()
        .unwrap();

        let text = String::from_utf8_lossy(&response);
        assert!(text.contains("CHUNK1:CHUNK2:CHUNK3"), "got: {text}");

        drop(tester);
        let _ = relay_h.await;

        chunked_h.abort();
        proxy_h.abort();
    }

    #[tokio::test]
    async fn test_relay_connection_teardown() {
        let stats = Arc::new(Stats::new());
        let (echo_addr, echo_h) = start_echo_server().await;
        let (proxy_addr, proxy_h) = start_connect_proxy().await;

        let (client, mut tester) = tcp_pair().await;
        let proxy_v4 = addr_v4(proxy_addr);
        let dst_v4 = SocketAddrV4::new(Ipv4Addr::LOCALHOST, echo_addr.port());

        let relay_h = tokio::spawn({
            let stats = stats.clone();
            async move { relay_to_dst(client, proxy_v4, &stats, dst_v4).await }
        });

        tester.write_all(b"TEARDOWN").await.unwrap();
        let mut buf = [0u8; 64];
        let n = tester.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"TEARDOWN");

        tester.shutdown().await.unwrap();
        let mut rest = Vec::new();
        tester.read_to_end(&mut rest).await.unwrap();

        let result = relay_h.await;
        assert!(result.is_ok(), "relay panicked on teardown");
        assert!(result.unwrap().is_ok(), "relay returned error on teardown");

        echo_h.abort();
        proxy_h.abort();
    }
}
