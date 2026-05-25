// SPDX-License-Identifier: MIT
use std::net::SocketAddrV4;
use std::os::unix::io::AsRawFd;
use std::sync::Arc;

use nix::sys::socket::{getsockopt, sockopt::OriginalDst};
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::stats::Stats;

pub fn get_original_dst(sock: &TcpStream) -> Option<SocketAddrV4> {
    use std::net::Ipv4Addr;
    let addr = getsockopt(sock, OriginalDst).ok()?;
    let ip = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
    let port = u16::from_be(addr.sin_port);
    Some(SocketAddrV4::new(ip, port))
}

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

async fn connect_handshake(
    proxy: &mut TcpStream,
    target: SocketAddrV4,
    verbose: bool,
) -> io::Result<Vec<u8>> {
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
                if verbose {
                    eprintln!(
                        "proxy rejected CONNECT: {}",
                        header.lines().next().unwrap_or("")
                    );
                }
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "proxy rejected CONNECT",
                ));
            }

            return Ok(buf[hdr_end..total].to_vec());
        }
    }
}

pub async fn handle(client: TcpStream, proxy_addr: SocketAddrV4, stats: Arc<Stats>, verbose: bool) {
    stats.conn_open();
    let ok = relay_inner(client, proxy_addr, &stats, verbose)
        .await
        .is_ok();
    stats.conn_close(ok);
}

async fn relay_inner(
    client: TcpStream,
    proxy_addr: SocketAddrV4,
    stats: &Stats,
    verbose: bool,
) -> io::Result<()> {
    let orig_dst = get_original_dst(&client)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "SO_ORIGINAL_DST failed"))?;

    if verbose {
        eprintln!("{}:{}", orig_dst.ip(), orig_dst.port());
    }

    client.set_nodelay(true)?;
    set_keepalive(&client);

    let mut proxy = TcpStream::connect(proxy_addr).await?;
    proxy.set_nodelay(true)?;
    set_keepalive(&proxy);

    let early_data = connect_handshake(&mut proxy, orig_dst, verbose).await?;

    if verbose {
        eprintln!("tunnel up: {}:{}", orig_dst.ip(), orig_dst.port());
    }

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
}
