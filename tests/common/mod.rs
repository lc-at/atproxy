// SPDX-License-Identifier: MIT
use std::net::SocketAddr;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

/// Echo server: reads from client, writes the same bytes back.
pub async fn echo_server(port: u16) -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind(("127.0.0.1", port)).await.unwrap();
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
pub async fn connect_proxy(port: u16) -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind(("127.0.0.1", port)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        loop {
            if let Ok((client, _)) = listener.accept().await {
                tokio::spawn(async move {
                    if let Err(e) = proxy_session(client).await {
                        let _ = e; // connection errors are expected during shutdown
                    }
                });
            }
        }
    });
    (addr, handle)
}

async fn proxy_session(mut client: TcpStream) -> io::Result<()> {
    // Read until \r\n\r\n
    let mut buf = vec![0u8; 4096];
    let mut total = 0;
    loop {
        if total >= buf.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "request too large",
            ));
        }
        let n = client.read(&mut buf[total..]).await?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "eof"));
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
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad CONNECT"))?;

    let (host, port_s) = target
        .rsplit_once(':')
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad target"))?;
    let port: u16 = port_s
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad port"))?;

    let origin = TcpStream::connect((host, port)).await?;
    client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;

    // Bidirectional relay with half-close
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

/// Chunked server: sends CHUNK1:CHUNK2:CHUNK3 with 200ms delays.
pub async fn chunked_server(port: u16) -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind(("127.0.0.1", port)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        loop {
            if let Ok((mut sock, _)) = listener.accept().await {
                tokio::spawn(async move {
                    // Drain trigger message
                    let mut drain = [0u8; 256];
                    let _ = sock.read(&mut drain).await;

                    let _ = sock.write_all(b"CHUNK1:").await;
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    let _ = sock.write_all(b"CHUNK2:").await;
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    let _ = sock.write_all(b"CHUNK3").await;
                });
            }
        }
    });
    (addr, handle)
}

/// RAII guard for a spawned subprocess. Kills on drop.
pub struct Proc {
    child: Child,
}

impl Proc {
    pub fn spawn(bin: &str, args: &[&str]) -> Self {
        let child = Command::new(bin)
            .args(args)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| panic!("failed to spawn {bin}: {e}"));
        Self { child }
    }

    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    pub fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }

    pub fn send_signal(&self, sig: libc::c_int) {
        unsafe {
            libc::kill(self.child.id() as libc::pid_t, sig);
        }
    }

    pub fn wait(mut self) -> std::process::ExitStatus {
        self.child.wait().unwrap()
    }

    pub fn is_running(&self) -> bool {
        Command::new("kill")
            .args(["-0", &self.pid().to_string()])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
}

impl Drop for Proc {
    fn drop(&mut self) {
        self.kill();
    }
}

pub fn iptables_flush() {
    let _ = Command::new("iptables")
        .args(["-t", "nat", "-F", "OUTPUT"])
        .output();
}

pub fn uid_rules_count(uid: u32) -> u32 {
    let output = Command::new("iptables")
        .args(["-t", "nat", "-n", "-L", "OUTPUT", "--line-numbers"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout
        .lines()
        .filter(|l| l.contains(&uid.to_string()) && l.contains("--uid-owner"))
        .count() as u32
}

pub fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

pub fn ensure_test_user(uid: u32) {
    let name = "testapp";
    if Command::new("id").arg(name).output().is_err() {
        let _ = Command::new("groupadd")
            .args(["-g", &uid.to_string(), name])
            .output();
        let _ = Command::new("useradd")
            .args([
                "-u",
                &uid.to_string(),
                "-g",
                name,
                "-m",
                "-s",
                "/bin/bash",
                name,
            ])
            .output();
    }
}

pub fn run_as_uid(uid: u32, cmd: &str) -> std::process::Output {
    if which("gosu") {
        Command::new("gosu")
            .arg(uid.to_string())
            .args(["sh", "-c", cmd])
            .output()
            .unwrap()
    } else {
        Command::new("su")
            .args(["-s", "/bin/sh", "testapp"])
            .arg("-c")
            .arg(cmd)
            .output()
            .unwrap()
    }
}

pub fn add_dummy_ip(ip: &str) {
    let _ = Command::new("ip")
        .args(["addr", "add", &format!("{}/32", ip), "dev", "lo"])
        .output();
}

pub fn remove_dummy_ip(ip: &str) {
    let _ = Command::new("ip")
        .args(["addr", "del", &format!("{}/32", ip), "dev", "lo"])
        .output();
}

/// Poll until a TCP port is accepting connections.
pub async fn wait_for_port(port: u16) -> bool {
    for _ in 0..30 {
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            tokio::time::sleep(Duration::from_millis(50)).await;
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

fn which(name: &str) -> bool {
    Command::new("which")
        .arg(name)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}
