// SPDX-License-Identifier: MIT
#![allow(dead_code)]
use std::fs;
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

/// Global lock to serialize tests that manipulate PATH for mock iptables.
static MOCK_LOCK: Mutex<()> = Mutex::new(());

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

/// Like [`echo_server`] but binds to `0.0.0.0`, so it accepts connections
/// to any of the machine's IPs (including dummy IPs added to `lo`).
#[allow(dead_code)]
pub async fn echo_server_any(port: u16) -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind(("0.0.0.0", port)).await.unwrap();
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
                tokio::spawn(async move { if let Err(_e) = proxy_session(client).await {} });
            }
        }
    });
    (addr, handle)
}

/// Variant of [`connect_proxy`] that exposes the number of CONNECT sessions
/// it accepted. The shared counter is incremented the moment a CONNECT line
/// is parsed — so the caller can assert whether the proxy was contacted.
pub async fn connect_proxy_counted(
    port: u16,
) -> (SocketAddr, Arc<std::sync::atomic::AtomicU32>, JoinHandle<()>) {
    let listener = TcpListener::bind(("127.0.0.1", port)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let counter = Arc::new(std::sync::atomic::AtomicU32::new(0));
    let counter_for_task = counter.clone();
    let handle = tokio::spawn(async move {
        loop {
            if let Ok((client, _)) = listener.accept().await {
                let c = counter_for_task.clone();
                tokio::spawn(async move {
                    if let Err(_e) = proxy_session_counted(client, c).await {}
                });
            }
        }
    });
    (addr, counter, handle)
}

async fn proxy_session_counted(
    mut client: TcpStream,
    counter: Arc<std::sync::atomic::AtomicU32>,
) -> io::Result<()> {
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

    // Count once we've confirmed it's a real CONNECT request.
    counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

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

async fn proxy_session(mut client: TcpStream) -> io::Result<()> {
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

/// Chunked server: sends CHUNK1:CHUNK2:CHUNK3 with delays.
pub async fn chunked_server(port: u16) -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind(("127.0.0.1", port)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        loop {
            if let Ok((mut sock, _)) = listener.accept().await {
                tokio::spawn(async move {
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

pub fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
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

fn which(name: &str) -> bool {
    Command::new("which")
        .arg(name)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// RAII context that installs mock `iptables`/`ip6tables` scripts in PATH.
///
/// The mock logs all invocations and, when called with `-t nat -S OUTPUT`,
/// outputs fake rules containing `MOCK_UID` so that cleanup logic can parse
/// and delete them.
pub struct MockIptables {
    pub log_path: PathBuf,
    tmpdir: PathBuf,
    saved_path: Option<String>,
    _lock: std::sync::MutexGuard<'static, ()>,
}

impl MockIptables {
    /// Install mock iptables binaries. Holds MOCK_LOCK for the lifetime of
    /// the returned guard, serializing PATH manipulation across tests.
    pub fn install(uid: u32) -> Self {
        let lock = MOCK_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let pid = std::process::id();
        let tmpdir = std::env::temp_dir().join(format!("atproxy-mock-{pid}"));
        fs::create_dir_all(&tmpdir).unwrap();

        let log_path = tmpdir.join("iptables.log");
        let log_display = log_path.display();

        // Shell script that logs args and simulates rule listing
        let script = format!(
            "#!/bin/sh\n\
             echo \"$(basename \"$0\") $@\" >> '{log_display}'\n\
             if [ \"$1\" = \"-t\" ] && [ \"$2\" = \"nat\" ] && [ \"$3\" = \"-S\" ]; then\n\
               echo '-P OUTPUT ACCEPT'\n\
               echo '-A OUTPUT -p tcp -m owner --uid-owner {uid} -j REDIRECT --to-port 9999'\n\
               echo '-A OUTPUT -p tcp -m owner --uid-owner {uid} -d 127.0.0.0/8 -j RETURN'\n\
             fi\n\
             exit 0\n"
        );

        let ipt_path = tmpdir.join("iptables");
        let ip6t_path = tmpdir.join("ip6tables");
        fs::write(&ipt_path, &script).unwrap();
        fs::write(&ip6t_path, &script).unwrap();
        fs::set_permissions(&ipt_path, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&ip6t_path, fs::Permissions::from_mode(0o755)).unwrap();

        // Save and prepend to PATH
        let saved_path = std::env::var("PATH").ok();
        let new_path = format!(
            "{}:{}",
            tmpdir.display(),
            saved_path.as_deref().unwrap_or("")
        );
        // SAFETY: Test-only PATH manipulation, serialized via MOCK_LOCK.
        unsafe { std::env::set_var("PATH", &new_path) };

        // Clear any stale log
        let _ = fs::remove_file(&log_path);

        Self {
            log_path,
            tmpdir,
            saved_path,
            _lock: lock,
        }
    }

    /// Read all logged iptables invocations as `(command, args)` pairs.
    pub fn calls(&self) -> Vec<(String, String)> {
        let content = fs::read_to_string(&self.log_path).unwrap_or_default();
        content
            .lines()
            .filter_map(|line| {
                let (cmd, args) = line.split_once(' ')?;
                Some((cmd.to_string(), args.to_string()))
            })
            .collect()
    }

    /// Read raw log lines.
    pub fn raw_calls(&self) -> Vec<String> {
        fs::read_to_string(&self.log_path)
            .unwrap_or_default()
            .lines()
            .map(String::from)
            .collect()
    }
}

impl Drop for MockIptables {
    fn drop(&mut self) {
        // SAFETY: Test-only PATH restoration, serialized via MOCK_LOCK.
        unsafe {
            if let Some(ref p) = self.saved_path {
                std::env::set_var("PATH", p);
            } else {
                std::env::remove_var("PATH");
            }
        }
        let _ = fs::remove_dir_all(&self.tmpdir);
    }
}
