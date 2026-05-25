// SPDX-License-Identifier: MIT
mod common;

use std::fs;
use std::process::{Command, Stdio};
use std::time::Duration;

use common::*;

const UID_TEST: u32 = 10000;
const TPROXY_PORT: u16 = 15280;
const PROXY_PORT: u16 = 18080;
const ORIGIN_PORT: u16 = 19999;
const ORIGIN_PORT2: u16 = 19998;
const ORIGIN_PORT3: u16 = 19997;
const DUMMY_IP: &str = "10.0.0.1";

fn bin() -> String {
    env!("CARGO_BIN_EXE_atproxy").to_string()
}

fn setup() {
    assert!(is_root(), "tests require root (iptables + SO_ORIGINAL_DST)");
    ensure_test_user(UID_TEST);
    add_dummy_ip(DUMMY_IP);
    iptables_flush();
}

fn cleanup() {
    iptables_flush();
    remove_dummy_ip(DUMMY_IP);
}

fn run_client(uid: u32, cmd: &str) -> String {
    let output = run_as_uid(uid, cmd);
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[tokio::test]
async fn test_iptables_apply_remove() {
    setup();

    let _ap = Proc::spawn(
        &bin(),
        &[
            &UID_TEST.to_string(),
            &format!("127.0.0.1:{PROXY_PORT}"),
            "-p",
            &TPROXY_PORT.to_string(),
        ],
    );
    assert!(wait_for_port(TPROXY_PORT).await, "atproxy did not start");

    assert!(
        uid_rules_count(UID_TEST) >= 1,
        "rules should exist after start"
    );
    let nat_output = Command::new("iptables")
        .args(["-t", "nat", "-n", "-L", "OUTPUT"])
        .output()
        .unwrap();
    let nat = String::from_utf8_lossy(&nat_output.stdout);
    assert!(nat.contains("REDIRECT"), "REDIRECT rule should exist");
    assert!(nat.contains("RETURN"), "RETURN rule should exist");

    drop(_ap);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        uid_rules_count(UID_TEST),
        0,
        "rules should be removed after exit"
    );

    cleanup();
}

#[tokio::test]
async fn test_clean_removes_stale_rules() {
    setup();

    Command::new("iptables")
        .args([
            "-t",
            "nat",
            "-A",
            "OUTPUT",
            "-p",
            "tcp",
            "-m",
            "owner",
            "--uid-owner",
            &UID_TEST.to_string(),
            "-j",
            "REDIRECT",
            "--to-port",
            "9999",
        ])
        .output()
        .unwrap();
    assert!(
        uid_rules_count(UID_TEST) >= 1,
        "stale rule should be present"
    );

    let clean = Proc::spawn(&bin(), &["--clean", &UID_TEST.to_string()]);
    let status = clean.wait();
    assert!(status.success(), "--clean should succeed");

    assert_eq!(uid_rules_count(UID_TEST), 0, "stale rule should be removed");
    cleanup();
}

#[tokio::test]
async fn test_loopback_not_redirected() {
    setup();

    let (_, echo_h) = echo_server(ORIGIN_PORT).await;
    let _ap = Proc::spawn(
        &bin(),
        &[
            &UID_TEST.to_string(),
            &format!("127.0.0.1:{PROXY_PORT}"),
            "-p",
            &TPROXY_PORT.to_string(),
        ],
    );
    assert!(wait_for_port(TPROXY_PORT).await);

    let result = run_client(
        UID_TEST,
        &format!("echo LOOPBACK_TEST | nc -w2 127.0.0.1 {ORIGIN_PORT}"),
    );
    assert!(
        result.contains("LOOPBACK_TEST"),
        "loopback should go direct, got: {result}"
    );

    drop(_ap);
    echo_h.abort();
    tokio::time::sleep(Duration::from_millis(200)).await;
    cleanup();
}

#[tokio::test]
async fn test_e2e_traffic_relay() {
    setup();

    let (_, echo_h) = echo_server(ORIGIN_PORT2).await;
    let (_, proxy_h) = connect_proxy(PROXY_PORT).await;

    let _ap = Proc::spawn(
        &bin(),
        &[
            &UID_TEST.to_string(),
            &format!("127.0.0.1:{PROXY_PORT}"),
            "-p",
            &TPROXY_PORT.to_string(),
            "-v",
        ],
    );
    assert!(wait_for_port(TPROXY_PORT).await);
    assert!(
        uid_rules_count(UID_TEST) >= 1,
        "iptables rules should be active"
    );

    let result = run_client(
        UID_TEST,
        &format!("echo RELAY_TEST | nc -w3 {DUMMY_IP} {ORIGIN_PORT2}"),
    );
    assert!(
        result.contains("RELAY_TEST"),
        "echo through proxy chain, got: {result}"
    );

    drop(_ap);
    echo_h.abort();
    proxy_h.abort();
    tokio::time::sleep(Duration::from_millis(200)).await;
    cleanup();
}

#[tokio::test]
async fn test_proxy_exclusion() {
    setup();

    let (_, echo80_h) = echo_server(80).await;
    let (_, proxy_h) = connect_proxy(PROXY_PORT).await;

    let _ap = Proc::spawn(
        &bin(),
        &[
            &UID_TEST.to_string(),
            &format!("127.0.0.1:{PROXY_PORT}"),
            "-p",
            &TPROXY_PORT.to_string(),
        ],
    );
    assert!(wait_for_port(TPROXY_PORT).await);
    assert!(uid_rules_count(UID_TEST) >= 1, "rules active");

    let result = run_client(
        UID_TEST,
        &format!(
            "printf 'CONNECT 127.0.0.1:80 HTTP/1.1\\r\\n\\r\\n' | nc -w3 127.0.0.1 {PROXY_PORT}"
        ),
    );
    assert!(
        result.contains("200 Connection Established"),
        "direct proxy connection should work via RETURN rule, got: {result}"
    );

    drop(_ap);
    echo80_h.abort();
    proxy_h.abort();
    tokio::time::sleep(Duration::from_millis(200)).await;
    cleanup();
}

#[tokio::test]
async fn test_large_payload_relay() {
    setup();

    let (_, echo_h) = echo_server(ORIGIN_PORT).await;
    let (_, proxy_h) = connect_proxy(PROXY_PORT).await;

    let _ap = Proc::spawn(
        &bin(),
        &[
            &UID_TEST.to_string(),
            &format!("127.0.0.1:{PROXY_PORT}"),
            "-p",
            &TPROXY_PORT.to_string(),
            "-v",
        ],
    );
    assert!(wait_for_port(TPROXY_PORT).await);

    let tmpdir = format!("/tmp/atproxy-test-{}", std::process::id());
    fs::create_dir_all(&tmpdir).unwrap();
    let payload_path = format!("{tmpdir}/payload.bin");
    let received_path = format!("{tmpdir}/received.bin");

    // Generate 1MB random payload
    Command::new("sh")
        .args([
            "-c",
            &format!("dd if=/dev/urandom of={payload_path} bs=1024 count=1024 2>/dev/null"),
        ])
        .output()
        .unwrap();

    fs::set_permissions(
        &payload_path,
        std::os::unix::fs::PermissionsExt::from_mode(0o644),
    )
    .unwrap();
    fs::set_permissions(&tmpdir, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();

    let expected_md5 = Command::new("sh")
        .args(["-c", &format!("md5sum {payload_path} | awk '{{print $1}}'")])
        .output()
        .unwrap();
    let expected = String::from_utf8_lossy(&expected_md5.stdout)
        .trim()
        .to_string();

    run_as_uid(
        UID_TEST,
        &format!("cat '{payload_path}' | nc -w30 {DUMMY_IP} {ORIGIN_PORT} > '{received_path}'"),
    );

    let actual_md5 = Command::new("sh")
        .args([
            "-c",
            &format!("md5sum {received_path} 2>/dev/null | awk '{{print $1}}'"),
        ])
        .output()
        .unwrap();
    let actual = String::from_utf8_lossy(&actual_md5.stdout)
        .trim()
        .to_string();
    let received_size = fs::metadata(&received_path).map(|m| m.len()).unwrap_or(0);

    assert_eq!(
        received_size, 1_048_576,
        "should receive all 1MB, got {received_size}"
    );
    assert_eq!(actual, expected, "md5 checksum should match");

    let _ = fs::remove_dir_all(&tmpdir);
    drop(_ap);
    echo_h.abort();
    proxy_h.abort();
    tokio::time::sleep(Duration::from_millis(200)).await;
    cleanup();
}

#[tokio::test]
async fn test_concurrent_connections() {
    setup();

    let (_, echo_h) = echo_server(ORIGIN_PORT).await;
    let (_, proxy_h) = connect_proxy(PROXY_PORT).await;

    let _ap = Proc::spawn(
        &bin(),
        &[
            &UID_TEST.to_string(),
            &format!("127.0.0.1:{PROXY_PORT}"),
            "-p",
            &TPROXY_PORT.to_string(),
            "-v",
        ],
    );
    assert!(wait_for_port(TPROXY_PORT).await);

    let tmpdir = format!("/tmp/atproxy-conc-{}", std::process::id());
    fs::create_dir_all(&tmpdir).unwrap();

    let mut children: Vec<std::process::Child> = Vec::new();
    for i in 1..=10 {
        let msg = format!("CONN{i}_HELLO");
        let outfile = format!("{tmpdir}/out.{i}");
        let child = Command::new("su")
            .args([
                "-s",
                "/bin/sh",
                "testapp",
                "-c",
                &format!("echo '{msg}' | nc -w10 {DUMMY_IP} {ORIGIN_PORT} > {outfile}"),
            ])
            .spawn()
            .unwrap();
        children.push(child);
    }

    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    for mut child in children {
        if std::time::Instant::now() < deadline {
            let _ = child.wait();
        } else {
            let _ = child.kill();
        }
    }

    let mut ok = true;
    for i in 1..=10 {
        let msg = format!("CONN{i}_HELLO");
        let content = fs::read_to_string(format!("{tmpdir}/out.{i}")).unwrap_or_default();
        if !content.contains(&msg) {
            eprintln!("connection {i} failed: expected '{msg}', got '{content}'");
            ok = false;
        }
    }
    assert!(ok, "all 10 concurrent connections should echo correctly");

    let _ = fs::remove_dir_all(&tmpdir);
    drop(_ap);
    echo_h.abort();
    proxy_h.abort();
    tokio::time::sleep(Duration::from_millis(200)).await;
    cleanup();
}

#[tokio::test]
async fn test_chunked_data_relay() {
    setup();

    let (_, chunked_h) = chunked_server(ORIGIN_PORT3).await;
    let (_, proxy_h) = connect_proxy(PROXY_PORT).await;

    let _ap = Proc::spawn(
        &bin(),
        &[
            &UID_TEST.to_string(),
            &format!("127.0.0.1:{PROXY_PORT}"),
            "-p",
            &TPROXY_PORT.to_string(),
            "-v",
        ],
    );
    assert!(wait_for_port(TPROXY_PORT).await);

    let result = run_client(
        UID_TEST,
        &format!("echo TRIGGER | nc -w5 {DUMMY_IP} {ORIGIN_PORT3}"),
    );
    assert!(
        result.contains("CHUNK1:CHUNK2:CHUNK3"),
        "all 3 chunks, got: {result}"
    );
    assert!(
        result.contains("CHUNK1:CHUNK2"),
        "chunks in order, got: {result}"
    );

    drop(_ap);
    chunked_h.abort();
    proxy_h.abort();
    tokio::time::sleep(Duration::from_millis(200)).await;
    cleanup();
}

#[tokio::test]
async fn test_connection_teardown() {
    setup();

    let (_, echo_h) = echo_server(ORIGIN_PORT).await;
    let (_, proxy_h) = connect_proxy(PROXY_PORT).await;

    let ap = Proc::spawn(
        &bin(),
        &[
            &UID_TEST.to_string(),
            &format!("127.0.0.1:{PROXY_PORT}"),
            "-p",
            &TPROXY_PORT.to_string(),
            "-v",
        ],
    );
    assert!(wait_for_port(TPROXY_PORT).await);

    let result = run_client(
        UID_TEST,
        &format!("echo TEARDOWN_TEST | nc -w3 {DUMMY_IP} {ORIGIN_PORT}"),
    );
    assert!(
        result.contains("TEARDOWN_TEST"),
        "echo before close, got: {result}"
    );

    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(ap.is_running(), "atproxy should survive client close");
    assert!(
        uid_rules_count(UID_TEST) >= 1,
        "iptables rules should be intact"
    );

    drop(ap);
    echo_h.abort();
    proxy_h.abort();
    tokio::time::sleep(Duration::from_millis(200)).await;
    cleanup();
}

#[tokio::test]
async fn test_sigterm_graceful_shutdown() {
    setup();

    let (_, echo_h) = echo_server(ORIGIN_PORT).await;
    let (_, proxy_h) = connect_proxy(PROXY_PORT).await;

    let ap = Proc::spawn(
        &bin(),
        &[
            &UID_TEST.to_string(),
            &format!("127.0.0.1:{PROXY_PORT}"),
            "-p",
            &TPROXY_PORT.to_string(),
            "-v",
        ],
    );
    assert!(wait_for_port(TPROXY_PORT).await);

    // Start a connection in background
    let mut nc = Command::new("su")
        .args([
            "-s",
            "/bin/sh",
            "testapp",
            "-c",
            &format!("echo SIGTERM_TEST | nc -w10 {DUMMY_IP} {ORIGIN_PORT}"),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    tokio::time::sleep(Duration::from_millis(500)).await;

    ap.send_signal(libc::SIGTERM);
    let exit_status = ap.wait();
    let code = exit_status.code().unwrap_or(-1);
    assert!(
        code == 0 || code == 143,
        "atproxy should exit cleanly, got {code}"
    );

    let _ = nc.kill();
    let _ = nc.wait();

    assert_eq!(
        uid_rules_count(UID_TEST),
        0,
        "iptables rules should be removed after SIGTERM"
    );

    echo_h.abort();
    proxy_h.abort();
    tokio::time::sleep(Duration::from_millis(200)).await;
    cleanup();
}
