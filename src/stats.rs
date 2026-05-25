// SPDX-License-Identifier: MIT
use std::sync::atomic::{AtomicI64, AtomicU32, Ordering};

pub struct Stats {
    total: AtomicU32,
    active: AtomicU32,
    failed: AtomicU32,
    bytes_up: AtomicI64,
    bytes_down: AtomicI64,
}

impl Stats {
    pub fn new() -> Self {
        Self {
            total: AtomicU32::new(0),
            active: AtomicU32::new(0),
            failed: AtomicU32::new(0),
            bytes_up: AtomicI64::new(0),
            bytes_down: AtomicI64::new(0),
        }
    }

    pub fn conn_open(&self) {
        self.total.fetch_add(1, Ordering::Relaxed);
        self.active.fetch_add(1, Ordering::Relaxed);
    }

    pub fn conn_close(&self, ok: bool) {
        if !ok {
            self.failed.fetch_add(1, Ordering::Relaxed);
        }
        self.active.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn add_up(&self, n: u64) {
        self.bytes_up.fetch_add(n as i64, Ordering::Relaxed);
    }

    pub fn add_down(&self, n: u64) {
        self.bytes_down.fetch_add(n as i64, Ordering::Relaxed);
    }
}

impl std::fmt::Display for Stats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "conns={}, active={}, failed={}, up={}KB, down={}KB",
            self.total.load(Ordering::Relaxed),
            self.active.load(Ordering::Relaxed),
            self.failed.load(Ordering::Relaxed),
            self.bytes_up.load(Ordering::Relaxed) / 1024,
            self.bytes_down.load(Ordering::Relaxed) / 1024,
        )
    }
}
