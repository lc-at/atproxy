// SPDX-License-Identifier: MIT
//! Connection statistics tracking.
//!
//! Tracks total, active, and failed connection counts as well as bytes
//! transferred upstream and downstream using atomic counters.

use std::sync::atomic::{AtomicI64, AtomicU32, Ordering};

/// Atomic connection statistics.
pub struct Stats {
    total: AtomicU32,
    active: AtomicU32,
    failed: AtomicU32,
    bytes_up: AtomicI64,
    bytes_down: AtomicI64,
}

impl Stats {
    /// Create a new zeroed stats instance.
    pub fn new() -> Self {
        Self {
            total: AtomicU32::new(0),
            active: AtomicU32::new(0),
            failed: AtomicU32::new(0),
            bytes_up: AtomicI64::new(0),
            bytes_down: AtomicI64::new(0),
        }
    }

    /// Record a new connection opening.
    pub fn conn_open(&self) {
        self.total.fetch_add(1, Ordering::Relaxed);
        self.active.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a connection closing. Track failure if `ok` is false.
    pub fn conn_close(&self, ok: bool) {
        if !ok {
            self.failed.fetch_add(1, Ordering::Relaxed);
        }
        self.active.fetch_sub(1, Ordering::Relaxed);
    }

    /// Record upstream bytes transferred.
    #[allow(clippy::cast_possible_wrap)]
    pub fn add_up(&self, n: u64) {
        self.bytes_up.fetch_add(n as i64, Ordering::Relaxed);
    }

    /// Record downstream bytes transferred.
    #[allow(clippy::cast_possible_wrap)]
    pub fn add_down(&self, n: u64) {
        self.bytes_down.fetch_add(n as i64, Ordering::Relaxed);
    }

    /// Total connections accepted.
    pub fn total(&self) -> u32 {
        self.total.load(Ordering::Relaxed)
    }

    /// Currently active connections.
    pub fn active(&self) -> u32 {
        self.active.load(Ordering::Relaxed)
    }

    /// Failed connections.
    pub fn failed(&self) -> u32 {
        self.failed.load(Ordering::Relaxed)
    }

    /// Kilobytes sent upstream.
    pub fn bytes_up_kb(&self) -> i64 {
        self.bytes_up.load(Ordering::Relaxed) / 1024
    }

    /// Kilobytes received downstream.
    pub fn bytes_down_kb(&self) -> i64 {
        self.bytes_down.load(Ordering::Relaxed) / 1024
    }
}

impl std::fmt::Display for Stats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "conns={}, active={}, failed={}, up={}KB, down={}KB",
            self.total(),
            self.active(),
            self.failed(),
            self.bytes_up_kb(),
            self.bytes_down_kb(),
        )
    }
}
