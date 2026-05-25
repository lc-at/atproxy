.PHONY: all android test unit-test integration-test version clean

all: target/release/atproxy

target/release/atproxy: $(wildcard src/*.rs) Cargo.toml build.rs
	cargo build --release

android: $(wildcard src/*.rs) Cargo.toml build.rs
	cargo build --release --target aarch64-unknown-linux-musl
	@mkdir -p target
	cp target/aarch64-unknown-linux-musl/release/atproxy target/atproxy-android-arm64

test: unit-test integration-test

unit-test:
	cargo test --bin atproxy

integration-test:
	cargo test --test integration -- --test-threads=1

version: target/release/atproxy
	@./target/release/atproxy --version

clean:
	cargo clean
	rm -f target/atproxy-android-arm64
