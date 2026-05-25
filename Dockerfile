FROM rust:1.95-slim-bookworm AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock* build.rs ./
COPY src/ src/
COPY tests/ tests/
RUN cargo build --release --bin atproxy
RUN cargo test --test integration --no-run 2>/dev/null || true
# Grab the compiled integration test binary
RUN find target/release/deps -type f -executable -name 'integration-*' ! -name '*.d' -exec cp {} /build/integration-test \;

FROM debian:bookworm-slim
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        iptables iproute2 procps gosu netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*
RUN groupadd -g 10000 testapp && useradd -u 10000 -g testapp -m -s /bin/bash testapp
WORKDIR /opt/atproxy
COPY --from=builder /build/target/release/atproxy ./atproxy
COPY --from=builder /build/integration-test ./integration-test
ENTRYPOINT ["./integration-test", "--test-threads=1"]
