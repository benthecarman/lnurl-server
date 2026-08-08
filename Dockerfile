FROM rust:1.88-bookworm@sha256:af306cfa71d987911a781c37b59d7d67d934f49684058f96cf72079c3626bfe0 AS builder

# Install build dependencies
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    clang \
    cmake \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy source code
COPY . .

# Build the application (--locked builds exactly what Cargo.lock pins)
RUN cargo build --release --locked


FROM debian:bookworm-slim@sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241

# libssl3 is needed by the OpenSSL-based LND gRPC client; ca-certificates for
# outbound HTTPS/WSS (Telegram, Nostr relays)
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --home-dir /var/lib/lnurl-server --create-home lnurl

COPY --from=builder /app/target/release/lnurl-server /usr/local/bin/lnurl-server

USER lnurl
WORKDIR /var/lib/lnurl-server

ENTRYPOINT ["/usr/local/bin/lnurl-server"]
