# Build Stage
FROM rust:1.84-slim-bookworm as builder

WORKDIR /usr/src/phantom
COPY . .

# Install dependencies (SQLCipher/openssl if needed, though we use pure rust or bundled)
RUN apt-get update && apt-get install -y pkg-config libssl-dev protobuf-compiler clang

# Build Server Release
RUN cargo build --release --bin phantom_server

# Runtime Stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y libssl3 ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /usr/src/phantom/target/release/phantom_server /app/phantom_server

# Expose Port
EXPOSE 3001

# Run
CMD ["./phantom_server"]
