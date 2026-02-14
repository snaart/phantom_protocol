# Build Stage
# Обновили до 1.93, чтобы соответствовать вашей локальной версии
FROM rust:1.93-slim-bookworm as builder

WORKDIR /usr/src/phantom
COPY . .

# Install dependencies
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