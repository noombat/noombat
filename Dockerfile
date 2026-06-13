# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

# ..... BUILD .....
FROM rust:1.95-bookworm AS builder

WORKDIR /build
COPY Cargo.toml rust-toolchain.toml ./
# Copy Cargo.lock if it exists (run `cargo generate-lockfile` before building).
COPY Cargo.lock* ./
COPY crates/ crates/
COPY migrations/ migrations/
COPY frontend/ frontend/
COPY templates/ templates/

# Build in release mode.
ENV SQLX_OFFLINE=true
RUN cargo build --release --bin noombat

# ..... RUNTIME .....
FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/noombat /usr/local/bin/noombat
COPY --from=builder /build/migrations /opt/noombat/migrations
COPY --from=builder /build/templates /opt/noombat/templates

WORKDIR /opt/noombat
EXPOSE 8443

ENTRYPOINT ["noombat"]
