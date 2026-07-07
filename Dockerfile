# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

# ..... FRONTEND BUILD .....
FROM node:22-bookworm-slim AS frontend

WORKDIR /build

# Copy the source trees that the Vite/Tailwind build needs:
# - frontend/ (Vite config, package.json, CSS entry point)
# - crates/noombat-api/templates/ (scanned by Tailwind @source)
COPY frontend/ frontend/
COPY crates/noombat-api/templates/ crates/noombat-api/templates/

WORKDIR /build/frontend
RUN npm install -g pnpm && pnpm install && pnpm build

# ..... RUST BUILD .....
# The `rust:1-bookworm` tag tracks the latest stable Rust 1.x release,
# matching the CI `stable` channel. The workspace MSRV (rust-version in
# Cargo.toml) is verified separately by the CI `msrv` job.
FROM rust:1-bookworm AS builder

WORKDIR /build
COPY Cargo.toml rust-toolchain.toml ./
# Copy Cargo.lock if it exists (run `cargo generate-lockfile` before building).
COPY Cargo.lock* ./
COPY crates/ crates/
COPY migrations/ migrations/
COPY frontend/ frontend/
COPY templates/ templates/
COPY policies/ policies/

# Copy the compiled frontend assets from the previous stage.
COPY --from=frontend /build/frontend/dist frontend/dist

# Build in release mode.
RUN cargo build --release --bin noombat

# ..... TYPST BINARY .....
# Copy the pre-built Typst CLI from the official container image.
# Pinned to the release series used by the project; bump when upgrading.
FROM ghcr.io/typst/typst:v0.15.0 AS typst

# ..... RUNTIME .....
FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        fonts-libertinus && \
    rm -rf /var/lib/apt/lists/*

COPY --from=typst /bin/typst /usr/local/bin/typst
COPY --from=builder /build/target/release/noombat /usr/local/bin/noombat
COPY --from=builder /build/migrations /opt/noombat/migrations
COPY --from=builder /build/templates /opt/noombat/templates
COPY --from=builder /build/policies /opt/noombat/policies
COPY --from=frontend /build/frontend/dist /opt/noombat/frontend/dist

WORKDIR /opt/noombat
EXPOSE 8443

ENTRYPOINT ["noombat"]
