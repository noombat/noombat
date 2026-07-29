# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

# Base images are pinned by digest as well as by tag.
# The digest makes the input immutable and is a prerequisite for the
# reproducibility gate in CI. Dependabot proposes digest bumps for review.
#
# Refresh a digest with:
#   docker buildx imagetools inspect <image>:<tag>

# ..... FRONTEND BUILD .....
FROM node:22-bookworm-slim@sha256:6c74791e557ce11fc957704f6d4fe134a7bc8d6f5ca4403205b2966bd488f6b3 AS frontend

WORKDIR /build

# Copy the source trees that the Vite/Tailwind build needs:
# - frontend/ (Vite config, package.json, CSS entry point)
# - crates/noombat-api/templates/ (scanned by Tailwind @source)
COPY frontend/ frontend/
COPY crates/noombat-api/templates/ crates/noombat-api/templates/

WORKDIR /build/frontend
# `--frozen-lockfile` makes a package.json/pnpm-lock.yaml mismatch
# fail the build rather than being resolved silently into a
# dependency set that no lockfile records.
RUN corepack enable && pnpm install --frozen-lockfile && pnpm build

# ..... RUST BUILD .....
# The `rust:1-bookworm` tag tracks the latest stable Rust 1.x release,
# matching the CI `stable` channel. The workspace MSRV (rust-version in
# Cargo.toml) is verified separately by the CI `msrv` job.
FROM rust:1-bookworm@sha256:77fac8b98f9f46062bb680b6d25d5bcaabfc400143952ebc572e924bcbedc3fa AS builder

WORKDIR /build
COPY Cargo.toml rust-toolchain.toml ./
# Copy Cargo.lock if it exists (run `cargo generate-lockfile` before building).
COPY Cargo.lock* ./
COPY crates/ crates/
COPY migrations/ migrations/
COPY frontend/ frontend/
COPY templates/ templates/

# Copy the compiled frontend assets from the previous stage.
COPY --from=frontend /build/frontend/dist frontend/dist

# Build in release mode.
RUN cargo build --release --bin noombat

# ..... TYPST BINARY .....
# Copy the pre-built Typst CLI from the official container image.
# Pinned to the release series used by the project; bump when upgrading.
FROM ghcr.io/typst/typst:0.15.0@sha256:b23ba03da5c085a2c8780bc9f2296db937abe1d0c75348cf2f8a9273199c3a14 AS typst

# ..... RUNTIME .....
FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates && \
    rm -rf /var/lib/apt/lists/* && \
    useradd --system --no-create-home noombat

COPY --from=typst /bin/typst /usr/local/bin/typst
COPY --from=builder /build/target/release/noombat /usr/local/bin/noombat
COPY --from=builder /build/migrations /opt/noombat/migrations
COPY --from=builder /build/templates /opt/noombat/templates
COPY --from=frontend /build/frontend/dist /opt/noombat/frontend/dist

WORKDIR /opt/noombat

USER noombat
EXPOSE 8443

ENTRYPOINT ["noombat"]
