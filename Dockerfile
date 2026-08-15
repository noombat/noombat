# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

# Base images are pinned by digest as well as by tag.
# The digest makes the input immutable and is a prerequisite for the
# reproducibility gate in CI. Dependabot proposes digest bumps for review.
#
# Refresh a digest with:
#   docker buildx imagetools inspect <image>:<tag>

# ..... FRONTEND BUILD .....
FROM node:24-bookworm-slim@sha256:3638d9a6fe4030bd716be989438248074489337ba3275657f93595428be4fc03 AS frontend

WORKDIR /build

# Copy the source trees that the Vite/Tailwind build needs:
# - frontend/ (Vite config, package.json, CSS entry point)
# - crates/noombat-api/templates/ (scanned by Tailwind @source)
COPY frontend/ frontend/
COPY crates/noombat-api/templates/ crates/noombat-api/templates/
COPY scripts/asset-manifest.sh scripts/asset-manifest.sh

WORKDIR /build/frontend
# `--frozen-lockfile` makes a package.json/pnpm-lock.yaml mismatch
# fail the build rather than being resolved silently into a
# dependency set that no lockfile records.
RUN corepack enable && pnpm install --frozen-lockfile && pnpm build

# Label the asset manifest with the release it was built from. The
# repository history is excluded by .dockerignore, so these cannot be
# derived here and are supplied by the caller; publish-container.yml
# and container-build.yml both pass them.
#
# Declared here, after the build, and not earlier: a changed ARG value
# invalidates the cache for every following instruction, and the
# commit SHA changes on every commit.
#
# The "unknown" defaults exist so that a bare `docker build .` still
# works for local development. An image built that way serves a
# manifest no monitor can match against a signed release; see
# docs/verifying-builds.md.
ARG NOOMBAT_VERSION=unknown
ARG NOOMBAT_COMMIT=unknown

# Emit the manifest alongside the assets it describes, so the running
# instance can serve it from /.well-known/noombat/assets.json for
# third-party monitors to diff against the signed release artefact.
RUN NOOMBAT_VERSION="$NOOMBAT_VERSION" NOOMBAT_COMMIT="$NOOMBAT_COMMIT" \
    sh /build/scripts/asset-manifest.sh dist/assets > dist/assets-manifest.json

# ..... RUST BUILD .....
# The `rust:1-bookworm` tag tracks the latest stable Rust 1.x release,
# matching the CI `stable` channel. The workspace MSRV (rust-version in
# Cargo.toml) is verified separately by the CI `msrv` job.
FROM rust:1-bookworm@sha256:0e2bcaef56d041a486784e54104a81aebe0da44bd03019bd70bc0401e42e4a97 AS builder

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
FROM ghcr.io/typst/typst:0.15.1@sha256:032e292249bcd378480cc7c142cfa324b63ef8aadeb88d7e7230320c4c9c422f AS typst

# ..... RUNTIME .....
FROM debian:bookworm-slim@sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241

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

# Declared last, for the same reason as in the frontend stage: a
# changed ARG value invalidates every following instruction, and the
# commit SHA changes on every commit. ARG scope is per-stage, so these
# must be re-declared here even though the frontend stage has them.
#
# Recording them as standard OCI labels means `docker inspect` reports
# the same version and commit the served asset manifest claims, so a
# disagreement between the two is visible without unpacking the image.
ARG NOOMBAT_VERSION=unknown
ARG NOOMBAT_COMMIT=unknown
LABEL org.opencontainers.image.version="$NOOMBAT_VERSION"
LABEL org.opencontainers.image.revision="$NOOMBAT_COMMIT"
LABEL org.opencontainers.image.source="https://github.com/noombat/noombat"

ENTRYPOINT ["noombat"]
