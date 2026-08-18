#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

# Build the Noombat binary for the local chat-interop loop, for use with
# compose.localbin.yml.
#
# Compiles in the Dockerfile's builder image because the binary has to run
# in the bookworm runtime image, which has glibc 2.36. Output, the cargo
# registry and the rustup toolchain all stay under target/, so repeated
# builds reuse them instead of re-downloading.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# Read out of the Dockerfile rather than repeated here, so this cannot
# compile against a different compiler than the image build uses.
BUILDER=$(grep -oE 'rust:1-bookworm@sha256:[0-9a-f]{64}' "$REPO_ROOT/Dockerfile" | head -1)
if [ -z "$BUILDER" ]; then
    echo "no pinned rust builder found in Dockerfile" >&2
    exit 1
fi

# RUSTUP_HOME is persisted because rust-toolchain.toml names a channel and
# not a version, so an unpersisted home re-downloads the toolchain on every
# run into a layer that --rm discards.
docker run --rm --user "$(id -u):$(id -g)" \
    -v "$REPO_ROOT:/build" -w /build \
    -e CARGO_HOME=/build/target/bookworm-cargo \
    -e RUSTUP_HOME=/build/target/bookworm-rustup \
    -e CARGO_TARGET_DIR=/build/target/bookworm \
    "$BUILDER" \
    cargo build --release --bin noombat "$@"

echo "built: $REPO_ROOT/target/bookworm/release/noombat"
