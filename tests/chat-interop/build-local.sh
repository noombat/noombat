#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

# Build the Noombat binary for the local chat-interop loop, for use with
# compose.localbin.yml.
#
# Compiles in the Dockerfile's builder image because the binary has to run
# in the bookworm runtime image, which has glibc 2.36. Output and the cargo
# registry stay under target/, so repeated builds write nothing to the
# Docker device.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# Pinned to the Dockerfile's builder stage, so the loop and the image build
# cannot use different compilers. The toolchain is named to stop rustup
# re-resolving rust-toolchain.toml's `stable` on every run; change the two
# together.
BUILDER="rust:1-bookworm@sha256:0e2bcaef56d041a486784e54104a81aebe0da44bd03019bd70bc0401e42e4a97"
TOOLCHAIN="1.97.1-x86_64-unknown-linux-gnu"

docker run --rm --user "$(id -u):$(id -g)" \
    -v "$REPO_ROOT:/build" -w /build \
    -e CARGO_HOME=/build/target/bookworm-cargo \
    -e CARGO_TARGET_DIR=/build/target/bookworm \
    -e RUSTUP_TOOLCHAIN="$TOOLCHAIN" \
    "$BUILDER" \
    cargo build --release --bin noombat "$@"

echo "built: $REPO_ROOT/target/bookworm/release/noombat"
