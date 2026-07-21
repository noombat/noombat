#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
#
# Build the entire workspace: frontend assets, WASM module, and the
# Rust server binary. Assumes prerequisites are installed (see
# README.md § Prerequisites).
#
# Usage:
#   ./scripts/build.sh            # full build (frontend + WASM + server)
#   ./scripts/build.sh --release  # release profile
#   ./scripts/build.sh --no-wasm  # skip the WASM build step

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

RELEASE=""
SKIP_WASM=false

for arg in "$@"; do
    case "$arg" in
        --release) RELEASE="--release" ;;
        --no-wasm) SKIP_WASM=true ;;
        *) echo "Unknown argument: $arg"; exit 1 ;;
    esac
done

# ..... Frontend dependencies .....

echo "Installing frontend dependencies..."
cd frontend
pnpm install --frozen-lockfile 2>/dev/null || pnpm install
cd "$REPO_ROOT"

# ..... WASM module (optional) .....

if [ "$SKIP_WASM" = false ]; then
    if command -v wasm-pack >/dev/null 2>&1; then
        echo "Building WASM chat module..."
        cd frontend
        pnpm build:wasm
        cd "$REPO_ROOT"
    else
        echo "Skipping WASM build: wasm-pack not found."
        echo "  Install with: cargo install wasm-pack"
        echo "  Add target:   rustup target add wasm32-unknown-unknown"
    fi
else
    echo "Skipping WASM build (--no-wasm)."
fi

# ..... Frontend assets .....

echo "Building frontend assets..."
cd frontend
pnpm build
cd "$REPO_ROOT"

# ..... Rust server .....

echo "Building Rust workspace..."
cargo build $RELEASE --workspace

echo ""
if [ -n "$RELEASE" ]; then
    echo "Build complete (release)."
    echo "  Server:   target/release/noombat"
    echo "  Sidecar:  target/release/noombat-chatmail-admin"
else
    echo "Build complete (debug)."
    echo "  Server:   target/debug/noombat"
    echo "  Sidecar:  target/debug/noombat-chatmail-admin"
fi
