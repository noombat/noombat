#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
#
# Build the entire workspace: frontend assets and the Rust server binary.
# Assumes prerequisites are installed (see README.md § Prerequisites).
#
# Usage:
#   ./scripts/build.sh            # full build (frontend + server)
#   ./scripts/build.sh --release  # release profile

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

RELEASE=""

for arg in "$@"; do
    case "$arg" in
        --release) RELEASE="--release" ;;
        *) echo "Unknown argument: $arg"; exit 1 ;;
    esac
done

# ..... Frontend dependencies .....

echo "Installing frontend dependencies..."
cd frontend
pnpm install --frozen-lockfile 2>/dev/null || pnpm install
cd "$REPO_ROOT"

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
