#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
#
# Clean the entire workspace: Rust, frontend, and WASM build artifacts.
# Usage: ./scripts/clean.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

echo "Cleaning Rust build artifacts..."
cargo clean

echo "Cleaning frontend dependencies and build output..."
rm -rf frontend/node_modules
rm -rf frontend/dist

echo "Cleaning WASM build output..."
# The .d.ts declaration file is committed; preserve it.
rm -f frontend/src/chat/wasm/*.js
rm -f frontend/src/chat/wasm/*.wasm
rm -f frontend/src/chat/wasm/*.json
rm -f frontend/src/chat/wasm/package.json
rm -rf frontend/src/chat/wasm/snippets
rm -f frontend/src/chat/wasm/.gitignore

echo "Cleaning sqlx offline query cache..."
rm -rf .sqlx

echo "Done."
