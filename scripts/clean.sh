#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
#
# Clean the entire workspace: Rust and frontend build artifacts.
# Usage: ./scripts/clean.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

echo "Cleaning Rust build artifacts..."
cargo clean

echo "Cleaning frontend dependencies and build output..."
rm -rf frontend/node_modules
rm -rf frontend/dist

echo "Cleaning sqlx offline query cache..."
rm -rf .sqlx

echo "Done."
