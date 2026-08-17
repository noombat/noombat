#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
#
# Run all verification steps: formatting, lints, tests, and
# frontend type-checking. Does not require a prior build or clean.
#
# Usage:
#   ./scripts/test.sh          # all checks
#   ./scripts/test.sh --quick  # Rust checks only (skip frontend)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

QUICK=false
FAIL=0

for arg in "$@"; do
    case "$arg" in
        --quick) QUICK=true ;;
        *) echo "Unknown argument: $arg"; exit 1 ;;
    esac
done

step() { echo ""; echo "==> $1"; }

run() {
    if "$@"; then
        return 0
    else
        FAIL=$((FAIL + 1))
        return 1
    fi
}

# ..... Rust .....

step "Checking formatting (cargo fmt)"
run cargo fmt --all -- --check

step "Running clippy (cargo clippy)"
run cargo clippy --workspace -- -D warnings

step "Running tests (cargo test)"
# Database-backed tests are #[ignore]d so this stays runnable without a
# PostgreSQL instance. To run them too, start a database, point
# DATABASE_URL at it, apply migrations, then:
#     cargo test --workspace -- --include-ignored
run cargo test --workspace

# ..... Manifests .....

# Neither Cargo nor npm warns when a declaration outlives the code that
# needed it, so nothing else here would notice.
step "Checking for unused dependency declarations"
if [ "$QUICK" = true ]; then
    run ./scripts/check-unused-deps.sh --rust-only
else
    run ./scripts/check-unused-deps.sh
fi

# No Dependabot ecosystem reads a workflow `services:` or `container:`
# image, so nothing else would notice one drifting from compose.
step "Checking container image pins"
run ./scripts/check-image-pins.sh

# ..... Frontend .....

if [ "$QUICK" = false ]; then
    step "Installing frontend dependencies"
    cd frontend
    pnpm install --frozen-lockfile 2>/dev/null || pnpm install
    cd "$REPO_ROOT"

    step "Checking TypeScript (tsc --noEmit)"
    cd frontend
    run pnpm exec tsc --noEmit
    cd "$REPO_ROOT"

    step "Linting frontend (eslint)"
    cd frontend
    run pnpm lint
    cd "$REPO_ROOT"
fi

# ..... REUSE .....

if command -v reuse >/dev/null 2>&1; then
    step "Checking REUSE compliance"
    run reuse lint
else
    echo ""
    echo "(Skipping REUSE check: reuse not installed)"
fi

# ..... Summary .....

echo ""
echo "=============================="
if [ "$FAIL" -eq 0 ]; then
    echo "  All checks passed."
else
    echo "  $FAIL check(s) failed."
fi
echo "=============================="

exit "$FAIL"
