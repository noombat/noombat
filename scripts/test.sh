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

# Records a failure and returns 0 regardless.
#
# Returning non-zero would end the run: `set -e` exits on a bare call
# whose status it can see, so the first failing gate would take the
# summary, the exit code built from FAIL, and every later gate with it.
# One failure at a time is the slowest way to learn what is broken.
run() {
    if ! "$@"; then
        FAIL=$((FAIL + 1))
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

# Three files name the DKIM selector and for months they named three
# different ones, which produces signatures no receiver can verify.
step "Checking the DKIM selector agrees everywhere"
run ./scripts/check-dkim-selector.sh

step "Checking locale parity"
run python3 ./scripts/check-locale-parity.py

# ..... Templates .....

# An inline <script> or style attribute is blocked by the served policy,
# so the page renders without whatever it was doing.
step "Checking templates against the CSP"
run ./scripts/check-inline-scripts.sh

# Askama validates only its own syntax, so an unterminated `<!--`
# compiles clean and swallows the rest of the rendered page.
step "Checking template comment balance"
run ./scripts/check-template-comments.sh

# Both spellings compile and render, so nothing else distinguishes a page
# that will follow the reading direction from one that will not.
step "Checking direction is expressed logically"
run ./scripts/check-logical-properties.sh

# ..... Design system .....

# Colours that resolve are not the same as colours that can be read, and
# the high-contrast mode is a WCAG claim rather than a preference.
step "Checking colour contrast"
run python3 ./scripts/check-contrast.py

# The palette-auditing half takes an input this repository does not carry,
# so fixtures stand in for it.
step "Checking the design-system mode against its fixtures"
run python3 ./scripts/check-contrast.py --self-test

# ..... Database .....

# A duplicate version or a missing down-migration is invisible until a
# deployment tries to roll back.
step "Checking migration shape"
run ./scripts/check-migrations.sh

# ..... Workflows .....

# A `uses:` outside the repository's Actions policy makes the whole
# workflow startup_failure, which creates no check runs and so leaves the
# commit reading green while nothing ran.
step "Checking the GitHub Actions allowlist"
run ./scripts/check-action-allowlist.sh

# The symptom of the same fault, and only answerable for a commit the
# remote has. Announced when skipped rather than passed over, because a
# check that quietly did not run is the thing this suite exists to catch.
if git rev-parse --verify --quiet '@{u}' > /dev/null 2>&1 &&
    git merge-base --is-ancestor HEAD '@{u}' > /dev/null 2>&1; then
    step "Checking for workflows rejected at startup"
    run ./scripts/check-workflow-startup.sh
else
    step "Skipping the startup check: HEAD is not on the remote yet"
fi

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

# ..... CV rendering .....

# Compiles hostile markup with the pinned typst image, so it needs
# docker and is the slowest check here. Its own CI job runs it either
# way; the skip is announced so a local pass is not read as covering it.
if [ "$QUICK" = false ]; then
    if command -v docker > /dev/null 2>&1; then
        step "Checking Typst injection"
        run ./scripts/check-typst-injection.sh
    else
        step "Skipping the Typst check: docker is not available"
    fi
fi

# ..... Chatmail certificate path .....

# Acquisition, import and reload against a local ACME server. Needs
# docker and builds the Chatmail image, so it is out of QUICK. The skip
# is announced: renewal without a reload is the failure this covers, and
# it is invisible everywhere else.
if [ "$QUICK" = false ]; then
    if command -v docker > /dev/null 2>&1; then
        step "Checking the Chatmail certificate path"
        run ./scripts/check-chatmail-cert.sh
    else
        step "Skipping the certificate path: docker is not available"
    fi
fi

# ..... Chatmail relay invariants .....

# Real mail through the relay: plaintext refused before the queue, and
# the accepted message's signature verified against the generated key.
# Needs an image and does not build one, so it skips rather than fails
# when the tag is absent.
if [ "$QUICK" = false ]; then
    RELAY_IMAGE="${IMAGE:-noombat-chatmail:verify}"
    if ! command -v docker > /dev/null 2>&1; then
        step "Skipping the relay invariants: docker is not available"
    elif ! docker image inspect "$RELAY_IMAGE" > /dev/null 2>&1; then
        step "Skipping the relay invariants: $RELAY_IMAGE is not built"
    else
        step "Checking the Chatmail relay invariants"
        run ./scripts/check-relay-invariants.sh
    fi
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
