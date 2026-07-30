#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
#
# Verify that the frontend build is byte-reproducible.
#
# A signature over an asset manifest is only meaningful if the same
# source produces the same assets. If the build embeds a timestamp, a
# build path, or an unordered map iteration, the attested hashes
# describe one particular build machine rather than the source, and an
# independent rebuild cannot corroborate them. This gate fails the
# moment such non-determinism is introduced, when the cause is still
# a single commit rather than a year of accumulated drift.
#
# Two builds run from the same working tree and the same installed
# dependency set. That is the weaker of the two properties worth
# having; the stronger one, that an independent machine reproduces
# the same bytes, is what docs/verifying-builds.md proposes.
#
# Usage: scripts/check-reproducible.sh
#        Run from the repository root. Leaves frontend/dist in place.

set -eu

cd "$(dirname "$0")/.."

WORK=$(mktemp -d)
# shellcheck disable=SC2064  # WORK is expanded now, deliberately.
trap "rm -rf '$WORK'" EXIT

hash_tree() {
    # Emit `sha256  path` for every file, ordered by path so the
    # comparison does not depend on directory traversal order.
    (cd "$1" && find . -type f -print | LC_ALL=C sort | xargs sha256sum)
}

echo "First build..."
(cd frontend && rm -rf dist && pnpm build >/dev/null)
cp -r frontend/dist "$WORK/first"

echo "Second build..."
(cd frontend && rm -rf dist && pnpm build >/dev/null)
cp -r frontend/dist "$WORK/second"

hash_tree "$WORK/first" > "$WORK/first.sha256"
hash_tree "$WORK/second" > "$WORK/second.sha256"

if diff -u "$WORK/first.sha256" "$WORK/second.sha256" > "$WORK/delta"; then
    echo ""
    echo "Build is reproducible: $(wc -l < "$WORK/first.sha256" | tr -d ' ') files identical."
    exit 0
fi

echo ""
echo "::error::the frontend build is not reproducible; two builds of the same tree differ"
echo ""
sed 's/^/    /' "$WORK/delta"
echo ""
echo "    Common causes: a timestamp or build path embedded in output,"
echo "    a hash seeded from wall-clock time, or iteration over an"
echo "    unordered collection during code generation."
exit 1
