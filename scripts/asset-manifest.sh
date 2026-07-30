#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
#
# Produce assets-manifest.json: the SHA-256 of every built frontend
# asset, together with the version and commit that produced them.
#
# The manifest is what gets signed. A signature over the manifest
# attests to the exact bytes of every script the browser will execute,
# which is the property that matters: a user, or a third-party
# monitor, can fetch the assets an instance actually serves and check
# them against hashes the project attested to at release time. Without
# it, "the source is open" says nothing about the code being served.
#
# The manifest is itself reproducible: paths are sorted, so two runs
# over identical inputs produce identical bytes.
#
# Usage: scripts/asset-manifest.sh [asset-directory] > assets-manifest.json
#        Defaults to frontend/dist/assets.

set -eu

DIR="${1:-frontend/dist/assets}"

if [ ! -d "$DIR" ]; then
    echo "asset directory not found: $DIR (run 'pnpm build' first)" >&2
    exit 1
fi

# NOOMBAT_VERSION and NOOMBAT_COMMIT override the git lookup, so the
# manifest can be generated inside a container build where the
# repository history is deliberately absent.
#
# `git describe --tags --exact-match` is empty off a tag; fall back to
# a description so a manifest built from a branch is still labelled.
VERSION="${NOOMBAT_VERSION:-}"
if [ -z "$VERSION" ]; then
    VERSION=$(git describe --tags --exact-match 2>/dev/null \
        || git describe --tags --always --dirty 2>/dev/null \
        || echo "unknown")
fi

COMMIT="${NOOMBAT_COMMIT:-}"
if [ -z "$COMMIT" ]; then
    COMMIT=$(git rev-parse HEAD 2>/dev/null || echo "unknown")
fi

printf '{\n'
printf '  "version": "%s",\n' "$VERSION"
printf '  "commit": "%s",\n' "$COMMIT"
printf '  "assets": {\n'

# Sorted so the manifest is byte-identical across runs. `sort` is run
# under LC_ALL=C so the ordering does not depend on the locale of
# whichever machine produced the manifest.
FIRST=1
find "$DIR" -type f -print \
    | LC_ALL=C sort \
    | while IFS= read -r file; do
        # Paths are recorded relative to the asset root and are
        # therefore the same regardless of checkout location.
        rel=${file#"$DIR"/}
        hash=$(sha256sum "$file" | cut -d' ' -f1)
        if [ "$FIRST" -eq 1 ]; then
            FIRST=0
        else
            printf ',\n'
        fi
        printf '    "%s": "%s"' "$rel" "$hash"
    done

printf '\n  }\n'
printf '}\n'
