#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
#
# Produce a manifest of a built image's contents: the SHA-256 of every
# file under the given roots, plus the installed Debian package versions.
#
# This is broader than scripts/asset-manifest.sh, which covers only the
# browser assets and is baked into the image for the
# /.well-known/noombat/assets.json endpoint.
#
# Two caveats belong with any use of this output.
#
#   1. Attestation is not reproducibility. These hashes record what was
#      shipped, so an operator can confirm their image matches the
#      release. Only the frontend assets are additionally known to be
#      byte-reproducible from source; the Rust and Typst binaries have
#      no reproducibility provisions, so an independent rebuild will
#      not match. docs/verifying-builds.md states which is which.
#   2. Package entries are names and versions, not content hashes. They
#      pin what the Debian archive was asked for, not what it returned.
#
# Files outside the given roots are not covered.
#
# Usage: scripts/image-manifest.sh <image-ref> <root>... > manifest.json
#
# Environment: NOOMBAT_VERSION, NOOMBAT_COMMIT label the output.

set -eu

IMAGE="${1:?image reference required}"
shift
[ "$#" -gt 0 ] || { echo "at least one root path required" >&2; exit 1; }

VERSION="${NOOMBAT_VERSION:-}"
if [ -z "$VERSION" ]; then
    VERSION=$(git describe --tags --always --dirty 2>/dev/null || echo unknown)
fi
COMMIT="${NOOMBAT_COMMIT:-}"
if [ -z "$COMMIT" ]; then
    COMMIT=$(git rev-parse HEAD 2>/dev/null || echo unknown)
fi

# Collected inside the container: one `sha256sum  path` line per file
# under each root that exists, then a blank line, then one
# `package version` line per installed package. Sorted under LC_ALL=C
# so the output does not depend on the locale of the host.
INNER='
for root in '"$*"'; do
    [ -e "$root" ] || continue
    find "$root" -type f -print 2>/dev/null
done | LC_ALL=C sort | while IFS= read -r f; do
    sha256sum "$f"
done
echo "---PACKAGES---"
dpkg-query -W -f="${Package} ${Version}\n" 2>/dev/null | LC_ALL=C sort
'

COLLECTED=$(docker run --rm --entrypoint /bin/sh "$IMAGE" -c "$INNER")

FILES=$(printf '%s\n' "$COLLECTED" | sed -n '1,/^---PACKAGES---$/p' | sed '$d')
PACKAGES=$(printf '%s\n' "$COLLECTED" | sed -n '/^---PACKAGES---$/,$p' | sed '1d')

printf '{\n'
printf '  "version": "%s",\n' "$VERSION"
printf '  "commit": "%s",\n' "$COMMIT"
printf '  "image": "%s",\n' "$IMAGE"

printf '  "files": {\n'
printf '%s\n' "$FILES" | awk '
    NF >= 2 {
        hash = $1
        # Reassemble the path, which may contain spaces, and strip the
        # leading slash so entries are relative to the image root.
        path = $2
        for (i = 3; i <= NF; i++) path = path " " $i
        sub(/^\//, "", path)
        if (seen++) printf ",\n"
        printf "    \"%s\": \"%s\"", path, hash
    }
    END { if (seen) printf "\n" }
'
printf '  },\n'

printf '  "packages": {\n'
printf '%s\n' "$PACKAGES" | awk '
    NF == 2 {
        if (seen++) printf ",\n"
        printf "    \"%s\": \"%s\"", $1, $2
    }
    END { if (seen) printf "\n" }
'
printf '  }\n'
printf '}\n'
