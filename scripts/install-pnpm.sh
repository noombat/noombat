#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
#
# Installs the pnpm release a package.json pins in its `packageManager`
# field, refusing it unless the registry publishes it under the hash pinned
# there.
#
# Usage: scripts/install-pnpm.sh [PACKAGE_JSON]   (default: frontend/package.json)
#
# npm checks the downloaded tarball against the registry's integrity value,
# and that value is checked here against the pinned hash, so the release
# installed is the one the pin names.
set -eu

package_json=${1:-frontend/package.json}
spec=$(node -p 'require(require("path").resolve(process.argv[1])).packageManager' "$package_json")

case "$spec" in
    pnpm@*+sha512.*) ;;
    *)
        echo "install-pnpm: $package_json pins no pnpm release with a sha512 hash: $spec" >&2
        exit 1
        ;;
esac

version=${spec#pnpm@}
version=${version%%+*}
hex=${spec##*+sha512.}
pinned="sha512-$(node -e '
    process.stdout.write(Buffer.from(process.argv[1], "hex").toString("base64"))' "$hex")"
published=$(npm view "pnpm@$version" dist.integrity)

if [ "$published" != "$pinned" ]; then
    echo "install-pnpm: the registry's pnpm@$version is $published," \
        "not $pinned as $package_json pins" >&2
    exit 1
fi

npm install --global "pnpm@$version"
