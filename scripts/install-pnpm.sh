#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
#
# Installs the pnpm release a package.json pins in its `packageManager`
# field, refusing it unless the registry publishes it under the hash pinned
# there, and the native executable it runs under the hash the lockfile beside
# that package.json records.
#
# Usage: scripts/install-pnpm.sh [PACKAGE_JSON]   (default: frontend/package.json)
#
# npm checks each downloaded tarball against the registry's integrity value,
# and those values are checked here against the pinned hashes, so what is
# installed is what the pins name. From pnpm 12 the `pnpm` package is a
# wrapper that runs a native executable from `@pnpm/exe.<target>`, a separate
# package its hash does not cover. pnpm 12 locks itself, executables
# included, in the first YAML document of pnpm-lock.yaml, so that record is
# the second pin, written by pnpm when it relocks after a bump.
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

# pnpm names its native packages by platform and architecture, with -musl
# for a Linux without glibc.
target=$(node -p '
    const t = process.platform + "-" + process.arch
    const linux = process.platform === "linux"
    const glibc = !linux || process.report.getReport().header.glibcVersionRuntime
    glibc ? t : t + "-musl"')
native="@pnpm/exe.$target@$version"
lockfile="$(dirname "$package_json")/pnpm-lock.yaml"
if [ ! -f "$lockfile" ]; then
    echo "install-pnpm: no $lockfile to read $native's hash from" >&2
    exit 1
fi
# The entry's `resolution: {integrity: ...}` line, from the first document
# only: the second holds the project's own dependencies.
native_pinned=$(awk -v want="  '$native':" '
    NR > 1 && /^---$/ { exit }
    found { sub(/.*integrity: /, ""); sub(/[,}].*/, ""); print; exit }
    $0 == want { found = 1 }' "$lockfile")
if [ -z "$native_pinned" ]; then
    escaped=$(printf '%s' "$version" | sed 's/\./\\./g')
    if sed -n '2,/^---$/p' "$lockfile" | grep -q "^  '@pnpm/exe\.[^']*@$escaped':"; then
        echo "install-pnpm: pnpm $version publishes no native executable for $target" >&2
    else
        echo "install-pnpm: $lockfile locks no pnpm $version executable; relock it" \
            "with pnpm $version (pnpm install --lockfile-only)" >&2
    fi
    exit 1
fi
native_published=$(npm view "$native" dist.integrity)
if [ "$native_published" != "$native_pinned" ]; then
    echo "install-pnpm: the registry's $native is $native_published," \
        "not $native_pinned as $lockfile locks" >&2
    exit 1
fi

# Its own install script, part of the pinned wrapper, links the native
# executable in place of the wrapper's commands. Naming it keeps that script
# running where npm's allowScripts policy is strict, and quiets npm's notice
# about install scripts nobody reviewed.
npm install --global --allow-scripts=pnpm "pnpm@$version"

# What runs must be what was checked: npm settings such as `libc`, `os` or
# `omit` can change which native package it installs, and a `pnpm` earlier
# on PATH would run instead. So the one native package beside pnpm must be
# exe.$target, and the pnpm on PATH must be its executable file.
pkg_dir="$(npm root --global)/pnpm"
natives=""
for dir in "$pkg_dir"/node_modules/@pnpm/exe.*; do
    [ -e "$dir" ] && natives="$natives ${dir##*/}"
done
natives=${natives# }
if [ "$natives" != "exe.$target" ]; then
    echo "install-pnpm: npm installed '${natives:-no native package}' beside pnpm," \
        "not exe.$target alone" >&2
    exit 1
fi
on_path=$(command -v pnpm) || on_path=""
if [ -z "$on_path" ] || ! [ "$on_path" -ef "$pkg_dir/node_modules/@pnpm/exe.$target/pnpm" ]; then
    echo "install-pnpm: the pnpm on PATH (${on_path:-none}) is not $native's executable" >&2
    exit 1
fi

installed=$(pnpm --version)
if [ "$installed" != "$version" ]; then
    echo "install-pnpm: pnpm --version reports '$installed' after installing $version" >&2
    exit 1
fi
