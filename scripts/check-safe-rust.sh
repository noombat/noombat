#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
#
# Assert that every crate root in the workspace forbids unsafe code, and
# that every workspace member takes the workspace's lints, which forbid it
# again in every target, tests and benches included.
#
# `#![forbid(unsafe_code)]` is per crate root, not per crate directory. A
# crate with two `[[bin]]` targets has two roots, and the attribute on one
# says nothing about the other. So every root is enumerated: the `[[bin]]`
# paths a crate declares, plus `src/lib.rs` and `src/main.rs` where they
# exist and are not already declared.

set -euo pipefail

cd "$(dirname "$0")/.."

fail=0
checked=0

# Each `path = "..."` that follows a `[[bin]]` header.
BIN_PATHS='/^\[\[bin\]\]/{b=1} b && /^path *=/{gsub(/^path *= *"|"$/,""); print; b=0}'

for manifest in crates/*/Cargo.toml; do
    crate_dir="$(dirname "$manifest")"
    crate_name="$(basename "$crate_dir")"

    # Declared `[[bin]]` paths, then the conventional roots. `sort -u`
    # because a crate usually declares its `main.rs` as a bin as well.
    # `if` rather than `[ ... ] && echo`: under `set -e` with `pipefail`
    # a false test as the last command aborts the whole script, which
    # presents as the check producing no output at all.
    roots="$(
        {
            awk "$BIN_PATHS" "$manifest"
            if [ -f "$crate_dir/src/lib.rs" ]; then echo "src/lib.rs"; fi
            if [ -f "$crate_dir/src/main.rs" ]; then echo "src/main.rs"; fi
        } | sort -u
    )"

    if [ -z "$roots" ]; then
        echo "  ?  $crate_name: no crate root found"
        fail=$((fail + 1))
        continue
    fi

    while IFS= read -r root; do
        path="$crate_dir/$root"
        checked=$((checked + 1))
        if [ ! -f "$path" ]; then
            echo "  ✗  $crate_name: $root is declared and missing"
            fail=$((fail + 1))
        elif grep -q 'forbid(unsafe_code)' "$path"; then
            echo "  ✓  $crate_name: $root"
        else
            echo "  ✗  $crate_name: $root has no #![forbid(unsafe_code)]"
            fail=$((fail + 1))
        fi
    done <<< "$roots"
done

# A pattern that stops matching would otherwise report a clean tree.
if [ "$checked" -lt 12 ]; then
    echo "::error::only $checked crate root(s) examined; the enumeration has stopped working"
    exit 2
fi

# Cargo applies `[workspace.lints]` only to a member whose manifest says
# `[lints] workspace = true`, and says nothing about one that does not.
# The members come from Cargo, so one outside crates/ is not missed. The
# table itself must still forbid unsafe code: Cargo accepts it emptied.
metadata="$(cargo metadata --no-deps --format-version 1)"
members_out="$(
    python3 -I -c '
import json, sys, tomllib
data = json.load(sys.stdin)
with open(data["workspace_root"] + "/Cargo.toml", "rb") as root:
    level = tomllib.load(root).get("workspace", {}).get("lints", {}).get("rust", {}).get("unsafe_code")
if isinstance(level, dict):
    level = level.get("level")
print("ok" if level == "forbid" else "missing", "[workspace.lints.rust]")
members = set(data["workspace_members"])
for package in data["packages"]:
    if package["id"] not in members:
        continue
    with open(package["manifest_path"], "rb") as manifest:
        lints = tomllib.load(manifest).get("lints", {})
    verdict = "ok" if lints.get("workspace") is True else "missing"
    print(verdict, package["name"])
' <<< "$metadata"
)"

members=0
while read -r verdict name; do
    if [ "$name" = "[workspace.lints.rust]" ]; then
        if [ "$verdict" = ok ]; then
            echo "  ✓  Cargo.toml: [workspace.lints.rust] forbids unsafe_code"
        else
            echo "  ✗  Cargo.toml: [workspace.lints.rust] does not forbid unsafe_code"
            fail=$((fail + 1))
        fi
        continue
    fi
    members=$((members + 1))
    if [ "$verdict" = ok ]; then
        echo "  ✓  $name: [lints] workspace = true"
    else
        echo "  ✗  $name: its Cargo.toml lacks [lints] workspace = true"
        fail=$((fail + 1))
    fi
done <<< "$members_out"

if [ "$members" -lt 12 ]; then
    echo "::error::only $members workspace member(s) examined; the enumeration has stopped working"
    exit 2
fi

echo ""
if [ "$fail" -gt 0 ]; then
    echo "::error::$fail crate root(s) or member(s) do not forbid unsafe code as required"
    exit 1
fi

echo "$checked crate root(s) forbid unsafe code; $members member(s) take the workspace lints."
