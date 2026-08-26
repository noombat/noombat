#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
#
# Assert that every crate root in the workspace forbids unsafe code.
#
# `#![forbid(unsafe_code)]` is per crate root, not per crate directory. A
# crate with two `[[bin]]` targets has two roots, and the attribute on one
# says nothing about the other. The check this replaces read `lib.rs` or
# `main.rs`, whichever it found first, and so never opened
# `noombat-chatmail-admin`'s second binary: it reported twelve crates
# passing while examining twelve of thirteen roots.
#
# Every root is enumerated here instead: the `[[bin]]` paths a crate
# declares, plus `src/lib.rs` and `src/main.rs` where they exist and are
# not already declared.

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

echo ""
if [ "$fail" -gt 0 ]; then
    echo "::error::$fail crate root(s) missing #![forbid(unsafe_code)]"
    exit 1
fi

echo "$checked crate root(s) forbid unsafe code."
