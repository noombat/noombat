#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
#
# Report dependencies that a manifest declares and the code never names.
#
# Cargo does not warn about this and neither does npm, so a declaration
# outlives the code that needed it silently. On 2026-08-16 that had
# accumulated five of them: noombat-chat declared tokio-tungstenite and
# serde_json, noombat-federation declared http-signature-normalization
# while using only its reqwest wrapper, noombat-server declared reqwest,
# and noombat-markup carried a serde_json dev-dependency. The
# tokio-tungstenite one had a cost beyond tidiness: Dependabot proposed
# 0.30.0 for it, which could not be taken, because axum pins that crate
# to 0.29.0 and the "upgrade" resolved to a second copy of it.
#
# WHAT THIS PROVES, AND WHAT IT DOES NOT.
#
# A hit here means the crate name never appears in the code. That is
# necessary but not sufficient evidence that the dependency can go: a
# dependency can be load-bearing without ever being named, by enabling a
# feature on a shared crate, by linking a C library, or by registering a
# runtime provider. This workspace has already been bitten by the first:
# meilisearch-sdk's default features turned on a second jsonwebtoken
# crypto backend and every login panicked, with nothing in the source
# naming it. So treat output as CANDIDATES. Confirm each one by deleting
# the line and running:
#
#   cargo check --workspace --all-targets
#   cargo tree --workspace -f '{p} {f}'   # compare before and after
#
# The check must be at workspace scope. A package-scoped run is a
# different build, not a smaller one, because Cargo unifies features
# across the whole workspace.
#
# Comments are stripped before searching. A doc comment that mentions a
# crate it no longer uses would otherwise hide exactly the case this
# looks for, which is how the tokio-tungstenite declaration survived: the
# crate's own docs say "WebSocket" in six places.
#
# Both halves inject a canary dependency that cannot exist. If a canary
# is not reported, the scan matched everything and proved nothing, and
# this exits 2 rather than passing. The npm half read clean for exactly
# that reason during development: the file list included package.json, so
# every dependency matched its own declaration.
#
# Usage:
#   ./scripts/check-unused-deps.sh              # Cargo and npm
#   ./scripts/check-unused-deps.sh --rust-only  # skip the npm half

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

RUST_ONLY=false
for arg in "$@"; do
    case "$arg" in
        --rust-only) RUST_ONLY=true ;;
        *) echo "Unknown argument: $arg" >&2; exit 1 ;;
    esac
done

CANARY="noombat-canary-that-cannot-exist"

# Declarations that are intentional. Both entries are placeholder crates:
# a licence header, `#![forbid(unsafe_code)]` and one doc line describing
# scope that is not built yet. They declare noombat-core so that the
# manifest is ready, and use nothing because there is nothing to use.
# Remove an entry here when its crate grows an implementation.
ALLOWLIST="
noombat-events:noombat-core
noombat-groups:noombat-core
workspace:noombat-events
workspace:noombat-groups
"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

FOUND=0
BROKEN=0
# One canary is injected per manifest scanned, and every one of them must
# come back reported. Counting them is what separates "nothing is unused"
# from "the search matched everything".
CANARY_EXPECTED=0
CANARY_SEEN=0

allowed() {
    grep -qxF "$1:$2" <<<"$ALLOWLIST"
}

# ..... Cargo .....

cargo_dep_names() {
    awk '
        /^\[/ {
            in_section = ($0 ~ /^\[(dependencies|dev-dependencies|build-dependencies)\]$/) ||
                         ($0 ~ /\.(dependencies|dev-dependencies|build-dependencies)\]$/)
            next
        }
        !in_section { next }
        /^[[:space:]]*#/ { next }
        /^[[:space:]]*$/ { next }
        {
            name = $0
            sub(/[[:space:]]*=.*/, "", name)
            gsub(/[[:space:]]/, "", name)
            if (name ~ /^[A-Za-z0-9_-]+$/) print name
        }
    ' "$1"
}

echo "==> Cargo"

# The parser only understands `foo = ...` inside a dependency table. A
# `[dependencies.foo]` table would be skipped in silence, under-reporting
# rather than failing, so refuse to run instead of reporting a clean
# result the layout cannot support.
if grep -lE '^\[(dev-|build-)?dependencies\.' Cargo.toml crates/*/Cargo.toml >/dev/null 2>&1; then
    echo "error: a manifest uses [dependencies.<name>] table syntax, which this" >&2
    echo "       parser does not read. Teach cargo_dep_names about it before" >&2
    echo "       trusting a clean result." >&2
    exit 2
fi

for manifest in crates/*/Cargo.toml; do
    crate_dir="$(dirname "$manifest")"
    crate="$(basename "$crate_dir")"

    blob="$WORK/$crate.rs.txt"
    : >"$blob"
    while IFS= read -r src; do
        sed 's://.*::' "$src" >>"$blob"
    done < <(find "$crate_dir/src" "$crate_dir/tests" "$crate_dir/benches" \
        "$crate_dir/examples" "$crate_dir/build.rs" -name '*.rs' 2>/dev/null)

    if [ ! -s "$blob" ]; then
        echo "  note: $crate has no readable sources; skipping" >&2
        continue
    fi

    CANARY_EXPECTED=$((CANARY_EXPECTED + 1))
    while IFS= read -r dep; do
        [ -n "$dep" ] || continue
        ident="${dep//-/_}"
        if grep -qE "\\b${ident}\\b" "$blob"; then
            continue
        fi
        if [ "$dep" = "$CANARY" ]; then
            CANARY_SEEN=$((CANARY_SEEN + 1))
            continue
        fi
        if allowed "$crate" "$dep"; then
            printf '  allowed %-24s %s\n' "$crate" "$dep"
            continue
        fi
        printf '  UNUSED  %-24s %s\n' "$crate" "$dep"
        FOUND=$((FOUND + 1))
    done < <(cargo_dep_names "$manifest"; echo "$CANARY")

done

# An entry in [workspace.dependencies] that no member inherits is a
# declaration nothing can reach.
echo "==> Cargo workspace"
while IFS= read -r dep; do
    [ -n "$dep" ] || continue
    if grep -qE "^[[:space:]]*${dep}[[:space:]]*(=|\.workspace)" crates/*/Cargo.toml; then
        continue
    fi
    if allowed "workspace" "$dep"; then
        continue
    fi
    printf '  ORPHAN  %-24s %s\n' "(workspace)" "$dep"
    FOUND=$((FOUND + 1))
done < <(awk '
    /^\[workspace\.dependencies\]/ { in_section = 1; next }
    /^\[/ { in_section = 0 }
    !in_section { next }
    /^[[:space:]]*#/ { next }
    /^[[:space:]]*$/ { next }
    {
        name = $0
        sub(/[[:space:]]*=.*/, "", name)
        gsub(/[[:space:]]/, "", name)
        if (name ~ /^[A-Za-z0-9_-]+$/) print name
    }
' Cargo.toml)

# ..... npm .....

npm_block_keys() {
    # $1 = package.json, $2 = block name
    awk -v block="\"$2\"" '
        $0 ~ block "[[:space:]]*:[[:space:]]*\\{" { in_block = 1; next }
        in_block && /^[[:space:]]*\}/ { in_block = 0; next }
        in_block && match($0, /"[^"]+"/) {
            print substr($0, RSTART + 1, RLENGTH - 2)
        }
    ' "$1"
}

npm_script_bodies() {
    awk '
        /"scripts"[[:space:]]*:[[:space:]]*\{/ { in_block = 1; next }
        in_block && /^[[:space:]]*\}/ { in_block = 0; next }
        in_block { print }
    ' "$1"
}

if [ "$RUST_ONLY" = false ]; then
    echo "==> npm"
    for pkg in frontend tests/e2e; do
        manifest="$pkg/package.json"
        [ -f "$manifest" ] || continue

        blob="$WORK/${pkg//\//_}.txt"
        : >"$blob"
        # Everything except the manifest itself and the lockfile. Including
        # either makes every dependency match its own declaration.
        while IFS= read -r f; do
            cat "$f" >>"$blob"
        done < <(find "$pkg" -type f \
            ! -path '*/node_modules/*' \
            ! -name 'package.json' \
            ! -name 'pnpm-lock.yaml' \
            ! -name 'package-lock.json' \
            ! -path '*/test-results/*' \
            ! -path '*/playwright-report/*' 2>/dev/null)
        # A tool named only in a `scripts` entry (prettier, tsc, vite) is
        # used. Take the script bodies, never the dependency lists beside
        # them in the same file.
        npm_script_bodies "$manifest" >>"$blob"

        declared=0
        CANARY_EXPECTED=$((CANARY_EXPECTED + 1))
        while IFS= read -r dep; do
            [ -n "$dep" ] || continue
            declared=$((declared + 1))
            if [ "$dep" = "$CANARY" ]; then
                CANARY_SEEN=$((CANARY_SEEN + 1))
                continue
            fi
            # @types/foo is load-bearing for foo without ever being named.
            base="$dep"
            case "$dep" in
                @types/*) base="${dep#@types/}"; base="${base//__/\/}" ;;
            esac
            if grep -qF "$dep" "$blob" || grep -qF "$base" "$blob"; then
                continue
            fi
            if allowed "$pkg" "$dep"; then
                continue
            fi
            printf '  UNUSED  %-24s %s\n' "$pkg" "$dep"
            FOUND=$((FOUND + 1))
        done < <(npm_block_keys "$manifest" dependencies
                 npm_block_keys "$manifest" devDependencies
                 echo "$CANARY")

        # Zero extracted names means the awk block parser stopped matching
        # the file's shape, not that the package declares nothing.
        if [ "$declared" -le 1 ]; then
            echo "error: parsed no dependencies out of $manifest" >&2
            BROKEN=1
        fi
    done
fi

echo

if [ "$CANARY_SEEN" -ne "$CANARY_EXPECTED" ]; then
    echo "error: $CANARY_SEEN of $CANARY_EXPECTED canaries were reported." >&2
    echo "       A canary that goes missing means the search matched it, so a" >&2
    echo "       clean result would mean nothing. Do not trust this run." >&2
    BROKEN=1
fi

if [ "$BROKEN" -ne 0 ]; then
    echo "Unused-dependency scan is BROKEN: it cannot be trusted to report." >&2
    exit 2
fi

if [ "$FOUND" -eq 0 ]; then
    echo "No unused declarations."
    exit 0
fi

echo "$FOUND candidate declaration(s). Confirm each by removing it and running" >&2
echo "cargo check --workspace --all-targets before deleting anything." >&2
exit 1
