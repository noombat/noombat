#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
#
# Report a pinned toolchain, a declared MSRV, or a tool pin that has fallen
# behind.
#
# rust-toolchain.toml names an exact version so that a Rust release cannot
# turn CI red without a commit: `channel = "stable"` did exactly that on
# 2026-09-02, when 1.98.0 brought a new clippy lint and a push that changed
# no Rust code failed. Pinning moves that breakage to a moment somebody
# chose.
#
# The cost of pinning is the opposite failure, which is silent: nobody
# notices the pin for a year, and the upgrade that follows carries a year
# of lints at once. This is what notices. It runs on a schedule rather than
# on push, because the answer changes with the calendar and not with the
# tree.
#
# The MSRV half asks the same question of the other end. `rust-version` is
# a promise to whoever builds this, and a floor left untouched for years
# forbids language features for no reason anybody still remembers.
#
# The tools half covers the two pins no updater moves: the cargo-deny
# release ci.yml installs, and pnpm in package.json's packageManager.
# Dependabot reads Cargo.lock and package.json's dependencies, not these.
# They are reported, never bumped: a cargo-deny release can change what
# deny.toml may say, and a pnpm major what the lockfile means. A new pnpm
# major only warns, since taking it is a decision rather than upkeep.
#
# None of this is a style rule, so all of it is configurable:
#   TOOLCHAIN_GRACE_DAYS   days a new stable may go untaken (default 21)
#   MSRV_MAX_BEHIND        releases the floor may trail stable (default 6)
#   TOOL_GRACE_DAYS        days a newer tool release may go untaken (default 21)
#
# Usage: scripts/check-toolchain-freshness.sh
# Needs curl, jq and GNU date, as the runner provides.

set -eu

GRACE_DAYS="${TOOLCHAIN_GRACE_DAYS:-21}"
MSRV_MAX_BEHIND="${MSRV_MAX_BEHIND:-6}"
TOOL_GRACE_DAYS="${TOOL_GRACE_DAYS:-21}"
MANIFEST_URL="https://static.rust-lang.org/dist/channel-rust-stable.toml"
CRATES_URL="https://crates.io/api/v1/crates/cargo-deny"
NPM_URL="https://registry.npmjs.org/pnpm"
# crates.io asks every client to name itself.
UA="noombat-toolchain-freshness (https://github.com/noombat/noombat)"

problems=0

fail() {
    printf '::error::%s\n' "$1" >&2
    problems=$((problems + 1))
}

# 1.98.0 -> 98. Pure on purpose: `fail` inside a command substitution
# increments a counter in a subshell, so the problem would be printed and
# then not counted. Validation is `require_1x`, called from the top level.
minor_of() {
    printf '%s\n' "$1" | cut -d. -f2
}

require_1x() {
    case "$1" in
        1.[0-9]*)
            return 0
            ;;
        *)
            fail "$2 '$1' is not a 1.x Rust release"
            return 1
            ;;
    esac
}

pinned=$(sed -n 's/^channel *= *"\([^"]*\)".*/\1/p' rust-toolchain.toml | head -1)
if [ -z "$pinned" ]; then
    fail "rust-toolchain.toml names no channel"
    exit 1
fi

msrv=$(sed -n 's/^rust-version *= *"\([0-9][0-9.]*\)".*/\1/p' Cargo.toml | head -1)
if [ -z "$msrv" ]; then
    fail "Cargo.toml declares no rust-version"
    exit 1
fi

if ! manifest=$(curl -fsSL --max-time 30 "$MANIFEST_URL"); then
    fail "cannot read $MANIFEST_URL"
    exit 1
fi

# From the `[pkg.rust]` section specifically. The manifest lists every
# component, each with its own `version`, and the first one in the file
# belongs to whichever package sorts first: reading it gave `0.99.0` and
# two confident errors about stable being older than the pin.
stable=$(printf '%s\n' "$manifest" | awk '
    /^\[pkg\.rust\]/ { in_rust = 1; next }
    /^\[/            { in_rust = 0 }
    in_rust && /^version = / { gsub(/"/, "", $3); print $3; exit }
')
released=$(printf '%s\n' "$manifest" | sed -n 's/^date = "\([0-9-]*\)".*/\1/p' | head -1)
if [ -z "$stable" ] || [ -z "$released" ]; then
    fail "could not read a version and date out of the stable manifest"
    exit 1
fi
require_1x "$stable" "current stable" || exit 1

printf 'pinned toolchain: %s\n' "$pinned"
printf 'declared MSRV:    %s\n' "$msrv"
printf 'current stable:   %s (released %s)\n' "$stable" "$released"
printf '\n'

# ..... The pin .....

case "$pinned" in
    1.*)
        require_1x "$pinned" "pinned toolchain" || exit 1
        pinned_minor=$(minor_of "$pinned")
        stable_minor=$(minor_of "$stable")
        pin_behind=$((stable_minor - pinned_minor))
        if [ "$pin_behind" -lt 0 ]; then
            fail "pinned $pinned is newer than stable $stable"
        elif [ "$pin_behind" -eq 0 ]; then
            printf '  ok  the pin is the current stable\n'
        elif [ "$pin_behind" -gt 1 ]; then
            # The grace window forgives the days after a release, not a
            # release missed outright. Keyed on the age of the newest
            # release alone, a pin eight versions old read as fresh for the
            # three weeks after every release, which is most of the time.
            fail "pinned $pinned trails stable $stable by $pin_behind releases: a whole\
 cycle has passed, so the grace window does not apply. Raise the pin in\
 rust-toolchain.toml."
        else
            # `date -d` is GNU, which is what the runner and the container
            # both provide. Refuse rather than guess if it is not there:
            # an unmeasured age would silently read as inside the window.
            if ! age_days=$(
                now=$(date -u +%s)
                then=$(date -u -d "$released" +%s 2>/dev/null) || exit 1
                printf '%s\n' $(((now - then) / 86400))
            ); then
                fail "cannot compute the age of $released; GNU date is required"
            elif [ "$age_days" -gt "$GRACE_DAYS" ]; then
                fail "pinned $pinned trails stable $stable, out $age_days days (grace\
 $GRACE_DAYS): raise the pin in rust-toolchain.toml, or raise TOOLCHAIN_GRACE_DAYS and\
 say why"
            else
                printf '  ok  stable %s is %s days old, inside the %s day grace window\n' \
                    "$stable" "$age_days" "$GRACE_DAYS"
            fi
        fi
        ;;
    *)
        fail "rust-toolchain.toml pins the floating channel '$pinned': a Rust release can\
 then turn CI red with no commit, which is what happened on 2026-09-02. Name an exact\
 version."
        ;;
esac

# ..... The floor .....

require_1x "$msrv" "declared MSRV" || exit 1
msrv_minor=$(minor_of "$msrv")
stable_minor=$(minor_of "$stable")
behind=$((stable_minor - msrv_minor))

if [ "$behind" -lt 0 ]; then
    fail "MSRV $msrv is newer than stable $stable"
elif [ "$behind" -gt "$MSRV_MAX_BEHIND" ]; then
    fail "MSRV $msrv trails stable $stable by $behind releases (limit $MSRV_MAX_BEHIND):\
 raise rust-version in Cargo.toml, or raise MSRV_MAX_BEHIND and say why"
else
    printf '  ok  MSRV %s is %s release(s) behind stable, limit %s\n' \
        "$msrv" "$behind" "$MSRV_MAX_BEHIND"
fi

# ..... Tools no updater moves .....

# Is $1 a later version than $2?
newer() {
    [ "$1" != "$2" ] && [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -1)" = "$1" ]
}

# The newest of "version<TAB>date" lines on stdin released by $cutoff.
# Pure, like minor_of: it prints and counts nothing.
due_of() {
    awk -F'\t' -v cutoff="$cutoff" '$2 <= cutoff { print $1 }' | sort -V | tail -1
}

# Report tool $1, pinned at $2, against releases $3 ("version<TAB>date"
# lines); $4 says what to do when the pin is behind.
report_tool() {
    newest=$(printf '%s\n' "$3" | cut -f1 | sort -V | tail -1)
    due=$(printf '%s\n' "$3" | due_of)
    if [ -z "$newest" ]; then
        fail "read no releases of $1"
    elif [ -n "$due" ] && newer "$due" "$2"; then
        fail "$1 $2 trails $due, out longer than $TOOL_GRACE_DAYS days (newest $newest): $4"
    elif newer "$newest" "$2"; then
        printf '  ok  %s %s; %s is newer, inside the %s day grace window\n' \
            "$1" "$2" "$newest" "$TOOL_GRACE_DAYS"
    else
        printf '  ok  %s %s is the newest release\n' "$1" "$2"
    fi
}

printf '\n'
if ! cutoff=$(date -u -d "$TOOL_GRACE_DAYS days ago" +%Y-%m-%dT%H:%M:%S 2>/dev/null); then
    fail "cannot compute the tool grace cutoff; GNU date is required"
    exit 1
fi

deny_pin=$(sed -n 's/^ *CARGO_DENY_VERSION: *"\([0-9][0-9.]*\)".*/\1/p' .github/workflows/ci.yml)
if [ "$(printf '%s\n' "$deny_pin" | grep -c .)" -ne 1 ]; then
    fail "need one CARGO_DENY_VERSION in .github/workflows/ci.yml, found: ${deny_pin:-none}"
elif ! crate=$(curl -fsSL --max-time 30 -A "$UA" "$CRATES_URL"); then
    fail "cannot read $CRATES_URL"
elif ! releases=$(printf '%s' "$crate" | jq -r '.versions[] | select(.yanked | not)
        | select(.num | test("^[0-9]+\\.[0-9]+\\.[0-9]+$"))
        | "\(.num)\t\(.created_at[:19])"'); then
    fail "cannot read cargo-deny's releases from crates.io's answer"
else
    report_tool cargo-deny "$deny_pin" "$releases" \
        "read its release notes against deny.toml, then raise CARGO_DENY_VERSION in ci.yml"
fi

pnpm_pins=$(sed -n 's/^ *"packageManager": *"pnpm@\([0-9][0-9.]*\)+.*/\1/p' \
    frontend/package.json tests/e2e/package.json | sort -u)
if [ "$(printf '%s\n' "$pnpm_pins" | grep -c .)" -ne 1 ]; then
    found=$(printf '%s ' $pnpm_pins)
    fail "need one pnpm release in packageManager across frontend/ and tests/e2e, found: $found"
elif ! packument=$(curl -fsSL --max-time 60 -A "$UA" "$NPM_URL"); then
    fail "cannot read $NPM_URL"
else
    major=${pnpm_pins%%.*}
    # Final releases only, from the registry's publication times.
    if ! releases=$(printf '%s' "$packument" | jq -r '.time | to_entries[]
            | select(.key | test("^[0-9]+\\.[0-9]+\\.[0-9]+$"))
            | "\(.key)\t\(.value[:19])"'); then
        fail "cannot read pnpm's releases from the registry's answer"
    else
        advice="raise packageManager, with its sha512, in frontend/ and tests/e2e/package.json,"
        advice="$advice then relock both with pnpm install --lockfile-only"
        report_tool pnpm "$pnpm_pins" "$(printf '%s\n' "$releases" | grep "^$major\.")" "$advice"
        next_due=$(printf '%s\n' "$releases" | grep "^$((major + 1))\." | due_of)
        if [ -n "$next_due" ]; then
            printf '::warning::pnpm %s, a new major, is out longer than %s days; the pin is %s\n' \
                "$next_due" "$TOOL_GRACE_DAYS" "$pnpm_pins"
        fi
    fi
fi

printf '\n'
if [ "$problems" -gt 0 ]; then
    printf '%d toolchain freshness problem(s)\n' "$problems" >&2
    exit 1
fi
printf 'toolchain, floor and tool pins are current\n'
