#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
#
# Reject physical-direction utilities in markup.
#
# `ml-4` is always a left margin; `ms-4` is a margin on the side the text
# starts, which follows the `dir` attribute. Nothing in a right-to-left
# locale rewrites the first form, so a page written with it stays
# left-to-right while its text runs the other way.
#
# This gate exists because the convention is invisible: both forms
# compile, render and pass every other check, so the only thing keeping a
# page consistent is whether the person writing it happened to know.
#
# Usage: check-logical-properties.sh [DIR...]
#        Defaults to the template tree and the island sources.
#
# Exit 0 clean, 1 violations found, 2 nothing scanned.

set -eu

if [ "$#" -gt 0 ]; then
    DIRS="$*"
else
    DIRS="crates/noombat-api/templates frontend/src"
fi

for d in $DIRS; do
    if [ ! -d "$d" ]; then
        echo "::error::directory not found: $d" >&2
        exit 1
    fi
done

# shellcheck disable=SC2086
FILES=$(find $DIRS -type f \( -name '*.html' -o -name '*.ts' -o -name '*.tsx' \) -print | sort)
COUNT=$(printf '%s\n' "$FILES" | grep -c . || true)

# A scan that reaches no file would otherwise read as a clean tree.
if [ "$COUNT" -eq 0 ]; then
    echo "::error::no markup found under $DIRS, so this check proves nothing" >&2
    exit 2
fi

# The physical half of each pair, and the logical utility to use instead.
# `mr`/`pr` are the end side and `ml`/`pl` the start side, which is why
# the replacement is not a rename of the same letter.
RULES="ml-:ms- mr-:me- pl-:ps- pr-:pe- text-left:text-start text-right:text-end"

VIOLATIONS=0
for rule in $RULES; do
    physical=${rule%%:*}
    logical=${rule##*:}

    # A utility ends at a quote or whitespace, and may carry a variant
    # prefix (`hover:`, `md:`). Matching the bare token would also match
    # the middle of a longer class, so the boundary is explicit.
    case "$physical" in
        *-) pattern="(^|[\"' ])([a-z-]+:)?${physical}[0-9a-z.]+" ;;
        *)  pattern="(^|[\"' ])([a-z-]+:)?${physical}([\"' ]|$)" ;;
    esac

    hits=$(printf '%s\n' "$FILES" | while IFS= read -r f; do
        [ -n "$f" ] || continue
        grep -HnE "$pattern" "$f" || true
    done)

    if [ -n "$hits" ]; then
        echo "::error::physical-direction utility ${physical} (use ${logical})"
        printf '%s\n' "$hits" | sed 's/^/    /'
        VIOLATIONS=$((VIOLATIONS + 1))
    else
        echo "  ok  ${physical} (use ${logical}): none found"
    fi
done

if [ "$VIOLATIONS" -gt 0 ]; then
    echo "::error::${VIOLATIONS} physical-direction class(es) found" >&2
    exit 1
fi

echo "Scanned $COUNT file(s) under $DIRS: direction is expressed logically throughout."
