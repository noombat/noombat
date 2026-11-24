#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
#
# Assert that every pinned action's SHA is the release its comment names.
#
# Actions are pinned to a full SHA with the release as a trailing comment
# (`@<sha> # v7.0.1`), and a reader trusts the comment. Dependabot moves
# the two together; a hand edit can leave a SHA that is not the release
# named, or a comment naming a tag that moves, such as `v4`, which says
# nothing about what is pinned. Each comment's tag is resolved through the
# API and compared with the SHA.
#
# Usage: scripts/check-action-tags.sh [workflow file...]
#        Defaults to every file in .github/workflows. Needs gh with a token.
# Exit 0 every pin matches, 1 a mismatch or an unusable comment, 2 a setup
# or API error.

set -eu

if [ "$#" -eq 0 ]; then
    set -- .github/workflows/*.yml
fi

PINS=$(grep -hoE 'uses: *[^ ]+@[0-9a-f]{40}( *#.*)?' "$@" | sed 's/^uses: *//' | sort -u)
if [ -z "$PINS" ]; then
    echo "::error::no pinned action found in $*; nothing was checked" >&2
    exit 2
fi

failures=0
checked=0
while IFS= read -r pin; do
    action=${pin%%@*}
    rest=${pin#*@}
    sha=${rest%% *}
    tag=$(printf '%s' "$rest" | sed -n 's/^[0-9a-f]\{40\} *# *\([^ ]*\).*/\1/p')
    # owner/repo, without the path of an action in a subdirectory.
    repo=$(printf '%s' "$action" | cut -d/ -f1-2)
    checked=$((checked + 1))
    if [ -z "$tag" ]; then
        echo "::error::$action@$sha has no release comment"
        failures=$((failures + 1))
        continue
    fi
    if ! printf '%s' "$tag" | grep -qE '^v?[0-9]+\.[0-9]+\.[0-9]+$'; then
        echo "::error::$action@$sha names '$tag', which is not one release: name the exact version"
        failures=$((failures + 1))
        continue
    fi
    if ! resolved=$(gh api "repos/$repo/commits/$tag" --jq .sha 2>/dev/null); then
        echo "::error::could not resolve $repo's $tag through the API" >&2
        exit 2
    fi
    if [ "$resolved" != "$sha" ]; then
        echo "::error::$action is pinned to $sha, but $tag is $resolved"
        failures=$((failures + 1))
    else
        echo "  ok  $action $tag"
    fi
done <<EOF
$PINS
EOF

if [ "$failures" -gt 0 ]; then
    echo "::error::$failures of $checked pin(s) do not match the release they name"
    exit 1
fi
echo "All $checked pin(s) are the release their comment names."
