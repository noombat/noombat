#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
#
# Reject a `uses:` the repository's Actions policy will not run.
#
# GitHub restricts this repository to actions owned by `noombat` or
# matching the patterns below, each pinned to a full-length commit SHA.
# A `uses:` outside that set does not fail a job: it makes the whole
# workflow `startup_failure`, which creates no jobs and therefore no
# check runs, so the commit still shows every other check green and
# nothing records that three jobs never ran.
#
# THE LIST BELOW MIRRORS A GITHUB REPOSITORY SETTING THAT IS NOT IN THIS
# TREE. Nothing can read the real one from here, so the two are kept in
# step by hand: adding an entry here is a request to the maintainer to
# add it there in the same change, and the workflow stays dead until
# they do.
#
# `actionlint` does not cover this. It validates the workflow schema and
# knows nothing about the policy.
#
# Usage: scripts/check-action-allowlist.sh [directory]
#        Defaults to .github/workflows.

set -eu

DIR="${1:-.github/workflows}"

ALLOWED_OWNERS="noombat"
ALLOWED_REPOS="actions/cache
actions/checkout
actions/setup-node
actions/upload-artifact
docker/build-push-action
docker/login-action
docker/setup-buildx-action
sigstore/cosign-installer"

if [ ! -d "$DIR" ]; then
    echo "::error::workflow directory not found: $DIR" >&2
    exit 2
fi

USES=$({ grep -rhoE '^[[:space:]]*(-[[:space:]]*)?uses:[[:space:]]*[^[:space:]#]+' "$DIR" || true; } |
    sed -E 's/.*uses:[[:space:]]*//' | sort -u)

if [ -z "$USES" ]; then
    echo "::error::no 'uses:' found under $DIR, so this check proves nothing" >&2
    exit 2
fi

COUNT=$(printf '%s\n' "$USES" | wc -l | tr -d ' ')
FAIL=0

for u in $USES; do
    case "$u" in
        ./*|docker://*)
            # A local composite action, or a container image reference,
            # neither of which the policy governs.
            printf '  local    %s\n' "$u"
            continue
            ;;
    esac

    repo="${u%%@*}"
    ref="${u##*@}"
    owner="${repo%%/*}"

    permitted=0
    for o in $ALLOWED_OWNERS; do
        [ "$owner" = "$o" ] && permitted=1
    done
    if [ "$permitted" -eq 0 ]; then
        printf '%s\n' "$ALLOWED_REPOS" | grep -qxF "$repo" && permitted=1
    fi

    if [ "$permitted" -eq 0 ]; then
        printf '  REFUSED  %-46s not in the repository Actions policy\n' "$repo"
        FAIL=$((FAIL + 1))
        continue
    fi

    # The policy requires a full-length SHA, not a tag and not a short one.
    if [ "$u" = "$ref" ] || [ "${#ref}" -ne 40 ] || ! printf '%s' "$ref" | grep -qE '^[0-9a-f]{40}$'; then
        printf '  UNPINNED %-46s ref is not a 40-character commit SHA\n' "$repo"
        FAIL=$((FAIL + 1))
        continue
    fi

    printf '  ok       %s\n' "$repo"
done

echo
if [ "$FAIL" -gt 0 ]; then
    echo "::error::$FAIL action(s) the Actions policy will refuse, out of $COUNT."
    echo "Adding one to the list in this script is not enough: the repository"
    echo "setting has to gain the same pattern, or every workflow using it"
    echo "reports startup_failure with no check runs and no visible cause."
    exit 1
fi

echo "All $COUNT action reference(s) are permitted and pinned to a full SHA."
