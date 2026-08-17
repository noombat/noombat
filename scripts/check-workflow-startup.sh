#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
#
# Report a workflow that was rejected before it ran.
#
# A workflow GitHub refuses, most often for a `uses:` outside the
# repository's Actions policy, concludes `startup_failure`: it creates no
# jobs, therefore no check runs, therefore nothing on the commit page,
# the pull request checks, or the tick in the commit history. Every other
# check stays green and the absence of the rejected one looks exactly
# like "it was not triggered".
#
# `scripts/check-action-allowlist.sh` catches the usual cause before a
# push. This catches the symptom afterwards, whatever the cause.
#
# Reads the public API, so no token is required, but one raises the rate
# limit from 60 requests an hour to 5000. Set GH_TOKEN or GITHUB_TOKEN.
#
# Usage: scripts/check-workflow-startup.sh [ref]
#        Defaults to the current HEAD.

set -eu

REPO="${NOOMBAT_REPO:-noombat/noombat}"
SHA="${1:-$(git rev-parse HEAD)}"
API="https://api.github.com/repos/$REPO/actions/runs?head_sha=$SHA&per_page=100"

fetch() {
    if [ -n "${1:-}" ]; then
        curl -sS --max-time 30 -H 'Accept: application/vnd.github+json' \
            -H "Authorization: Bearer $1" "$API"
    else
        curl -sS --max-time 30 -H 'Accept: application/vnd.github+json' "$API"
    fi
}

TOKEN="${GH_TOKEN:-${GITHUB_TOKEN:-}}"
BODY=$(fetch "$TOKEN")

# A stale token in the environment is common and must not be reported as
# a broken commit: the endpoint is public, so drop the credential and
# ask again rather than failing.
case "$BODY" in
    *'"Bad credentials"'*|*'"message": "Requires authentication"'*)
        echo "  (ignoring a rejected token and retrying without one)"
        BODY=$(fetch "")
        ;;
esac

# An empty or error payload must not read as a clean commit.
COUNT=$(printf '%s' "$BODY" | sed -n 's/.*"total_count"[[:space:]]*:[[:space:]]*\([0-9]*\).*/\1/p' | head -1)
if [ -z "$COUNT" ]; then
    echo "::error::no usable response from the runs API for $SHA" >&2
    printf '%s\n' "$BODY" | head -5 >&2
    exit 2
fi

echo "Checked $COUNT workflow run(s) for $SHA."

# The API pretty-prints, so the separator is `": "`, not `":"`. Matching
# the compact form finds nothing and reports every commit clean.
REJECTED=$(printf '%s' "$BODY" |
    { grep -cE '"conclusion"[[:space:]]*:[[:space:]]*"startup_failure"' || true; })
[ "$REJECTED" = "0" ] && REJECTED=""

if [ -n "$REJECTED" ]; then
    echo "::error::a workflow was rejected before it ran, so it produced no check runs"
    echo "  Open the Actions tab for $SHA: the run has an empty job list and a"
    echo "  banner naming the reason. A disallowed or unpinned 'uses:' is the"
    echo "  usual cause; scripts/check-action-allowlist.sh reports that one"
    echo "  before a push."
    exit 1
fi

echo "No workflow was rejected at startup."
