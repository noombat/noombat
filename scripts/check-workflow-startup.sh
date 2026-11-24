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
#        scripts/check-workflow-startup.sh --since TIMESTAMP
#        The first checks one commit, the current HEAD by default. The
#        second checks every run created since TIMESTAMP (UTC, as
#        2026-11-22T06:00:00Z) on any branch, which is what a periodic
#        watch needs: a path-filtered workflow creates no run on a commit
#        outside its paths, so one commit can miss a rejection on an
#        earlier commit or a pull request branch.

set -eu

REPO="${NOOMBAT_REPO:-noombat/noombat}"
SHA="${1:-HEAD}"

fetch() {
    if [ -n "${1:-}" ]; then
        curl -sS --max-time 30 -H 'Accept: application/vnd.github+json' \
            -H "Authorization: Bearer $1" "$API"
    else
        curl -sS --max-time 30 -H 'Accept: application/vnd.github+json' "$API"
    fi
}

# The payload, retried without a stale token: the endpoint is public, so a
# rejected credential must not be reported as a finding.
query() {
    # A transport failure leaves BODY empty, which the count check below
    # reports with exit 2 rather than curl's own code.
    BODY=$(fetch "${GH_TOKEN:-${GITHUB_TOKEN:-}}") || BODY=""
    case "$BODY" in
        *'"Bad credentials"'*|*'"message": "Requires authentication"'*)
            echo "  (ignoring a rejected token and retrying without one)"
            BODY=$(fetch "") || BODY=""
            ;;
    esac
    # An empty or error payload must not read as a clean result.
    COUNT=$(printf '%s' "$BODY" |
        sed -n 's/.*"total_count"[[:space:]]*:[[:space:]]*\([0-9]*\).*/\1/p' | head -1)
    if [ -z "$COUNT" ]; then
        echo "::error::no usable response from the runs API" >&2
        printf '%s\n' "$BODY" | head -5 >&2
        exit 2
    fi
}

if [ "$SHA" = "--since" ]; then
    SINCE="${2:-}"
    stamp='^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$'
    if ! printf '%s' "$SINCE" | grep -qE "$stamp"; then
        echo "::error::--since needs a UTC timestamp such as 2026-11-22T06:00:00Z, not '$SINCE'" >&2
        exit 2
    fi
    # `>=` URL-encoded; zero is the clean answer here, unlike for one commit.
    API="https://api.github.com/repos/$REPO/actions/runs"
    API="$API?status=startup_failure&created=%3E%3D$SINCE&per_page=100"
    query
    if [ "$COUNT" != "0" ]; then
        echo "::error::$COUNT run(s) rejected before they ran since $SINCE," \
            "so they produced no check runs:"
        printf '%s' "$BODY" |
            grep -oE '"html_url"[[:space:]]*:[[:space:]]*"[^"]*/actions/runs/[0-9]+"' |
            sed 's/.*"\(https[^"]*\)"/  \1/'
        echo "  Each has an empty job list and a banner naming the reason. A"
        echo "  disallowed or unpinned 'uses:' is the usual cause;"
        echo "  scripts/check-action-allowlist.sh reports that one before a push."
        exit 1
    fi
    echo "No workflow was rejected at startup since $SINCE."
    exit 0
fi

# `head_sha` matches exactly, and the API answers `total_count: 0` for
# anything shorter rather than refusing, so an abbreviated SHA reads as a
# clean commit. Expand what was given, and refuse rather than query with
# something the API will silently not match.
FULL=$(git rev-parse --verify --quiet "${SHA}^{commit}" 2>/dev/null) && SHA="$FULL"
if ! printf '%s' "$SHA" | grep -qE '^[0-9a-f]{40}$'; then
    echo "::error::need a full 40-character commit SHA, and '$SHA' could not be expanded to one" >&2
    exit 2
fi

API="https://api.github.com/repos/$REPO/actions/runs?head_sha=$SHA&per_page=100"

query

echo "Checked $COUNT workflow run(s) for $SHA."

# Nothing examined is not a clean commit. Without this the two ways of
# reaching zero, an unpushed commit and a mistyped SHA, both report that
# no workflow was rejected.
if [ "$COUNT" = "0" ]; then
    echo "::error::no workflow runs recorded for $SHA, so nothing was examined" >&2
    exit 2
fi

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
