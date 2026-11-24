#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
#
# Refuse to release a commit that is not on main, or that main's
# workflows did not pass.
#
# A tag can name any commit, nothing requires a status check before a
# push to main, a push runs each workflow once, on its last commit only,
# and a path filter can skip even that. So the release asks, of the exact
# commit it would sign, that main contains it and that every workflow
# listed below has a successful push or manual run on it. A pull_request
# run does not count: it tested a merge with the base, not this commit.
#
# Each workflow's runs on the commit are read by its file, so a renamed
# workflow or a commit with more runs than one page holds is not
# misread, and a workflow seen passing is not asked again. Runs still in
# progress are waited for, up to the timeout. A workflow with no run on
# the commit refuses the release once a short grace for runs not yet
# created has passed. Each refusal is its own error line, saying how to
# start a run, from the Actions tab or with gh.
#
# Usage: scripts/check-release-tested.sh SHA [TIMEOUT_SECONDS]
#        Needs gh with a token (GH_TOKEN) and a checkout holding main.
#        NOOMBAT_REPO and MAIN_REF override the repository and the
#        branch; RELEASE_GRACE the grace in seconds; RELEASE_WORKFLOWS
#        the list below, one "name|file" per line, for a test against a
#        subset.
# Exit 0 tested, 1 refused, 2 usage or setup error.

set -eu

REPO="${NOOMBAT_REPO:-noombat/noombat}"
MAIN_REF="${MAIN_REF:-origin/main}"
GRACE="${RELEASE_GRACE:-120}"
TIMEOUT="${2:-1800}"
INTERVAL=30
REF="${GITHUB_REF_NAME:-<the tag>}"

# Every workflow that tests a commit on main: its name, then its file.
# The scheduled checks are left out (toolchain freshness, advisories,
# the startup watch, interop against the latest GoToSocial): their
# answers depend on the date, not the commit.
WORKFLOWS="${RELEASE_WORKFLOWS:-CI|ci.yml
E2E & interop|ci-e2e.yml
CI (Frontend)|ci-frontend.yml
Container build verification|verify.yml
Accessibility|ci-accessibility.yml
REUSE|ci-reuse.yml
CodeQL|codeql.yml
Typst injection|typst.yml
Shell scripts|shellcheck.yml}"

SHA=$(git rev-parse --verify --quiet "${1:-}^{commit}" 2>/dev/null) || SHA=""
if ! printf '%s' "$SHA" | grep -qE '^[0-9a-f]{40}$'; then
    echo "::error::need a commit, and '${1:-}' does not name one here" >&2
    exit 2
fi
if ! git rev-parse --verify --quiet "$MAIN_REF" >/dev/null; then
    echo "::error::$MAIN_REF is not in this checkout; fetch it (fetch-depth: 0)" >&2
    exit 2
fi
if ! git merge-base --is-ancestor "$SHA" "$MAIN_REF"; then
    echo "::error::$SHA is not on $MAIN_REF, so main's workflows never tested it"
    exit 1
fi
echo "$SHA is on $MAIN_REF."

# One workflow's state on the commit, from its runs there: success,
# pending, missing, or failed: and the latest conclusion. A success
# outranks a failure, since it shows the commit passed; a run still
# going outranks a failure, since it may be a re-run.
state_of() {
    printf '%s' "$1" | jq -r '
        [.workflow_runs[] | select(.event == "push" or .event == "workflow_dispatch")]
        | if length == 0 then "missing"
          elif any(.conclusion == "success") then "success"
          elif any(.status != "completed") then "pending"
          else "failed:" + (max_by(.created_at) | .conclusion // "unknown") end'
}

passed=" "
start=$(date +%s)
while :; do
    elapsed=$(( $(date +%s) - start ))
    waiting=""
    refused=0
    report=""
    while IFS='|' read -r name file; do
        [ -n "$name" ] || continue
        case "$passed" in
            *" $file "*) state=success ;;
            *)
                url="repos/$REPO/actions/workflows/$file/runs?head_sha=$SHA&per_page=100"
                if ! runs=$(gh api "$url"); then
                    echo "::error::no usable response from the runs API for $file on $SHA;" \
                        "a 404 means the default branch has no workflow of that file name" >&2
                    exit 2
                fi
                if ! total=$(printf '%s' "$runs" | jq -e '.total_count'); then
                    echo "::error::the runs API's answer for $file holds no run count" >&2
                    exit 2
                fi
                if [ "$total" -gt 100 ]; then
                    echo "::error::$file has $total runs on $SHA, more than the one page read" >&2
                    exit 2
                fi
                state=$(state_of "$runs")
                if [ "$state" = success ]; then
                    passed="$passed$file "
                fi
                ;;
        esac
        report="$report
  $state  $name"
        case "$state" in
            success) ;;
            pending) waiting=1 ;;
            missing)
                if [ "$elapsed" -lt "$GRACE" ]; then
                    waiting=1
                else
                    echo "::error::$name has no run on $SHA: start one (Actions tab, $name," \
                        "Run workflow on $REF; or gh workflow run $file --ref $REF)," \
                        "then re-run this workflow"
                    refused=$((refused + 1))
                fi
                ;;
            *)
                echo "::error::$name concluded ${state#failed:} on $SHA: re-run it, or start" \
                    "a run (Actions tab, $name, Run workflow on $REF; or gh workflow run" \
                    "$file --ref $REF), then re-run this workflow"
                refused=$((refused + 1))
                ;;
        esac
    done <<EOF
$WORKFLOWS
EOF
    if [ "$refused" -gt 0 ]; then
        echo "::error::the release is refused: $refused workflow(s) did not pass on $SHA"
        echo "States on $SHA:$report"
        exit 1
    fi
    if [ -z "$waiting" ]; then
        echo "Every workflow passed on $SHA:$report"
        exit 0
    fi
    if [ "$elapsed" -ge "$TIMEOUT" ]; then
        echo "::error::still waiting after ${TIMEOUT}s:$report"
        exit 1
    fi
    echo "Waiting (${elapsed}s):$report"
    sleep "$INTERVAL"
done
