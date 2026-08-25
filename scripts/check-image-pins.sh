#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
#
# Assert that container images named in workflows are pinned, and that
# they agree with the compose files that name the same image.
#
# Nothing else checks this, and no updater proposes it. Dependabot's
# docker ecosystem reads Dockerfiles, docker-compose reads compose files,
# and github-actions reads `uses:`. A `services:` or `container:` image in
# a workflow is read by none of the three, so it is the one place an image
# reference can sit and never move.
#
# That is not hypothetical. On 2026-08-17 Dependabot #48 raised
# Meilisearch from v1.52 to v1.53 in `compose.yml` and could not touch the
# copy in `ci.yml`. Merging it as proposed would have left CI asserting
# against one Meilisearch while every deployment ran another, and nothing
# would have said so: both start, both serve, and the integration suite
# passes either way. It was caught by grepping for the old tag by hand.
#
# TWO RULES.
#
#   1. Agreement. If a workflow and a compose file name the same image,
#      they must resolve to the same digest. This is the failure above.
#
#   2. Pinning. Every image, in a workflow OR a compose file, must carry
#      an `@sha256:` digest. A floating tag cannot agree with anything,
#      drifts on its own, and is invisible to Dependabot, which proposes
#      digest updates only for pinned images.
#
# Rule 2 has an allowlist, because two images are deliberately unpinned
# and the reasons differ. Each entry has to carry its reason, and they are
# printed on every run so that "allowlisted" does not quietly become
# "forgotten".
#
# WHAT THIS DOES NOT DO. It compares what the files say, not what a
# registry resolves them to. A digest that no longer exists upstream will
# pass here and fail at pull time; `docker pull` is what settles that.
#
# Usage:
#   ./scripts/check-image-pins.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

# `file:image` entries that may be unpinned, each with the reason it is.
# Remove an entry rather than editing it if the reason stops holding.
ALLOWLIST_IMAGES="
mcr.microsoft.com/playwright
superseriousbusiness/gotosocial
"

allow_reason() {
    case "$1" in
        mcr.microsoft.com/playwright)
            echo "job container, must equal the @playwright/test version in tests/e2e; no ecosystem proposes it"
            ;;
        superseriousbusiness/gotosocial)
            echo "floating on purpose in tests/interop/compose.latest.yml, which ci-interop-latest.yml runs on a schedule; pinned by digest in compose.yml for the merge path"
            ;;
        *) echo "no reason recorded" ;;
    esac
}

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

FAIL=0

# Strip the parts that do not distinguish an image: the default registry
# and the `library/` namespace docker.io implies. `docker.io/library/postgres`
# and `postgres` are the same image and must compare equal, or the
# agreement rule silently never fires.
normalise() {
    sed -e 's|^docker\.io/||' -e 's|^library/||'
}

# Emit "file<TAB>name<TAB>digest" for every `image:` line in the files
# given. `digest` is empty when the reference carries no `@sha256:`.
collect() {
    for f in "$@"; do
        [ -f "$f" ] || continue
        # `|| true` because a workflow with no images is normal, and under
        # `pipefail` grep's exit 1 would otherwise kill the whole script
        # with no output at all. ci-frontend.yml is such a file.
        { grep -nE '^[[:space:]]*image:[[:space:]]*[^[:space:]]+' "$f" || true; } |
            while IFS= read -r line; do
                ref="${line##*image:}"
                ref="$(echo "$ref" | tr -d '[:space:]')"
                name="${ref%%@*}"
                name="${name%%:*}"
                name="$(echo "$name" | normalise)"
                case "$ref" in
                    *@sha256:*) digest="${ref##*@}" ;;
                    *) digest="" ;;
                esac
                printf '%s\t%s\t%s\n' "$f" "$name" "$digest"
            done
    done
}

# An image a compose service BUILDS is produced from a Dockerfile in this
# repository, so it has no upstream digest to pin and no ecosystem that
# could propose one. Naming it is what lets `buildx bake` tag what it
# builds and `compose up` find it, so the name has to be allowed to stand
# without a digest. Collected per service, since only a service carrying
# both `image:` and `build:` qualifies.
built_images() {
    for f in "$@"; do
        [ -f "$f" ] || continue
        awk '
            function flush() {
                if (img != "" && built) print img
                img = ""; built = 0
            }
            /^  [A-Za-z0-9_.-]+:[ \t]*$/ { flush(); insvc = 1; next }
            /^[A-Za-z]/               { flush(); insvc = 0 }
            insvc && /^[ \t]+image:[ \t]*/ {
                v = $0
                sub(/^[ \t]*image:[ \t]*/, "", v)
                sub(/[ \t]*$/, "", v)
                sub(/@.*$/, "", v)
                sub(/:[^:\/]*$/, "", v)
                img = v
            }
            insvc && /^[ \t]+build:[ \t]*$/ { built = 1 }
            END { flush() }
        ' "$f"
    done
}

collect .github/workflows/*.yml >"$WORK/workflow.tsv"
# compose*.yml, not compose.yml: overrides are scanned too, so an image
# can never escape the check by living in one. compose.latest.yml holds
# a deliberately floating GoToSocial and is allowlisted below, which is
# the difference between an exception and an oversight.
collect compose.yml compose.dev.yml tests/*/compose*.yml >"$WORK/compose.tsv"
built_images compose.yml compose.dev.yml tests/*/compose*.yml | normalise >"$WORK/built.txt"

workflow_count=$(wc -l <"$WORK/workflow.tsv")
compose_count=$(wc -l <"$WORK/compose.tsv")

# A parser that matches nothing reports a clean tree, whatever the truth.
if [ "$workflow_count" -eq 0 ] || [ "$compose_count" -eq 0 ]; then
    echo "error: parsed $workflow_count workflow and $compose_count compose image(s)." >&2
    echo '       Both must be non-zero; the image: pattern has stopped matching.' >&2
    exit 2
fi

echo "Scanned $workflow_count workflow image(s) against $compose_count compose image(s)."
echo

# ..... Rule 1: agreement .....

while IFS=$'\t' read -r file name digest; do
    [ -n "$digest" ] || continue
    while IFS=$'\t' read -r cfile cname cdigest; do
        [ "$cname" = "$name" ] || continue
        [ -n "$cdigest" ] || continue
        if [ "$cdigest" != "$digest" ]; then
            printf '  DISAGREE %s\n' "$name"
            printf '           %s  %s\n' "$file" "$digest"
            printf '           %s  %s\n' "$cfile" "$cdigest"
            FAIL=1
        fi
    done <"$WORK/compose.tsv"
done <"$WORK/workflow.tsv"

# ..... Rule 2: pinning .....
#
# Applied to compose files as well as workflows. Covering workflows
# alone, on the reasoning that compose is the source of truth and
# therefore already pinned, does not hold: `gotosocial:latest` and
# `caddy:2-alpine` can sit unpinned in tests/interop/compose.yml while
# the check reports a clean tree.
#
# Pinning compose images matters for a second reason beyond
# reproducibility. Dependabot's docker-compose ecosystem proposes digest
# updates for pinned images, which is how postgres and meilisearch get
# bumped, and proposes nothing for a floating tag. An unpinned image is
# not merely unreproducible, it is unmaintained.

while IFS=$'\t' read -r file name digest; do
    [ -n "$digest" ] && continue
    if grep -qxF "$name" "$WORK/built.txt" 2>/dev/null; then
        printf '  built    %-42s %s\n' "$name" "built here, so there is no upstream digest"
        continue
    fi
    if grep -qxF "$name" <<<"$ALLOWLIST_IMAGES"; then
        printf '  allowed  %-42s %s\n' "$name" "$(allow_reason "$name")"
        continue
    fi
    printf '  UNPINNED %-42s %s\n' "$name" "$file"
    FAIL=1
done < <(cat "$WORK/workflow.tsv" "$WORK/compose.tsv")

echo
if [ "$FAIL" -eq 0 ]; then
    echo "Workflow images are pinned and agree with the compose files."
    exit 0
fi

echo "Image pin check FAILED." >&2
echo "A workflow image that disagrees with compose means CI tests one thing" >&2
echo "and deployments run another. An unpinned one cannot agree with anything." >&2
exit 1
