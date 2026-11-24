#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
#
# Assert that container images named in workflows are pinned, that they
# agree with the compose files that name the same image, that the
# Playwright job container matches @playwright/test, that the e2e job's
# Caddy binary is the release compose's Caddy image names, and that the
# Dockerfile's Node major is the one .nvmrc and frontend/package.json name.
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
# FIVE RULES.
#
#   1. Agreement. If a workflow and a compose file name the same image,
#      they must resolve to the same digest. This is the failure above.
#
#   2. Pinning. Every image, in a workflow OR a compose file, must carry
#      an `@sha256:` digest. A floating tag cannot agree with anything,
#      drifts on its own, and is invisible to Dependabot, which proposes
#      digest updates only for pinned images.
#
#   3. Playwright. The job container's tag must name the exact
#      @playwright/test version in tests/e2e; its browsers fit no other.
#
#   4. Caddy. The e2e job has no Docker and downloads a Caddy release
#      binary. Its version must be the one every compose file's Caddy tag
#      names, so a Dependabot bump of the image fails here until the
#      download moves with it.
#
#   5. Node. The Dockerfile's `node:N` stage must be the major .nvmrc
#      names, which every setup-node step reads, and the lower bound of
#      frontend/package.json's `engines`.
#
# Rule 2 has an allowlist for images that are deliberately unpinned. Each
# entry has to carry its reason, and the reasons are printed on every run
# so that "allowlisted" does not quietly become "forgotten".
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

# Image names, as `normalise` below leaves them, that may be unpinned,
# each with the reason it is.
# Remove an entry rather than editing it if the reason stops holding.
ALLOWLIST_IMAGES="
superseriousbusiness/gotosocial
"

allow_reason() {
    case "$1" in
        superseriousbusiness/gotosocial)
            echo "floating on purpose in tests/interop/compose.latest.yml, which" \
                "ci-interop-latest.yml runs on a schedule; pinned by digest in compose.yml" \
                "for the merge path"
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
#
# The glob is what makes that true, so keep it a glob. Naming files
# individually here leaves every compose file added later outside the
# check, and an image sitting outside it is not reported as unpinned: it
# is not seen at all, so the run stays green and shorter. The count
# printed below is the guard against that, and it must move whenever a
# compose file is added.
collect compose*.yml tests/*/compose*.yml >"$WORK/compose.tsv"
built_images compose*.yml tests/*/compose*.yml | normalise >"$WORK/built.txt"

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

# ..... Rule 3: the Playwright job container .....

PW_IMAGE="mcr.microsoft.com/playwright"
pw_spec='s/^[[:space:]]*"@playwright\/test":[[:space:]]*"\([^"]*\)".*/\1/p'
pw_line='^[[:space:]]*(image|container):[[:space:]]*"?mcr\.microsoft\.com/playwright:'
pw_want="$(sed -n "$pw_spec" tests/e2e/package.json)"
# A distro and an architecture suffix are fine; a prerelease or canary is not.
pw_tag="^v${pw_want//./\\.}(-[a-z]+(-(amd64|arm64))?)?\$"
pw_seen=0
while IFS= read -r line; do
    file="${line%%:*}"
    tag="${line##*"$PW_IMAGE":}"
    tag="${tag%%#*}"
    tag="$(echo "$tag" | tr -d '[:space:]"')"
    tag="${tag%%@*}"
    pw_seen=$((pw_seen + 1))
    if [[ "$tag" =~ $pw_tag ]]; then
        printf '  matches  %-42s %s\n' "$PW_IMAGE" "$tag in $file, as tests/e2e pins"
    else
        printf '  MISMATCH %-42s %s\n' "$PW_IMAGE" \
            "$tag in $file, but tests/e2e pins @playwright/test $pw_want"
        FAIL=1
    fi
done < <(grep -HE "$pw_line" .github/workflows/*.yml || true)

# A side that parses to nothing would pass without comparing.
if [ -z "$pw_want" ] || [ "$pw_seen" -eq 0 ]; then
    echo "error: found @playwright/test '${pw_want}' and $pw_seen Playwright job container(s)." >&2
    echo '       Both must be found; a pattern in rule 3 has stopped matching.' >&2
    exit 2
fi

# ..... Rule 4: the e2e job's Caddy binary .....

caddy_bin="$({ grep -ohE 'caddyserver/caddy/releases/download/v[0-9]+\.[0-9]+\.[0-9]+/' \
    .github/workflows/*.yml || true; } | sed -E 's|.*/v([^/]+)/$|\1|' | sort -u)"
caddy_re='^[[:space:]]*image:[[:space:]]*"?(docker\.io/)?(library/)?caddy:'
caddy_seen=0
if [ -z "$caddy_bin" ]; then
    echo "error: found no Caddy release download in the workflows." >&2
    echo '       The e2e job downloads one; a pattern in rule 4 has stopped matching.' >&2
    exit 2
fi
if [ "$(printf '%s\n' "$caddy_bin" | grep -c .)" -gt 1 ]; then
    printf '  MISMATCH %-42s %s\n' "caddy" "the workflows download several releases:" $caddy_bin
    FAIL=1
fi
while IFS= read -r line; do
    file="${line%%:*}"
    tag="${line##*caddy:}"
    tag="$(echo "$tag" | tr -d '[:space:]"')"
    tag="${tag%%@*}"
    caddy_seen=$((caddy_seen + 1))
    if [[ "$tag" =~ ^${caddy_bin//./\\.}(-[a-z]+)?$ ]]; then
        printf '  matches  %-42s %s\n' "caddy" "$tag in $file, the release the e2e job downloads"
    else
        printf '  MISMATCH %-42s %s\n' "caddy" \
            "$tag in $file, but the e2e job downloads Caddy $caddy_bin"
        FAIL=1
    fi
done < <(grep -HE "$caddy_re" compose*.yml tests/*/compose*.yml || true)

if [ "$caddy_seen" -eq 0 ]; then
    echo "error: found no Caddy image in the compose files." >&2
    echo '       Rule 4 compared nothing; its image pattern has stopped matching.' >&2
    exit 2
fi

# ..... Rule 5: the Node major .....

node_rc="$(tr -d '[:space:]' <.nvmrc)"
node_image="$(sed -nE \
    's/^FROM[[:space:]]+(docker\.io\/)?(library\/)?node:([0-9]+)[^0-9].*/\3/p' Dockerfile)"
node_engines="$(sed -nE \
    's/^[[:space:]]*"node":[[:space:]]*">=[[:space:]]*([0-9]+)[^0-9].*/\1/p' frontend/package.json)"
if ! [[ "$node_rc" =~ ^[0-9]+$ ]] || [ -z "$node_image" ] || [ -z "$node_engines" ]; then
    echo "error: found Node '$node_rc' in .nvmrc, '$node_image' in the Dockerfile and" \
        "'$node_engines' in frontend/package.json's engines." >&2
    echo '       Each must be one major; a pattern in rule 5 has stopped matching.' >&2
    exit 2
fi
if [ "$node_image" = "$node_rc" ] && [ "$node_engines" = "$node_rc" ]; then
    printf '  matches  %-42s %s\n' "node" "$node_rc in .nvmrc, the Dockerfile and the engines field"
else
    msg=".nvmrc names $node_rc, the Dockerfile $node_image,"
    msg="$msg frontend/package.json's engines $node_engines"
    printf '  MISMATCH %-42s %s\n' "node" "$msg"
    FAIL=1
fi

echo
if [ "$FAIL" -eq 0 ]; then
    echo "Workflow images are pinned and agree with the compose files."
    exit 0
fi

echo "Image pin check FAILED." >&2
echo "A workflow image that disagrees with compose means CI tests one thing" >&2
echo "and deployments run another. An unpinned one cannot agree with anything." >&2
exit 1
