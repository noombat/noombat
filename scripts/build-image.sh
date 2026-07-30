#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
#
# Build a Noombat container image with the standard build arguments.
#
# Both verify.yml and release.yml call this, so the invocation exists once.
#
# Usage: scripts/build-image.sh <dockerfile> <tag> [version] [commit]
#
#   dockerfile  Dockerfile | Dockerfile.chatmail
#   tag         Local image tag, e.g. noombat-server:release
#   version     Defaults to $NOOMBAT_VERSION, else `git describe`
#   commit      Defaults to $NOOMBAT_COMMIT, else `git rev-parse HEAD`

set -eu

DOCKERFILE="${1:?dockerfile required}"
TAG="${2:?tag required}"
VERSION="${3:-${NOOMBAT_VERSION:-}}"
COMMIT="${4:-${NOOMBAT_COMMIT:-}}"

if [ -z "$VERSION" ]; then
    VERSION=$(git describe --tags --always --dirty 2>/dev/null || echo unknown)
fi
if [ -z "$COMMIT" ]; then
    COMMIT=$(git rev-parse HEAD 2>/dev/null || echo unknown)
fi

echo "Building $TAG from $DOCKERFILE (version=$VERSION commit=$COMMIT)"

docker build \
    --file "$DOCKERFILE" \
    --build-arg "NOOMBAT_VERSION=$VERSION" \
    --build-arg "NOOMBAT_COMMIT=$COMMIT" \
    --tag "$TAG" \
    .

echo "Built $TAG ($(docker image inspect --format '{{.Id}}' "$TAG"))"
