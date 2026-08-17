#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
#
# Seed the local actor that `run.sh` federates with.
#
# `run.sh` asserts against `alice`: WebFinger for `acct:alice@<domain>`,
# the actor document at `/users/alice`, and that actor's outbox. None of
# those exist until somebody creates the row, so this has to run between
# `compose up` and `run.sh`.
#
# It lives here rather than inline in the workflow because the ap_id has
# to match the domain the server believes it has, and that domain differs
# per topology. The CI job used to inline an INSERT with
# `http://localhost:8443/users/alice`, which was correct only for the
# native-on-localhost setup it was written for and silently wrong for the
# Compose stack, where the server runs as `noombat.local` behind Caddy.
# Deriving it from one place is what stops the two drifting again.
#
# Idempotent: `ON CONFLICT (ap_id) DO NOTHING`, so re-running is safe.
#
# Usage:
#   tests/interop/seed.sh [compose-file ...]
#
# Takes as many compose files as the stack was started with, so that
# `compose exec` resolves against the same configuration rather than
# relying on the project name happening to match:
#
#   tests/interop/seed.sh tests/interop/compose.yml tests/interop/compose.latest.yml
#
# Environment:
#   NOOMBAT_DOMAIN  domain the server serves as   (default noombat.local)
#   NOOMBAT_PORT    port the actor URLs carry     (default 8443)
#   NOOMBAT_SCHEME  scheme the actor URLs carry   (default https)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

if [ "$#" -eq 0 ]; then
    set -- tests/interop/compose.yml
fi
COMPOSE_ARGS=()
for f in "$@"; do
    COMPOSE_ARGS+=(-f "$f")
done
DOMAIN="${NOOMBAT_DOMAIN:-noombat.local}"
PORT="${NOOMBAT_PORT:-8443}"
SCHEME="${NOOMBAT_SCHEME:-https}"

AP_ID="${SCHEME}://${DOMAIN}:${PORT}/users/alice"

# A fixed key rather than a generated one: the point is a stable actor
# document, and interop asserts on the document rather than on signatures
# made with this key.
PUBLIC_KEY='-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAngu+UeqfsU3AJHhVHk2k
MEjaIOzbOWRPu1TsqUpGq0IX/mhQUC6/mkF9+H27ziERaM+77JB7MQ9q1ITLnukj
TlmQhgUrsstMV1ZiU+9WqJ+NmlpdoQ4zVFXEf7IJHmZ+mYxei/qhVrnBDvV4e1KR
iOTxUYyqWrI7BFGrA3eR22zb9K5/CwOuTw0uYGGhkxfMalBXd4k1AyYGsHo/riQY
xOCucw31jlUavoajo3CPXWXgCi+F6mumsIm7snaFNiCG8d8jqXZ8aSC8JcGImf95
Gg3J3oGE9ZiAue0WmYC+oMDzLBJtqN0V/c1OsU7PsP8+8fllvlfBluhuTfR/O19J
RQIDAQAB
-----END PUBLIC KEY-----'

echo "Seeding alice as ${AP_ID}"

docker compose "${COMPOSE_ARGS[@]}" exec -T db \
    psql -v ON_ERROR_STOP=1 -U noombat -d noombat <<SQL
INSERT INTO actors
    (actor_type, ap_id, username, domain, public_key_pem, is_local)
VALUES
    ('individual', '${AP_ID}', 'alice', '${DOMAIN}', '${PUBLIC_KEY}', TRUE)
ON CONFLICT (ap_id) DO NOTHING;
SQL

# Assert rather than trust. A silent zero-row insert leaves run.sh to
# fail later with a WebFinger 404, which reads like an interop defect
# rather than a missing fixture.
count=$(docker compose "${COMPOSE_ARGS[@]}" exec -T db \
    psql -tA -U noombat -d noombat \
    -c "SELECT count(*) FROM actors WHERE ap_id = '${AP_ID}';")

if [ "$(echo "$count" | tr -d '[:space:]')" != "1" ]; then
    echo "error: alice was not seeded; found $count row(s) for ${AP_ID}" >&2
    exit 1
fi

echo "Seeded."
