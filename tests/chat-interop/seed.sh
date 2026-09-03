#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
#
# Seed the two accounts the chat interop suite signs in as.
#
# Seeded in SQL rather than through `POST /api/v1/auth/register`, which
# refuses with 503 unless the instance has an SMTP relay: that path mints
# a password and awaits a recovery challenge, so an instance that cannot
# send mail does not offer it. The Chatmail relay in this stack is not
# that mailer. It carries end-to-end encrypted mail between people and
# never reads it, while instance mail is a plaintext the server composed,
# and the two are kept apart rather than given one configuration with two
# meanings. run.sh asserts the refusal instead of working around it.
#
# `auth_key_hash` is the Argon2id hash of the key in
# fixture-credential.sh, which is what `POST /api/v1/auth/login` verifies
# against. Regenerate the pair, and prove it still verifies, with:
#
#     cargo test -p noombat-identity interop_fixture
#
# Idempotent, so re-running against a live stack is safe.
#
# Usage:
#   tests/chat-interop/seed.sh [compose-file ...]
#
# Environment:
#   CHAT_INTEROP_PROJECT  compose project name (default chat-interop)
#   NOOMBAT_DOMAIN        authority the actor ids carry (default test.local)

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
cd "$REPO_ROOT"

# shellcheck source=tests/chat-interop/fixture-credential.sh
. "$HERE/fixture-credential.sh" || {
    echo "::error::cannot read $HERE/fixture-credential.sh" >&2
    exit 1
}

if [ "$#" -eq 0 ]; then
    set -- tests/chat-interop/compose.yml
fi
COMPOSE_ARGS=()
for f in "$@"; do
    COMPOSE_ARGS+=(-f "$f")
done

# The project name is pinned rather than derived from the directory, and
# has to match the one the stack was started with: the compose services
# name images the project prefixes, so a different project here reaches a
# different set of containers, or none.
PROJECT="${CHAT_INTEROP_PROJECT:-chat-interop}"

# Matches NOOMBAT_DOMAIN in compose.yml. Ids are assembled the way
# `create_actor` assembles them, so a seeded actor is indistinguishable
# from a registered one.
DOMAIN="${NOOMBAT_DOMAIN:-test.local}"

# Matches the credentials in compose.yml.
DB_USER=chatinterop
DB_NAME=chatinterop

compose() { docker compose -p "$PROJECT" "${COMPOSE_ARGS[@]}" "$@"; }
psql_noombat() { compose exec -T db psql -U "$DB_USER" -d "$DB_NAME" "$@"; }

# A key pair per account, generated per run rather than committed. The
# chat suite never signs a federated delivery, so these are here because
# the column is NOT NULL and because an account that cannot federate at
# all is not the account the rest of the suite exercises.
#
# `private_key_pem` goes in as plaintext although compose.yml sets a KEK.
# `envelope::open` returns any value that is not valid Base64 unchanged,
# and a PEM is not, so the server reads back what was written. It logs a
# warning per read saying so.
KEY_DIR="$(mktemp -d)"
trap 'rm -rf "$KEY_DIR"' EXIT

seed_actor() {
    local username="$1" hash="$2"
    local ap_id="https://${DOMAIN}/users/${username}"

    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
        -out "$KEY_DIR/$username.pem" 2>/dev/null
    openssl rsa -in "$KEY_DIR/$username.pem" -pubout \
        -out "$KEY_DIR/$username.pub" 2>/dev/null
    local private_key public_key
    private_key="$(cat "$KEY_DIR/$username.pem")"
    public_key="$(cat "$KEY_DIR/$username.pub")"

    echo "Seeding ${username} as ${ap_id}"
    psql_noombat -v ON_ERROR_STOP=1 -q <<SQL
INSERT INTO actors
    (actor_type, ap_id, username, domain, public_key_pem, private_key_pem,
     is_local, auth_key_hash)
VALUES
    ('individual', '${ap_id}', '${username}', '${DOMAIN}',
     '${public_key}', '${private_key}', TRUE, '${hash}')
ON CONFLICT (ap_id) DO UPDATE
    SET auth_key_hash = EXCLUDED.auth_key_hash,
        public_key_pem = EXCLUDED.public_key_pem,
        private_key_pem = EXCLUDED.private_key_pem;
SQL
}

seed_actor alice "$CHAT_ALICE_AUTH_KEY_HASH"
seed_actor bob "$CHAT_BOB_AUTH_KEY_HASH"

# Assert rather than trust: a statement reports success against zero
# rows, and a missing credential leaves an account that exists and cannot
# sign in, which run.sh would report as a Chatmail failure several
# assertions later.
seeded=$(psql_noombat -tAc \
    "SELECT count(*) FROM actors
      WHERE is_local
        AND actor_status = 'active'
        AND auth_key_hash IS NOT NULL
        AND username IN ('alice', 'bob');" | tr -d '[:space:]')

if [ "$seeded" != "2" ]; then
    echo "::error::expected 2 seeded accounts with a credential, found ${seeded:-none}" >&2
    exit 1
fi

echo "Seeded alice and bob."
