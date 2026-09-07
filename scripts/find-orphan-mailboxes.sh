#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
#
# List Chatmail mailboxes on the relay that no Noombat account claims.
#
# A one-off, for deployments that ran the relay before account creation
# moved behind the admin sidecar. The checkpassword helper used to create
# a mailbox on first login, so anyone could bring an address into
# existence by attempting to log in. Removing that branch stops new
# mailboxes appearing; it does nothing about ones already there, and an
# existing directory blocks the real user forever: the create endpoint
# answers 409 and provisioning fails.
#
# Reports. It does not delete, because the two states it cannot tell
# apart both look like an orphan:
#
#   - a squatted address, which should be removed;
#   - a legitimate account whose `actors.chatmail_addr` was cleared by a
#     failed or half-finished provisioning, which holds real mail.
#
# Deleting the second loses a user's messages, so the decision is the
# operator's. `DELETE /admin/v1/accounts/{addr}` on the sidecar is how a
# confirmed squat is removed.
#
# Usage:
#   ./scripts/find-orphan-mailboxes.sh
#   VMAIL_CONTAINER=chatmail DB_CONTAINER=db ./scripts/find-orphan-mailboxes.sh
#   VMAIL_HOME=/home/vmail ./scripts/find-orphan-mailboxes.sh

set -uo pipefail

VMAIL_CONTAINER="${VMAIL_CONTAINER:-chatmail}"
DB_CONTAINER="${DB_CONTAINER:-db}"
VMAIL_HOME="${VMAIL_HOME:-/home/vmail}"
DB_USER="${DB_USER:-noombat}"
DB_NAME="${DB_NAME:-noombat}"

fatal() { printf 'error: %s\n' "$1" >&2; exit 2; }

command -v docker >/dev/null 2>&1 || fatal "docker is not on PATH"

docker inspect "$VMAIL_CONTAINER" >/dev/null 2>&1 \
    || fatal "no container named '$VMAIL_CONTAINER' (set VMAIL_CONTAINER)"
docker inspect "$DB_CONTAINER" >/dev/null 2>&1 \
    || fatal "no container named '$DB_CONTAINER' (set DB_CONTAINER)"

# One directory per address, and only those holding a password file: a
# directory without one authenticates nobody and is not an account.
ON_DISK=$(docker exec "$VMAIL_CONTAINER" sh -c \
    "find '$VMAIL_HOME' -mindepth 2 -maxdepth 2 -name password -printf '%h\n' 2>/dev/null | xargs -r -n1 basename")
DISK_STATUS=$?
if [ "$DISK_STATUS" -ne 0 ]; then
    fatal "could not list mailboxes in '$VMAIL_CONTAINER' (exit $DISK_STATUS)"
fi

IN_DB=$(docker exec "$DB_CONTAINER" psql -U "$DB_USER" -d "$DB_NAME" -tAc \
    "SELECT chatmail_addr FROM actors WHERE chatmail_addr IS NOT NULL;")
DB_STATUS=$?
if [ "$DB_STATUS" -ne 0 ]; then
    fatal "could not query '$DB_CONTAINER' (exit $DB_STATUS)"
fi

# Read the counts before comparing. An empty result from either side is
# the interesting case, not a clean bill of health: an empty database
# answer would report every mailbox as an orphan.
DISK_COUNT=$(printf '%s\n' "$ON_DISK" | grep -c . || true)
DB_COUNT=$(printf '%s\n' "$IN_DB" | grep -c . || true)

printf 'Mailboxes on the relay: %s\n' "$DISK_COUNT"
printf 'Addresses in the database: %s\n' "$DB_COUNT"
echo ""

if [ "$DISK_COUNT" -eq 0 ]; then
    echo "No mailboxes on the relay. Nothing to reconcile."
    exit 0
fi

if [ "$DB_COUNT" -eq 0 ]; then
    echo "The database reports no Chatmail addresses at all."
    echo "Refusing to call every mailbox an orphan on that basis: check that"
    echo "DB_CONTAINER, DB_USER and DB_NAME name the right database first."
    exit 2
fi

ORPHANS=$(printf '%s\n' "$ON_DISK" | grep -vxF -f <(printf '%s\n' "$IN_DB") || true)
ORPHAN_COUNT=$(printf '%s\n' "$ORPHANS" | grep -c . || true)

if [ "$ORPHAN_COUNT" -eq 0 ]; then
    echo "Every mailbox is claimed by an account. Nothing to do."
    exit 0
fi

printf 'Mailboxes no account claims: %s\n\n' "$ORPHAN_COUNT"
printf '%s\n' "$ORPHANS" | while IFS= read -r address; do
    [ -n "$address" ] || continue
    size=$(docker exec "$VMAIL_CONTAINER" du -sh "$VMAIL_HOME/$address" 2>/dev/null | cut -f1)
    messages=$(docker exec "$VMAIL_CONTAINER" sh -c \
        "find '$VMAIL_HOME/$address/Maildir' -type f -not -name password 2>/dev/null | wc -l")
    printf '  %-40s %6s  %s message(s)\n' "$address" "${size:-?}" "${messages:-?}"
done

cat <<'GUIDANCE'

Each line is a mailbox with no matching `actors.chatmail_addr`. A message
count of 0 and a recent creation date is the shape of a squat; anything
holding mail deserves a look before it is removed, because a legitimate
account whose provisioning half-finished looks identical from here.

To remove one, once you have decided:

  curl -X DELETE -H "Authorization: Bearer $CHATMAIL_ADMIN_SECRET" \
    https://<relay>:9100/admin/v1/accounts/<address>

That deletes the maildir and the password file, and blocks inbound
delivery to the address. It does not stop the address being created
again, and nothing does: creation is the sidecar's authenticated
endpoint, so re-creation is a deliberate act.
GUIDANCE

exit 1
