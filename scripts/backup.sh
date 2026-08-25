#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
#
# Backup script for a Noombat Compose deployment.
#
# Usage:
#   ./scripts/backup.sh /path/to/backup/dir
#
# Produces:
#   <dir>/noombat-pg-<date>.sql.gz        PostgreSQL dump
#   <dir>/noombat-meili-<date>.tar.gz     Meilisearch data snapshot
#   <dir>/noombat-chatmail-<date>.tar.gz  Chatmail maildir archive
#   <dir>/noombat-media-<date>.tar.gz     Uploaded media, when stored locally
#
# Not covered here: the `caddy-data` volume, which holds the ACME account
# key and the relay certificate. It has its own script,
# scripts/backup-caddy-data.sh, and needs running on the same schedule.

set -euo pipefail

BACKUP_DIR="${1:?Usage: $0 /path/to/backup/dir}"
DATE="$(date +%Y%m%d-%H%M%S)"

mkdir -p "$BACKUP_DIR"

echo "==> Dumping PostgreSQL..."
DB_CONTAINER="$(podman ps --format '{{.Names}}' | grep -E '[-_]db[-_]' | head -1)"
if [ -z "$DB_CONTAINER" ]; then
    echo "    ERROR: could not find the PostgreSQL container. Is the Compose stack running?" >&2
    exit 1
fi
podman exec "$DB_CONTAINER" pg_dump -U noombat noombat \
    | gzip > "$BACKUP_DIR/noombat-pg-$DATE.sql.gz"

echo "==> Snapshotting Meilisearch data..."
# The volume name depends on the compose project; default is "noombat_meili-data".
MEILI_VOLUME="$(podman volume ls --format '{{.Name}}' | grep meili-data | head -1)"
if [ -n "$MEILI_VOLUME" ]; then
    MEILI_MOUNT="$(podman volume inspect "$MEILI_VOLUME" --format '{{.Mountpoint}}')"
    tar -czf "$BACKUP_DIR/noombat-meili-$DATE.tar.gz" -C "$MEILI_MOUNT" .
else
    echo "    (Meilisearch volume not found; skipping.)"
fi

echo "==> Archiving Chatmail maildirs..."
CHATMAIL_VOLUME="$(podman volume ls --format '{{.Name}}' | grep chatmail-data | head -1)"
if [ -n "$CHATMAIL_VOLUME" ]; then
    CHATMAIL_MOUNT="$(podman volume inspect "$CHATMAIL_VOLUME" --format '{{.Mountpoint}}')"
    tar -czf "$BACKUP_DIR/noombat-chatmail-$DATE.tar.gz" -C "$CHATMAIL_MOUNT" .
else
    echo "    (Chatmail volume not found; skipping.)"
fi

echo "==> Archiving uploaded media..."
# Absent when the instance stores media in an S3-compatible bucket, which
# is a legitimate configuration and not a failed backup. The message says
# which of the two it is, because a silent skip is how avatars go
# unarchived for months without anyone noticing.
MEDIA_VOLUME="$(podman volume ls --format '{{.Name}}' | grep media-data | head -1)"
if [ -n "$MEDIA_VOLUME" ]; then
    MEDIA_MOUNT="$(podman volume inspect "$MEDIA_VOLUME" --format '{{.Mountpoint}}')"
    tar -czf "$BACKUP_DIR/noombat-media-$DATE.tar.gz" -C "$MEDIA_MOUNT" .
else
    echo "    (no media-data volume; expected if NOOMBAT_S3_ENDPOINT is set,"
    echo "     otherwise uploaded media is NOT being backed up.)"
fi

echo "==> Backup complete: $BACKUP_DIR"
ls -lh "$BACKUP_DIR"/noombat-*-"$DATE"*
