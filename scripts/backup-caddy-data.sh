#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
#
# Back up Caddy's storage volume: the ACME account key and every
# certificate it holds.
#
# WHY THIS IS WORTH BACKING UP, when nothing else here is. The volume
# holds a private key that identifies this deployment to the certificate
# authority. Losing it is recoverable, in that Caddy registers a new
# account and issues again, but the reissue counts against Let's
# Encrypt's duplicate-certificate limit, which is five per week per exact
# set of names. A redeploy loop after losing the volume can therefore
# lock the relay out of a certificate for days, and the relay refuses to
# start without one.
#
# WHAT IS IN IT, and why the archive is treated as a secret:
#
#   caddy/acme/<ca>/users/<email>/<email>.key   the ACME account key
#   caddy/certificates/<ca>/<host>/<host>.key   one private key per host
#
# Anyone holding those key files can serve traffic as this instance for
# as long as the certificates are valid. The archive is written 0600 and
# belongs wherever the database backups belong, which is not beside them
# on the same host.
#
# Usage:
#   ./scripts/backup-caddy-data.sh [DESTINATION_DIR]
#
# Cron, daily, keeping fourteen days:
#   17 4 * * * /path/to/noombat/scripts/backup-caddy-data.sh /var/backups/caddy
#
# Minute 17 rather than 0: GitHub and most schedulers drop jobs queued at
# the top of the hour under load, and the same contention applies to a
# host running everything else on the hour.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

DESTINATION="${1:-${CADDY_BACKUP_DIR:-./backups/caddy}}"
KEEP_DAYS="${CADDY_BACKUP_KEEP_DAYS:-14}"
VOLUME="${CADDY_VOLUME:-noombat_caddy-data}"

# Refuse a volume that is not there. Docker creates an empty one on
# demand, so a mistyped name produces a valid archive of nothing, which
# is the backup that cannot be told from a good one until it is needed.
if ! docker volume inspect "$VOLUME" >/dev/null 2>&1; then
    echo "::error::no volume named '$VOLUME'" >&2
    echo "  List them with: docker volume ls" >&2
    echo "  Override with:  CADDY_VOLUME=<name> $0" >&2
    exit 1
fi

mkdir -p "$DESTINATION"

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
archive="$DESTINATION/caddy-data-$stamp.tar.gz"

# Read the volume through a throwaway container rather than reaching into
# /var/lib/docker: the path is not stable across engines, and on a
# rootless or Podman host it does not exist at all.
#
# The image is the one already pulled for the reverse proxy, so this adds
# no download and no digest to track.
#
# The archive is streamed to stdout and redirected, rather than written
# through a bind mount. A container writing into a mounted directory
# writes as root, and the host user then cannot chmod its own backup.
umask 077
docker run --rm \
    -v "$VOLUME:/data:ro" \
    docker.io/library/caddy:2-alpine@sha256:5f5c8640aae01df9654968d946d8f1a56c497f1dd5c5cda4cf95ab7c14d58648 \
    tar -czf - -C /data . > "$archive"

# Assert the archive contains a key, rather than that tar exited 0. An
# empty or wrong volume produces a valid, useless archive: 45 bytes of
# gzip header that restores nothing, and a backup that cannot be
# distinguished from a good one until it is needed.
keys="$(tar -tzf "$archive" | grep -c '\.key$' || true)"
if [ "$keys" -eq 0 ]; then
    echo "::error::$archive holds no private key, so it would restore nothing" >&2
    echo "  Volume read: $VOLUME" >&2
    echo "  Check the volume name with: docker volume ls" >&2
    rm -f "$archive"
    exit 1
fi

echo "  $archive"
echo "  $keys key(s), $(du -h "$archive" | cut -f1)"

# Prune after a successful write, never before: a failed backup that had
# already deleted its predecessors leaves nothing at all.
if [ "$KEEP_DAYS" -gt 0 ]; then
    pruned="$(find "$DESTINATION" -name 'caddy-data-*.tar.gz' \
        -mtime "+$KEEP_DAYS" -print -delete | wc -l)"
    [ "$pruned" -gt 0 ] && echo "  pruned $pruned archive(s) older than ${KEEP_DAYS}d"
fi

exit 0
