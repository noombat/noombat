#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
#
# Keep the relay's certificate current, and reload the daemons when it
# changes.
#
# Renewal is the half of certificate management that fails silently.
# Postfix and Dovecot read the chain once, at startup, so a renewed file
# changes nothing they serve: they keep presenting the expired chain
# until something reloads them. The relay reports healthy throughout, and
# the only symptom is clients refusing to connect, up to ninety days
# after the deployment that caused it.
#
# Two jobs, in one supervised loop:
#
#   IMPORT   When CHATMAIL_CADDY_DATA names Caddy's storage, copy the
#            certificate Caddy holds for MAIL_DOMAIN into the paths
#            Postfix and Dovecot are configured with. Caddy owns
#            acquisition and renewal; the daemons keep stable paths and
#            need no knowledge of ACME.
#
#   RELOAD   Whenever the live certificate changes, by import or by any
#            other means, reload both daemons.
#
# Watching rather than being called means the reload works whatever
# delivered the certificate: Caddy, an operator dropping a file in, or an
# ACME client on the host.

set -u

CERT_FILE="${CHATMAIL_CERT_FILE:-/etc/ssl/certs/chatmail.pem}"
KEY_FILE="${CHATMAIL_KEY_FILE:-/etc/ssl/private/chatmail.key}"
CADDY_DATA="${CHATMAIL_CADDY_DATA:-}"
INTERVAL="${CHATMAIL_CERT_WATCH_INTERVAL:-300}"

fingerprint() {
    sha256sum "$1" 2>/dev/null | cut -d' ' -f1
}

# Caddy files each certificate under the directory of the ACME endpoint
# that issued it, so the glob covers a production endpoint, a staging one
# and the local Pebble alike, and does not have to be told which is in
# use. Newest wins, because a renewal writes a second directory rather
# than replacing the first when the endpoint changes.
caddy_certificate() {
    [ -n "$CADDY_DATA" ] || return 1
    ls -1t "$CADDY_DATA"/caddy/certificates/*/"$MAIL_DOMAIN"/"$MAIL_DOMAIN".crt \
        2>/dev/null | head -1
}

import_from_caddy() {
    src_crt="$(caddy_certificate)" || return 1
    [ -n "$src_crt" ] || return 1
    src_key="${src_crt%.crt}.key"
    [ -f "$src_key" ] || return 1

    # Compare before writing. An unconditional copy would change the
    # mtime every pass and, if the reload keyed off that, reload the
    # daemons every five minutes forever.
    [ "$(fingerprint "$src_crt")" = "$(fingerprint "$CERT_FILE")" ] && return 1

    echo "[cert-watch] importing $src_crt"
    # Write through a temporary file in the same directory and rename, so
    # a reader never sees a half-written chain. The key first: a chain
    # newer than its key is the pair that fails.
    if ! { cp "$src_key" "$KEY_FILE.tmp" &&
        chmod 640 "$KEY_FILE.tmp" &&
        mv "$KEY_FILE.tmp" "$KEY_FILE"; }; then
        echo "[cert-watch] could not install the key; leaving the pair alone" >&2
        rm -f "$KEY_FILE.tmp"
        return 1
    fi
    if ! { cp "$src_crt" "$CERT_FILE.tmp" &&
        chmod 644 "$CERT_FILE.tmp" &&
        mv "$CERT_FILE.tmp" "$CERT_FILE"; }; then
        echo "[cert-watch] could not install the chain" >&2
        rm -f "$CERT_FILE.tmp"
        return 1
    fi
    return 0
}

: "${MAIL_DOMAIN:?MAIL_DOMAIN must be set}"

# `--import` is the entrypoint's use: try once, say whether a usable
# certificate is now in place, and reload nothing, because the daemons
# this would reload have not started yet.
if [ "${1:-}" = "--import" ]; then
    import_from_caddy
    [ -s "$CERT_FILE" ] && [ -s "$KEY_FILE" ]
    exit $?
fi

last="$(fingerprint "$CERT_FILE")"
if [ -z "$last" ]; then
    echo "[cert-watch] $CERT_FILE is unreadable; watching for it to appear" >&2
fi
if [ -n "$CADDY_DATA" ]; then
    echo "[cert-watch] importing $MAIL_DOMAIN from $CADDY_DATA, checking every ${INTERVAL}s"
else
    echo "[cert-watch] watching $CERT_FILE every ${INTERVAL}s (no Caddy storage configured)"
fi

while sleep "$INTERVAL"; do
    import_from_caddy

    current="$(fingerprint "$CERT_FILE")"

    # Empty means unreadable, which is what a renewal caught mid-write
    # looks like. Reloading against a half-written file would take the
    # daemons down for a condition that resolves itself, so leave them
    # alone and look again next time.
    [ -n "$current" ] || continue
    [ "$current" = "$last" ] && continue

    echo "[cert-watch] certificate changed, reloading Postfix and Dovecot"

    # Report each failure separately, and keep the old fingerprint unless
    # both succeeded so the next pass retries. Recording a failed reload
    # as done is the state where the daemons serve an expired chain and
    # nothing ever tries again.
    reloaded=0
    if postfix reload; then
        reloaded=$((reloaded + 1))
    else
        echo "[cert-watch] postfix reload FAILED, still serving the old chain" >&2
    fi
    if doveadm reload; then
        reloaded=$((reloaded + 1))
    else
        echo "[cert-watch] doveadm reload FAILED, still serving the old chain" >&2
    fi

    if [ "$reloaded" -eq 2 ]; then
        last="$current"
        echo "[cert-watch] reloaded both daemons"
    fi
done
