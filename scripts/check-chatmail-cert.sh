#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
#
# Exercise the relay's certificate path against a local ACME server.
#
# WHAT THIS PROVES, and why it could not be proved before. The relay's
# certificate is acquired by Caddy, imported by the `cert-watch` service,
# and served by Postfix and Dovecot, and the reload after a renewal is
# the step that fails silently: both daemons read the chain once, so a
# renewed file changes nothing they serve and the relay reports healthy
# while every client fails the handshake. None of that could run outside
# a real deployment, because `chat.localhost` can never hold a chain any
# ACME server will issue.
#
# Pebble issues one, so the whole path runs here.
#
# THE DOMAIN IS `noombat.test`, NOT `localhost`. Caddy routes any
# `.localhost` name to its own internal CA whatever `acme_ca` says, so a
# localhost run silently exercises the internal issuer instead of ACME
# and proves nothing about the production path. This was measured: the
# first run of this harness reported `"issuer":"local"` for
# `chat.localhost` and `"issuer":"pebble:14000-dir"` for
# `chat.noombat.test`.
#
# Usage:
#   ./scripts/check-chatmail-cert.sh          run and tear down
#   KEEP=1 ./scripts/check-chatmail-cert.sh   leave the stack up

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

export NOOMBAT_DOMAIN="${NOOMBAT_DOMAIN:-noombat.test}"
CHAT_DOMAIN="chat.${NOOMBAT_DOMAIN}"
PEBBLE_IMAGE="ghcr.io/letsencrypt/pebble:latest@sha256:ddf230642b1a584f519f32e347de1b05a6e4c1f6c35c1863b33effeab5f78199"
PEBBLE_DIR="$REPO_ROOT/tests/acme/.pebble"
COMPOSE=(docker compose -f compose.yml -f compose.acme.yml)

say() { printf '  %s\n' "$*"; }
fail() { printf '  FAIL: %s\n' "$*" >&2; FAILURES=$((FAILURES + 1)); }
FAILURES=0

cleanup() {
    if [ -z "${KEEP:-}" ]; then
        "${COMPOSE[@]}" down -v >/dev/null 2>&1
        # The extracted CA goes too. It is regenerated in a second, and
        # left behind it fails `reuse lint`, so running this gate would
        # break another one.
        rm -rf "$PEBBLE_DIR"
        say "stack removed"
    else
        say "stack left up (KEEP is set); remove it with:"
        say "  docker compose -f compose.yml -f compose.acme.yml down -v"
    fi
}
trap cleanup EXIT

# ..... Pebble's own CA .....

# Pebble serves its ACME API under a certificate signed by a CA that it
# does not publish over HTTP, so Caddy cannot fetch it the way it fetches
# the issuing root. Extracting it from the image keeps this repository
# free of certificates.
say "extracting Pebble's API certificate authority"
mkdir -p "$PEBBLE_DIR"
container="$(docker create "$PEBBLE_IMAGE" 2>/dev/null)"
if [ -z "$container" ]; then
    fail "could not create a container from $PEBBLE_IMAGE"
    exit 1
fi
docker cp "$container:/test/certs/pebble.minica.pem" "$PEBBLE_DIR/minica.pem" >/dev/null 2>&1
docker rm "$container" >/dev/null 2>&1
if [ ! -s "$PEBBLE_DIR/minica.pem" ]; then
    fail "pebble.minica.pem was not extracted; nothing below would be meaningful"
    exit 1
fi
say "extracted $(wc -c < "$PEBBLE_DIR/minica.pem") bytes"

# ..... Acquisition .....

say "starting Pebble and Caddy for ${CHAT_DOMAIN}"
"${COMPOSE[@]}" up -d pebble caddy >/dev/null 2>&1 || {
    fail "compose up failed"
    exit 1
}

say "waiting for Caddy to obtain a certificate"
issued=""
for _ in $(seq 1 60); do
    if "${COMPOSE[@]}" logs caddy 2>/dev/null \
        | grep -q "certificate obtained successfully.*${CHAT_DOMAIN}"; then
        issued=yes
        break
    fi
    sleep 2
done

if [ -z "$issued" ]; then
    fail "Caddy obtained no certificate for ${CHAT_DOMAIN} in 120s"
    "${COMPOSE[@]}" logs caddy 2>&1 | grep -iE "error|acme" | tail -10 >&2
    exit 1
fi

# The issuer, not merely the fact of a certificate. Caddy's internal CA
# also reports "obtained successfully", so without this assertion a run
# that never spoke ACME at all would pass.
issuer="$("${COMPOSE[@]}" logs caddy 2>/dev/null \
    | grep "certificate obtained successfully" \
    | grep "${CHAT_DOMAIN}" \
    | tail -1 \
    | sed -n 's/.*"issuer":"\([^"]*\)".*/\1/p')"
case "$issuer" in
    pebble*) say "issued by ${issuer}" ;;
    "")      fail "no issuer recorded, so the ACME path is unproven" ;;
    *)       fail "issued by '${issuer}', not the ACME server: the ACME path did not run" ;;
esac

# ..... Import .....

say "starting the relay, which must import rather than generate"
"${COMPOSE[@]}" up -d chatmail >/dev/null 2>&1

imported=""
for _ in $(seq 1 60); do
    if "${COMPOSE[@]}" logs chatmail 2>/dev/null \
        | grep -q "imported the certificate Caddy issued"; then
        imported=yes
        break
    fi
    sleep 2
done
[ -n "$imported" ] || fail "the relay did not import Caddy's certificate"

# What the relay serves must be what Caddy issued, not something it made
# for itself. Comparing the issuer distinguishes the two; comparing only
# that a certificate exists does not.
served_issuer="$("${COMPOSE[@]}" exec -T chatmail \
    openssl x509 -in /etc/ssl/certs/chatmail.pem -noout -issuer 2>/dev/null)"
case "$served_issuer" in
    *Pebble*) say "the relay serves a Pebble-issued chain" ;;
    "")       fail "could not read the relay's certificate" ;;
    *)        fail "the relay serves '${served_issuer}', which Pebble did not issue" ;;
esac

# ..... Reload .....

# The assertion this harness exists for: a renewal that is not followed
# by a reload leaves the expired chain in service with no other symptom.
#
# Renewal is forced at the source, by discarding what Caddy holds.
# Editing the relay's own copy proves nothing: the importer restores it
# on the next pass, the daemons still hold what the file contains, and
# declining to reload is then correct.
#
# Waited for in two stages, because Caddy backs off for a minute after a
# failed order. A single combined bound blames the reload for a slow
# renewal, which made this gate fail one run in two at 90s.
issued_before="$("${COMPOSE[@]}" logs caddy 2>/dev/null \
    | grep -c "certificate obtained successfully.*${CHAT_DOMAIN}")"
before_serial="$("${COMPOSE[@]}" exec -T chatmail \
    openssl x509 -in /etc/ssl/certs/chatmail.pem -noout -serial 2>/dev/null)"

say "forcing a renewal"
"${COMPOSE[@]}" exec -T caddy sh -c 'rm -rf /data/caddy/certificates' >/dev/null 2>&1
"${COMPOSE[@]}" restart caddy >/dev/null 2>&1

renewed=""
for _ in $(seq 1 90); do
    issued_now="$("${COMPOSE[@]}" logs caddy 2>/dev/null \
        | grep -c "certificate obtained successfully.*${CHAT_DOMAIN}")"
    if [ "$issued_now" -gt "$issued_before" ]; then
        renewed=yes
        break
    fi
    sleep 2
done
if [ -z "$renewed" ]; then
    fail "Caddy issued no replacement certificate in 180s, so the reload is untested"
    "${COMPOSE[@]}" logs caddy 2>&1 | grep -iE "error|retry" | tail -5 >&2
else
    reloaded=""
    for _ in $(seq 1 30); do
        if "${COMPOSE[@]}" logs chatmail 2>/dev/null | grep -q "reloaded both daemons"; then
            reloaded=yes
            break
        fi
        sleep 2
    done
    [ -n "$reloaded" ] || fail "the certificate was renewed and no reload followed"
fi

after_serial="$("${COMPOSE[@]}" exec -T chatmail \
    openssl x509 -in /etc/ssl/certs/chatmail.pem -noout -serial 2>/dev/null)"
if [ -z "$after_serial" ]; then
    fail "could not read the renewed certificate"
elif [ "$before_serial" = "$after_serial" ]; then
    fail "the serial did not change, so no renewal was imported: ${after_serial}"
else
    say "renewed ${before_serial#serial=} to ${after_serial#serial=}"
fi

# ..... Verdict .....

echo
if [ "$FAILURES" -gt 0 ]; then
    printf '::error::%d certificate-path check(s) failed\n' "$FAILURES" >&2
    exit 1
fi
say "acquisition, import and reload all ran against a local ACME server."
