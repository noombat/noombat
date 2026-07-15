#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

# Interoperability test runner for Noombat.
#
# Usage:
#   tests/interop/run.sh <noombat_url> <gotosocial_url>
#
# Examples:
#   # CI (HTTP, services on the runner network):
#   tests/interop/run.sh http://localhost:8443 http://gotosocial:8080
#
#   # Local (HTTPS via Caddy, after `docker compose up`):
#   tests/interop/run.sh https://noombat.local:8443 https://gotosocial.local:8443
#
# When no arguments are given, the script exits with usage help.
#
# Exit codes:
#   0: all tests passed
#   1: one or more tests failed

set -u

if [ $# -lt 2 ]; then
    echo "Usage: $0 <noombat_url> <gotosocial_url>"
    exit 1
fi

NOOMBAT="$1"
GOTOSOCIAL="$2"

# Additional curl flags, e.g. CURL_OPTS="--insecure" for self-signed
# certs in the local (Compose+Caddy) environment.
CURL_OPTS="${CURL_OPTS:-}"

PASS=0
FAIL=0
SKIP=0

pass() { PASS=$((PASS + 1)); printf "  \033[32mPASS\033[0m  %s\n" "$1"; }
fail() { FAIL=$((FAIL + 1)); printf "  \033[31mFAIL\033[0m  %s\n" "$1"; }
skip() { SKIP=$((SKIP + 1)); printf "  \033[33mSKIP\033[0m  %s\n" "$1"; }

# ..... WAIT FOR SERVICES .....

wait_for() {
    local name="$1" url="$2" max=60 i=0
    printf "Waiting for %s..." "$name"
    while ! curl $CURL_OPTS -sf -o /dev/null "$url" 2>/dev/null; do
        i=$((i + 1))
        if [ "$i" -ge "$max" ]; then
            printf " TIMEOUT\n"
            fail "$name did not become ready within ${max}s"
            return 1
        fi
        sleep 1
        printf "."
    done
    printf " ready (%ds)\n" "$i"
    return 0
}

# ..... TEST CASES .....

echo ""
echo "=============================="
echo "  Noombat Interoperability Tests"
echo "=============================="
echo ""

wait_for "Noombat" "$NOOMBAT/healthz" || exit 1

# GotoSocial may not be available (e.g. image pull failure).
GTS_AVAILABLE=true
wait_for "GotoSocial" "$GOTOSOCIAL/readyz" || GTS_AVAILABLE=false

echo ""
echo "--- Noombat S2S Protocol ---"
echo ""

# 1. WebFinger.
echo "WebFinger:"
NOOMBAT_HOST="${NOOMBAT#*://}"
NOOMBAT_HOST="${NOOMBAT_HOST%/}"
NOOMBAT_DOMAIN="${NOOMBAT_HOST%%:*}"
BODY=$(curl $CURL_OPTS -sf "$NOOMBAT/.well-known/webfinger?resource=acct:alice@${NOOMBAT_DOMAIN}" 2>/dev/null)
if echo "$BODY" | grep -q '"subject"'; then
    pass "WebFinger returns a subject for the query"
else
    fail "WebFinger did not return a subject"
fi

# 2. NodeInfo well-known.
echo "NodeInfo:"
BODY=$(curl $CURL_OPTS -sf "$NOOMBAT/.well-known/nodeinfo" 2>/dev/null)
if echo "$BODY" | grep -q 'nodeinfo/2.1'; then
    pass "NodeInfo well-known advertises 2.1 endpoint"
else
    fail "NodeInfo well-known missing 2.1 link"
fi

# 3. NodeInfo 2.1 document.
BODY=$(curl $CURL_OPTS -sf "$NOOMBAT/nodeinfo/2.1" 2>/dev/null)
if echo "$BODY" | grep -q '"name":"noombat"'; then
    pass "NodeInfo 2.1 identifies software as noombat"
else
    fail "NodeInfo 2.1 software name incorrect"
fi

if echo "$BODY" | grep -q 'noombat:JobListing'; then
    pass "NodeInfo 2.1 includes supportedVocabulary"
else
    fail "NodeInfo 2.1 missing supportedVocabulary"
fi

# 4. Actor JSON.
echo "Actor fetch:"
BODY=$(curl $CURL_OPTS -sf -H "Accept: application/activity+json" \
    "$NOOMBAT/users/alice" 2>/dev/null)
if echo "$BODY" | grep -q '"Person"'; then
    pass "Actor returns type Person"
else
    fail "Actor did not return type Person"
fi

if echo "$BODY" | grep -q '"preferredUsername":"alice"'; then
    pass "Actor returns correct preferredUsername"
else
    fail "Actor preferredUsername incorrect"
fi

if echo "$BODY" | grep -q 'sharedInbox'; then
    pass "Actor includes endpoints.sharedInbox"
else
    fail "Actor missing endpoints.sharedInbox"
fi

if echo "$BODY" | grep -q 'publicKey'; then
    pass "Actor includes publicKey"
else
    fail "Actor missing publicKey"
fi

# 5. AP ID canonical format.
echo "AP ID format:"
AP_ID=$(echo "$BODY" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
EXPECTED_PREFIX="${NOOMBAT}/users/"
if echo "$AP_ID" | grep -q "^${EXPECTED_PREFIX}"; then
    pass "Actor AP ID uses the configured domain"
else
    fail "Actor AP ID incorrect: $AP_ID (expected prefix: $EXPECTED_PREFIX)"
fi

# 6. Outbox collection.
echo "Outbox:"
BODY=$(curl $CURL_OPTS -sf "$NOOMBAT/users/alice/outbox" 2>/dev/null)
if echo "$BODY" | grep -q '"OrderedCollection"'; then
    pass "Outbox returns OrderedCollection"
else
    fail "Outbox did not return OrderedCollection"
fi

# 7. Shared inbox route exists.
echo "Shared inbox:"
STATUS=$(curl $CURL_OPTS -s -o /dev/null -w "%{http_code}" \
    -X POST -H "Content-Type: application/activity+json" \
    -d '{}' "$NOOMBAT/inbox" 2>/dev/null)
# Expect 400 or 401 (bad signature), not 404 (route missing).
if [ "$STATUS" != "404" ] && [ "$STATUS" != "000" ]; then
    pass "Shared inbox route exists (HTTP $STATUS)"
else
    fail "Shared inbox route returned $STATUS (expected non-404)"
fi

# ..... GotoSocial cross-instance checks .....

echo ""
echo "--- GotoSocial Interop ---"
echo ""

if ! $GTS_AVAILABLE; then
    skip "GotoSocial not available; skipping cross-instance tests"
else
    # 8. GotoSocial NodeInfo.
    echo "GotoSocial NodeInfo:"
    BODY=$(curl $CURL_OPTS -sf "$GOTOSOCIAL/nodeinfo/2.0" 2>/dev/null)
    if echo "$BODY" | grep -q '"gotosocial"'; then
        pass "GotoSocial NodeInfo identifies software"
    else
        fail "GotoSocial NodeInfo software name incorrect"
    fi

    # 9. GotoSocial WebFinger (only if a user exists).
    echo "GotoSocial WebFinger:"
    GTS_HOST="${GOTOSOCIAL#*://}"
    GTS_HOST="${GTS_HOST%/}"
    GTS_DOMAIN="${GTS_HOST%%:*}"
    BODY=$(curl $CURL_OPTS -sf "$GOTOSOCIAL/.well-known/webfinger?resource=acct:admin@${GTS_DOMAIN}" 2>/dev/null)
    if echo "$BODY" | grep -q '"subject"'; then
        pass "GotoSocial WebFinger returns a subject"
    else
        skip "GotoSocial WebFinger: no user found (account seeding required)"
    fi

    # 10. GotoSocial actor fetch (only if WebFinger returned a link).
    ACTOR_LINK=$(echo "$BODY" | grep -o '"href":"[^"]*"' | grep 'users' | head -1 | cut -d'"' -f4)
    if [ -n "$ACTOR_LINK" ]; then
        echo "GotoSocial actor:"
        ACTOR_BODY=$(curl $CURL_OPTS -sf -H "Accept: application/activity+json" "$ACTOR_LINK" 2>/dev/null)
        if echo "$ACTOR_BODY" | grep -q '"Person"'; then
            pass "GotoSocial actor returns type Person"
        else
            fail "GotoSocial actor fetch failed"
        fi
    fi
fi

# ..... SUMMARY .....

echo ""
echo "=============================="
printf "  Results: \033[32m%d passed\033[0m" "$PASS"
if [ "$FAIL" -gt 0 ]; then
    printf ", \033[31m%d failed\033[0m" "$FAIL"
fi
if [ "$SKIP" -gt 0 ]; then
    printf ", \033[33m%d skipped\033[0m" "$SKIP"
fi
echo ""
echo "=============================="
echo ""

if [ "$FAIL" -gt 0 ]; then
    exit 1
else
    exit 0
fi
