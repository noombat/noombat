#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

# Interoperability test runner for Noombat.
#
# Prerequisites:
#   docker compose -f tests/interop/compose.yml up -d --build
#
# This script waits for both Noombat and GotoSocial to become
# healthy, seeds test data, and runs a suite of S2S protocol-level
# checks against both servers.
#
# Exit codes:
#   0: all tests passed
#   1: one or more tests failed

set -euo pipefail

COMPOSE="docker compose -f tests/interop/compose.yml"
NOOMBAT="https://noombat.local:8443"
GOTOSOCIAL="https://gotosocial.local:8443"

# Caddy uses an internal CA; extract its root certificate for curl.
# The root CA PEM is written to the Caddy data volume at a known path.
CADDY_CA=""

PASS=0
FAIL=0
SKIP=0

pass() { PASS=$((PASS + 1)); printf "  \033[32mPASS\033[0m  %s\n" "$1"; }
fail() { FAIL=$((FAIL + 1)); printf "  \033[31mFAIL\033[0m  %s\n" "$1"; }
skip() { SKIP=$((SKIP + 1)); printf "  \033[33mSKIP\033[0m  %s\n" "$1"; }
info() { printf "  \033[36mINFO\033[0m  %s\n" "$1"; }

# curl wrapper that trusts the Caddy internal CA and resolves the
# .local test domains to 127.0.0.1 (the host, where Caddy's port 443
# is mapped to 8443). Without --resolve, curl would attempt a DNS
# lookup for noombat.local / gotosocial.local, which would fail.
CURL_RESOLVE=(
    --resolve "noombat.local:8443:127.0.0.1"
    --resolve "gotosocial.local:8443:127.0.0.1"
)

ccurl() {
    if [ -n "$CADDY_CA" ]; then
        curl --cacert "$CADDY_CA" "${CURL_RESOLVE[@]}" "$@"
    else
        curl --insecure "${CURL_RESOLVE[@]}" "$@"
    fi
}

# ..... WAIT FOR SERVICES .....

wait_for() {
    local name="$1" url="$2" max=60 i=0
    printf "Waiting for %s..." "$name"
    while ! ccurl -sf -o /dev/null "$url" 2>/dev/null; do
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

extract_caddy_ca() {
    # Caddy stores its root CA at /data/caddy/pki/authorities/local/root.crt.
    local tmp
    tmp=$(mktemp)
    if $COMPOSE cp caddy:/data/caddy/pki/authorities/local/root.crt "$tmp" 2>/dev/null; then
        CADDY_CA="$tmp"
        info "Caddy internal CA extracted to $tmp"
    else
        info "Could not extract Caddy CA; using --insecure"
    fi
}

# ..... SEED TEST DATA .....

seed_noombat() {
    info "Seeding Noombat test actor..."
    # Create a test actor via the admin token. The actor creation
    # endpoint is the C2S outbox POST (which requires the admin token
    # and auto-creates the actor if not already present). For seeding
    # we use a direct SQL insert via the database container.
    $COMPOSE exec -T db psql -U noombat -d noombat -c "
        INSERT INTO actors
            (actor_type, ap_id, username, domain, public_key_pem, is_local)
        VALUES
            ('individual', 'https://noombat.local/users/alice',
             'alice', 'noombat.local',
             '-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAngu+UeqfsU3AJHhVHk2k
MEjaIOzbOWRPu1TsqUpGq0IX/mhQUC6/mkF9+H27ziERaM+77JB7MQ9q1ITLnukj
TlmQhgUrsstMV1ZiU+9WqJ+NmlpdoQ4zVFXEf7IJHmZ+mYxei/qhVrnBDvV4e1KR
iOTxUYyqWrI7BFGrA3eR22zb9K5/CwOuTw0uYGGhkxfMalBXd4k1AyYGsHo/riQY
xOCucw31jlUavoajo3CPXWXgCi+F6mumsIm7snaFNiCG8d8jqXZ8aSC8JcGImf95
Gg3J3oGE9ZiAue0WmYC+oMDzLBJtqN0V/c1OsU7PsP8+8fllvlfBluhuTfR/O19J
RQIDAQAB
-----END PUBLIC KEY-----',
             TRUE)
        ON CONFLICT (ap_id) DO NOTHING;
    " > /dev/null 2>&1
}

seed_gotosocial() {
    info "Seeding GotoSocial test account..."
    # GotoSocial provides a CLI for account creation.
    $COMPOSE exec -T gotosocial \
        /gotosocial/gotosocial admin account create \
        --username bob \
        --email bob@gotosocial.local \
        --password 'TestPassword123!' 2>/dev/null || true

    $COMPOSE exec -T gotosocial \
        /gotosocial/gotosocial admin account confirm \
        --username bob 2>/dev/null || true
}

# ..... TEST CASES .....

echo ""
echo "=============================="
echo "  Noombat Interoperability Tests"
echo "=============================="
echo ""

extract_caddy_ca
wait_for "Noombat" "$NOOMBAT/healthz" || exit 1

# GotoSocial may not be available (e.g. image pull failure in CI).
GTS_AVAILABLE=true
wait_for "GotoSocial" "$GOTOSOCIAL/nodeinfo/2.0" || GTS_AVAILABLE=false

seed_noombat
if $GTS_AVAILABLE; then
    seed_gotosocial
fi

echo ""
echo "--- Noombat S2S Protocol ---"
echo ""

# 1. WebFinger.
echo "WebFinger:"
BODY=$(ccurl -sf "$NOOMBAT/.well-known/webfinger?resource=acct:alice@noombat.local" 2>/dev/null) || true
if echo "$BODY" | grep -q '"acct:alice@noombat.local"'; then
    pass "WebFinger returns correct subject for alice"
else
    fail "WebFinger did not return correct subject"
fi

# 2. NodeInfo well-known.
echo "NodeInfo:"
BODY=$(ccurl -sf "$NOOMBAT/.well-known/nodeinfo" 2>/dev/null) || true
if echo "$BODY" | grep -q 'nodeinfo/2.1'; then
    pass "NodeInfo well-known advertises 2.1 endpoint"
else
    fail "NodeInfo well-known missing 2.1 link"
fi

# 3. NodeInfo 2.1 document.
BODY=$(ccurl -sf "$NOOMBAT/nodeinfo/2.1" 2>/dev/null) || true
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
BODY=$(ccurl -sf -H "Accept: application/activity+json" \
    "$NOOMBAT/users/alice" 2>/dev/null) || true
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

# 5. Outbox collection.
echo "Outbox:"
BODY=$(ccurl -sf "$NOOMBAT/users/alice/outbox" 2>/dev/null) || true
if echo "$BODY" | grep -q '"OrderedCollection"'; then
    pass "Outbox returns OrderedCollection"
else
    fail "Outbox did not return OrderedCollection"
fi

# 6. Shared inbox route exists.
echo "Shared inbox:"
STATUS=$(ccurl -s -o /dev/null -w "%{http_code}" \
    -X POST -H "Content-Type: application/activity+json" \
    -d '{}' "$NOOMBAT/inbox" 2>/dev/null) || true
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
    # 7. GotoSocial NodeInfo.
    echo "GotoSocial NodeInfo:"
    BODY=$(ccurl -sf "$GOTOSOCIAL/nodeinfo/2.0" 2>/dev/null) || true
    if echo "$BODY" | grep -q '"gotosocial"'; then
        pass "GotoSocial NodeInfo identifies software"
    else
        fail "GotoSocial NodeInfo software name incorrect"
    fi

    # 8. GotoSocial WebFinger for seeded account.
    echo "GotoSocial WebFinger:"
    BODY=$(ccurl -sf "$GOTOSOCIAL/.well-known/webfinger?resource=acct:bob@gotosocial.local" 2>/dev/null) || true
    if echo "$BODY" | grep -q 'bob@gotosocial.local'; then
        pass "GotoSocial WebFinger returns correct subject for bob"
    else
        fail "GotoSocial WebFinger incorrect for bob"
    fi

    # 9. Noombat actor AP ID uses the correct domain (no port leak).
    # Verifies that the AP ID in the actor JSON uses the canonical
    # domain (noombat.local) without the host-mapped port (8443),
    # which is essential for cross-instance federation.
    echo "AP ID format:"
    BODY=$(ccurl -sf -H "Accept: application/activity+json" \
        "$NOOMBAT/users/alice" 2>/dev/null) || true
    AP_ID=$(echo "$BODY" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
    if [ "$AP_ID" = "https://noombat.local/users/alice" ]; then
        pass "Noombat actor AP ID uses canonical domain (no port)"
    else
        fail "Noombat actor AP ID incorrect: $AP_ID"
    fi

    # 10. Noombat can fetch GotoSocial actor.
    BODY=$(ccurl -sf -H "Accept: application/activity+json" \
        "$GOTOSOCIAL/users/bob" 2>/dev/null) || true
    if echo "$BODY" | grep -q '"preferredUsername":"bob"'; then
        pass "GotoSocial actor fetchable with correct preferredUsername"
    else
        fail "GotoSocial actor fetch failed or preferredUsername incorrect"
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

# Clean up temporary CA file.
if [ -n "$CADDY_CA" ] && [ -f "$CADDY_CA" ]; then
    rm -f "$CADDY_CA"
fi

if [ "$FAIL" -gt 0 ]; then
    exit 1
else
    exit 0
fi
