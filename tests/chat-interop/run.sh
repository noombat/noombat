#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

# Chat interoperability test runner for Noombat.
#
# Tests:
#         00. The Chatmail admin sidecar is serving.
#   01 - 03. Account registration (alice, bob, duplicate rejection).
#   04 - 05. Login (correct credentials, wrong credentials).
#   06 - 07. Chat WebSocket route existence, chat report endpoint.
#   08 - 09. Auth page rendering (login, register).
#   10 - 11. Closed federation checks (allowlisted domain, config).
#
# Usage:
#   tests/chat-interop/run.sh [noombat_url]
#
# Defaults to http://localhost:8443 when no argument is given.
#
# A skip exits non-zero when CI is set. Locally a skip is a convenience;
# under CI it is coverage that silently did not run.

set -u

NOOMBAT="${1:-http://localhost:8443}"
CURL_OPTS="${CURL_OPTS:-}"

PASS=0
FAIL=0
SKIP=0

pass() { PASS=$((PASS + 1)); printf "  \033[32mPASS\033[0m  %s\n" "$1"; }
fail() { FAIL=$((FAIL + 1)); printf "  \033[31mFAIL\033[0m  %s\n" "$1"; }
skip() { SKIP=$((SKIP + 1)); printf "  \033[33mSKIP\033[0m  %s\n" "$1"; }

# Generate a mock auth_key (64 hex chars). In CI this would use the
# real PBKDF2+HKDF derivation; for the shell test, a deterministic
# hex string suffices because the server hashes whatever it receives.
mock_auth_key() {
    local char="${1:-a}"
    printf '%064s' '' | tr ' ' "$char"
}

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

echo ""
echo "=============================="
echo "  Noombat Chat Interop Tests"
echo "=============================="
echo ""

wait_for "Noombat" "$NOOMBAT/healthz" || exit 1

# The Chatmail admin sidecar. Asserted here because nothing else notices
# when it is down: the container healthcheck is an IMAP NOOP, which
# Dovecot answers whether or not the sidecar is running, and the sidecar
# crash-looped in every shipped image for the life of the project without
# a single test failing. If this cannot be reached, password rotation,
# doveadm kick, maildir deletion and transport_maps are all dead.
# Every admin route requires the shared secret and there is no health
# route, so an unauthenticated 401 is the liveness signal: it proves the
# process is up and serving. A crash-loop gives a connection error
# instead, which is exactly what this exists to catch.
CHATMAIL_ADMIN="${CHATMAIL_ADMIN:-http://localhost:9100}"
ADMIN_CODE=$(curl $CURL_OPTS -s -o /dev/null -w '%{http_code}' \
  "$CHATMAIL_ADMIN/admin/v1/accounts/probe@example.invalid/exists" 2>/dev/null) || ADMIN_CODE="000"
if [ "$ADMIN_CODE" = "401" ]; then
    pass "Chatmail admin sidecar is serving (401 without the secret)"
else
    fail "Chatmail admin sidecar unreachable at $CHATMAIL_ADMIN (got '$ADMIN_CODE', expected 401)"
fi

# ..... Account Registration .....

echo ""
echo "--- Account Registration ---"
echo ""

AUTH_KEY_ALICE=$(mock_auth_key a)

# 1. Register alice.
BODY=$(curl $CURL_OPTS -sf -X POST \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"alice\",\"auth_key\":\"$AUTH_KEY_ALICE\"}" \
    "$NOOMBAT/api/v1/auth/register" 2>/dev/null)

if echo "$BODY" | grep -q '"access_token"'; then
    pass "Register alice: received session tokens"
    ALICE_TOKEN=$(echo "$BODY" | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4)
else
    fail "Register alice failed: $BODY"
    ALICE_TOKEN=""
fi

# 2. Register bob.
AUTH_KEY_BOB=$(mock_auth_key b)
BODY=$(curl $CURL_OPTS -sf -X POST \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"bob\",\"auth_key\":\"$AUTH_KEY_BOB\"}" \
    "$NOOMBAT/api/v1/auth/register" 2>/dev/null)

if echo "$BODY" | grep -q '"access_token"'; then
    pass "Register bob: received session tokens"
    BOB_TOKEN=$(echo "$BODY" | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4)
else
    fail "Register bob failed: $BODY"
    BOB_TOKEN=""
fi

# 3. Duplicate registration rejected.
BODY=$(curl $CURL_OPTS -s -X POST \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"alice\",\"auth_key\":\"$AUTH_KEY_ALICE\"}" \
    "$NOOMBAT/api/v1/auth/register" 2>/dev/null)

if echo "$BODY" | grep -qi "already"; then
    pass "Duplicate registration rejected"
else
    fail "Duplicate registration not rejected: $BODY"
fi

# ..... Login .....

echo ""
echo "--- Login ---"
echo ""

# 4. Login with correct credentials.
BODY=$(curl $CURL_OPTS -sf -X POST \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"alice\",\"auth_key\":\"$AUTH_KEY_ALICE\"}" \
    "$NOOMBAT/api/v1/auth/login" 2>/dev/null)

if echo "$BODY" | grep -q '"access_token"'; then
    pass "Login alice: received session tokens"
else
    fail "Login alice failed: $BODY"
fi

# 5. Login with wrong credentials.
AUTH_KEY_WRONG=$(mock_auth_key f)
STATUS=$(curl $CURL_OPTS -s -o /dev/null -w "%{http_code}" \
    -X POST \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"alice\",\"auth_key\":\"$AUTH_KEY_WRONG\"}" \
    "$NOOMBAT/api/v1/auth/login" 2>/dev/null)

if [ "$STATUS" = "401" ] || [ "$STATUS" = "403" ]; then
    pass "Login with wrong password returns $STATUS"
else
    fail "Login with wrong password returned $STATUS (expected 401 or 403)"
fi

# ..... Chat WebSocket .....

echo ""
echo "--- Chat WebSocket ---"
echo ""

# 6. WebSocket endpoint exists (upgrade request, expect 400 or 101).
if [ -n "$ALICE_TOKEN" ]; then
    STATUS=$(curl $CURL_OPTS -s -o /dev/null -w "%{http_code}" \
        -H "Authorization: Bearer $ALICE_TOKEN" \
        -H "Connection: Upgrade" \
        -H "Upgrade: websocket" \
        -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
        -H "Sec-WebSocket-Version: 13" \
        "$NOOMBAT/api/v1/chat/ws" 2>/dev/null)
    # 101 = upgrade, 400 = bad request (missing chat provisioning),
    # anything except 404 means the route exists.
    if [ "$STATUS" != "404" ] && [ "$STATUS" != "000" ]; then
        pass "Chat WebSocket route exists (HTTP $STATUS)"
    else
        fail "Chat WebSocket route returned $STATUS (expected non-404)"
    fi
else
    skip "Chat WebSocket test: no token (registration failed)"
fi

# 7. Chat report endpoint exists.
if [ -n "$ALICE_TOKEN" ]; then
    STATUS=$(curl $CURL_OPTS -s -o /dev/null -w "%{http_code}" \
        -X POST \
        -H "Authorization: Bearer $ALICE_TOKEN" \
        -H "Content-Type: application/json" \
        -d '{"target_addr":"spam@example.com","reason":"spam"}' \
        "$NOOMBAT/api/v1/chat/reports" 2>/dev/null)
    if [ "$STATUS" = "201" ]; then
        pass "Chat report submitted (HTTP 201)"
    elif [ "$STATUS" = "403" ]; then
        pass "Chat report route exists (HTTP 403, auth gating)"
    else
        fail "Chat report returned $STATUS"
    fi
else
    skip "Chat report test: no token"
fi

# ..... Auth Pages .....

echo ""
echo "--- Auth Pages ---"
echo ""

# 8. Login page renders.
STATUS=$(curl $CURL_OPTS -s -o /dev/null -w "%{http_code}" \
    "$NOOMBAT/auth/login" 2>/dev/null)
if [ "$STATUS" = "200" ]; then
    pass "Login page renders (HTTP 200)"
else
    fail "Login page returned $STATUS"
fi

# 9. Register page renders.
STATUS=$(curl $CURL_OPTS -s -o /dev/null -w "%{http_code}" \
    "$NOOMBAT/auth/register" 2>/dev/null)
if [ "$STATUS" = "200" ]; then
    pass "Register page renders (HTTP 200)"
else
    fail "Register page returned $STATUS"
fi

# ..... Closed Federation .....

echo ""
echo "--- Closed Federation ---"
echo ""

# 10. Allowlisted domain: chat page loads for an authenticated user.
if [ -n "$ALICE_TOKEN" ]; then
    HTTP_CODE=$(curl $CURL_OPTS -sf -o /dev/null -w '%{http_code}' "$NOOMBAT/chat" \
      -H "Cookie: noombat_session=${ALICE_TOKEN}" 2>/dev/null) || HTTP_CODE="000"
    if [ "$HTTP_CODE" = "200" ]; then
        pass "Chat page loads for authenticated user (HTTP 200)"
    else
        fail "Chat page returned $HTTP_CODE (expected 200)"
    fi
else
    skip "Closed federation allowlist test: no token"
fi

# 11. Chatmail configuration, read from NodeInfo.
#
# NodeInfo carries it whatever the viewer's state. The credential page
# does not: `chat_credentials.html` names the domain only in the branch
# for an account that already has credentials, and nothing in this suite
# provisions one, so asking that page for the domain asserted a state the
# suite never creates and could only ever fail.
CHATMAIL_DOMAIN="${CHATMAIL_DOMAIN:-chat.test.local}"
NODEINFO=$(curl $CURL_OPTS -sf "$NOOMBAT/nodeinfo/2.1" 2>/dev/null) || NODEINFO=""

if echo "$NODEINFO" | grep -q '"noombat:chatmailAvailable":true'; then
    pass "NodeInfo advertises Chatmail as available"
else
    fail "NodeInfo does not advertise Chatmail as available"
fi

if echo "$NODEINFO" | grep -q "\"noombat:chatmailDomain\":\"$CHATMAIL_DOMAIN\""; then
    pass "NodeInfo names the configured Chatmail domain ($CHATMAIL_DOMAIN)"
else
    fail "NodeInfo does not name $CHATMAIL_DOMAIN as the Chatmail domain"
fi

# 12. The credential page serves for an authenticated account.
#
# Asserted on the status alone, deliberately: an account with no
# credentials gets the unprovisioned branch, whose only distinguishing
# text is translated and so is not a stable thing to match on.
if [ -n "$ALICE_TOKEN" ]; then
    CRED_CODE=$(curl $CURL_OPTS -s -o /dev/null -w '%{http_code}' \
      "$NOOMBAT/settings/chat" \
      -H "Cookie: noombat_session=${ALICE_TOKEN}" 2>/dev/null) || CRED_CODE="000"
    if [ "$CRED_CODE" = "200" ]; then
        pass "Credential page serves for an authenticated user (HTTP 200)"
    else
        fail "Credential page returned $CRED_CODE (expected 200)"
    fi
else
    skip "Credential page check: no token"
fi

# ..... Summary .....

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
fi

# Every skip stands in for an assertion that never ran, and the summary
# above reports it in the same green shape as a pass. Locally that is a
# convenience; under CI it is a suite guarding nothing while reporting
# success. tests/e2e/accessibility.spec.ts refuses to skip under CI for
# the same reason.
if [ -n "${CI:-}" ] && [ "$SKIP" -gt 0 ]; then
    echo "::error::$SKIP chat interop test(s) skipped under CI; a skipped test asserts nothing"
    exit 1
fi

exit 0
