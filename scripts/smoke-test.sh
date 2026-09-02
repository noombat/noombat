#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
# Verify that a running Noombat server responds correctly.
#
# Prerequisites: the server must be running on localhost:8443.
#
# Usage:
#   cargo run --bin noombat &       # start server in background
#   sleep 2                         # wait for startup
#   ./scripts/smoke-test.sh
#   kill %1                         # stop server

set -euo pipefail

BASE="http://localhost:8443"
PASS=0
FAIL=0

check() {
    local description="$1"
    local url="$2"
    local expected_status="$3"
    local content_type="${4:-}"

    local args=(-s -o /dev/null -w '%{http_code}')
    if [ -n "$content_type" ]; then
        args+=(-H "Accept: $content_type")
    fi

    local status
    status=$(curl "${args[@]}" "$url")

    if [ "$status" = "$expected_status" ]; then
        echo "  ✓  $description (HTTP $status)"
        PASS=$((PASS + 1))
    else
        echo "  ✗  $description: expected $expected_status, got $status"
        FAIL=$((FAIL + 1))
    fi
}

check_json() {
    local description="$1"
    local url="$2"
    local jq_filter="$3"
    local expected="$4"
    local accept="${5:-application/json}"

    local body
    body=$(curl -s -H "Accept: $accept" "$url")
    local actual
    actual=$(echo "$body" | python3 -c "import sys,json; print(json.loads(sys.stdin.read())$jq_filter)" 2>/dev/null || echo "PARSE_ERROR")

    if [ "$actual" = "$expected" ]; then
        echo "  ✓  $description"
        PASS=$((PASS + 1))
    else
        echo "  ✗  $description: expected '$expected', got '$actual'"
        FAIL=$((FAIL + 1))
    fi
}

check_post() {
    local description="$1"
    local url="$2"
    local expected_status="$3"
    local auth_header="${4:-}"
    local body_json="${5:-{}}"

    local args=(-s -o /dev/null -w '%{http_code}' -X POST)
    args+=(-H 'Content-Type: application/json')
    if [ -n "$auth_header" ]; then
        args+=(-H "Authorization: $auth_header")
    fi
    args+=(-d "$body_json")

    local status
    status=$(curl "${args[@]}" "$url")

    if [ "$status" = "$expected_status" ]; then
        echo "  ✓  $description (HTTP $status)"
        PASS=$((PASS + 1))
    else
        echo "  ✗  $description: expected $expected_status, got $status"
        FAIL=$((FAIL + 1))
    fi
}

echo ""
echo "===== Noombat Smoke Tests ====="
echo ""

echo "..... Health ....."
check "GET /healthz returns 200" "$BASE/healthz" "200"

echo ""
echo "..... WebFinger ....."
check "GET /.well-known/webfinger without params returns 400" \
    "$BASE/.well-known/webfinger" "400"
check "GET /.well-known/webfinger with unknown user returns 404" \
    "$BASE/.well-known/webfinger?resource=acct:nobody@localhost" "404"

echo ""
echo "..... NodeInfo ....."
check "GET /.well-known/nodeinfo returns 200" \
    "$BASE/.well-known/nodeinfo" "200"
check "GET /nodeinfo/2.1 returns 200" \
    "$BASE/nodeinfo/2.1" "200"
check_json "NodeInfo software name is 'noombat'" \
    "$BASE/nodeinfo/2.1" "['software']['name']" "noombat"

echo ""
echo "..... Actor ....."
check "GET /users/nonexistent returns 404" \
    "$BASE/users/nonexistent" "404" "application/activity+json"

echo ""
echo "..... Outbox ....."
# Posting to an outbox acts as that account, so it takes a session. This
# script runs against an arbitrary deployment and holds no credential,
# which bounds what it can assert here: the refusals, which need none.
#
# Set NOOMBAT_SESSION_TOKEN to an access token from
# `POST /api/v1/auth/login` to add the authenticated case below.
TOKEN="${NOOMBAT_SESSION_TOKEN:-}"

check_post "POST outbox without a session returns 403" \
    "$BASE/users/alice/outbox" "403" \
    "" '{"content":"test"}'

check_post "POST outbox with a bad session returns 403" \
    "$BASE/users/alice/outbox" "403" \
    "Bearer not-a-valid-token" '{"content":"test"}'

# An anonymous caller gets the same answer for an account that exists
# and one that does not, so this endpoint cannot be used to enumerate
# usernames. Authentication is checked before the lookup so that it holds.
check_post "POST outbox for a nonexistent user returns 403 unauthenticated" \
    "$BASE/users/nonexistent/outbox" "403" \
    "" '{"content":"test"}'

if [ -n "$TOKEN" ]; then
    # With a session the lookup runs and the distinction reappears: the
    # caller has proved who they are, so naming a missing account tells
    # them nothing they could not already find out.
    check_post "POST outbox for a nonexistent user returns 404 with a session" \
        "$BASE/users/nonexistent/outbox" "404" \
        "Bearer $TOKEN" '{"content":"test"}'
fi

echo ""
echo "..... Moderation ....."

# A null UUID for a nonexistent actor.
NULL_ID="00000000-0000-0000-0000-000000000000"

check_post "POST suspend without auth returns 403" \
    "$BASE/api/v1/admin/actors/$NULL_ID/suspend" "403" \
    "" '{"reason":"test"}'

check_post "POST unsuspend without auth returns 403" \
    "$BASE/api/v1/admin/actors/$NULL_ID/unsuspend" "403"

check_post "POST resolve chat report without auth returns 403" \
    "$BASE/api/v1/admin/chat-reports/$NULL_ID/resolve" "403" \
    "" '{"action":"dismiss"}'

check "GET chat reports without auth returns 403" \
    "$BASE/api/v1/admin/chat-reports" "403"

check "GET reports without auth returns 403" \
    "$BASE/api/v1/admin/reports" "403"

echo ""
echo "══ Results: $PASS passed, $FAIL failed ══"
echo ""

[ "$FAIL" -eq 0 ] || exit 1
