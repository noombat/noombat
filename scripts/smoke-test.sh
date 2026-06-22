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
TOKEN="${NOOMBAT_ADMIN_TOKEN:-dev-token-change-me}"

check_post "POST outbox without token returns 403" \
    "$BASE/users/alice/outbox" "403" \
    "" '{"content":"test"}'

check_post "POST outbox with wrong token returns 403" \
    "$BASE/users/alice/outbox" "403" \
    "Bearer wrong-token" '{"content":"test"}'

check_post "POST outbox for nonexistent user returns 404" \
    "$BASE/users/nonexistent/outbox" "404" \
    "Bearer $TOKEN" '{"content":"test"}'

echo ""
echo "══ Results: $PASS passed, $FAIL failed ══"
echo ""

[ "$FAIL" -eq 0 ] || exit 1
