#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

# Chat interoperability test runner for Noombat.
#
# Tests:
#         00. The Chatmail admin sidecar is serving.
#         01. Password sign-up is refused, this instance having no mailer.
#   02 - 04. Login (alice, bob, wrong credentials).
#   05 - 06. Chat WebSocket route existence, chat report endpoint.
#   07 - 08. Auth page rendering (login, register).
#   09 - 10. Closed federation checks (allowlisted domain, config).
#   11 - 12. Chatmail provisioning and sending.
#        13. Delivery, read back over IMAP.
#        14. Plain text through the relay's filter.
#
# Usage:
#   tests/chat-interop/seed.sh tests/chat-interop/compose.yml
#   tests/chat-interop/run.sh [noombat_url]
#
# Defaults to http://localhost:8443 when no argument is given.
#
# seed.sh first: the accounts are seeded in SQL rather than registered,
# because password sign-up needs an instance mailer and this stack has
# none. Test 01 asserts that refusal.
#
# A skip exits non-zero when CI is set. Locally a skip is a convenience;
# under CI it is coverage that silently did not run.

set -u

NOOMBAT="${1:-http://localhost:8443}"
CURL_OPTS="${CURL_OPTS:-}"

HERE="$(cd "$(dirname "$0")" && pwd)"
# The keys seed.sh stored hashes of. Sourced rather than repeated, so the
# key here and the hash there cannot drift apart. Checked explicitly:
# this script runs under `set -u` without `set -e`, so an unreadable
# source would otherwise carry on and fail every assertion below for a
# reason that looks nothing like a missing file.
# shellcheck source=tests/chat-interop/fixture-credential.sh
. "$HERE/fixture-credential.sh" || {
    echo "::error::cannot read $HERE/fixture-credential.sh" >&2
    exit 1
}

PASS=0
FAIL=0
SKIP=0

pass() { PASS=$((PASS + 1)); printf "  \033[32mPASS\033[0m  %s\n" "$1"; }
fail() { FAIL=$((FAIL + 1)); printf "  \033[31mFAIL\033[0m  %s\n" "$1"; }
skip() { SKIP=$((SKIP + 1)); printf "  \033[33mSKIP\033[0m  %s\n" "$1"; }
# A known defect is a check that fails while the defect stands. It is
# reported without failing the run; once the defect is fixed the check
# fails the run instead, and is turned into a plain pass or fail.
KNOWN=0
known() { KNOWN=$((KNOWN + 1)); printf "  \033[35mKNOWN\033[0m %s\n" "$1"; }

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
# `--insecure`, deliberately. This probe runs on the host, where the
# name on the relay's certificate does not resolve, and what it asserts
# is that the process is up and serving rather than that the chain is
# valid. Certificate validation is exercised by the provisioning path
# below, which goes through Noombat inside the network and fails the
# handshake if the CA is wrong.
CHATMAIL_ADMIN="${CHATMAIL_ADMIN:-https://localhost:9100}"
ADMIN_CODE=$(curl $CURL_OPTS --insecure -s -o /dev/null -w '%{http_code}' \
  "$CHATMAIL_ADMIN/admin/v1/accounts/probe@example.invalid/exists" 2>/dev/null) || ADMIN_CODE="000"
if [ "$ADMIN_CODE" = "401" ]; then
    pass "Chatmail admin sidecar is serving (401 without the secret)"
else
    fail "Chatmail admin sidecar unreachable at $CHATMAIL_ADMIN (got '$ADMIN_CODE', expected 401)"
fi

# ..... Sign-up .....

echo ""
echo "--- Sign-up ---"
echo ""

CREDS_ALICE="{\"username\":\"alice\",\"auth_key\":\"$CHAT_ALICE_AUTH_KEY\"}"
CREDS_BOB="{\"username\":\"bob\",\"auth_key\":\"$CHAT_BOB_AUTH_KEY\"}"

# 1. Password sign-up is refused, because this instance has no mailer.
#
# alice and bob are seeded by seed.sh instead. The refusal is asserted
# rather than stepped around: that path mints a credential the server can
# never reset, so it is offered only where a recovery challenge can be
# sent, and the Chatmail relay here is not the instance's mailer. If one
# is ever added to this stack, this assertion is what says so, and the
# accounts can go back to being registered.
#
# That a taken username is refused is asserted against a database in
# noombat-identity's registration tests, which is where it can run.
STATUS=$(curl $CURL_OPTS -s -o /dev/null -w "%{http_code}" -X POST \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"carol\",\"auth_key\":\"$(mock_auth_key c)\",\
\"email\":\"carol@interop.invalid\"}" \
    "$NOOMBAT/api/v1/auth/register" 2>/dev/null)

if [ "$STATUS" = "503" ]; then
    pass "Password sign-up refused without an instance mailer (HTTP 503)"
else
    fail "Registration returned $STATUS (expected 503 without an instance mailer)"
fi

# ..... Login .....

echo ""
echo "--- Login ---"
echo ""

# 2. Sign in as alice, whose credential seed.sh stored.
BODY=$(curl $CURL_OPTS -sf -X POST \
    -H "Content-Type: application/json" \
    -d "$CREDS_ALICE" \
    "$NOOMBAT/api/v1/auth/login" 2>/dev/null)

if echo "$BODY" | grep -q '"access_token"'; then
    pass "Login alice: received session tokens"
    ALICE_TOKEN=$(echo "$BODY" | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4)
else
    fail "Login alice failed (did seed.sh run?): $BODY"
    ALICE_TOKEN=""
fi

# 3. Sign in as bob, who receives the message alice sends below.
BODY=$(curl $CURL_OPTS -sf -X POST \
    -H "Content-Type: application/json" \
    -d "$CREDS_BOB" \
    "$NOOMBAT/api/v1/auth/login" 2>/dev/null)

if echo "$BODY" | grep -q '"access_token"'; then
    pass "Login bob: received session tokens"
    BOB_TOKEN=$(echo "$BODY" | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4)
else
    fail "Login bob failed (did seed.sh run?): $BODY"
    BOB_TOKEN=""
fi

# 4. Login with wrong credentials.
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

# 5. WebSocket endpoint exists (upgrade request, expect 400 or 101).
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
    skip "Chat WebSocket test: no token (sign-in failed)"
fi

# 6. Chat report endpoint exists.
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

# 7. Login page renders.
STATUS=$(curl $CURL_OPTS -s -o /dev/null -w "%{http_code}" \
    "$NOOMBAT/auth/login" 2>/dev/null)
if [ "$STATUS" = "200" ]; then
    pass "Login page renders (HTTP 200)"
else
    fail "Login page returned $STATUS"
fi

# 8. Register page renders.
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

# 9. Allowlisted domain: chat page loads for an authenticated user.
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

# 10. Chatmail configuration, read from NodeInfo.
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

# 11. Provisioning against the relay, which is the integration this suite
# is named for.
#
# It reaches the relay over IMAP with implicit TLS, so it passes only if
# the certificate the relay serves verifies: the chatmail container signs
# a leaf with a CA it generates at boot, the compose file shares that CA,
# and Noombat trusts it through SSL_CERT_FILE.
if [ -n "$ALICE_TOKEN" ]; then
    PROV_BODY=$(curl $CURL_OPTS -s -w '\n%{http_code}' \
      -X POST -H "Cookie: noombat_session=${ALICE_TOKEN}" \
      "$NOOMBAT/api/v1/me/provision_chat" 2>/dev/null) || PROV_BODY=""
    PROV_CODE=$(printf '%s' "$PROV_BODY" | tail -n1)
    ALICE_CHATMAIL_PASSWORD=$(printf '%s' "$PROV_BODY" \
      | grep -o '"chatmail_password":"[^"]*"' | cut -d'"' -f4)
    if [ "$PROV_CODE" = "200" ]; then
        pass "Chat provisioned against the relay (HTTP 200)"
    else
        fail "Chat provisioning returned $PROV_CODE (expected 200)"
    fi

    # The credential page names the domain only for an account that has
    # credentials, so this asserts that provisioning actually happened,
    # rather than that the instance is configured.
    CRED_PAGE=$(curl $CURL_OPTS -sf "$NOOMBAT/settings/chat" \
      -H "Cookie: noombat_session=${ALICE_TOKEN}" 2>/dev/null) || CRED_PAGE=""
    if echo "$CRED_PAGE" | grep -q "$CHATMAIL_DOMAIN"; then
        pass "Credential page names $CHATMAIL_DOMAIN for the provisioned account"
    else
        fail "Credential page does not name $CHATMAIL_DOMAIN after provisioning"
    fi
else
    skip "Chat provisioning: no token"
fi

# ..... Account creation is not a login .....

echo ""
echo "--- Account creation ---"
echo ""

# An outsider must not be able to bring an address into existence by
# logging in: a relay that created the mailbox here, storing the password
# the caller offered, would let anyone claim any unused address over the
# published IMAP port and hold that chat identity permanently.
#
# The assertion is on the account, through the sidecar, not on the login
# result: a relay can create the account and then refuse the session a
# moment later, so "the login failed" would pass against that defect.
CHATMAIL_ADMIN_SECRET="${CHATMAIL_ADMIN_SECRET:-chat-interop-admin-secret-for-tests-only}"
SQUATTED="squatter@${CHATMAIL_DOMAIN}"

if ! command -v python3 >/dev/null 2>&1; then
    skip "Squat probe: python3 is needed to drive an IMAP session"
else
    SQUAT_CODE=0
    "$(dirname "$0")/squat-probe.py" localhost 993 "$SQUATTED" "attacker-chosen" \
      > /dev/null 2>&1 || SQUAT_CODE=$?
    case "$SQUAT_CODE" in
        0) pass "An IMAP login for an unknown address is refused" ;;
        1) fail "An IMAP login for $SQUATTED succeeded with a password nobody issued" ;;
        *) fail "The squat probe could not reach the relay (exit $SQUAT_CODE)" ;;
    esac

    EXISTS=$(curl $CURL_OPTS --insecure -s \
      -H "Authorization: Bearer ${CHATMAIL_ADMIN_SECRET}" \
      "$CHATMAIL_ADMIN/admin/v1/accounts/${SQUATTED}/exists" 2>/dev/null) || EXISTS=""
    case "$EXISTS" in
        *'"exists":false'*)
            pass "An unknown address is not created by an IMAP login attempt" ;;
        *'"exists":true'*)
            fail "$SQUATTED was created by a login attempt: create-on-login is back" ;;
        *)
            fail "Could not read account existence from the sidecar (got '$EXISTS')" ;;
    esac
fi

# The other half: a squat attempt against a real user's address must not
# stop that user provisioning. Had the attempt created the mailbox with
# the attacker's password, the IMAP login inside provisioning would fail
# against it and chat would never work for that account.
if [ -z "$BOB_TOKEN" ]; then
    skip "Squat then provision: bob has no session"
elif ! command -v python3 >/dev/null 2>&1; then
    skip "Squat then provision: python3 is needed to drive an IMAP session"
else
    "$(dirname "$0")/squat-probe.py" localhost 993 "bob@${CHATMAIL_DOMAIN}" "attacker-chosen" \
      > /dev/null 2>&1 || true

    BOB_PROV=$(curl $CURL_OPTS -s -w '\n%{http_code}' -X POST \
      -H "Cookie: noombat_session=${BOB_TOKEN}" \
      "$NOOMBAT/api/v1/me/provision_chat" 2>/dev/null) || BOB_PROV=""
    PROVISION_CODE=$(printf '%s' "$BOB_PROV" | tail -n1)
    [ -n "$PROVISION_CODE" ] || PROVISION_CODE="000"
    BOB_CHATMAIL_PASSWORD=$(printf '%s' "$BOB_PROV" \
      | grep -o '"chatmail_password":"[^"]*"' | cut -d'"' -f4)
    if [ "$PROVISION_CODE" = "200" ]; then
        pass "A squat attempt does not stop the real user provisioning"
    else
        fail "bob could not provision after a squat attempt (HTTP $PROVISION_CODE)"
    fi
fi

# 12 and 13 send a real OpenPGP message, encrypted with gpg to a key made
# for bob, so that sending does not depend on what the relay's filter
# lets through, and read bob's mailbox over IMAP as his mail client would.
# 14 sends plain text, which must be refused.
WORK=""
if command -v gpg >/dev/null 2>&1; then
    WORK=$(mktemp -d)
    export GNUPGHOME="$WORK/gnupg"
    mkdir -m 700 "$GNUPGHOME"
    # --rfc4880 throughout, so the data is the encrypted packet every
    # Chatmail relay takes (type 18): GnuPG 2.4 can give its own new keys
    # the OCB feature and then write the OCB packet (type 20), depending on
    # how it was built, and those relays and this server refuse that, as
    # Delta Chat never writes it. The key it makes this way is RSA.
    gpg --batch --quiet --rfc4880 --pinentry-mode loopback --passphrase '' \
      --quick-gen-key "bob@${CHATMAIL_DOMAIN}" default default never 2>/dev/null
    printf 'noombat chat interop: delivered and encrypted' > "$WORK/plain"
    gpg --batch --quiet --trust-model always --rfc4880 --output "$WORK/cipher" \
      --encrypt --recipient "bob@${CHATMAIL_DOMAIN}" "$WORK/plain" 2>/dev/null
    if gpg --list-packets "$WORK/cipher" 2>/dev/null | grep -q '^:aead encrypted packet'; then
        fail "gpg wrote an OCB packet (type 20), which Chatmail relays refuse"
        rm -f "$WORK/cipher"
    fi
fi

# 12. Sending, which is the only assertion that leaves over SMTP.
#
# SMTP resolves its TLS roots through lettre and IMAP through the chat
# connector, so the two can disagree: provisioning and fetching succeed
# while submission fails against the same relay. Everything above passed
# for a full day with submission broken, because nothing sent.
#
# bob's mailbox already exists: the account-creation section above
# provisions him, after squatting his address, so this call is a no-op
# that returns "chat already provisioned" and is ignored.
SENT=no
if [ -n "$ALICE_TOKEN" ] && [ -n "$BOB_TOKEN" ] && [ -n "${ALICE_CHATMAIL_PASSWORD:-}" ]; then
    curl $CURL_OPTS -s -o /dev/null -X POST \
      -H "Cookie: noombat_session=${BOB_TOKEN}" \
      "$NOOMBAT/api/v1/me/provision_chat" 2>/dev/null || true

    if ! command -v python3 >/dev/null 2>&1; then
        skip "Chat send: python3 is needed to drive the relay WebSocket"
    elif [ -z "$WORK" ] || [ ! -s "$WORK/cipher" ]; then
        skip "Chat send: gpg is needed to encrypt the message"
    else
        SEND_OUT=$("$(dirname "$0")/send-probe.py" \
          "$NOOMBAT" "$ALICE_TOKEN" "$ALICE_CHATMAIL_PASSWORD" \
          "bob@${CHATMAIL_DOMAIN}" "$WORK/cipher" 2>&1)
        SEND_CODE=$?
        if [ "$SEND_CODE" = "0" ]; then
            pass "Message sent to bob@${CHATMAIL_DOMAIN} over SMTP"
            SENT=yes
        else
            fail "Sending to bob@${CHATMAIL_DOMAIN} failed: $SEND_OUT"
        fi
    fi
else
    skip "Chat send: no token or no provisioned credential"
fi

# 13. Delivery, as bob's mail client sees it.
#
# "sent" is the relay accepting a submission, which says nothing about
# delivery. Before delivering, Dovecot checks that the recipient exists
# with a password-less lookup; if that lookup fails, every delivery is
# deferred and no mailbox receives mail.
if [ "$SENT" != yes ]; then
    skip "Delivery: nothing was sent"
elif [ -z "${BOB_CHATMAIL_PASSWORD:-}" ]; then
    skip "Delivery: bob has no provisioned credential"
else
    "$(dirname "$0")/fetch-probe.py" localhost 993 "bob@${CHATMAIL_DOMAIN}" \
      "$BOB_CHATMAIL_PASSWORD" "alice@${CHATMAIL_DOMAIN}" 1 \
      > "$WORK/payloads" 2>"$WORK/fetch-errors"
    FETCH_CODE=$?
    if [ "$FETCH_CODE" = "2" ]; then
        fail "Delivery: could not read bob's mailbox: $(cat "$WORK/fetch-errors")"
    elif grep -qxF "$(base64 -w0 < "$WORK/cipher")" "$WORK/payloads"; then
        pass "alice's message reached bob's mailbox"
        if gpg --batch --quiet --decrypt "$WORK/cipher" 2>/dev/null \
             | cmp -s - "$WORK/plain"; then
            pass "The message bob received is OpenPGP that his key opens"
        else
            fail "bob's key does not open the message he received"
        fi
    else
        fail "alice's message never reached bob's mailbox"
    fi
fi

# 14. Plain text.
#
# The server wraps every body it sends in PGP/MIME, so the shape proves
# nothing: what matters is that the body is an encrypted OpenPGP message.
# The server refuses anything else before sending, which this checks; the
# relay's filter refuses it again for a client submitting over SMTP
# directly, which scripts/check-relay-invariants.sh checks.
if [ -z "$ALICE_TOKEN" ] || [ -z "${ALICE_CHATMAIL_PASSWORD:-}" ]; then
    skip "Plain text: no token or no provisioned credential"
elif ! command -v python3 >/dev/null 2>&1; then
    skip "Plain text: python3 is needed to drive the relay WebSocket"
else
    PLAIN_OUT=$("$(dirname "$0")/send-probe.py" "$NOOMBAT" "$ALICE_TOKEN" \
      "$ALICE_CHATMAIL_PASSWORD" "bob@${CHATMAIL_DOMAIN}" 2>&1)
    PLAIN_CODE=$?
    if [ "$PLAIN_CODE" = "0" ]; then
        fail "A plain-text body was sent as if it were OpenPGP"
    elif printf '%s' "$PLAIN_OUT" | grep -q "not OpenPGP-encrypted"; then
        pass "A plain-text body is refused before it is sent"
    else
        fail "Plain text: the send failed for another reason: $PLAIN_OUT"
    fi
fi

# 15. The sender is the login.
#
# A member sends only as the address they log in as: the submission port
# refuses any other sender before a message is taken. alice's own address
# is the control, so a relay refusing every sender cannot pass.
if [ -z "${ALICE_CHATMAIL_PASSWORD:-}" ]; then
    skip "Sender: alice has no provisioned credential"
elif ! command -v python3 >/dev/null 2>&1; then
    skip "Sender: python3 is needed to drive SMTP"
else
    SENDER_PROBE="$(dirname "$0")/sender-probe.py"
    AS_ALICE=$("$SENDER_PROBE" localhost 465 "alice@${CHATMAIL_DOMAIN}" "$ALICE_CHATMAIL_PASSWORD" \
      "alice@${CHATMAIL_DOMAIN}" "bob@${CHATMAIL_DOMAIN}" 2>&1)
    AS_BOB=$("$SENDER_PROBE" localhost 465 "alice@${CHATMAIL_DOMAIN}" "$ALICE_CHATMAIL_PASSWORD" \
      "bob@${CHATMAIL_DOMAIN}" "bob@${CHATMAIL_DOMAIN}" 2>&1)
    if [ "$AS_ALICE" != accepted ]; then
        fail "Sender: alice could not send as herself: $AS_ALICE"
    elif [ "${AS_BOB%% *}" = refused ]; then
        pass "alice cannot send as bob: $AS_BOB"
    elif [ "$AS_BOB" = accepted ]; then
        fail "alice was allowed to send as bob"
    else
        fail "Sender: the probe did not complete: $AS_BOB"
    fi
fi

if [ -n "$WORK" ]; then
    gpgconf --kill gpg-agent 2>/dev/null || true
    rm -rf "$WORK"
    unset GNUPGHOME
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
if [ "$KNOWN" -gt 0 ]; then
    printf ", \033[35m%d known defect(s)\033[0m" "$KNOWN"
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
