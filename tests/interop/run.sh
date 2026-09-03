#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

# Interoperability test runner for Noombat.
#
# Usage:
#   tests/interop/run.sh <noombat_url> <gotosocial_url>
#
# Example (after `docker compose -f tests/interop/compose.yml up -d --wait`
# and `tests/interop/seed.sh`):
#
#   CURL_OPTS="--insecure" tests/interop/run.sh \
#     https://noombat.localhost:8443 https://gotosocial.localhost:8443
#
# Both URLs have to be the ones the two instances know themselves by.
# AP ids are absolute, so an id generated behind one authority and
# fetched through another is a different resource, and WebFinger is
# matched against the configured domain exactly, port included.
#
# ..... WHAT THIS ASSERTS, AND WHERE .....
#
# The first section reads Noombat's own endpoints. Those checks are
# about shape: WebFinger, NodeInfo, the actor document, the outbox. Any
# implementation could be substituted for the peer without changing a
# single one of their outcomes, so on their own they say nothing about
# federating.
#
# The second section drives one round trip and then asks *GoToSocial*
# what it holds. It is the only part that can fail for a reason internal
# to federation:
#
#   Follow   Noombat signs a POST to GoToSocial's inbox. GoToSocial
#            verifies the signature, which makes it resolve `alice`
#            through WebFinger, fetch the actor document, and check the
#            signature against the key in it. It then sends an Accept
#            back, which Noombat verifies the same way in reverse.
#   Follow   The same exchange in the other direction, driven through
#            GoToSocial's own API. It is what makes the Create below
#            leave Noombat at all: delivery targets are the *followers*
#            of the posting actor, and a home timeline holds statuses
#            from the accounts its owner follows, so both ends of the
#            timeline assertion need `bob` to follow `alice` rather
#            than the reverse.
#   Create   Noombat signs a delivery of a Note to the follower's inbox.
#            GoToSocial verifies it, stores the status, and puts it in
#            the follower's home timeline.
#
# So the cross-instance assertions are made against GoToSocial's API as
# the followed account, plus two against Noombat's own collections:
# `following` lists accepted follows only and is therefore the evidence
# that the Accept arrived and verified, and `followers` is the same
# evidence for the inbound Follow. Both are read with the session token,
# because both collections are private by default: fetched anonymously
# they answer 404, and a privacy setting would be reported here as a
# federation failure.
#
# Environment:
#   CURL_OPTS             extra curl flags, e.g. --insecure for Caddy's CA
#   CI                    when set, a skip is a failure and an
#                         unreachable peer is fatal
#
# Noombat's authenticated routes act for whoever the session says they
# are, so this suite signs in as the seeded actor and carries the access
# token it gets back. There is no instance-wide bearer to borrow.
#
# Exit codes:
#   0: all tests passed
#   1: one or more tests failed (or, under CI, were skipped)

set -u

if [ $# -lt 2 ]; then
    echo "Usage: $0 <noombat_url> <gotosocial_url>"
    exit 1
fi

NOOMBAT="${1%/}"
GOTOSOCIAL="${2%/}"

HERE="$(cd "$(dirname "$0")" && pwd)"
# Checked explicitly: this script runs under `set -u` without `set -e`,
# so that a failing assertion records a FAIL instead of aborting the run,
# and an unreadable source would otherwise carry on into a 60-second poll
# and fail for an unrelated-looking reason.
# shellcheck source=tests/interop/fixtures.sh
. "$HERE/fixtures.sh" || {
    echo "::error::cannot read $HERE/fixtures.sh" >&2
    exit 1
}

# Additional curl flags, e.g. CURL_OPTS="--insecure" for self-signed
# certs in the local (Compose+Caddy) environment.
CURL_OPTS="${CURL_OPTS:-}"

# The credential seed.sh stored for the fixture actor. Sourced rather
# than repeated, so the key here and the hash there cannot drift apart.
# Checked like fixtures.sh above, and for the same reason.
# shellcheck source=tests/interop/fixture-credential.sh
. "$HERE/fixture-credential.sh" || {
    echo "::error::cannot read $HERE/fixture-credential.sh" >&2
    exit 1
}

# Filled in by the sign-in step, once Noombat is known to be up.
SESSION_TOKEN=""

# Seconds to wait for an activity to cross. Delivery is queued on
# Noombat's side and processed asynchronously on GoToSocial's, so every
# cross-instance assertion is a poll rather than a read.
CROSS_TIMEOUT="${INTEROP_CROSS_TIMEOUT:-60}"

# GitHub sets CI. A skipped assertion is one that did not run, which the
# summary line otherwise renders as indistinguishable from a suite that
# passed, so on the merge path a skip is a failure.
CI_MODE=false
if [ -n "${CI:-}" ]; then
    CI_MODE=true
fi

PASS=0
FAIL=0
SKIP=0

pass() { PASS=$((PASS + 1)); printf "  \033[32mPASS\033[0m  %s\n" "$1"; }
fail() { FAIL=$((FAIL + 1)); printf "  \033[31mFAIL\033[0m  %s\n" "$1"; }
skip() { SKIP=$((SKIP + 1)); printf "  \033[33mSKIP\033[0m  %s\n" "$1"; }

# ..... HELPERS .....

# First string value for a JSON key. Enough for the handful of flat
# fields read here, and it keeps the runner to curl and coreutils.
jstr() {
    echo "$1" | grep -o "\"$2\":\"[^\"]*\"" | head -1 | cut -d'"' -f4
}

# Run a predicate once a second until it succeeds or the budget runs out.
poll() {
    local max="$1"
    shift
    local i=0
    until "$@"; do
        i=$((i + 1))
        if [ "$i" -ge "$max" ]; then
            return 1
        fi
        sleep 1
    done
    return 0
}

wait_for() {
    local name="$1" url="$2" max=60 i=0
    printf "Waiting for %s..." "$name"
    while ! curl $CURL_OPTS -sf -o /dev/null "$url" 2>/dev/null; do
        i=$((i + 1))
        if [ "$i" -ge "$max" ]; then
            printf " TIMEOUT\n"
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

if ! wait_for "Noombat" "$NOOMBAT/healthz"; then
    echo "::error::Noombat did not become ready; no test can run"
    exit 1
fi

# An unreachable peer is a missing suite, not a passing one. It is
# recorded as a skip and the run continues, so that the Noombat half is
# still reported; the skip is what fails the run under CI. Locally the
# same skip is tolerated, so somebody working on the Noombat half is not
# blocked by a failed image pull.
GTS_AVAILABLE=true
if ! wait_for "GoToSocial" "$GOTOSOCIAL/readyz"; then
    GTS_AVAILABLE=false
    if $CI_MODE; then
        echo "::error::GoToSocial did not become ready; the cross-instance suite cannot run"
    fi
fi

echo ""
echo "--- Noombat S2S protocol (Noombat's own endpoints) ---"
echo ""

# The authority, port included: `state.domain` is what WebFinger
# compares the resource against and what every generated id is built
# from, and in this topology it carries the port.
NOOMBAT_AUTHORITY="${NOOMBAT#*://}"
GTS_AUTHORITY="${GOTOSOCIAL#*://}"

# 1. WebFinger.
echo "WebFinger:"
BODY=$(curl $CURL_OPTS -sf "$NOOMBAT/.well-known/webfinger?resource=acct:${NOOMBAT_ACTOR}@${NOOMBAT_AUTHORITY}" 2>/dev/null)
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

if echo "$BODY" | grep -q 'noombat:JobPosting'; then
    pass "NodeInfo 2.1 includes supportedVocabulary"
else
    fail "NodeInfo 2.1 missing supportedVocabulary"
fi

# 4. Actor JSON.
echo "Actor fetch:"
BODY=$(curl $CURL_OPTS -sf -H "Accept: application/activity+json" \
    "$NOOMBAT/users/$NOOMBAT_ACTOR" 2>/dev/null)
if echo "$BODY" | grep -q '"Person"'; then
    pass "Actor returns type Person"
else
    fail "Actor did not return type Person"
fi

if echo "$BODY" | grep -q "\"preferredUsername\":\"$NOOMBAT_ACTOR\""; then
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
BODY=$(curl $CURL_OPTS -sf "$NOOMBAT/users/$NOOMBAT_ACTOR/outbox" 2>/dev/null)
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
# An unsigned delivery has to be refused as a client error: 5xx tells the
# peer the fault is ours and to keep redelivering.
if [ "$STATUS" = "401" ] || [ "$STATUS" = "400" ]; then
    pass "Shared inbox refuses an unsigned delivery (HTTP $STATUS)"
else
    fail "Shared inbox returned $STATUS for an unsigned delivery (expected 400 or 401)"
fi

# 8. Sign in to Noombat as the seeded actor.
#
#    Asserted here, among the Noombat checks, rather than beside the
#    first request that needs it: a refusal is a fault in this instance
#    or in the fixture, and reporting it from the middle of the
#    federation section would read like a peer problem.
echo "Noombat sign-in:"
SESSION_TOKEN=$(jstr "$(curl $CURL_OPTS -s -X POST \
    -H 'Content-Type: application/json' \
    -d "{\"username\":\"${NOOMBAT_ACTOR}\",\"auth_key\":\"${FIXTURE_AUTH_KEY}\"}" \
    "$NOOMBAT/api/v1/auth/login" 2>/dev/null)" access_token)
if [ -n "$SESSION_TOKEN" ]; then
    pass "Signed in as ${NOOMBAT_ACTOR}"
else
    fail "could not sign in as ${NOOMBAT_ACTOR}; did seed.sh run?"
fi

# ..... Cross-instance federation .....

echo ""
echo "--- Federation round trip (asserted in GoToSocial) ---"
echo ""

if ! $GTS_AVAILABLE; then
    skip "GoToSocial not available; no activity can be exchanged"
else
    # 9. GoToSocial NodeInfo. Liveness, kept because it names the peer
    #    in the log when something below fails.
    echo "GoToSocial NodeInfo:"
    BODY=$(curl $CURL_OPTS -sf "$GOTOSOCIAL/nodeinfo/2.0" 2>/dev/null)
    if echo "$BODY" | grep -q '"gotosocial"'; then
        pass "GoToSocial NodeInfo identifies software"
    else
        fail "GoToSocial NodeInfo software name incorrect"
    fi

    # 10. Sign in to GoToSocial as the seeded account.
    #
    #    Everything below reads GoToSocial's state through its own API,
    #    and that API answers nothing useful to an unauthenticated
    #    caller: the ActivityPub endpoints require a signature, and the
    #    client API requires a user token. GoToSocial supports the
    #    authorization_code grant only, so this is the app registration,
    #    the sign-in form, the consent form and the code exchange.
    echo "GoToSocial sign-in:"
    GTS_TOKEN=""
    GTS_APP=$(curl $CURL_OPTS -s -X POST "$GOTOSOCIAL/api/v1/apps" \
        -H 'Content-Type: application/json' \
        -d '{"client_name":"noombat-interop","redirect_uris":"urn:ietf:wg:oauth:2.0:oob","scopes":"read write"}' \
        2>/dev/null)
    GTS_CLIENT_ID=$(jstr "$GTS_APP" client_id)
    GTS_CLIENT_SECRET=$(jstr "$GTS_APP" client_secret)

    if [ -n "$GTS_CLIENT_ID" ] && [ -n "$GTS_CLIENT_SECRET" ]; then
        AUTHORIZE="$GOTOSOCIAL/oauth/authorize?client_id=${GTS_CLIENT_ID}&redirect_uri=urn:ietf:wg:oauth:2.0:oob&response_type=code&scope=read+write"
        JAR=$(mktemp)
        # The first call is what puts the authorisation request in the
        # session; signing in without it returns to a form with nothing
        # to consent to.
        curl $CURL_OPTS -s -c "$JAR" -o /dev/null "$AUTHORIZE" 2>/dev/null
        curl $CURL_OPTS -s -b "$JAR" -c "$JAR" -o /dev/null -X POST \
            --data-urlencode "username=${GTS_ACTOR_EMAIL}" \
            --data-urlencode "password=${GTS_ACTOR_PASSWORD}" \
            "$GOTOSOCIAL/auth/sign_in" 2>/dev/null
        curl $CURL_OPTS -s -b "$JAR" -c "$JAR" -o /dev/null "$AUTHORIZE" 2>/dev/null
        # The code comes back in the Location header, not the body.
        REDIRECT=$(curl $CURL_OPTS -s -b "$JAR" -c "$JAR" -o /dev/null \
            -w '%{redirect_url}' -X POST "$GOTOSOCIAL/oauth/authorize" 2>/dev/null)
        rm -f "$JAR"
        GTS_CODE="${REDIRECT##*code=}"
        if [ -n "$GTS_CODE" ] && [ "$GTS_CODE" != "$REDIRECT" ]; then
            GTS_TOKEN=$(jstr "$(curl $CURL_OPTS -s -X POST "$GOTOSOCIAL/oauth/token" \
                -H 'Content-Type: application/json' \
                -d "{\"grant_type\":\"authorization_code\",\"client_id\":\"${GTS_CLIENT_ID}\",\"client_secret\":\"${GTS_CLIENT_SECRET}\",\"code\":\"${GTS_CODE}\",\"redirect_uri\":\"urn:ietf:wg:oauth:2.0:oob\",\"scope\":\"read write\"}" \
                2>/dev/null)" access_token)
        fi
    fi

    GTS_ACCOUNT_ID=""
    if [ -n "$GTS_TOKEN" ]; then
        GTS_ACCOUNT_ID=$(jstr "$(curl $CURL_OPTS -s \
            -H "Authorization: Bearer $GTS_TOKEN" \
            "$GOTOSOCIAL/api/v1/accounts/verify_credentials" 2>/dev/null)" id)
    fi

    if [ -n "$GTS_ACCOUNT_ID" ]; then
        pass "signed in to GoToSocial as ${GTS_ACTOR} (account ${GTS_ACCOUNT_ID})"
    else
        fail "could not sign in to GoToSocial as ${GTS_ACTOR}; did seed.sh run?"
    fi

    if [ -z "$GTS_ACCOUNT_ID" ]; then
        skip "Follow round trip: no GoToSocial session"
        skip "Accept recorded by Noombat: no GoToSocial session"
        skip "Reverse Follow round trip: no GoToSocial session"
        skip "Create { Note } round trip: no GoToSocial session"
    else
        # 11. The account is created locked, so a Follow would sit in
        #     the requests queue and no Accept would ever be sent. There
        #     is no admin CLI for this, only the API, which is why it is
        #     here and not in seed.sh.
        echo "GoToSocial follow policy:"
        LOCKED=$(curl $CURL_OPTS -s -X PATCH \
            -H "Authorization: Bearer $GTS_TOKEN" \
            -H 'Content-Type: application/json' \
            -d '{"locked":false}' \
            "$GOTOSOCIAL/api/v1/accounts/update_credentials" 2>/dev/null \
            | grep -o '"locked":[a-z]*' | head -1 | cut -d: -f2)
        if [ "$LOCKED" = "false" ]; then
            pass "${GTS_ACTOR} accepts follows without approval"
        else
            fail "could not clear the manual-approval flag on ${GTS_ACTOR} (locked=$LOCKED)"
        fi

        GTS_ACTOR_AP_ID="$GOTOSOCIAL/users/$GTS_ACTOR"
        NOOMBAT_ACTOR_AP_ID="$NOOMBAT/users/$NOOMBAT_ACTOR"
        # GoToSocial records a remote account's `url`, not its AP id,
        # and Noombat's actor document carries `/@alice` there.
        NOOMBAT_ACTOR_URL="$NOOMBAT/@$NOOMBAT_ACTOR"

        # 12. Follow, from Noombat to GoToSocial.
        echo "Follow (Noombat -> GoToSocial):"
        STATUS=$(curl $CURL_OPTS -s -o /dev/null -w "%{http_code}" \
            -X POST -H "Authorization: Bearer $SESSION_TOKEN" \
            -H 'Content-Type: application/json' \
            -d "{\"target_ap_id\":\"$GTS_ACTOR_AP_ID\"}" \
            "$NOOMBAT/users/$NOOMBAT_ACTOR/following" 2>/dev/null)
        if [ "$STATUS" = "202" ]; then
            pass "Noombat accepted the Follow for delivery (HTTP 202)"
        else
            fail "Noombat refused to enqueue the Follow (HTTP $STATUS)"
        fi

        # Asserted in GoToSocial's own state. Reaching this line means
        # GoToSocial received a signed Follow, resolved the actor
        # through WebFinger, fetched the actor document over TLS and
        # verified the signature against the key in it.
        gts_has_follower() {
            curl $CURL_OPTS -s -H "Authorization: Bearer $GTS_TOKEN" \
                "$GOTOSOCIAL/api/v1/accounts/$GTS_ACCOUNT_ID/followers?limit=80" \
                2>/dev/null | grep -qF "$NOOMBAT_ACTOR_URL"
        }
        if poll "$CROSS_TIMEOUT" gts_has_follower; then
            pass "GoToSocial lists ${NOOMBAT_ACTOR} among ${GTS_ACTOR}'s followers"
        else
            fail "GoToSocial never recorded the follow from ${NOOMBAT_ACTOR_URL}"
        fi

        # The reverse direction: `following` lists accepted follows
        # only, so this is Noombat having received GoToSocial's Accept
        # and verified its signature.
        echo "Accept (GoToSocial -> Noombat):"
        # Read as the owner. The follower and following collections are
        # private by default, so an anonymous fetch is answered 404 and
        # this would report a federation failure for a privacy setting.
        noombat_follows_bob() {
            curl $CURL_OPTS -s -H "Authorization: Bearer $SESSION_TOKEN" \
                "$NOOMBAT/users/$NOOMBAT_ACTOR/following" \
                2>/dev/null | grep -qF "$GTS_ACTOR_AP_ID"
        }
        if poll "$CROSS_TIMEOUT" noombat_follows_bob; then
            pass "Noombat's following collection lists ${GTS_ACTOR} (Accept verified)"
        else
            fail "Noombat never accepted the follow; no verified Accept arrived"
        fi

        # 13. Follow, from GoToSocial to Noombat.
        #
        # Required by the Create below, twice over. Noombat picks its
        # delivery targets with `get_follower_inboxes`, which selects
        # `follows.following_id = alice`, so the follow made above
        # (alice -> bob) enqueues nothing and the activity never leaves
        # the instance. GoToSocial's home timeline is the mirror of that
        # from the other side: it holds statuses from the accounts bob
        # follows. Both need this direction.
        #
        # Resolved by AP id rather than by `alice@authority`. GoToSocial
        # already holds the actor at this point, having fetched it to
        # verify the Follow above, so the id is a lookup rather than a
        # second discovery, and a WebFinger hiccup cannot be reported
        # here as a delivery failure.
        echo "Follow (GoToSocial -> Noombat):"
        GTS_SEARCH=$(curl $CURL_OPTS -s --get \
            -H "Authorization: Bearer $GTS_TOKEN" \
            --data-urlencode "q=${NOOMBAT_ACTOR_AP_ID}" \
            --data-urlencode "type=accounts" \
            --data-urlencode "resolve=true" \
            "$GOTOSOCIAL/api/v2/search" 2>/dev/null)
        GTS_REMOTE_ID=$(jstr "$GTS_SEARCH" id)
        if [ -n "$GTS_REMOTE_ID" ]; then
            pass "GoToSocial resolved ${NOOMBAT_ACTOR} (account ${GTS_REMOTE_ID})"
        else
            fail "GoToSocial could not resolve ${NOOMBAT_ACTOR_AP_ID}: $(echo "$GTS_SEARCH" | head -c 200)"
        fi

        # The response is read for its status only. A follow of a remote
        # account comes back `"following":false,"requested":true` and
        # stays that way until the Accept has crossed, so the body says
        # nothing yet about whether anything federated.
        STATUS=$(curl $CURL_OPTS -s -o /dev/null -w "%{http_code}" -X POST \
            -H "Authorization: Bearer $GTS_TOKEN" \
            "$GOTOSOCIAL/api/v1/accounts/$GTS_REMOTE_ID/follow" 2>/dev/null)
        if [ "$STATUS" = "200" ]; then
            pass "GoToSocial accepted the Follow for delivery (HTTP 200)"
        else
            fail "GoToSocial refused to enqueue the Follow (HTTP $STATUS)"
        fi

        # Asserted in Noombat's own state. `followers` lists accepted
        # follows only, so an entry there is Noombat having verified an
        # inbound signed Follow against a key it fetched from
        # GoToSocial, and having auto-accepted it.
        # As the owner, for the reason given at the following poll above.
        noombat_has_follower() {
            curl $CURL_OPTS -s -H "Authorization: Bearer $SESSION_TOKEN" \
                "$NOOMBAT/users/$NOOMBAT_ACTOR/followers" \
                2>/dev/null | grep -qF "$GTS_ACTOR_AP_ID"
        }
        if poll "$CROSS_TIMEOUT" noombat_has_follower; then
            pass "Noombat's followers collection lists ${GTS_ACTOR}"
        else
            fail "Noombat never recorded a follow from ${GTS_ACTOR_AP_ID}"
        fi

        # And the Accept in the other direction. GoToSocial only moves a
        # request into `following` once the Accept has arrived and its
        # signature verified, and only an accepted follow puts anything
        # in a home timeline, so this is what makes the assertion below
        # diagnosable rather than a bare timeout.
        echo "Accept (Noombat -> GoToSocial):"
        gts_follows_noombat() {
            curl $CURL_OPTS -s -H "Authorization: Bearer $GTS_TOKEN" \
                "$GOTOSOCIAL/api/v1/accounts/$GTS_ACCOUNT_ID/following?limit=80" \
                2>/dev/null | grep -qF "$NOOMBAT_ACTOR_URL"
        }
        if poll "$CROSS_TIMEOUT" gts_follows_noombat; then
            pass "GoToSocial lists ${NOOMBAT_ACTOR} among ${GTS_ACTOR}'s following (Accept verified)"
        else
            fail "GoToSocial never accepted the follow of ${NOOMBAT_ACTOR_URL}"
        fi

        # 14. Create { Note }, delivered to the follower's inbox.
        echo "Create { Note } (Noombat -> GoToSocial):"
        MARKER="interop-note-$(date +%s)-$$"
        CREATE=$(curl $CURL_OPTS -s -X POST \
            -H "Authorization: Bearer $SESSION_TOKEN" \
            -H 'Content-Type: application/json' \
            -d "{\"post_type\":\"note\",\"content\":\"$MARKER\",\"visibility\":\"public\"}" \
            "$NOOMBAT/users/$NOOMBAT_ACTOR/outbox" 2>/dev/null)
        # The activity id is the object id with `/activity` appended, so
        # the id with no further path segment is the Note's.
        POST_URI=$(echo "$CREATE" | grep -o '"id":"[^"]*/posts/[^"/]*"' \
            | head -1 | cut -d'"' -f4)
        if [ -n "$POST_URI" ]; then
            pass "Noombat published a Note ($POST_URI)"
        else
            fail "Noombat did not return a Note id: $(echo "$CREATE" | head -c 200)"
        fi

        # Asserted in GoToSocial's own state, and the strongest single
        # check here: the status is in the follower's timeline only if
        # GoToSocial verified the HTTP Signature on a POST Noombat made,
        # parsed the activity and stored the object.
        gts_timeline_has_post() {
            [ -n "$POST_URI" ] || return 1
            curl $CURL_OPTS -s -H "Authorization: Bearer $GTS_TOKEN" \
                "$GOTOSOCIAL/api/v1/timelines/home?limit=40" \
                2>/dev/null | grep -qF "$POST_URI"
        }
        if poll "$CROSS_TIMEOUT" gts_timeline_has_post; then
            pass "GoToSocial holds the Note in ${GTS_ACTOR}'s home timeline"
        else
            fail "the Note never reached ${GTS_ACTOR}'s home timeline"
        fi

        # 15. Create { Note }, the other direction.
        #
        # Everything above exercises Noombat's *outbound* path or its
        # handling of Follow and Accept. Without this, nothing GoToSocial
        # authored reaches Noombat's ingestion at all, and that path has
        # proven to hide several defects at once. This is the only
        # assertion in the suite that drives it.
        #
        # It works because ${NOOMBAT_ACTOR} follows ${GTS_ACTOR} above, so
        # a public status by ${GTS_ACTOR} is delivered here unprompted.
        echo "Create { Note } (GoToSocial -> Noombat):"
        INBOUND_MARKER="interop-inbound-$(date +%s)-$$"
        GTS_STATUS=$(curl $CURL_OPTS -s -X POST \
            -H "Authorization: Bearer $GTS_TOKEN" \
            -H 'Content-Type: application/json' \
            -d "{\"status\":\"$INBOUND_MARKER\",\"visibility\":\"public\"}" \
            "$GOTOSOCIAL/api/v1/statuses" 2>/dev/null)
        GTS_STATUS_URI=$(jstr "$GTS_STATUS" "uri")
        if [ -n "$GTS_STATUS_URI" ]; then
            pass "GoToSocial published a status ($GTS_STATUS_URI)"
        else
            fail "GoToSocial did not return a status uri: $(echo "$GTS_STATUS" | head -c 200)"
        fi

        # Asserted through the feed ${NOOMBAT_ACTOR} would actually be
        # served. Reaching it means Noombat verified the HTTP Signature on
        # a delivery GoToSocial made, resolved the signer from a keyId
        # that is a URL rather than a fragment, accepted addressing sent
        # as a single string, stored the post and rendered it.
        noombat_feed_has_inbound() {
            [ -n "$INBOUND_MARKER" ] || return 1
            curl $CURL_OPTS -s "$NOOMBAT/feed?page=1&user=$NOOMBAT_ACTOR" \
                2>/dev/null | grep -qF "$INBOUND_MARKER"
        }
        if poll "$CROSS_TIMEOUT" noombat_feed_has_inbound; then
            pass "Noombat holds ${GTS_ACTOR}'s Note in ${NOOMBAT_ACTOR}'s feed"
        else
            fail "${GTS_ACTOR}'s Note never reached ${NOOMBAT_ACTOR}'s feed"
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
fi

if $CI_MODE && [ "$SKIP" -gt 0 ]; then
    echo "::error::${SKIP} assertion(s) were skipped; under CI that is a failure"
    exit 1
fi

exit 0
