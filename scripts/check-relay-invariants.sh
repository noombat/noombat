#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
#
# Send real mail through the relay and check the two things it exists to
# guarantee. One container, because both are properties of the same
# message path.
#
# ONE. THE ENCRYPTION-ONLY INVARIANT. A 5xx reply alone is not the
# property: an after-queue filter also refuses plaintext, by accepting
# it, spooling it and mailing it back in a notification that carries it
# across the network. So this asserts the reply is 5xx, that Postfix
# logged NOQUEUE rather than a queue id, and that nothing was delivered.
#
# TWO. DKIM SIGNING. A present `DKIM-Signature:` header would pass on a
# signature over the wrong body made with a key OpenDKIM failed to load,
# so `scripts/verify-dkim.py` does the arithmetic. A relay whose signer
# has stopped must defer rather than deliver unsigned.
#
# CAPTURE. Delivery is pointed at a `pipe(8)` transport that tees to a
# file, replacing the last hop only, downstream of both the filter and
# the signer.
#
# Usage:
#   ./scripts/check-relay-invariants.sh          run and tear down
#   IMAGE=noombat-chatmail:latest ./scripts/check-relay-invariants.sh
#   KEEP=1 ./scripts/check-relay-invariants.sh   leave the container up

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

IMAGE="${IMAGE:-noombat-chatmail:verify}"
CONTAINER="noombat-relay-invariants"
MAIL_DOMAIN="chat.localhost"
SELECTOR="noombat"
WORKDIR="$(mktemp -d)"

FAILURES=0
say() { printf '  %s\n' "$*"; }
fail() {
    printf '::error::%s\n' "$*" >&2
    FAILURES=$((FAILURES + 1))
}

cleanup() {
    if [ -z "${KEEP:-}" ]; then
        docker rm -f "$CONTAINER" >/dev/null 2>&1
    else
        say "KEEP is set, leaving $CONTAINER running"
    fi
    rm -rf "$WORKDIR"
}
trap cleanup EXIT

in_relay() { docker exec "$CONTAINER" "$@"; }

# ..... BRING THE RELAY UP .....

docker rm -f "$CONTAINER" >/dev/null 2>&1
# The admin sidecar refuses to start without a secret and s6 restarts it
# for as long as the container lives, which buries the log this gate
# reads. Nothing here talks to the sidecar; the value only has to exist.
if ! docker run -d --name "$CONTAINER" \
    -e MAIL_DOMAIN="$MAIL_DOMAIN" \
    -e CHATMAIL_ADMIN_SECRET="relay-invariants-gate" \
    -e FILTERMAIL_RATE_PER_MINUTE=6 \
    -e FILTERMAIL_RATE_BURST=2 \
    "$IMAGE" >/dev/null; then
    fail "could not start $IMAGE"
    exit 1
fi

# perl, not bash's /dev/tcp: the container's shell is dash, where the
# redirect is a plain "no such file" and the wait would time out however
# healthy the relay was.
port_open() {
    in_relay perl -e '
        use IO::Socket::INET;
        my $sock = IO::Socket::INET->new(
            PeerAddr => "127.0.0.1", PeerPort => $ARGV[0], Timeout => 2);
        exit($sock ? 0 : 1)
    ' "$1" >/dev/null 2>&1
}

say "waiting for the relay to answer on 25"
ready=""
for _ in $(seq 1 60); do
    if port_open 25; then
        ready=yes
        break
    fi
    sleep 1
done
if [ -z "$ready" ]; then
    fail "the relay never answered on port 25"
    docker logs "$CONTAINER" 2>&1 | tail -30 >&2
    exit 1
fi

# The filter is a separate daemon now, and Postfix answers 4xx when it
# is missing rather than admitting mail unfiltered. Check it is up, so a
# later pass is not a pass by the wrong route.
if ! port_open 10026; then
    fail "the before-queue filter is not listening on 10026"
fi

docker cp scripts/fixtures/smtp-submit.pl "$CONTAINER:/tmp/smtp-submit.pl" >/dev/null

in_relay sh -c '
    postconf -e "virtual_transport=capture:dummy"
    postconf -M "capture/unix=capture unix - n n - 10 pipe \
        flags=Rq user=nobody argv=/usr/bin/tee -a /tmp/captured.eml"
    postfix reload
' >/dev/null 2>&1
sleep 2

# Returns the captured message size, having first cleared the queue and
# the capture file so each case starts from nothing.
submit() {
    local kind="$1" tag="$2"
    in_relay sh -c 'postsuper -d ALL >/dev/null 2>&1
        : > /tmp/captured.eml
        chmod 666 /tmp/captured.eml'
    in_relay perl /tmp/smtp-submit.pl \
        --host 127.0.0.1 --port 25 --body "$kind" --tag "$tag" \
        >"$WORKDIR/$tag.log" 2>&1
    sleep 5
}

# The last reply the conversation received, and the step it came at.
# Not the reply to the message alone: a relay whose signer is down
# refuses at MAIL FROM and never reaches end-of-data, and reading only
# the last step would report that as no answer at all.
verdict_of() {
    awk 'NF > 1 { $1 = ""; sub(/^ +/, ""); last = $0 } END { print last }' "$WORKDIR/$1.log"
}
step_of() { awk 'NF > 1 { last = $1 } END { print last }' "$WORKDIR/$1.log"; }
captured_bytes() { in_relay sh -c 'wc -c < /tmp/captured.eml' | tr -d '[:space:]'; }
queued_now() { in_relay sh -c 'mailq 2>/dev/null | grep -c "^[A-F0-9]"' | tr -d '[:space:]'; }

# ..... ONE: THE ENCRYPTION-ONLY INVARIANT .....

printf '\n== the encryption-only invariant ==\n'

submit encrypted accepted
verdict="$(verdict_of accepted)"
if [ "${verdict:0:1}" = "2" ]; then
    say "an encrypted message is accepted: $verdict"
else
    fail "an encrypted message was not accepted: ${verdict:-no reply at all}"
fi
accepted_bytes="$(captured_bytes)"
if [ "${accepted_bytes:-0}" -gt 0 ]; then
    say "and delivered: $accepted_bytes bytes"
    docker cp "$CONTAINER:/tmp/captured.eml" "$WORKDIR/accepted.eml" >/dev/null
else
    fail "an encrypted message was accepted but never delivered"
fi

submit plain refused
verdict="$(verdict_of refused)"
if [ "${verdict:0:1}" = "5" ]; then
    say "a plaintext message is refused: $verdict"
else
    fail "a plaintext message was not refused: ${verdict:-no reply at all}"
fi

refused_bytes="$(captured_bytes)"
if [ "${refused_bytes:-1}" -eq 0 ]; then
    say "nothing was delivered, so no notification carried the plaintext back"
else
    fail "a refused message still produced $refused_bytes bytes of delivery"
fi

still_queued="$(queued_now)"
if [ "${still_queued:-1}" -eq 0 ]; then
    say "and the queue is empty"
else
    fail "a refused message left $still_queued item(s) in the queue"
fi

# Postfix allocates a queue id at end-of-DATA for an after-queue filter
# and allocates none here, which is the evidence nothing was written.
#
# The log goes to a file before it is searched: `grep -q` exits at the
# first match, `docker logs` then takes SIGPIPE, and under `pipefail` a
# match is reported as failure.
docker logs "$CONTAINER" >"$WORKDIR/relay.log" 2>&1
if grep -q "proxy-reject: END-OF-MESSAGE" "$WORKDIR/relay.log"; then
    say "Postfix recorded proxy-reject at end-of-data, so no queue file was made"
else
    fail "no proxy-reject in the log; the refusal did not happen before the queue"
fi

# ..... TWO: DKIM SIGNING .....

printf '\n== DKIM signing ==\n'

if [ -f "$WORKDIR/accepted.eml" ]; then
    key_in_relay="/etc/opendkim/keys/$MAIL_DOMAIN/$SELECTOR.txt"
    docker cp "$CONTAINER:$key_in_relay" "$WORKDIR/$SELECTOR.txt" >/dev/null 2>&1
    if [ ! -s "$WORKDIR/$SELECTOR.txt" ]; then
        fail "the relay generated no $SELECTOR.txt to verify against"
    elif python3 scripts/verify-dkim.py \
        --message "$WORKDIR/accepted.eml" \
        --key-txt "$WORKDIR/$SELECTOR.txt" \
        --expect-domain "$MAIL_DOMAIN" \
        --expect-selector "$SELECTOR"; then
        say "against the key the relay generated and prints for publication"
    else
        fail "the delivered message's signature does not verify"
    fi
else
    fail "no accepted message was captured, so there is no signature to verify"
fi

# A signer that has stopped must defer, not deliver unsigned. Under
# `accept` the mail goes out unsigned and the first sign of it is a peer
# relay rejecting this domain days later.
# The absolute path matters: `docker exec` gets a PATH without
# /command, so a bare `s6-svc` is "not found" and a fallback would
# quietly test something else.
say "stopping the signer"
if ! in_relay /command/s6-svc -d /run/service/opendkim; then
    fail "could not stop the opendkim service"
fi
# Poll rather than sleep. The listening socket outlives the process by
# under a second, and a fixed wait is either a flake or dead time.
stopped=""
for _ in $(seq 1 15); do
    if ! port_open 8891; then
        stopped=yes
        break
    fi
    sleep 1
done
if [ -z "$stopped" ]; then
    fail "the signer was told to stop and is still accepting on 8891"
fi

submit encrypted unsigned
verdict="$(verdict_of unsigned)"
if [ "${verdict:0:1}" = "4" ]; then
    say "with the signer stopped, mail is deferred at the $(step_of unsigned) step: $verdict"
else
    fail "with the signer stopped the relay answered ${verdict:-nothing}, not a 4xx"
fi

if [ "$(captured_bytes)" -eq 0 ]; then
    say "and nothing was delivered unsigned"
else
    fail "a message was delivered while the signer was stopped"
fi

say "restarting the signer"
if ! in_relay /command/s6-svc -u /run/service/opendkim; then
    fail "could not restart the opendkim service"
fi
sleep 5

# Restart and re-test, so the deferral above is attributable to the
# signer being stopped rather than to anything else that may have gone
# wrong by then.
submit encrypted resumed
verdict="$(verdict_of resumed)"
if [ "${verdict:0:1}" = "2" ]; then
    say "with the signer back, mail flows again: $verdict"
else
    fail "the relay did not recover after the signer restarted: ${verdict:-no reply}"
fi

# ..... THREE: THE SUBMISSION AND PEER CHECKS .....

printf '\n== the per-direction checks ==\n'

# Driven at the filter's own ports rather than through Postfix. The
# submission path needs SASL, which needs an account; the filter's ports
# are loopback-only inside the container and exercise exactly the logic
# under test.
filter() {
    in_relay perl /tmp/smtp-submit.pl --host 127.0.0.1 "$@" 2>&1 | tail -1
}

verdict="$(filter --port 10026 --body encrypted --tag OUT-MISMATCH \
    --from user@$MAIL_DOMAIN --header-from other@$MAIL_DOMAIN)"
if [[ "$verdict" == *" 550 "* ]]; then
    say "a submission whose From disagrees with the envelope is refused"
else
    fail "a mismatched From was not refused on submission: ${verdict:-nothing}"
fi

in_relay sh -c ': > /tmp/captured.eml; chmod 666 /tmp/captured.eml'
verdict="$(filter --port 10027 --body encrypted --tag IN-STRIP \
    --from peer@peer.invalid --header-from other@peer.invalid)"
sleep 4
if [[ "$verdict" == *" 250 "* ]] \
    && in_relay grep -q "^Return-Path: <MAILER-DAEMON>" /tmp/captured.eml; then
    say "the same mismatch from a peer is kept, with the envelope sender stripped"
else
    fail "an incoming mismatch was not stripped: ${verdict:-nothing}"
fi

verdict="$(filter --port 10027 --body encrypted --tag IN-UNALIGNED \
    --from peer@peer.invalid --header-from peer@elsewhere.invalid)"
if [[ "$verdict" == *" 250 "* ]]; then
    say "an unsigned peer message is left to OpenDKIM rather than refused here"
else
    fail "an unsigned peer message was refused by the filter: ${verdict:-nothing}"
fi

# Burst is 2 for this container, so the third in a row must be refused,
# and at MAIL FROM rather than after the body.
limited=""
for i in 1 2 3 4; do
    verdict="$(filter --port 10026 --body encrypted --tag "RATE$i")"
    if [[ "$verdict" == *" 450 "* ]]; then
        limited="$i"
        break
    fi
done
if [[ -n "$limited" ]]; then
    step_name="$(echo "$verdict" | awk '{print $1}')"
    say "the rate limit refuses submission $limited, at the $step_name step"
else
    fail "four submissions in a row were all accepted with a burst of 2"
fi

# ..... VERDICT .....

printf '\n'
if [ "$FAILURES" -gt 0 ]; then
    printf '::error::%d relay invariant failure(s)\n' "$FAILURES" >&2
    docker logs "$CONTAINER" 2>&1 | tail -40 >&2
    exit 1
fi

say "the relay carries only encrypted mail, and signs what it carries"
