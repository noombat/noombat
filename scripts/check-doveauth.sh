#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
#
# Exercise the Dovecot checkpassword helper directly, against a throwaway
# VMAIL_HOME.
#
# The helper runs before anybody is authenticated, so what it does for an
# address it has never seen is a security property and not a detail. It
# used to create the account, storing whatever password the caller
# offered: an outsider could claim any unused address on the relay over
# published IMAP (993) or submission (465). This asserts the branch is
# gone, and asserts it by looking at the filesystem rather than at an exit
# code, because the defect being guarded against is one that *succeeds*.
#
# Runs in seconds with no container, so it belongs on the fast path. The
# chat-interop suite covers the same property end to end through a real
# Dovecot; this covers it on every push.
#
# Usage:
#   ./scripts/check-doveauth.sh

set -uo pipefail

HELPER="$(cd "$(dirname "$0")/.." && pwd)/chatmail-config/noombat-doveauth"
FAILURES=0

if [ ! -x "$HELPER" ]; then
    echo "FAIL: $HELPER is missing or not executable"
    exit 1
fi

# Run the helper the way Dovecot does: credentials on fd 3, null
# separated, with a program to exec on success.
#
# The exec target is `true`, so a pass is exit 0 and nothing else.
run_helper() {
    local user="$1" pass="$2" root="$3"
    printf '%s\0%s\0' "$user" "$pass" > "$root/creds"
    VMAIL_HOME="$root" "$HELPER" true 3< "$root/creds"
}

check() {
    local label="$1" expected="$2" actual="$3"
    if [ "$expected" = "$actual" ]; then
        echo "ok   $label"
    else
        echo "FAIL $label: expected $expected, got $actual"
        FAILURES=$((FAILURES + 1))
    fi
}

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# An account the application has provisioned.
mkdir -p "$WORK/alice@chat.test/Maildir/cur"
printf '%s' "correct-horse" > "$WORK/alice@chat.test/password"

run_helper "alice@chat.test" "correct-horse" "$WORK"
check "an existing account with the right password authenticates" 0 $?

run_helper "alice@chat.test" "wrong" "$WORK"
check "an existing account with the wrong password is refused" 1 $?

run_helper "" "somepass" "$WORK"
check "an empty username is refused" 1 $?

run_helper "alice@chat.test" "" "$WORK"
check "an empty password is refused" 1 $?

# The P0. An address with no password file must be refused, and must not
# be brought into existence by the attempt.
run_helper "squatter@chat.test" "attacker-chosen" "$WORK"
check "an unknown address is refused" 1 $?

if [ -e "$WORK/squatter@chat.test" ]; then
    echo "FAIL an unknown address must not be created by a login attempt:"
    echo "     $WORK/squatter@chat.test exists after the attempt"
    find "$WORK/squatter@chat.test" | sed 's/^/       /'
    FAILURES=$((FAILURES + 1))
else
    echo "ok   an unknown address is not created by a login attempt"
fi

# Same address, second attempt: a helper that created on the first would
# now "verify" the attacker's own password and return 0.
run_helper "squatter@chat.test" "attacker-chosen" "$WORK"
check "a repeated attempt on an unknown address is still refused" 1 $?

echo
if [ "$FAILURES" -eq 0 ]; then
    echo "check-doveauth: all checks passed"
    exit 0
fi
echo "check-doveauth: $FAILURES check(s) failed"
exit 1
