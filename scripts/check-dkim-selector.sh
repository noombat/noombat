#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
#
# Assert that everything naming the DKIM selector names the same one.
#
# Two files in this repository name it: the relay entrypoint, which
# generates the selector, and the setup wizard, which checks for the
# published record. The deployment guide is a third.
#
# The guide is deliberately not checked here. A gate must not take a
# documentation file as an input: prose is reworded and reformatted
# freely, and `docs/` is held back from this repository, so parsing it
# means comparing against a file absent from every CI checkout and
# reporting a pass for having checked less than it looks like. The two
# sources compared below are both versioned and both present in CI.
# Keeping the guide correct is a documentation review.
#
# Every one of those is individually plausible, and the failure is
# silent in the worst direction. An operator publishes what the guide
# says; the relay signs with a selector no record exists for; receiving
# relays get a signature they cannot verify. A message that fails DKIM
# is treated worse than one carrying no signature at all, so the
# mismatch is not a missing feature but an active harm, and nothing in
# the system reports it: the relay logs a successful signing, the wizard
# reports a missing record, and neither mentions the other.
#
# Usage:
#   ./scripts/check-dkim-selector.sh

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

ENTRYPOINT="chatmail-config/entrypoint.sh"
WIZARD="scripts/chatmail-setup.sh"

FAILURES=0
note() { printf '  %s\n' "$*"; }
fail() { printf '::error::%s\n' "$*" >&2; FAILURES=$((FAILURES + 1)); }

# The relay is the source of truth: it is what actually signs.
selector="$(sed -n 's/^DKIM_SELECTOR=\([A-Za-z0-9_-]*\).*/\1/p' "$ENTRYPOINT" | head -1)"
if [ -z "$selector" ]; then
    fail "no DKIM_SELECTOR in $ENTRYPOINT, so there is nothing to compare against"
    exit 2
fi
note "the relay signs with: $selector"

# The wizard must check that selector, and must not be looping over
# guesses: a loop passes on any of several names, which is how it
# reported success while never trying the real one.
if grep -qE '^\s*for selector in' "$WIZARD"; then
    fail "$WIZARD still loops over candidate selectors instead of checking $selector"
fi
wizard_selector="$(sed -n 's/^DKIM_SELECTOR="\([A-Za-z0-9_-]*\)".*/\1/p' "$WIZARD" | head -1)"
if [ "$wizard_selector" != "$selector" ]; then
    fail "$WIZARD checks '${wizard_selector:-nothing}', the relay signs with '$selector'"
else
    note "the wizard checks:   $wizard_selector"
fi

if [ "$FAILURES" -gt 0 ]; then
    printf '::error::%d DKIM selector disagreement(s)\n' "$FAILURES" >&2
    exit 1
fi

note "the relay and the wizard both name '$selector'. The deployment guide is
      not compared here; see the note at the top of this file."
