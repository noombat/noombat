#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

# The two accounts the interop suite federates between, declared once so
# that seed.sh, which creates them, and run.sh, which signs in as the
# GoToSocial one to read that instance's state, cannot disagree about a
# name. A mismatch reports as a federation failure rather than a typo.
#
# Not secrets: fixtures for a throwaway instance that lives for the
# length of one `docker compose up`.

NOOMBAT_ACTOR="${NOOMBAT_ACTOR:-alice}"

# GoToSocial's sign-in form takes the email, not the username, so run.sh
# needs both. The password must satisfy its strength check.
GTS_ACTOR="${GTS_ACTOR:-bob}"
GTS_ACTOR_EMAIL="${GTS_ACTOR_EMAIL:-bob@interop.invalid}"
GTS_ACTOR_PASSWORD="${GTS_ACTOR_PASSWORD:-Interop-Test-1}"
