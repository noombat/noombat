# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
#
# The credentials the chat interop fixture accounts sign in with.
#
# Sourced by seed.sh, which stores the hashes, and by run.sh, which sends
# the keys to `POST /api/v1/auth/login`. One file so the two cannot drift
# apart: a mismatch would surface as a 401 in the middle of a suite that
# is about Chatmail, not about sign-in.
#
# Why seeded rather than registered: `POST /api/v1/auth/register` refuses
# with 503 unless the instance has an SMTP relay, because that path mints
# a password and awaits a recovery challenge. This stack runs a Chatmail
# relay, which carries end-to-end encrypted mail between people and is
# deliberately not the instance's own mailer, so there is no relay for
# instance mail here and registration cannot succeed. run.sh asserts that
# refusal rather than working around it.
#
# The keys are 64 hex characters because that is what the server accepts,
# and readable on purpose: finding one near a real deployment should be
# self-evidently wrong. They authenticate two throwaway accounts on a
# throwaway stack.
#
# The hashes are committed because neither script can run Argon2.
# Regenerate them, and prove they still verify, with:
#
#     cargo test -p noombat-identity interop_fixture

CHAT_ALICE_AUTH_KEY="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
CHAT_ALICE_AUTH_KEY_HASH='$argon2id$v=19$m=19456,t=2,p=1$g8hhtkSUN9WveG+7LxCLEw$6gSprdlVzTyv5sVm+egpOkkeq8flK63U+0BMfNDY+2U'
CHAT_BOB_AUTH_KEY="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
CHAT_BOB_AUTH_KEY_HASH='$argon2id$v=19$m=19456,t=2,p=1$QXggrOPjcsG1/SAxIjNJgw$t4P4lyYQX1KIWOer1E+uyyTGiK2HJ82XN1rG21FbOGM'
