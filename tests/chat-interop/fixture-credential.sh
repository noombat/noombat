# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
#
# The credentials the chat interop fixture accounts sign in with.
#
# Sourced by seed.sh, which stores the hashes, and by run.sh, which sends
# the keys to `POST /api/v1/auth/login`, and frank's and grace's passwords
# to the browser check, whose login page derives the keys. One file so
# they cannot drift apart: a mismatch would surface as a failed sign-in in
# the middle of a suite that is about Chatmail.
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
# and, but for the two a browser derives below, readable on purpose:
# finding one near a real deployment should be self-evidently wrong. They
# authenticate six throwaway accounts on a throwaway stack.
#
# The hashes are committed because neither script can run Argon2.
# Regenerate them, and prove they still verify, with:
#
#     cargo test -p noombat-identity interop_fixture
#
# frank's and grace's keys are what the login page derives from their
# passwords; `frontend/src/auth.spec.ts` checks that they still are, and
# a failure there prints the keys to commit.

CHAT_ALICE_AUTH_KEY="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
CHAT_ALICE_AUTH_KEY_HASH='$argon2id$v=19$m=19456,t=2,p=1$g8hhtkSUN9WveG+7LxCLEw$6gSprdlVzTyv5sVm+egpOkkeq8flK63U+0BMfNDY+2U'
CHAT_BOB_AUTH_KEY="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
CHAT_BOB_AUTH_KEY_HASH='$argon2id$v=19$m=19456,t=2,p=1$QXggrOPjcsG1/SAxIjNJgw$t4P4lyYQX1KIWOer1E+uyyTGiK2HJ82XN1rG21FbOGM'
CHAT_CAROL_AUTH_KEY="cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
CHAT_CAROL_AUTH_KEY_HASH='$argon2id$v=19$m=19456,t=2,p=1$lfL/uVBZwANJXzcUSCblrQ$ys3zjjD6DwgRUGdIKCoLHw0AmFsEWi1S44QWfwEj3d8'
CHAT_DAVE_AUTH_KEY="dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
CHAT_DAVE_AUTH_KEY_HASH='$argon2id$v=19$m=19456,t=2,p=1$+61jYA8rkRbcmypL9A+X2Q$WeZdqVrZ5T8eLFp/GhYBM3EwNNvTfCEyW8VWogstwtM'

# frank and grace sign in through the login page, in a browser (check 19),
# which sends what `deriveAuthKey` (frontend/src/auth.ts) derives from the
# password at `test.local`; these keys are that, and the hashes hash them.
CHAT_FRANK_PASSWORD="frank-chat-interop-password"
CHAT_FRANK_AUTH_KEY="4191317f072250915f904ea70c1d3c6b6decf373494f2e787cc67883cc812654"
CHAT_FRANK_AUTH_KEY_HASH='$argon2id$v=19$m=19456,t=2,p=1$53Yeic1aHj8JY3SL4SsH8A$MrvnEDfd4gHc/L+mID+PztubJfp8aSUynDglFWYAS1s'
CHAT_GRACE_PASSWORD="grace-chat-interop-password"
CHAT_GRACE_AUTH_KEY="34c3f535098cb560cf900da01623444fa9a995dddcb64ab6092500e4101dbbdf"
CHAT_GRACE_AUTH_KEY_HASH='$argon2id$v=19$m=19456,t=2,p=1$sm4wBsulfg4QFxOAbWdGRg$e2hkWSgm/1r8MAOPeltyzaCapVoVH02wsPMkejFze04'
