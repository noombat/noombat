# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
#
# The credential the interop fixture actor signs in with.
#
# Sourced by seed.sh, which stores the hash, and by run.sh, which sends
# the key to `POST /api/v1/auth/login`. One file so the two cannot drift
# apart: a mismatch would surface as a 403 several hundred lines into a
# suite that is about federation, not about sign-in.
#
# Why a login at all: the routes run.sh exercises act for whoever the
# session says they are, and a session is the only way in. There is no
# instance-wide bearer to borrow.
#
# Why no password derivation: `auth_key` is derived in the browser and
# the server only ever sees 64 hex characters, so a fixture can pick a
# key directly and store the Argon2id hash of it.
#
# The key is the hex of "noombat-interop-fixture-key-0001", readable on
# purpose: finding it near a real deployment should be self-evidently
# wrong. It authenticates one throwaway actor on a throwaway stack.
#
# The hash is committed because neither script can run Argon2.
# Regenerate it, and prove it still verifies, with:
#
#     cargo test -p noombat-identity interop_fixture

FIXTURE_AUTH_KEY="6e6f6f6d6261742d696e7465726f702d666978747572652d6b65792d30303031"
FIXTURE_AUTH_KEY_HASH='$argon2id$v=19$m=19456,t=2,p=1$OrYtSXsp6m7JgG8s4LWwjA$Rgj/6eac1RI2cZVsmB9NBMX4KqOy2Mj6x5oyLz9cqNI'
