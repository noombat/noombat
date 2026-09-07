#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
"""Attempt an IMAP login for an address that has never been provisioned.

Stands in for an outsider with no account. The relay's checkpassword
helper used to create the mailbox on this login, storing whatever
password arrived, which let anyone claim any unused address over the
published IMAP port. This probe makes that request; run.sh then asks the
sidecar whether an account now exists.

Exits 0 when the login is refused, which is the expected outcome. It
exits 1 if the login *succeeds*, because that means the account was
created for us. Neither exit code is the real assertion: an account can
be created by a login that is then refused for some other reason, so what
run.sh checks afterwards is whether any filesystem state appeared.

Certificate verification is off. The relay's CA is generated at boot
inside the container and its leaf names `chat.test.local`, while this
probe reaches it as localhost. The subject here is account creation, not
the chain, which the provisioning path through Noombat covers.

Usage: squat-probe.py <host> <port> <address> <password>
"""

import imaplib
import ssl
import sys


def main() -> int:
    if len(sys.argv) != 5:
        print(__doc__, file=sys.stderr)
        return 2
    host, port, address, password = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        connection = imaplib.IMAP4_SSL(host, port, ssl_context=context, timeout=20)
    except Exception as error:  # noqa: BLE001 - any failure to reach 993 is fatal here
        print(f"could not open an IMAP session to {host}:{port}: {error}", file=sys.stderr)
        return 2

    try:
        connection.login(address, password)
    except imaplib.IMAP4.error as error:
        print(f"login refused, as expected: {error}")
        return 0
    finally:
        try:
            connection.logout()
        except Exception:  # noqa: BLE001 - the session may already be gone
            pass

    print(f"LOGIN {address} SUCCEEDED without the account ever being provisioned", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
