#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

"""Read the encrypted payloads waiting in a mailbox, as a mail client sees them.

Usage: fetch-probe.py HOST PORT ADDRESS PASSWORD SENDER COUNT

Logs in over IMAP with implicit TLS and waits, up to a minute because
delivery is asynchronous, until INBOX holds COUNT messages from SENDER.
Prints the payload of each message's `application/octet-stream` part,
base64-encoded, one per line. Exits 0 once COUNT have arrived, 1 if fewer
did, and 2 if the session could not be opened.

The relay's certificate is not verified: this runs on the host, where the
name it was issued for does not resolve.
"""

import base64
import email
import email.policy
import imaplib
import ssl
import sys
import time

WAIT_SECONDS = 60


def payloads(connection: imaplib.IMAP4_SSL, sender: str) -> list[bytes]:
    connection.select("INBOX", readonly=True)
    status, data = connection.search(None, "FROM", f'"{sender}"')
    if status != "OK":
        return []
    found = []
    for number in data[0].split():
        status, fetched = connection.fetch(number, "(BODY.PEEK[])")
        if status != "OK" or not fetched or not isinstance(fetched[0], tuple):
            continue
        message = email.message_from_bytes(fetched[0][1], policy=email.policy.default)
        for part in message.walk():
            if part.get_content_type() == "application/octet-stream":
                found.append(part.get_payload(decode=True) or b"")
    return found


def main() -> int:
    if len(sys.argv) != 7:
        print(__doc__, file=sys.stderr)
        return 2
    host, port, address, password, sender = sys.argv[1], int(sys.argv[2]), *sys.argv[3:6]
    count = int(sys.argv[6])

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        connection = imaplib.IMAP4_SSL(host, port, ssl_context=context, timeout=20)
        connection.login(address, password)
    except Exception as error:  # noqa: BLE001 - any failure to sign in is fatal here
        print(f"could not open an IMAP session as {address}: {error}", file=sys.stderr)
        return 2

    try:
        deadline = time.monotonic() + WAIT_SECONDS
        found = payloads(connection, sender)
        while len(found) < count and time.monotonic() < deadline:
            time.sleep(2)
            found = payloads(connection, sender)
    finally:
        try:
            connection.logout()
        except Exception:  # noqa: BLE001 - the session may already be gone
            pass

    for payload in found:
        print(base64.b64encode(payload).decode())
    return 0 if len(found) >= count else 1


if __name__ == "__main__":
    sys.exit(main())
