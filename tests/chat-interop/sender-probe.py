#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

"""Ask the relay's submission port to take mail from a given sender.

Usage: sender-probe.py HOST PORT LOGIN PASSWORD SENDER RECIPIENT

Logs in as LOGIN, gives SENDER as MAIL FROM and RECIPIENT as RCPT TO, and
stops there: Postfix decides on the sender by the time RCPT TO is answered,
and nothing is sent. Prints "accepted" or "refused CODE MESSAGE", and exits
0 either way, or 2 if the session could not be completed.

The relay's certificate is not verified: this runs on the host, where the
name it was issued for does not resolve.
"""

import smtplib
import ssl
import sys


def main() -> int:
    if len(sys.argv) != 7:
        print(__doc__, file=sys.stderr)
        return 2
    host, port, login, password, sender, recipient = sys.argv[1], int(sys.argv[2]), *sys.argv[3:7]

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        with smtplib.SMTP_SSL(host, port, context=context, timeout=20) as smtp:
            smtp.login(login, password)
            for code, message in (smtp.mail(sender), smtp.rcpt(recipient)):
                if code >= 400:
                    print(f"refused {code} {message.decode(errors='replace')}")
                    return 0
            smtp.rset()
            print("accepted")
            return 0
    except (OSError, smtplib.SMTPException) as error:
        print(f"could not complete the session: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
