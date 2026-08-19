#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

"""Send one chat message over the relay WebSocket and report the outcome.

Usage: send-probe.py BASE_URL SESSION_TOKEN CHATMAIL_PASSWORD RECIPIENT
Exit 0 when the server confirms the send, 1 otherwise.

Sending is the only part of the Chatmail integration that leaves over
SMTP, and SMTP resolves its TLS roots through lettre rather than through
the connector IMAP uses. A suite that provisions and fetches but never
sends therefore passes with the submission path broken.

A hand-rolled client because the harness has only curl, whose build here
carries no WebSockets feature, and because the exchange is three frames.
"""

import base64
import hashlib
import json
import os
import socket
import struct
import sys
from urllib.parse import urlparse

TIMEOUT_SECONDS = 30
GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def handshake(sock, authority, token):
    """Upgrade the connection, returning any bytes read past the headers."""
    key = base64.b64encode(os.urandom(16)).decode()
    sock.sendall(
        (
            "GET /api/v1/chat/ws HTTP/1.1\r\n"
            f"Host: {authority}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            f"Cookie: noombat_session={token}\r\n"
            "\r\n"
        ).encode()
    )

    response = b""
    while b"\r\n\r\n" not in response:
        chunk = sock.recv(4096)
        if not chunk:
            raise RuntimeError("connection closed during the handshake")
        response += chunk

    status = response.split(b"\r\n", 1)[0].decode(errors="replace")
    if "101" not in status:
        raise RuntimeError(f"upgrade refused: {status}")

    accept = base64.b64encode(hashlib.sha1((key + GUID).encode()).digest())
    if accept not in response:
        raise RuntimeError("the server did not echo the expected accept key")

    return response.split(b"\r\n\r\n", 1)[1]


def send_text(sock, payload):
    """Write one masked text frame. A client frame must be masked."""
    data = payload.encode()
    frame = bytearray([0x81])
    if len(data) < 126:
        frame.append(0x80 | len(data))
    elif len(data) < (1 << 16):
        frame.append(0x80 | 126)
        frame += struct.pack(">H", len(data))
    else:
        frame.append(0x80 | 127)
        frame += struct.pack(">Q", len(data))
    mask = os.urandom(4)
    frame += mask
    frame += bytes(byte ^ mask[i % 4] for i, byte in enumerate(data))
    sock.sendall(bytes(frame))


class Frames:
    """Text frames, over a buffer that may already hold handshake overflow."""

    def __init__(self, sock, buffered):
        self.sock = sock
        self.buf = buffered

    def _take(self, count):
        while len(self.buf) < count:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise RuntimeError("connection closed")
            self.buf += chunk
        taken, self.buf = self.buf[:count], self.buf[count:]
        return taken

    def next_text(self):
        while True:
            first, second = self._take(2)
            opcode = first & 0x0F
            length = second & 0x7F
            if length == 126:
                length = struct.unpack(">H", self._take(2))[0]
            elif length == 127:
                length = struct.unpack(">Q", self._take(8))[0]
            payload = self._take(length)
            if opcode == 0x8:
                raise RuntimeError("the server closed the connection")
            if opcode == 0x1:
                return json.loads(payload.decode())


def await_type(frames, wanted):
    """Read until `wanted` arrives, or the server reports an error.

    Unsolicited `message` frames are expected: the session streams the
    mailbox on connect, and this probe cares about neither.
    """
    while True:
        message = frames.next_text()
        kind = message.get("type")
        if kind == wanted:
            return message
        if kind == "error":
            raise RuntimeError(f"server error: {message.get('message')}")


def main():
    if len(sys.argv) != 5:
        print(__doc__.splitlines()[2], file=sys.stderr)
        return 2
    base, token, password, recipient = sys.argv[1:]

    url = urlparse(base)
    if url.scheme != "http":
        print("only http:// is supported; the suite uses the published port", file=sys.stderr)
        return 2
    port = url.port or 80

    sock = socket.create_connection((url.hostname, port), timeout=TIMEOUT_SECONDS)
    sock.settimeout(TIMEOUT_SECONDS)
    try:
        frames = Frames(sock, handshake(sock, f"{url.hostname}:{port}", token))

        send_text(sock, json.dumps({"type": "auth", "password": password}))
        await_type(frames, "ready")

        # The body is opaque to the relay, which forwards ciphertext.
        body = base64.b64encode(b"noombat chat interop probe").decode()
        send_text(sock, json.dumps({"type": "send", "to": recipient, "body_b64": body}))
        confirmed = await_type(frames, "sent")

        print(f"sent to {confirmed.get('to')}")
        return 0
    except (OSError, RuntimeError, ValueError) as error:
        print(f"{error}", file=sys.stderr)
        return 1
    finally:
        sock.close()


if __name__ == "__main__":
    sys.exit(main())
