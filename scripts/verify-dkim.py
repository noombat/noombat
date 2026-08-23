#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
"""Verify a message's DKIM-Signature against a public key, offline.

A helper for `scripts/check-relay-invariants.sh`, not a gate itself.

Offline because a test relay has no DNS to publish the TXT record in.
The key is read from the `.txt` file `opendkim-genkey` wrote, which is
the same material the operator is told to publish.

RSA verification uses `openssl dgst` rather than a Python module that a
CI runner does not install by default.

Usage:
  verify-dkim.py --message FILE --key-txt FILE [--expect-domain d] \\
                 [--expect-selector s]
"""

import argparse
import base64
import hashlib
import re
import subprocess
import sys
import tempfile
from pathlib import Path


def split_message(raw: bytes) -> tuple[list[bytes], bytes]:
    """Return the header lines (each without its CRLF) and the body."""
    normalised = raw.replace(b"\r\n", b"\n")
    try:
        head, body = normalised.split(b"\n\n", 1)
    except ValueError:
        head, body = normalised, b""

    # Unfold: a line starting with space or tab continues the one above.
    headers: list[bytes] = []
    for line in head.split(b"\n"):
        if line[:1] in (b" ", b"\t") and headers:
            headers[-1] += b"\r\n" + line
        else:
            headers.append(line)
    return headers, body.replace(b"\n", b"\r\n")


def parse_tags(value: str) -> dict[str, str]:
    tags: dict[str, str] = {}
    for part in value.split(";"):
        if "=" not in part:
            continue
        key, _, val = part.partition("=")
        tags[key.strip()] = val.strip()
    return tags


def canonicalise_body(body: bytes, method: str) -> bytes:
    if method == "relaxed":
        lines = [re.sub(rb"[ \t]+", b" ", line).rstrip(b" \t") for line in body.split(b"\r\n")]
        body = b"\r\n".join(lines)
    # Both methods strip trailing empty lines and end with exactly one CRLF.
    body = body.rstrip(b"\r\n")
    return body + b"\r\n" if body else b"\r\n"


def canonicalise_header(line: bytes, method: str) -> bytes:
    if method == "simple":
        return line
    name, _, value = line.partition(b":")
    value = value.replace(b"\r\n", b" ")
    value = re.sub(rb"[ \t]+", b" ", value).strip()
    return name.strip().lower() + b":" + value


def take_headers(headers: list[bytes], names: list[str], method: str) -> bytes:
    """Assemble the signed header block, per RFC 6376 section 5.4.2.

    Each name in `h=` consumes one matching header, taken from the
    bottom of the message upward, so a name repeated in `h=` picks up
    successive occurrences.
    """
    remaining = list(headers)
    out = []
    for name in names:
        wanted = name.strip().lower().encode()
        for i in range(len(remaining) - 1, -1, -1):
            candidate = remaining[i]
            if candidate.partition(b":")[0].strip().lower() == wanted:
                out.append(canonicalise_header(candidate, method))
                del remaining[i]
                break
    return b"\r\n".join(out)


def public_key_pem(key_txt: Path) -> bytes:
    """Rebuild a PEM public key from what opendkim-genkey wrote."""
    text = key_txt.read_text(encoding="utf-8", errors="replace")
    joined = "".join(re.findall(r'"([^"]*)"', text))
    match = re.search(r"p=([A-Za-z0-9+/=]+)", joined)
    if not match:
        raise SystemExit(f"no p= tag in {key_txt}")
    der = match.group(1)
    wrapped = "\n".join(der[i : i + 64] for i in range(0, len(der), 64))
    return f"-----BEGIN PUBLIC KEY-----\n{wrapped}\n-----END PUBLIC KEY-----\n".encode()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--message", required=True, type=Path)
    ap.add_argument("--key-txt", required=True, type=Path)
    ap.add_argument("--expect-domain")
    ap.add_argument("--expect-selector")
    args = ap.parse_args()

    raw = args.message.read_bytes()
    headers, body = split_message(raw)

    signatures = [h for h in headers if h.partition(b":")[0].strip().lower() == b"dkim-signature"]
    if not signatures:
        print("FAIL: the message carries no DKIM-Signature header")
        return 1
    if len(signatures) > 1:
        print(f"FAIL: {len(signatures)} DKIM-Signature headers, expected exactly one")
        return 1

    sig_line = signatures[0]
    tags = parse_tags(sig_line.partition(b":")[2].decode("utf-8", "replace").replace("\r\n", ""))

    algorithm = tags.get("a", "")
    if algorithm != "rsa-sha256":
        print(f"FAIL: unsupported algorithm {algorithm!r}; this checker knows rsa-sha256")
        return 1

    if args.expect_domain and tags.get("d") != args.expect_domain:
        print(f"FAIL: signed for d={tags.get('d')!r}, expected {args.expect_domain!r}")
        return 1
    if args.expect_selector and tags.get("s") != args.expect_selector:
        print(f"FAIL: selector s={tags.get('s')!r}, expected {args.expect_selector!r}")
        return 1

    header_method, _, body_method = tags.get("c", "simple/simple").partition("/")
    body_method = body_method or "simple"

    # The body hash first: it is what ties the signature to this body
    # rather than to any body.
    digest = hashlib.sha256(canonicalise_body(body, body_method)).digest()
    if base64.b64encode(digest).decode() != tags.get("bh", ""):
        print("FAIL: bh= does not match the body; the signature covers a different message")
        return 1

    # Then the signature itself, over the signed headers plus this
    # header with its own b= emptied.
    signed = take_headers(headers, tags.get("h", "").split(":"), header_method)
    stripped = re.sub(rb"([;\s]b=)[^;]*", rb"\1", sig_line, count=1)
    block = signed + b"\r\n" + canonicalise_header(stripped, header_method)

    try:
        signature = base64.b64decode(re.sub(r"\s+", "", tags.get("b", "")))
    except Exception as exc:  # noqa: BLE001 - any decode failure is a failure
        print(f"FAIL: b= is not valid base64: {exc}")
        return 1

    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        (tmp / "key.pem").write_bytes(public_key_pem(args.key_txt))
        (tmp / "sig.bin").write_bytes(signature)
        (tmp / "data.bin").write_bytes(block)
        result = subprocess.run(
            [
                "openssl", "dgst", "-sha256",
                "-verify", str(tmp / "key.pem"),
                "-signature", str(tmp / "sig.bin"),
                str(tmp / "data.bin"),
            ],
            capture_output=True,
            text=True,
        )

    if result.returncode != 0:
        print("FAIL: the signature does not verify against the generated key")
        print(f"  openssl said: {(result.stdout + result.stderr).strip()}")
        return 1

    print(f"  signature verifies: d={tags.get('d')} s={tags.get('s')} c={tags.get('c')}")
    print(f"  body hash matches over {len(body)} bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
