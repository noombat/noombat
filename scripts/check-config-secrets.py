#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
#
# Assert that every credential-bearing field on `Config` is typed
# `Secret` rather than `String`.
#
# `Secret` is what redacts a value from `Debug` output and what makes
# `NOOMBAT_X_FILE` work. A field declared `Option<String>` gets neither,
# and nothing else notices: the instance boots and the setting works.
#
# Names are the only available signal, so anything credential-shaped must
# be `Secret` or listed in ALLOWED with a reason.

import re
import sys
from pathlib import Path

CONFIG = Path("crates/noombat-server/src/main.rs")

# A field whose name matches any of these is treated as credential
# bearing. `_url` is included because a connection string carries its
# password inline, which is how `database_url` and `redis_url` came to
# need this in the first place.
CREDENTIAL_SHAPED = re.compile(
    r"(secret|token|password|passwd|credential|_key$|^key$|^kek$|_url$)"
)

# Fields whose names match but which carry no credential. Each needs a
# reason, and the reason is checked by a human at review, not here.
ALLOWED = {
    "meili_url": "the search endpoint, with the key in meili_key beside it",
    "chatmail_admin_url": "an internal address, no credential in it",
    "s3_access_key": "an access key ID is an identifier, published in every signed request",
}


def config_fields(text):
    """Yield (line_number, name, type) for each field on `Config`."""
    lines = text.split("\n")
    start = next(
        (i for i, l in enumerate(lines) if re.match(r"\s*(pub )?struct Config\b", l)),
        None,
    )
    if start is None:
        print("could not find `struct Config`; this gate is pointed at the wrong file")
        sys.exit(2)
    depth = 0
    for i in range(start, len(lines)):
        depth += lines[i].count("{") - lines[i].count("}")
        m = re.match(r"\s{4}(?:pub )?([a-z_0-9]+):\s*(.+?),\s*$", lines[i])
        if m:
            yield i + 1, m.group(1), m.group(2)
        if depth == 0 and i > start:
            return
    print("`struct Config` has no closing brace; refusing to guess")
    sys.exit(2)


def main():
    text = CONFIG.read_text(encoding="utf-8")
    fields = list(config_fields(text))
    if not fields:
        print(f"no fields parsed out of {CONFIG}; the gate would pass on anything")
        return 2

    problems = []
    checked = 0
    for line_no, name, type_ in fields:
        if not CREDENTIAL_SHAPED.search(name):
            continue
        if name in ALLOWED:
            continue
        checked += 1
        if "Secret" not in type_:
            problems.append((line_no, name, type_))

    if not checked:
        print("no credential-bearing fields matched; the pattern has stopped working")
        return 2

    for line_no, name, type_ in problems:
        print(f"{CONFIG}:{line_no}: `{name}` is `{type_}`, not `Secret`")
    if problems:
        print()
        print(f"{len(problems)} credential-bearing field(s) on `Config` are not `Secret`.")
        print("A bare String is not redacted from Debug output and cannot be given")
        print("as NOOMBAT_<NAME>_FILE. Use `Secret`, or add the field to ALLOWED in")
        print(f"{__file__} with the reason it carries no credential.")
        return 1

    print(f"ok: {checked} credential-bearing field(s) on `Config`, all `Secret`")
    print(f"    ({len(ALLOWED)} allowed by name, {len(fields)} fields scanned)")
    return 0


sys.exit(main())
