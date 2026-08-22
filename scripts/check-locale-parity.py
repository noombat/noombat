#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

"""Assert that every locale defines exactly the keys the baseline does.

A missing key does not fail at build time or at boot. It fails when a
reader in that locale reaches the page that uses it, and what they see is
the key name, in the middle of otherwise translated text. Nothing else in
this repository would report it, so a translation drifts silently from
the moment a key is added to the baseline and not to the others.

Extra keys fail too. An extra key is either a rename that only half
happened, in which case the other half is a missing key somewhere, or a
translation for something that no longer exists, in which case it is
carrying weight for nothing.

The set of locales is read from `AVAILABLE_LOCALES`, not from the
directory listing. Those two disagreed for months: seven files existed
and three could be negotiated, so four translations were maintained that
no reader could ever reach. Checking the files alone would have passed
throughout.

Usage:
  check-locale-parity.py

Exit 0 every locale agrees, 1 a locale differs, 2 nothing was compared.
"""

import re
import sys
from pathlib import Path

LOCALE_DIR = Path("crates/noombat-api/locales")
I18N_SOURCE = Path("crates/noombat-api/src/i18n.rs")

# A top-level key: no indentation, no comment, no list item. The files
# are flat by convention, and an indented line is reported rather than
# skipped, so the convention cannot quietly stop holding.
TOP_LEVEL_KEY = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s*:")


def available_locales(source: str) -> list[str]:
    """The locales the application will actually negotiate."""
    match = re.search(r"AVAILABLE_LOCALES:\s*&\[&str\]\s*=\s*&\[([^\]]*)\]", source)
    if not match:
        raise LookupError(f"no AVAILABLE_LOCALES in {I18N_SOURCE}")
    return re.findall(r'"([^"]+)"', match.group(1))


def default_locale(source: str) -> str:
    """The baseline every other locale is compared against."""
    match = re.search(r'DEFAULT_LOCALE:\s*&str\s*=\s*"([^"]+)"', source)
    if not match:
        raise LookupError(f"no DEFAULT_LOCALE in {I18N_SOURCE}")
    return match.group(1)


def keys_of(path: Path) -> tuple[set[str], list[str]]:
    """Top-level keys, and any line that is indented under one."""
    keys, nested = set(), []
    for number, line in enumerate(path.read_text().split("\n"), start=1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line[0].isspace():
            nested.append(f"{path.name}:{number}")
            continue
        match = TOP_LEVEL_KEY.match(line)
        if match:
            keys.add(match.group(1))
    return keys, nested


def main() -> int:
    if not I18N_SOURCE.is_file():
        print(f"::error::{I18N_SOURCE} not found; run from the repository root", file=sys.stderr)
        return 2

    source = I18N_SOURCE.read_text()
    try:
        locales = available_locales(source)
        baseline_tag = default_locale(source)
    except LookupError as error:
        print(f"::error::{error}", file=sys.stderr)
        return 2

    if baseline_tag not in locales:
        print(
            f"::error::DEFAULT_LOCALE {baseline_tag} is not in AVAILABLE_LOCALES {locales}",
            file=sys.stderr,
        )
        return 1

    # A locale that can be negotiated and has no file renders every key
    # as its own name, so this is a failure and not a skip.
    missing_files = [tag for tag in locales if not (LOCALE_DIR / f"{tag}.yml").is_file()]
    if missing_files:
        for tag in missing_files:
            print(f"::error::{tag} is negotiable and has no {tag}.yml", file=sys.stderr)
        return 1

    # A file that no locale names is a translation nobody can reach.
    named = {f"{tag}.yml" for tag in locales}
    unreachable = sorted(p.name for p in LOCALE_DIR.glob("*.yml") if p.name not in named)
    for name in unreachable:
        print(
            f"::error file={LOCALE_DIR / name}::{name} is not in AVAILABLE_LOCALES, "
            "so no reader can ever see it",
            file=sys.stderr,
        )

    baseline, nested = keys_of(LOCALE_DIR / f"{baseline_tag}.yml")

    # Before any comparison, not after. An empty baseline makes every
    # locale look like it defines surplus keys, so running the
    # comparisons first buries the one line that explains the run.
    if not baseline:
        print(
            f"::error::{baseline_tag} has no keys, so nothing was compared",
            file=sys.stderr,
        )
        return 2

    failures = len(unreachable)

    for location in nested:
        print(
            f"::error::{location} is indented, and this check only compares top-level keys",
            file=sys.stderr,
        )
        failures += 1

    for tag in locales:
        if tag == baseline_tag:
            continue
        keys, nested = keys_of(LOCALE_DIR / f"{tag}.yml")
        for location in nested:
            print(f"::error::{location} is indented, and is not compared", file=sys.stderr)
            failures += 1

        for key in sorted(baseline - keys):
            print(
                f"::error file={LOCALE_DIR / f'{tag}.yml'}::{tag} is missing '{key}', "
                f"which {baseline_tag} defines; readers see the key name",
                file=sys.stderr,
            )
            failures += 1
        for key in sorted(keys - baseline):
            print(
                f"::error file={LOCALE_DIR / f'{tag}.yml'}::{tag} defines '{key}', "
                f"which {baseline_tag} does not",
                file=sys.stderr,
            )
            failures += 1

    if failures:
        print(f"::error::{failures} locale parity failure(s)", file=sys.stderr)
        return 1

    print(
        f"Compared {len(baseline)} keys across {len(locales)} locale(s) "
        f"against {baseline_tag}: all agree."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
