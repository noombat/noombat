#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
#
# Assert that CodeQL still analyses what the workflow says it analyses.
#
# A `paths-ignore` pattern goes wrong in two directions, and only one of
# them announces itself:
#
#   1. It excludes every file of a configured language. CodeQL treats
#      that as fatal rather than as nothing to do: `database finalize`
#      exits 32 with "detected code written in Python but could not
#      process any of it". Loud, and it has happened here once, when
#      `scripts/**` was excluded and every Python file was under it.
#
#   2. It excludes files nobody meant to exclude, while leaving enough
#      behind for the job to pass. Nothing reports this. Coverage
#      shrinks and every check stays green.
#
# The first is a count. The second needs a baseline, so the directories
# holding excluded files are listed in `.github/codeql/excluded-dirs.txt`
# and any change to that set fails until the file is updated in the same
# commit. Directories rather than individual files: adding a test must
# not churn the baseline, while a pattern that reaches into a new part of
# the tree must.
#
# The languages come from the workflow's matrix rather than from a list
# here, so adding a language to one without the other is itself an error.
#
# Usage:
#   python3 scripts/check-codeql-config.py
#   python3 scripts/check-codeql-config.py --baseline   # rewrite the list

import re
import subprocess
import sys
from pathlib import Path

WORKFLOW = Path(".github/workflows/codeql.yml")
CONFIG = Path(".github/codeql/codeql-config.yml")
BASELINE = Path(".github/codeql/excluded-dirs.txt")

# Which files each language's extractor reads. A language in the matrix
# with no entry here is an error rather than a skip: silently checking
# nothing is the failure this script exists to prevent.
LANGUAGE_SUFFIXES = {
    "rust": (".rs",),
    "python": (".py",),
    "javascript-typescript": (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"),
}

MATRIX_LANGUAGE = re.compile(r"^\s*-\s*language:\s*(\S+)\s*$")
LIST_ENTRY = re.compile(r'^\s*-\s*"([^"]+)"\s*$')


def workflow_languages():
    """The languages the CodeQL workflow's matrix names."""
    text = WORKFLOW.read_text(encoding="utf-8")
    return [m.group(1) for line in text.split("\n")
            if (m := MATRIX_LANGUAGE.match(line))]


def ignored_patterns():
    """The `paths-ignore` entries, read without a YAML library.

    Nothing else in `scripts/` needs one, and adding a dependency to a
    gate is a way to make the gate skippable.
    """
    patterns, inside = [], False
    for line in CONFIG.read_text(encoding="utf-8").split("\n"):
        if line.startswith("paths-ignore:"):
            inside = True
            continue
        if inside:
            if (m := LIST_ENTRY.match(line)):
                patterns.append(m.group(1))
            elif line.strip() and not line.lstrip().startswith("#"):
                break
    return patterns


def glob_to_regex(pattern):
    """CodeQL path globs: `**` spans separators, `*` does not."""
    out, i = [], 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out.append("(?:[^/]+/)*")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return "".join(out)


def matcher(pattern):
    if "*" not in pattern and "?" not in pattern:
        prefix = pattern.rstrip("/")
        return lambda p: p == prefix or p.startswith(prefix + "/")
    compiled = re.compile("^" + glob_to_regex(pattern) + "$")
    return lambda p: bool(compiled.match(p))


def tracked_files():
    result = subprocess.run(["git", "ls-files"], capture_output=True, text=True)
    if result.returncode != 0:
        print("::error::git ls-files failed; run this from the repository root",
              file=sys.stderr)
        sys.exit(2)
    return [line for line in result.stdout.split("\n") if line]


def analysed_by(language, path):
    if language == "actions":
        return path.startswith(".github/workflows/") and path.endswith((".yml", ".yaml"))
    return path.endswith(LANGUAGE_SUFFIXES[language])


def main(argv):
    for required in (WORKFLOW, CONFIG):
        if not required.is_file():
            print(f"::error::{required} not found; run from the repository root",
                  file=sys.stderr)
            return 2

    languages = workflow_languages()
    if not languages:
        print("::error::no languages found in the workflow matrix, so this "
              "check proves nothing", file=sys.stderr)
        return 2

    unknown = [l for l in languages
               if l != "actions" and l not in LANGUAGE_SUFFIXES]
    if unknown:
        print(f"::error::the workflow analyses {', '.join(unknown)}, which this "
              "check does not know how to count; add the extensions above",
              file=sys.stderr)
        return 2

    excluded = [matcher(p) for p in ignored_patterns()]
    files = tracked_files()

    def is_excluded(path):
        return any(match(path) for match in excluded)

    failures = 0
    excluded_dirs = set()

    for language in languages:
        theirs = [f for f in files if analysed_by(language, f)]
        gone = [f for f in theirs if is_excluded(f)]
        kept = len(theirs) - len(gone)
        excluded_dirs.update(str(Path(f).parent) for f in gone)
        if kept == 0:
            print(f"  EMPTY    {language}: all {len(theirs)} file(s) excluded, "
                  "which fails the job rather than skipping the language")
            failures += 1
        else:
            print(f"  ok       {language}: {kept} analysed, {len(gone)} excluded")

    found = sorted(excluded_dirs)

    if "--baseline" in argv:
        # The generated file needs its own licence header, and `reuse
        # lint` reads the literal below as a second expression belonging
        # to this file. These markers are its documented way to say the
        # text is data rather than a declaration.
        # REUSE-IgnoreStart
        BASELINE.write_text(
            "# SPDX-License-Identifier: AGPL-3.0-or-later\n"
            "# SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes\n"
            "#\n"
            "# Directories holding files that `paths-ignore` keeps out of CodeQL.\n"
            "# Generated by scripts/check-codeql-config.py --baseline. A change\n"
            "# here is a change in what is scanned, so it belongs in the same\n"
            "# commit as the pattern that caused it.\n"
            "\n" + "".join(f"{d}\n" for d in found),
            encoding="utf-8",
        )
        # REUSE-IgnoreEnd
        print(f"\nwrote {BASELINE} with {len(found)} directory(ies)")
        return 0

    if not BASELINE.is_file():
        print(f"::error::{BASELINE} is missing; generate it with --baseline",
              file=sys.stderr)
        return 2

    expected = sorted(
        line.strip() for line in BASELINE.read_text(encoding="utf-8").split("\n")
        if line.strip() and not line.startswith("#")
    )

    for directory in sorted(set(found) - set(expected)):
        print(f"  NEW      {directory} is newly excluded from CodeQL")
        failures += 1
    for directory in sorted(set(expected) - set(found)):
        print(f"  STALE    {directory} is listed but no longer excluded")
        failures += 1

    print()
    if failures:
        print(f"::error::{failures} CodeQL configuration problem(s). A newly "
              "excluded directory is a reduction in what is scanned: keep it "
              "and record it with --baseline, or narrow the pattern.")
        return 1

    print(f"CodeQL analyses {len(languages)} language(s); "
          f"{len(expected)} excluded directory(ies), all expected.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
