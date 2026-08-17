#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
#
# Reject templates whose HTML comment delimiters do not balance.
#
# Askama validates its own {% %} and {# #} syntax and passes HTML through
# untouched, so a comment left open compiles clean and is visible only in
# a browser. The damage is not confined to the file: the comment runs to
# the next --> in the rendered page, which is usually in the layout being
# extended, taking the markup between them with it.
#
# Three faults, the first two reported at the line the comment was opened:
#
#   1. A <!-- that reaches end of file with no -->.
#   2. A <!-- inside an open comment. HTML has no nested comments, so the
#      enclosing comment ends at a --> written for something else. An
#      end-of-file check alone misses this: the file ends outside a
#      comment and only the delimiter counts disagree.
#   3. A --> that closes nothing, reported where it appears.
#
# Delimiters are counted as occurrences, not per line: a line may hold
# several and one comment may span many.
#
# Usage: scripts/check-template-comments.sh [directory]
#        Defaults to crates/noombat-api/templates.

set -eu

DIR="${1:-crates/noombat-api/templates}"

if [ ! -d "$DIR" ]; then
    echo "::error::template directory not found: $DIR" >&2
    exit 2
fi

FILES=$(find "$DIR" -type f -name '*.html' -print | sort)

COUNT=0
if [ -n "$FILES" ]; then
    COUNT=$(printf '%s\n' "$FILES" | wc -l)
fi

# A scan that reaches no file would otherwise read as a clean tree.
if [ "$COUNT" -eq 0 ]; then
    echo "::error::no .html templates found under $DIR, so this check proves nothing" >&2
    exit 2
fi

VIOLATIONS=$(printf '%s\n' "$FILES" | while IFS= read -r f; do
    awk -v FNAME="$f" '
        BEGIN { incomment = 0; openline = 0; named = 0; opens = 0; closes = 0; hits = 0 }
        {
            line = $0
            while (length(line) > 0) {
                opened = index(line, "<!--")
                closed = index(line, "-->")
                if (incomment) {
                    # An opening delimiter inside a comment is comment
                    # text to the browser, so the comment it appears in
                    # is the one that lost its -->.
                    if (opened > 0 && (closed == 0 || opened < closed)) {
                        opens++
                        if (!named) {
                            printf "%s:%d: <!-- opened here has no --> and swallows the <!-- at line %d\n",
                                FNAME, openline, FNR
                            hits++
                            named = 1
                        }
                        line = substr(line, opened + 4)
                    } else if (closed > 0) {
                        closes++
                        line = substr(line, closed + 3)
                        incomment = 0
                        named = 0
                    } else {
                        line = ""
                    }
                } else {
                    if (opened > 0 && (closed == 0 || opened < closed)) {
                        opens++
                        line = substr(line, opened + 4)
                        incomment = 1
                        openline = FNR
                        named = 0
                    } else if (closed > 0) {
                        closes++
                        printf "%s:%d: stray --> closing no open comment\n", FNAME, FNR
                        hits++
                        line = substr(line, closed + 3)
                    } else {
                        line = ""
                    }
                }
            }
        }
        END {
            if (incomment) {
                printf "%s:%d: <!-- opened here is never closed\n", FNAME, openline
                hits++
            }
            # Backstop: the three faults above account for every way the
            # counts can differ, so a silent disagreement means the scan
            # above is wrong rather than the template.
            if (opens != closes && hits == 0) {
                printf "%s:%d: %d <!-- against %d --> and the scan named no cause\n",
                    FNAME, FNR, opens, closes
            }
        }
    ' "$f"
done)

if [ -n "$VIOLATIONS" ]; then
    BAD=$(printf '%s\n' "$VIOLATIONS" | wc -l)
    echo "::error::unbalanced HTML comment in $DIR"
    printf '%s\n' "$VIOLATIONS" | sed 's/^/    /'
    echo ""
    echo "::error::$BAD unbalanced HTML comment(s) across $COUNT template(s)"
    exit 1
fi

echo "Scanned $COUNT template(s) under $DIR: every <!-- has its own -->."
