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
# A delimiter is what a browser would count, not what the source looks
# like. {# ... #} is removed before the scan, because Askama removes it
# before any HTML exists, so a --> inside one closes nothing. Askama
# nests those, so the removal counts depth rather than stopping at the
# first #}. The abrupt forms the HTML tokeniser accepts are read the way
# it reads them: --!> ends a comment, and <!--> and <!---> are whole
# empty comments rather than an opening delimiter.
#
# Four faults, the first two reported at the line the comment was opened:
#
#   1. A <!-- that reaches end of file with no -->.
#   2. A <!-- inside an open comment. HTML has no nested comments, so the
#      enclosing comment ends at a --> written for something else. An
#      end-of-file check alone misses this: the file ends outside a
#      comment and only the delimiter counts disagree.
#   3. A --> that closes nothing, reported where it appears.
#   4. An {% if %} branch that opens or closes a comment its sibling
#      branches do not, reported at the line the branch opened. The
#      source balances and the rendered page does not, differently
#      depending on the branch taken. Commenting a block out under a
#      condition is written this way too and is reported the same, since
#      nothing in the text says that two conditions always agree.
#
# Delimiters are counted as occurrences, not per line: a line may hold
# several and one comment may span many.
#
# Blind spot: this counts delimiters, it never renders. A comment left
# open and a later stray --> cancel out and read as one long deliberate
# comment. Branches are checked for {% if %} only, not {% for %} bodies
# or {% match %} arms.
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
        # Drop {# ... #}, which may span lines and does nest, so an inner
        # #} closes the inner comment only. The line is rebuilt rather
        # than blanked, so the scan sees the text a browser would and FNR
        # keeps naming the real line.
        function strip_askama(s,    out, po, pc) {
            out = ""
            while (length(s) > 0) {
                po = index(s, "{#")
                if (askdepth > 0) {
                    pc = index(s, "#}")
                    if (pc == 0) return out
                    if (po > 0 && po < pc) {
                        askdepth++
                        s = substr(s, po + 2)
                    } else {
                        askdepth--
                        s = substr(s, pc + 2)
                    }
                } else {
                    if (po == 0) return out s
                    out = out substr(s, 1, po - 1)
                    s = substr(s, po + 2)
                    askdepth = 1
                }
            }
            return out
        }

        # Every open {% if %} is charged, so a delimiter pair nested in
        # an inner branch leaves the outer branch balanced.
        function charge(n,    i) {
            for (i = 1; i <= depth; i++) bdelta[i] += n
        }

        function close_branch(    d) {
            if (depth == 0) return
            d = bdelta[depth]
            if (d > 0) {
                printf "%s:%d: this %s branch opens %d comment(s) it does not close, so the rendered page depends on the branch taken\n",
                    FNAME, bline[depth], bkind[depth], d
                hits++
            } else if (d < 0) {
                printf "%s:%d: this %s branch closes %d comment(s) it did not open, so the rendered page depends on the branch taken\n",
                    FNAME, bline[depth], bkind[depth], -d
                hits++
            }
            bdelta[depth] = 0
        }

        # Whitespace control writes {%- and -%}, so the keyword is not
        # always the first thing in the tag body.
        function tag_word(b) {
            sub(/^[-+~]+/, "", b)
            sub(/^[ \t]+/, "", b)
            if (b ~ /^if([^A-Za-z0-9_]|$)/)          return "if"
            if (b ~ /^else[ \t]+if([^A-Za-z0-9_]|$)/) return "elseif"
            if (b ~ /^elif([^A-Za-z0-9_]|$)/)        return "elseif"
            if (b ~ /^else([^A-Za-z0-9_]|$)/)        return "else"
            if (b ~ /^endif([^A-Za-z0-9_]|$)/)       return "endif"
            return ""
        }

        function tag(b,    w) {
            w = tag_word(b)
            if (w == "if") {
                depth++
                bdelta[depth] = 0
                bline[depth] = FNR
                bkind[depth] = "{% if %}"
            } else if (w == "elseif" || w == "else") {
                if (depth > 0) {
                    close_branch()
                    bline[depth] = FNR
                    bkind[depth] = (w == "else") ? "{% else %}" : "{% else if %}"
                }
            } else if (w == "endif") {
                if (depth > 0) {
                    close_branch()
                    depth--
                }
            }
        }

        BEGIN {
            askdepth = 0; incomment = 0; openline = 0; named = 0
            opens = 0; closes = 0; hits = 0; depth = 0
        }
        {
            line = strip_askama($0)
            # One scan for both alphabets: an {% if %} inside a comment
            # still branches, and a delimiter inside a branch still has
            # to be charged to it.
            while (length(line) > 0) {
                popen  = index(line, "<!--")
                pclose = index(line, "-->")
                pbang  = index(line, "--!>")
                ptag   = index(line, "{%")
                # No two of these can start at the same column, so first
                # match wins outright.
                best = 0; kind = ""
                if (popen  > 0 && (best == 0 || popen  < best)) { best = popen;  kind = "open"  }
                if (pclose > 0 && (best == 0 || pclose < best)) { best = pclose; kind = "close" }
                if (pbang  > 0 && (best == 0 || pbang  < best)) { best = pbang;  kind = "bang"  }
                if (ptag   > 0 && (best == 0 || ptag   < best)) { best = ptag;   kind = "tag"   }
                if (best == 0) break
                line = substr(line, best)

                if (kind == "tag") {
                    ends = index(line, "%}")
                    if (ends == 0) {
                        tag(substr(line, 3))
                        line = ""
                    } else {
                        tag(substr(line, 3, ends - 3))
                        line = substr(line, ends + 2)
                    }
                } else if (kind == "open") {
                    after = substr(line, 5, 2)
                    if (!incomment && substr(after, 1, 1) == ">") {
                        # <!--> is a whole empty comment.
                        line = substr(line, 6)
                    } else if (!incomment && after == "->") {
                        # <!---> likewise.
                        line = substr(line, 7)
                    } else if (incomment) {
                        # An opening delimiter inside a comment is comment
                        # text to the browser, so the comment it appears in
                        # is the one that lost its -->.
                        opens++
                        if (!named) {
                            printf "%s:%d: <!-- opened here has no --> and swallows the <!-- at line %d\n",
                                FNAME, openline, FNR
                            hits++
                            named = 1
                        }
                        line = substr(line, 5)
                    } else {
                        opens++
                        incomment = 1
                        openline = FNR
                        named = 0
                        charge(1)
                        line = substr(line, 5)
                    }
                } else {
                    if (incomment) {
                        closes++
                        incomment = 0
                        named = 0
                        charge(-1)
                    } else if (kind == "close") {
                        closes++
                        printf "%s:%d: stray --> closing no open comment\n", FNAME, FNR
                        hits++
                    }
                    # Outside a comment --!> is ordinary text, so it is
                    # stepped over without a word.
                    line = substr(line, (kind == "bang") ? 5 : 4)
                }
            }
        }
        END {
            if (incomment) {
                printf "%s:%d: <!-- opened here is never closed\n", FNAME, openline
                hits++
            }
            # Backstop: the faults above account for every way the counts
            # can differ, so a silent disagreement means the scan above is
            # wrong rather than the template.
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
