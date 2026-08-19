#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
#
# Guard against markup that a strict Content-Security-Policy blocks.
#
# The instance serves
#   script-src 'self'; style-src 'self'
# with neither 'unsafe-inline' nor 'unsafe-eval'. Under that policy
# the browser refuses to execute inline script and refuses to apply
# inline style. Four constructs are therefore rejected here:
#
#   1. <script> elements without a src attribute.
#   2. Inline event-handler attributes (onclick, onchange, ...).
#   3. <style> elements and style="..." attributes.
#   4. javascript: URLs.
#
# HTML comments are stripped before matching, so documentation that
# names these constructs does not trip the guard. Comments spanning
# several lines are handled, and line numbers are preserved.
#
# Line-oriented matching means a <script> opening tag split across
# several lines is reported even when a src attribute appears on a
# later line. That direction of error is deliberate: it fails the
# build rather than admitting an inline block.
#
# Usage: scripts/check-inline-scripts.sh [directory]
#        Defaults to crates/noombat-api/templates.

set -eu

DIR="${1:-crates/noombat-api/templates}"

if [ ! -d "$DIR" ]; then
    echo "::error::template directory not found: $DIR" >&2
    exit 1
fi

# A scan that reaches no file would otherwise read as a clean tree.
COUNT=$(find "$DIR" -type f -name '*.html' -print | wc -l)
if [ "$COUNT" -eq 0 ]; then
    echo "::error::no .html templates found under $DIR, so this check proves nothing" >&2
    exit 2
fi

# Emit every template line as `path:lineno:content` with HTML
# comments blanked out.
stripped() {
    find "$DIR" -type f -name '*.html' -print | sort | while IFS= read -r f; do
        awk -v FNAME="$f" '
            BEGIN { incomment = 0 }
            {
                line = $0
                out = ""
                while (length(line) > 0) {
                    if (incomment) {
                        idx = index(line, "-->")
                        if (idx == 0) { line = "" }
                        else { line = substr(line, idx + 3); incomment = 0 }
                    } else {
                        idx = index(line, "<!--")
                        if (idx == 0) { out = out line; line = "" }
                        else {
                            out = out substr(line, 1, idx - 1)
                            line = substr(line, idx + 4)
                            incomment = 1
                        }
                    }
                }
                printf "%s:%d:%s\n", FNAME, FNR, out
            }
        ' "$f"
    done
}

SOURCE=$(stripped)

FAIL=0

report() {
    # $1: human-readable description, $2: matching lines (may be empty)
    if [ -n "$2" ]; then
        echo "::error::$1"
        echo "$2" | sed 's/^/    /'
        echo ""
        FAIL=$((FAIL + 1))
    else
        echo "  ok  $1: none found"
    fi
}

# 1. Opening <script> tags that carry no src attribute.
INLINE_SCRIPTS=$(printf '%s\n' "$SOURCE" | grep -E '<script([^>]*)>' | grep -v 'src=' || true)
report "inline <script> element (use a Vite entry point and src=\"/assets/...\")" \
    "$INLINE_SCRIPTS"

# 2. Inline event-handler attributes.
INLINE_HANDLERS=$(printf '%s\n' "$SOURCE" \
    | grep -E '[[:space:]]on[a-z]+[[:space:]]*=' || true)
report "inline event handler (use a delegated listener keyed on a data-* attribute)" \
    "$INLINE_HANDLERS"

# 3. Inline styles, as <style> blocks or style attributes.
INLINE_STYLES=$(printf '%s\n' "$SOURCE" \
    | grep -E '<style|[[:space:]]style[[:space:]]*=' || true)
report "inline style (declare a class in frontend/src/main.css instead)" \
    "$INLINE_STYLES"

# 4. javascript: URLs.
JS_URLS=$(printf '%s\n' "$SOURCE" | grep 'javascript:' || true)
report "javascript: URL" "$JS_URLS"

if [ "$FAIL" -gt 0 ]; then
    echo "::error::$FAIL Content-Security-Policy violation class(es) found in $DIR"
    exit 1
fi

echo ""
echo "Scanned $COUNT template(s) under $DIR: all compatible with script-src 'self'; style-src 'self'."
