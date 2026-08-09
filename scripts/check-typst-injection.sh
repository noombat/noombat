#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
#
# Compile the CV markup corpus with the real Typst compiler and assert
# that hostile input is inert.
#
# The unit tests in `noombat-markup` assert that no user-derived byte
# leaves a string literal. That is a claim about generated source. This
# is the claim about what Typst then does with it, and the two can
# disagree: an escaping rule can be right about the bytes and wrong
# about the grammar. Only the compiler settles it.
#
# Each attack payload embeds `#panic("NB_EXEC_MARKER")`. If the emitter
# ever lets one reach code or math context, Typst evaluates it and the
# compile fails with that marker, which is what makes execution
# observable. Note that a payload can also execute *silently*
# (`eval("1+1")` succeeds and exits 0), which is why the payloads use
# panic rather than something quieter.
#
# Benign documents are compiled too. A corpus of nothing but attacks
# would still pass if the emitter were changed to discard its input.
#
# Usage:
#   ./scripts/check-typst-injection.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

# Pinned by digest, matching the Dockerfile's typst stage. An unpinned
# tag would let the thing under test change without the test changing.
TYPST_IMAGE="ghcr.io/typst/typst:0.15.0@sha256:b23ba03da5c085a2c8780bc9f2296db937abe1d0c75348cf2f8a9273199c3a14"
MARKER="NB_EXEC_MARKER"

CORPUS="$(mktemp -d)"
trap 'rm -rf "$CORPUS"' EXIT

echo "Generating the corpus from the emitter..."
NOOMBAT_TYPST_CORPUS_DIR="$CORPUS" \
    cargo test -p noombat-markup --lib -- --exact typst_conv::tests::emit_typst_corpus >/dev/null

shopt -s nullglob
files=("$CORPUS"/*.typ)
shopt -u nullglob

if [ ${#files[@]} -eq 0 ]; then
    echo "error: the emitter produced no corpus files" >&2
    echo "       (did emit_typst_corpus stop honouring NOOMBAT_TYPST_CORPUS_DIR?)" >&2
    exit 1
fi

FAIL=0

for path in "${files[@]}"; do
    name="$(basename "$path")"
    if output=$(docker run --rm \
        -v "$CORPUS":/corpus -w /corpus \
        "$TYPST_IMAGE" compile "$name" "${name%.typ}.pdf" 2>&1); then
        printf '  ok    %s\n' "$name"
        continue
    fi

    FAIL=1
    if grep -q "$MARKER" <<<"$output"; then
        printf '  EXEC  %s  <-- the payload executed\n' "$name" >&2
    else
        printf '  ERROR %s  <-- did not compile\n' "$name" >&2
    fi
    sed 's/^/        /' <<<"$output" | head -5 >&2
done

echo
if [ "$FAIL" -eq 0 ]; then
    echo "${#files[@]} document(s) compiled; no payload executed."
else
    echo "Typst injection check FAILED." >&2
fi

exit "$FAIL"
