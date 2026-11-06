#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
#
# Load every compose combination this repository runs, so one that cannot
# start (a dependency cycle, overlays that do not merge) fails here rather
# than at `up` on a server. Each `${VAR:?}` gets a placeholder value.
#
# Usage:
#   ./scripts/check-compose-config.sh

set -euo pipefail
cd "$(dirname "$0")/.."

COMBOS=(
    "compose.yml"
    "compose.yml compose.dev.yml"
    "compose.yml compose.prod.yml"
    "compose.yml compose.acme.yml"
    "compose.yml compose.test.yml"
    "tests/interop/compose.yml"
    "tests/interop/compose.yml tests/interop/compose.latest.yml"
    "tests/chat-interop/compose.yml"
    "tests/chat-interop/compose.yml tests/chat-interop/compose.localbin.yml"
)

FAIL=0

# A file in no combination is never loaded, so that fails too.
for f in compose*.yml tests/*/compose*.yml; do
    case " ${COMBOS[*]} " in
        *" $f "*) ;;
        *) printf '  UNCHECKED %s: add the combination that uses it\n' "$f"; FAIL=1 ;;
    esac
done

for combo in "${COMBOS[@]}"; do
    read -ra files <<<"$combo"
    args=()
    vars=()
    for f in "${files[@]}"; do args+=(-f "$f"); done
    required=$( { grep -oh '\${[A-Z_]*:?' "${files[@]}" || true; } |
        sed 's/^\${//; s/:?$//' | sort -u)
    for v in $required; do vars+=("$v=placeholder-0123456789abcdef"); done
    if out=$(env "${vars[@]}" docker compose "${args[@]}" config -q 2>&1); then
        printf '  ok        %s\n' "$combo"
    else
        printf '  FAILED    %s\n' "$combo"
        grep -v 'level=warning' <<<"$out" | sed 's/^/            /'
        FAIL=1
    fi
done

echo
if [ "$FAIL" -eq 0 ]; then
    echo "Every compose combination loads."
    exit 0
fi
echo "Compose check FAILED." >&2
exit 1
