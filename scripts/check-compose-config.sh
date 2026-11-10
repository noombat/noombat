#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
#
# Load every compose combination this repository runs, so one that cannot
# start (a dependency cycle, overlays that do not merge) fails here rather
# than at `up` on a server. Each `${VAR:?}` gets a placeholder value.
#
# Then check the host ports production publishes. An overlay cannot take
# away a port the base file publishes, because Compose merges port lists,
# so a published port only shows up in the merged result.
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

# Caddy's HTTP and HTTPS, and the relay's SMTP, submission and IMAPS; the
# application stays on the internal network, behind Caddy.
expected="caddy:443 caddy:80 chatmail:25 chatmail:465 chatmail:993"
published=$(docker compose -f compose.yml -f compose.prod.yml \
        config --no-interpolate --format json |
    python3 -c 'import json, sys
for name, svc in json.load(sys.stdin)["services"].items():
    for port in svc.get("ports", []):
        print(name + ":" + str(port["published"]))' | sort | xargs)
if [ "$published" = "$expected" ]; then
    printf '  ok        production ports: %s\n' "$published"
else
    printf '  FAILED    production ports: %s (expected %s)\n' "$published" "$expected"
    FAIL=1
fi

echo
if [ "$FAIL" -eq 0 ]; then
    echo "Every compose combination loads, and production publishes only its ports."
    exit 0
fi
echo "Compose check FAILED." >&2
exit 1
