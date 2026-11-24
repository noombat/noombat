#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
#
# Start the federation interop stack, wait for it, seed it and run the
# suite: the sequence ci-e2e.yml and ci-interop-latest.yml share.
#
# Usage: tests/interop/ci.sh run|logs|down [extra compose file...]
#        The stack is tests/interop/compose.yml plus any extra files, such
#        as tests/interop/compose.latest.yml. `run` builds nothing: the
#        Noombat image must already be built or loaded. The workflow maps
#        noombat.localhost and gotosocial.localhost to the runner first.

set -euo pipefail
cd "$(dirname "$0")/../.." || exit 1

cmd="${1:-}"
[ "$#" -gt 0 ] && shift
files=(tests/interop/compose.yml "$@")
compose=(docker compose)
for f in "${files[@]}"; do
    compose+=(-f "$f")
done

case "$cmd" in
    run)
        "${compose[@]}" up -d --wait --no-build
        # `--wait` returns as soon as the containers are up or healthy,
        # which is not the same as Noombat having run its migrations and
        # bound its port behind Caddy. Ask the endpoint the tests will use.
        ready=""
        for _ in $(seq 1 30); do
            if curl -ksf https://noombat.localhost:8443/healthz > /dev/null; then
                ready=1
                break
            fi
            sleep 2
        done
        if [ -z "$ready" ]; then
            echo "::error::Noombat did not become ready within 60 seconds"
            "${compose[@]}" logs --no-color
            exit 1
        fi
        echo "Noombat is ready"
        # Both accounts, on both instances: run.sh federates between them,
        # and neither instance creates them (Noombat has no open
        # registration route, GoToSocial runs with registration closed).
        tests/interop/seed.sh "${files[@]}"
        # --insecure: Caddy issues its own certificate for these names.
        # With CI set, as GitHub sets it, run.sh treats a skip as a failure
        # and an unreachable peer as fatal, so assertions that did not run
        # cannot read as a pass.
        CURL_OPTS="${CURL_OPTS:---insecure}" tests/interop/run.sh \
            https://noombat.localhost:8443 https://gotosocial.localhost:8443
        ;;
    logs)
        "${compose[@]}" logs --no-color
        ;;
    down)
        "${compose[@]}" down -v
        ;;
    *)
        echo "usage: tests/interop/ci.sh run|logs|down [extra compose file...]" >&2
        exit 2
        ;;
esac
