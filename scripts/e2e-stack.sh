#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
#
# Raise or tear down the minimal stack an end-to-end run needs.
#
#   scripts/e2e-stack.sh up      services, assets, seed, server
#   scripts/e2e-stack.sh down    server, containers, volumes
#   scripts/e2e-stack.sh status  what is currently running
#
# This wraps `compose.yml` plus `compose.dev.yml` rather than replacing
# them: that overlay exists to publish Postgres, Redis and Meilisearch on
# host ports, which is exactly what a run from the host needs. Only those
# three services are started. A bare `up -d` would also build and start
# `noombat` and `chatmail`, and building the server image is the
# expensive path when the debug binary already on disk serves Playwright
# identically.
#
# WHAT IS DELIBERATELY NOT PERSISTENT. Containers and the database
# volume are torn down by `down`, every time. Migrations run at server
# boot and the seed below is two INSERTs, so there is nothing in them
# worth keeping, and an accumulating stack is what filled the
# maintainer's disk on 2026-08-11. What persists is this file, on the
# host mount, so it survives a sandbox rebuild.
#
# THE FRONTEND BUILD IS REQUIRED, not optional. Without
# `frontend/dist/assets-manifest.json` the served manifest 404s and the
# asset-provenance test SKIPS rather than fails, which reads as a pass.
#
# Two traps this script encodes, both learned the hard way:
#   - Never `pkill -f target/debug/noombat`. The pattern matches the
#     invoking shell's own command line and kills it. A PID file is used
#     instead.
#   - Chromium cannot be installed in the sandbox: its download redirects
#     to a host the firewall denies. Run Playwright with
#     `--project=firefox`.

set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_DIR="${E2E_RUN_DIR:-${TMPDIR:-/tmp}/noombat-e2e}"
PID_FILE="$RUN_DIR/server.pid"
LOG_FILE="$RUN_DIR/server.log"

COMPOSE=(docker compose -f "$REPO/compose.yml" -f "$REPO/compose.dev.yml")
SERVICES=(db redis meilisearch)

# The seeded posts' primary keys, fixed so the specs can address the
# permalinks without discovering them first.
#
# Both values are hard-coded in .github/workflows/ci-e2e.yml, in
# tests/e2e/smoke.spec.ts, in tests/e2e/accessibility.spec.ts and in
# tests/e2e/security-headers.spec.ts. Nothing gates the drift, so change
# them everywhere together.
#
# Two posts, not one, because `post_type` selects the template:
# posts.rs renders article.html for 'article' and post.html for anything
# else. Seeding only an article leaves post.html rendered by nothing,
# which is the state that let a broken article.html ship.
ARTICLE_ID="00000000-0000-4000-8000-000000000001"
NOTE_ID="00000000-0000-4000-8000-000000000002"

# Matches compose.dev.yml's published ports and ci-e2e.yml's values.
export NOOMBAT_DATABASE_URL="postgres://noombat:noombat@localhost:5432/noombat"
export NOOMBAT_DOMAIN="${NOOMBAT_DOMAIN:-localhost}"
export NOOMBAT_HOST="0.0.0.0"
export NOOMBAT_PORT="${NOOMBAT_PORT:-8443}"
export NOOMBAT_REDIS_URL="redis://localhost:6379"
export NOOMBAT_MEILI_URL="http://localhost:7700"
export NOOMBAT_MEILI_KEY="${MEILI_MASTER_KEY:-noombat-dev-key}"
export NOOMBAT_ADMIN_TOKEN="${ADMIN_TOKEN:-ci-test-token}"
# Effectively disable per-IP limiting: a run makes many requests from one
# address, and the production figures are not test figures.
export NOOMBAT_RATE_LIMIT="10000"
export NOOMBAT_FED_RATE_LIMIT="10000"
export NOOMBAT_CV_DOWNLOAD_LIMIT="10000"

say() { printf '  %s\n' "$*"; }

host_free() { df -Ph "$REPO" | awk 'NR==2 {print $4}'; }

wait_for() {
  local what="$1" tries="$2"; shift 2
  local i
  for ((i = 0; i < tries; i++)); do
    if "$@" >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  say "TIMED OUT waiting for $what"
  return 1
}

up() {
  say "host disk before: $(host_free) free"

  say "starting $(printf '%s ' "${SERVICES[@]}")"
  "${COMPOSE[@]}" up -d "${SERVICES[@]}" >/dev/null 2>&1 || {
    say "compose up failed"; return 1
  }
  wait_for "postgres" 60 docker compose -f "$REPO/compose.yml" -f "$REPO/compose.dev.yml" \
    exec -T db pg_isready -U noombat || return 1
  say "services up"

  say "building the server (debug: the release profile costs ~9 GB more for no test benefit)"
  ( cd "$REPO" && CARGO_INCREMENTAL=0 cargo build --bin noombat ) >/dev/null 2>&1 || {
    say "cargo build failed"; return 1
  }

  if [ ! -d "$REPO/frontend/dist" ]; then
    say "frontend/dist is missing; run 'pnpm build' in frontend/ first"
    return 1
  fi
  "$REPO/scripts/asset-manifest.sh" > "$REPO/frontend/dist/assets-manifest.json" || {
    say "asset manifest generation failed"; return 1
  }
  say "asset manifest generated (without it the provenance test skips silently)"

  mkdir -p "$RUN_DIR"
  # `exec` matters. Without it, `( cd ... && nohup ... & )` records the
  # PID of the subshell, and the server is that subshell's child, so
  # `down` kills the wrapper and orphans a server still holding :8443.
  # With `exec` the subshell is replaced by the server, so the PID in
  # the file is the server's own.
  ( cd "$REPO" && exec nohup ./target/debug/noombat > "$LOG_FILE" 2>&1 ) &
  echo $! > "$PID_FILE"
  wait_for "the server on :$NOOMBAT_PORT" 60 \
    curl -fsS -o /dev/null "http://localhost:$NOOMBAT_PORT/" || {
    say "server did not come up; see $LOG_FILE"; return 1
  }
  say "server up (pid $(cat "$PID_FILE"), log $LOG_FILE)"

  seed
  say "host disk after: $(host_free) free"
  say ""
  say "run the suite with:"
  say "  cd tests/e2e && CI=true ADMIN_TOKEN=$NOOMBAT_ADMIN_TOKEN \\"
  say "    pnpm exec playwright test --project=firefox"
}

seed() {
  # All three statements go in one `-c`, so psql wraps them in a single
  # transaction: the posts select the actor's generated id, and a
  # half-applied seed would fail the permalink tests for a reason two
  # steps removed from the cause.
  #
  # One post of each type, because post_type selects the template: the
  # route renders article.html for 'article' and post.html for anything
  # else. content_md carries headings because the table of contents is
  # derived from the Markdown, not from content_html.
  "${COMPOSE[@]}" exec -T -e PGPASSWORD=noombat db \
    psql -U noombat -d noombat -q -c "
      INSERT INTO actors
        (actor_type, ap_id, username, domain, public_key_pem, is_local)
      VALUES
        ('individual', 'http://localhost:$NOOMBAT_PORT/users/testuser',
         'testuser', '$NOOMBAT_DOMAIN',
         '-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0placeholder
-----END PUBLIC KEY-----',
         TRUE)
      ON CONFLICT (ap_id) DO NOTHING;

      INSERT INTO posts
        (id, actor_id, ap_id, post_type, title, content_md, content_html,
         visibility, ap_object)
      SELECT
        '$ARTICLE_ID',
        a.id,
        'http://localhost:$NOOMBAT_PORT/users/testuser/posts/$ARTICLE_ID',
        'article',
        'Seeded Test Article',
        E'## Introduction\n\nThis article is seeded so the permalink has something to render.\n\n## Second section\n\nA second heading, so the table of contents holds more than one entry.',
        '<h2 id=\"introduction\">Introduction</h2><p>This article is seeded so the permalink has something to render.</p><h2 id=\"second-section\">Second section</h2><p>A second heading, so the table of contents holds more than one entry.</p>',
        'public',
        jsonb_build_object(
          '@context', 'https://www.w3.org/ns/activitystreams',
          'type', 'Create',
          'actor', 'http://localhost:$NOOMBAT_PORT/users/testuser',
          'object', jsonb_build_object(
            'id', 'http://localhost:$NOOMBAT_PORT/users/testuser/posts/$ARTICLE_ID',
            'type', 'Article',
            'name', 'Seeded Test Article',
            'attributedTo', 'http://localhost:$NOOMBAT_PORT/users/testuser',
            'to', jsonb_build_array('https://www.w3.org/ns/activitystreams#Public')))
      FROM actors a
      WHERE a.username = 'testuser' AND a.is_local
      ON CONFLICT DO NOTHING;

      INSERT INTO posts
        (id, actor_id, ap_id, post_type, content_md, content_html,
         visibility, ap_object)
      SELECT
        '$NOTE_ID',
        a.id,
        'http://localhost:$NOOMBAT_PORT/users/testuser/posts/$NOTE_ID',
        'note',
        E'A seeded note, so post.html is rendered by something.',
        '<p>A seeded note, so post.html is rendered by something.</p>',
        'public',
        jsonb_build_object(
          '@context', 'https://www.w3.org/ns/activitystreams',
          'type', 'Create',
          'actor', 'http://localhost:$NOOMBAT_PORT/users/testuser',
          'object', jsonb_build_object(
            'id', 'http://localhost:$NOOMBAT_PORT/users/testuser/posts/$NOTE_ID',
            'type', 'Note',
            'attributedTo', 'http://localhost:$NOOMBAT_PORT/users/testuser',
            'to', jsonb_build_array('https://www.w3.org/ns/activitystreams#Public')))
      FROM actors a
      WHERE a.username = 'testuser' AND a.is_local
      ON CONFLICT DO NOTHING;" >/dev/null 2>&1 \
    && say "test actor, article and note seeded" \
    || say "seeding failed (the authenticated groups and the permalink tests will fail)"

  # Confirmed, not assumed. `INSERT ... SELECT` inserts nothing and still
  # exits 0 when the actor lookup matches no row, so the message above
  # would report a seed that did not happen.
  local found
  found="$("${COMPOSE[@]}" exec -T -e PGPASSWORD=noombat db \
    psql -U noombat -d noombat -tAc \
    "SELECT count(*) FROM posts
      WHERE (id = '$ARTICLE_ID' AND post_type = 'article')
         OR (id = '$NOTE_ID' AND post_type = 'note');" \
    2>/dev/null | tr -d '[:space:]')"
  if [ "$found" = "2" ]; then
    say "article permalink: /@testuser/posts/$ARTICLE_ID"
    say "note permalink:    /@testuser/posts/$NOTE_ID"
  else
    say "POSTS NOT SEEDED (found $found of 2): the permalink tests will fail"
  fi
}

down() {
  if [ -f "$PID_FILE" ]; then
    local pid i
    pid="$(cat "$PID_FILE")"
    # By PID, never by pattern: `pkill -f target/debug/noombat` matches
    # the invoking shell's own command line and kills it.
    kill "$pid" 2>/dev/null
    # Verify rather than assume. Reporting "stopped" while the port is
    # still held is worse than reporting nothing, because the next `up`
    # then fails to bind and the cause is two steps back.
    for ((i = 0; i < 10; i++)); do
      kill -0 "$pid" 2>/dev/null || break
      sleep 1
    done
    if kill -0 "$pid" 2>/dev/null; then
      kill -9 "$pid" 2>/dev/null
      sleep 1
      say "server did not stop on SIGTERM; killed (pid $pid)"
    else
      say "server stopped (pid $pid)"
    fi
    rm -f "$PID_FILE"
  else
    say "no server pid file; nothing to stop"
  fi

  # Last check on the thing that actually matters: is the port free?
  if curl -fsS -o /dev/null --max-time 2 "http://localhost:$NOOMBAT_PORT/" 2>/dev/null; then
    say "WARNING: something is still serving on :$NOOMBAT_PORT"
    say "  find it with: pgrep -a noombat"
  fi

  # -v drops the database volume too. Nothing in it survives a run that
  # is worth keeping: migrations run at boot and `seed` rebuilds its rows.
  "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 \
    && say "containers and volumes removed"

  say "host disk: $(host_free) free"
  say "images kept. To reclaim ~400 MB: docker image prune -af"
}

status() {
  say "host disk: $(host_free) free"
  if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
    say "server: running (pid $(cat "$PID_FILE"))"
  else
    say "server: not running"
  fi
  "${COMPOSE[@]}" ps --format '  {{.Service}}  {{.Status}}' 2>/dev/null \
    || say "no compose project running"
}

case "${1:-}" in
  up) up ;;
  down) down ;;
  status) status ;;
  *)
    echo "usage: ${BASH_SOURCE[0]##*/} {up|down|status}" >&2
    exit 2
    ;;
esac
