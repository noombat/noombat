#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
# Initialise the Noombat development environment.
#
# Prerequisites:
#   - Rust >= 1.88.0
#   - Podman with `podman-compose` or Docker with Docker Compose
#   - sqlx-cli: `cargo install sqlx-cli --no-default-features --features rustls,postgres`
#
# Usage:
#   chmod +x scripts/dev-setup.sh
#   ./scripts/dev-setup.sh

set -euo pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

info() { echo -e "${GREEN}[+]${NC} $1"; }
fail() { echo -e "${RED}[!]${NC} $1"; exit 1; }

# ..... CHECK PREREQUISITES .....

command -v cargo >/dev/null 2>&1 || fail "cargo not found; install Rust via https://rustup.rs/"

# Detect container-compose command.
if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    COMPOSE="docker compose"
elif command -v podman-compose >/dev/null 2>&1; then
    COMPOSE="podman-compose"
else
    fail "neither 'docker compose' nor 'podman-compose' found"
fi
info "Using compose command: $COMPOSE"

# Detect container CLI (for exec).
if command -v docker >/dev/null 2>&1; then
    CONTAINER_CLI="docker"
elif command -v podman >/dev/null 2>&1; then
    CONTAINER_CLI="podman"
else
    fail "neither 'docker' nor 'podman' found"
fi

command -v sqlx >/dev/null 2>&1 || {
    info "Installing sqlx-cli..."
    cargo install sqlx-cli --no-default-features --features rustls,postgres
}

# ..... ENVIRONMENT FILE .....

if [ ! -f .env ]; then
    info "Creating .env from .env.example..."
    cp .env.example .env
fi

# Source the .env for this script.
set -a; source .env; set +a

# ..... START INFRASTRUCTURE .....

info "Starting PostgreSQL, Redis, and Meilisearch..."
$COMPOSE up -d db redis meilisearch

info "Waiting for PostgreSQL to accept connections..."
# Determine the container name (Docker Compose v2 uses hyphens,
# podman-compose uses underscores).
DB_CONTAINER=$($CONTAINER_CLI ps --format '{{.Names}}' | grep -E '(noombat[-_]db[-_]|^db$)' | head -1)
if [ -z "$DB_CONTAINER" ]; then
    # Fallback: wait a fixed period.
    info "Could not identify db container by name; waiting 5 s..."
    sleep 5
else
    until $CONTAINER_CLI exec "$DB_CONTAINER" pg_isready -U noombat >/dev/null 2>&1; do
        sleep 1
    done
fi

# ..... DATABASE SETUP .....

info "Creating database (if it does not already exist)..."
sqlx database create \
    --database-url "${NOOMBAT_DATABASE_URL}" 2>/dev/null || true

info "Running migrations..."
sqlx migrate run \
    --source migrations/ \
    --database-url "${NOOMBAT_DATABASE_URL}"

# ..... GENERATE Cargo.lock .....

if [ ! -f Cargo.lock ]; then
    info "Generating Cargo.lock..."
    cargo generate-lockfile
fi

# ..... BUILD .....

info "Building the workspace (debug mode)..."
cargo build --workspace

# ..... RUN TESTS .....

info "Running tests..."
cargo test --workspace

info "Setup complete. Start the server with:  cargo run --bin noombat"
