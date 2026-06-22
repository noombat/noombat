# Noombat

*The Fediverse professional networking platform.*

The project mascot is the [**Numbat**](https://en.wikipedia.org/wiki/Numbat) (*Myrmecobius fasciatus*), a diurnal marsupial and the sole surviving member of its taxonomic family.
It is also the faunal emblem of Western Australia.

The **Noombat** spelling comes from the Aboriginal Australian **[Noongar](https://en.wikipedia.org/wiki/Noongar)** peoples' pronunciation.
We acknowledge and credit its linguistic heritage and treat it with care.
We do not claim Noongar identity.

The project implements the ActivityPub protocol and is built primarily in Rust.

- **Source code:** <https://codeberg.org/noombat/noombat>
- **Project website:** <https://noombat.org> (To be developed and deployed)
- **Flagship instance:** <https://noombat.social> (To be developed and deployed)

## Goals

The project's main (ambitious?) goals are to interoperate with the broader Fediverse while enabling users to:
maintain professional profiles;
generate PDF curricula vitae based on their professional profiles;
search and publish employment opportunities;
reference scholarly publications via DOI;
publish long-form articles;
participate in professional groups;
organise events;
and exchange end-to-end encrypted direct messages via an integrated Chatmail server.

## Prerequisites

- Rust ≥ 1.88.0
- PostgreSQL ≥ 16
- Redis ≥ 7
- Meilisearch ≥ 1.12
- pnpm ≥ 9
- Podman with `podman-compose` or Docker with Docker Compose

## Quick Start

```sh
# Clone and enter the repository.
git clone https://codeberg.org/noombat/noombat.git
cd noombat

# Copy the example environment file and adjust values.
cp .env.example .env

# Start the infrastructure services (or: podman-compose up -d db redis meilisearch).
docker compose up -d db redis meilisearch

# Install sqlx-cli for migration management.
cargo install sqlx-cli --no-default-features --features rustls,postgres

# Create the database and run migrations.
sqlx database create --database-url postgres://noombat:noombat@localhost/noombat
sqlx migrate run --source migrations/

# Build and run the server.
cargo run --bin noombat
```

The server listens on `http://localhost:8443` by default.

## Project Structure

```
noombat/
├── Cargo.toml                    # Workspace root.
├── crates/
│   ├── noombat-core/             # Core domain types, error types, and extension-point traits for Noombat.
│   ├── noombat-ap/               # ActivityPub serialisation, vocabulary extensions, and JSON-LD error bodies.
│   ├── noombat-identity/         # Actor repository, key generation, and post persistence.
│   ├── noombat-federation/       # ActivityPub S2S federation: inbox, outbox, delivery, WebFinger, NodeInfo, and HTTP Signature verification.
│   ├── noombat-markup/           # (Markdown and KaTeX) to HTML pipeline and Markdown to Typst converter.
│   ├── noombat-jobs/             # Job listing CRUD, search, and matching.
│   ├── noombat-groups/           # Group actor logic, membership, and redistribution.
│   ├── noombat-events/           # Event CRUD, RSVP, and calendar feeds.
│   ├── noombat-chat/             # IMAP/SMTP transport proxy for Chatmail; deltachat-rpc-server fallback.
│   ├── noombat-api/              # Axum routes, server-side HTML Askama templates, and internationalisation.
│   └── noombat-server/           # Binary entry point, configuration, and migration runner.
├── frontend/                     # SolidJS islands and HTMX assets (pnpm).
├── migrations/                   # SQL migrations (sqlx).
├── policies/                     # Cedar authorisation policies and schema.
├── templates/                    # Typst CV templates.
├── docker-compose.yml
├── noombat.toml                  # Default configuration.
└── Dockerfile
```

## Configuration

Configuration is loaded from `noombat.toml` and environment variables prefixed with `NOOMBAT_`.
Environment variables take precedence.
Required settings:

| Key                  | Env Var                      | Description                                         |
|----------------------|------------------------------|-----------------------------------------------------|
| `domain`             | `NOOMBAT_DOMAIN`             | Instance domain.                                    |
| `database_url`       | `NOOMBAT_DATABASE_URL`       | PostgreSQL connection URL.                          |
| `host`               | `NOOMBAT_HOST`               | Listen address (default `0.0.0.0`).                 |
| `port`               | `NOOMBAT_PORT`               | Listen port (default `8443`).                       |
| `open_registrations` | `NOOMBAT_OPEN_REGISTRATIONS` | Enable open registration (default `true`).          |
| `admin_token`        | `NOOMBAT_ADMIN_TOKEN`        | Bearer token for C2S outbox POST (development-only).|
| `policies_dir`       | `NOOMBAT_POLICIES_DIR`       | Path to Cedar policy files (default `policies`).    |

## Endpoints

| Path                              | Method | Description                          |
|-----------------------------------|--------|--------------------------------------|
| `/`                               | GET    | Home feed page.                      |
| `/feed`                           | GET    | Feed HTMX partial (paginated).       |
| `/users/{username}`               | GET    | Actor (AP JSON or HTML profile).     |
| `/users/{username}`               | PATCH  | Update actor (bearer token required).|
| `/users/{username}`               | DELETE | Delete actor (bearer token required).|
| `/users/{username}/inbox`         | POST   | ActivityPub S2S inbox.               |
| `/users/{username}/outbox`        | GET    | ActivityPub outbox collection.       |
| `/users/{username}/outbox`        | POST   | Create Note (bearer token required). |
| `/users/{username}/followers`     | GET    | ActivityPub followers collection.    |
| `/users/{username}/following`     | GET    | ActivityPub following collection.    |
| `/users/{username}/posts/{id}`    | GET    | Single post (AP JSON or HTML).       |
| `/.well-known/webfinger`          | GET    | Actor discovery (RFC 7033).          |
| `/.well-known/nodeinfo`           | GET    | NodeInfo discovery.                  |
| `/nodeinfo/2.1`                   | GET    | NodeInfo 2.1 document.               |
| `/healthz`                        | GET    | Health check.                        |

## Development

```sh
# Run tests across the workspace.
cargo test --workspace

# Check formatting and lints.
cargo fmt --all -- --check
cargo clippy --workspace -- -D warnings

# Check REUSE licensing compliance (requires: pipx install reuse).
reuse lint

# Prepare sqlx offline query data (requires a running database).
cargo sqlx prepare --workspace
```

## Licence

AGPL-3.0-or-later. This project is [REUSE-compliant](https://reuse.software/).
See `LICENSES/AGPL-3.0-or-later.txt` for the full text.
