# Noombat

*The Fediverse professional networking platform.*

The project mascot is the [**Numbat**](https://en.wikipedia.org/wiki/Numbat) (*Myrmecobius fasciatus*), a diurnal marsupial and the sole surviving member of its taxonomic family.
It is also the faunal emblem of Western Australia.

The **Noombat** spelling comes from the Aboriginal Australian **[Noongar](https://en.wikipedia.org/wiki/Noongar)** peoples' pronunciation.
We acknowledge and credit its linguistic heritage and treat it with care.
We do not claim Noongar identity.

The project implements the ActivityPub protocol and is built primarily in Rust.

- **Source code:** <https://github.com/noombat/noombat>
- **Project website:** <https://noombat.org> (To be developed and deployed)
- **Flagship instance:** <https://noombat.social> (To be developed and deployed)

## Security

Chat is end-to-end encrypted, but the web client executes JavaScript the instance operator serves, which bounds what that encryption can promise:
confidentiality against a passive server holds, integrity against an active one does not.
[`SECURITY.md`](SECURITY.md) states the threat model, the vulnerability reporting process, and the three available responses, including using Delta Chat against the same account to remove the operator from the code-supply path.

Releases publish a Sigstore-signed manifest of every served asset;
[`docs/verifying-builds.md`](docs/verifying-builds.md) explains how to check an instance against it.

## Goals

The project's main (ambitious?) goals are to interoperate with the broader Fediverse while enabling users to:
maintain professional profiles;
generate PDF curricula vitae based on their professional profiles;
search and publish employment opportunities;
reference scholarly publications via DOI;
publish long-form articles;
participate in professional groups;
organise events;
and exchange end-to-end encrypted direct messages via an integrated Chatmail relay.

## Prerequisites

- Rust ≥ 1.94.0
- PostgreSQL ≥ 16
- Redis ≥ 7
- Meilisearch ≥ 1.12
- Node.js ≥ 20 (required by pnpm)
- pnpm ≥ 9
- Podman with `podman-compose` or Docker with Docker Compose

## Quick Start

```sh
# Clone and enter the repository.
git clone https://github.com/noombat/noombat.git
cd noombat

# Copy the example environment file and adjust values.
cp .env.example .env

# Start the infrastructure services (or: podman-compose ... up -d db redis meilisearch).
# The dev override exposes host ports for psql, redis-cli, and the Meilisearch dashboard,
# and sets Meilisearch to development mode.
# Note: encrypted chat requires the chatmail service (see the Deployment section).
# For development without chat, the three services below are sufficient.
docker compose -f compose.yml -f compose.dev.yml up -d db redis meilisearch

# Install sqlx-cli for migration management.
cargo install sqlx-cli --no-default-features --features rustls,postgres

# Create the database and run migrations.
sqlx database create --database-url postgres://noombat:noombat@localhost/noombat
sqlx migrate run --source migrations/

# Build the frontend assets.
cd frontend
pnpm install
pnpm build
cd ..

# Build and run the server.
cargo run --bin noombat
```

The server listens on `http://localhost:8443` by default.

## Project Structure

```
noombat/
├── Cargo.toml                    # Workspace root.
├── crates/
│   ├── noombat-core/             # Core domain types, error types, and extension-point traits.
│   ├── noombat-ap/               # ActivityPub serialisation, vocabulary extensions, and JSON-LD error bodies.
│   ├── noombat-markup/           # (Markdown and KaTeX) to HTML pipeline and Markdown to Typst converter.
│   ├── noombat-federation/       # ActivityPub S2S federation: inbox, outbox, delivery, WebFinger, NodeInfo, HTTP Signatures.
│   ├── noombat-identity/         # Auth (local, Mastodon OAuth, ORCID), profiles, CV generation, DOI resolution.
│   ├── noombat-jobs/             # Job listing CRUD, search, and matching.
│   ├── noombat-groups/           # Group actor logic, membership, and redistribution.
│   ├── noombat-events/           # Event CRUD, RSVP, and calendar feeds.
│   ├── noombat-chat/             # IMAP/SMTP ciphertext relay for Chatmail, provisioning, moderation.
│   ├── noombat-chatmail-admin/   # Chatmail relay admin sidecar daemon (independent binary).
│   ├── noombat-api/              # Axum routes, Askama templates, session cookies, middleware, i18n.
│   └── noombat-server/           # Binary entry point, configuration, and migration runner.
├── frontend/                     # SolidJS islands, HTMX assets, and auth scripts (pnpm).
│   └── src/
│       ├── auth.ts               # Client-side split key derivation and token refresh.
│       ├── chat/                 # SolidJS chat island, OpenPGP.js crypto, Autocrypt state machine, credential blob.
│       ├── editor/               # SolidJS (Markdown and KaTeX) editor island.
│       └── htmx.ts               # HTMX bundled entry point.
├── migrations/                   # SQL migrations (sqlx).
├── templates/                    # Typst CV templates.
├── tests/
│   ├── chat-interop/             # Chat and Delta Chat interoperability tests.
│   ├── e2e/                      # Playwright end-to-end smoke tests.
│   └── interop/                  # Federation interoperability tests (Mastodon, Lemmy, etc.).
├── compose.yml
├── noombat.toml                  # Default configuration.
├── Dockerfile                    # Server container image.
├── Dockerfile.chatmail           # (Chatmail relay and admin sidecar) container image.
└── chatmail-config/              # Postfix, Dovecot, and s6-overlay configuration for the Chatmail container.
```

## Configuration

Configuration is loaded from `noombat.toml` and environment variables prefixed with `NOOMBAT_`.
Environment variables take precedence.

### Required settings

| Key            | Env Var                | Description                         |
|----------------|------------------------|-------------------------------------|
| `domain`       | `NOOMBAT_DOMAIN`       | Instance domain.                    |
| `database_url` | `NOOMBAT_DATABASE_URL` | PostgreSQL connection URL.          |
| `host`         | `NOOMBAT_HOST`         | Listen address (default `0.0.0.0`). |
| `port`         | `NOOMBAT_PORT`         | Listen port (default `8443`).       |

### Authentication

| Key                | Env Var                    | Description                                                      |
|--------------------|----------------------------|------------------------------------------------------------------|
| `jwt_secret`       | `NOOMBAT_JWT_SECRET`       | JWT signing secret (HS256, ≥ 32 bytes). Required for production. |
| `access_ttl_secs`  | `NOOMBAT_ACCESS_TTL_SECS`  | Access-token lifetime in seconds (default `900`).                |
| `refresh_ttl_secs` | `NOOMBAT_REFRESH_TTL_SECS` | Refresh-token lifetime in seconds (default `2592000`).           |
| `admin_token`      | `NOOMBAT_ADMIN_TOKEN`      | Dev-only bearer token for C2S outbox POST. Omit in production.   |

### Registration and federation

| Key                  | Env Var                      | Description                                                       |
|----------------------|------------------------------|-------------------------------------------------------------------|
| `open_registrations` | `NOOMBAT_OPEN_REGISTRATIONS` | Enable open registration (default `true`).                        |
| `redis_url`          | `NOOMBAT_REDIS_URL`          | Redis connection URL (enables rate limiting and session storage). |

### ORCID integration

| Key                   | Env Var                       | Description                                                            |
|-----------------------|-------------------------------|------------------------------------------------------------------------|
| `orcid_client_id`     | `NOOMBAT_ORCID_CLIENT_ID`     | ORCID OAuth application ID (from <https://orcid.org/developer-tools>). |
| `orcid_client_secret` | `NOOMBAT_ORCID_CLIENT_SECRET` | ORCID OAuth application secret.                                        |

### Encrypted chat (Chatmail)

| Key                     | Env Var                         | Description                                                              |
|-------------------------|---------------------------------|--------------------------------------------------------------------------|
| `chatmail_domain`       | `NOOMBAT_CHATMAIL_DOMAIN`       | Co-deployed Chatmail relay domain (e.g. `chat.noombat.social`).          |
| `chatmail_available`    | `NOOMBAT_CHATMAIL_AVAILABLE`    | Enable Chatmail integration (default `false`).                           |
| `chatmail_admin_url`    | `NOOMBAT_CHATMAIL_ADMIN_URL`    | Admin sidecar REST API URL (internal-only, e.g. `http://chatmail:9100`). |
| `chatmail_admin_secret` | `NOOMBAT_CHATMAIL_ADMIN_SECRET` | Shared secret for admin sidecar authentication.                          |

The `CHATMAIL_ALLOWLIST_URL` variable is configured on the Chatmail relay container (not the Noombat application server).

## Endpoints

### Pages (HTML, server-rendered)

| Path                        | Description                           |
|-----------------------------|---------------------------------------|
| `/`                         | Home feed.                            |
| `/@{username}`              | Profile (human-facing URL).           |
| `/auth/login`               | Sign-in page.                         |
| `/auth/register`            | Registration page.                    |
| `/auth/totp`                | TOTP two-factor authentication setup. |
| `/auth/upgrade`             | Set password for OAuth-only accounts. |
| `/chat`                     | Encrypted chat interface.             |
| `/compose`                  | Post composer.                        |
| `/search/html`              | Search results.                       |
| `/settings`                 | Settings hub.                         |
| `/settings/profile`         | Edit profile.                         |
| `/settings/experience`      | Add work experience.                  |
| `/settings/education`       | Add education.                        |
| `/settings/skills`          | Manage skills.                        |
| `/settings/publications`    | Add publication by DOI.               |
| `/settings/links`           | Manage verified links.                |
| `/settings/jobs/new`        | Post a job listing.                   |
| `/settings/privacy`         | Privacy and safety settings.          |
| `/settings/blocked`         | Blocked and muted accounts.           |
| `/settings/follow-requests` | Pending follow requests.              |
| `/settings/chat`            | Chat credential export.               |
| `/settings/migrate`         | Account migration (aliases and Move). |

### API (JSON)

| Path                                      | Method | Description                               |
|-------------------------------------------|--------|-------------------------------------------|
| `/api/v1/auth/register`                   | POST   | Register a local account.                 |
| `/api/v1/auth/login`                      | POST   | Log in (returns session tokens).          |
| `/api/v1/auth/refresh`                    | POST   | Refresh session tokens.                   |
| `/api/v1/auth/logout`                     | POST   | Revoke session.                           |
| `/api/v1/auth/password`                   | POST   | Set password (OAuth account upgrade).     |
| `/api/v1/auth/totp/enrol`                 | POST   | Begin TOTP enrolment.                     |
| `/api/v1/auth/totp/verify`                | POST   | Verify and enable TOTP.                   |
| `/api/v1/auth/totp`                       | DELETE | Disable TOTP.                             |
| `/api/v1/auth/mastodon`                   | GET    | Initiate Mastodon OAuth flow.             |
| `/api/v1/auth/mastodon/callback`          | GET    | Mastodon OAuth callback.                  |
| `/api/v1/auth/orcid`                      | GET    | Initiate ORCID OAuth flow.                |
| `/api/v1/auth/orcid/callback`             | GET    | ORCID OAuth callback.                     |
| `/api/v1/me/chatmail_cred`                | GET    | Retrieve encrypted credential blob.       |
| `/api/v1/me/chatmail_cred`                | PUT    | Store encrypted credential blob.          |
| `/api/v1/chat/reports`                    | POST   | Submit a chat message report.             |
| `/api/v1/chat/ws`                         | GET    | Chat WebSocket (upgrade).                 |
| `/api/v1/admin/actors/{id}/suspend`       | POST   | Suspend an actor (moderator/admin).       |
| `/api/v1/admin/actors/{id}/unsuspend`     | POST   | Unsuspend an actor (moderator/admin).     |
| `/api/v1/admin/chat-reports/{id}/resolve` | POST   | Resolve a chat report (moderator/admin).  |
| `/api/v1/admin/chat-reports`              | GET    | List open chat reports (moderator/admin). |
| `/api/v1/admin/reports`                   | GET    | List open AP reports (moderator/admin).   |

### ActivityPub and discovery

| Path                                            | Method | Description                      |
|-------------------------------------------------|--------|----------------------------------|
| `/users/{username}`                             | GET    | Actor (AP JSON or HTML profile). |
| `/users/{username}`                             | PATCH  | Update actor.                    |
| `/users/{username}`                             | DELETE | Delete actor.                    |
| `/users/{username}/inbox`                       | POST   | ActivityPub S2S inbox.           |
| `/users/{username}/outbox`                      | GET    | ActivityPub outbox collection.   |
| `/users/{username}/outbox`                      | POST   | Create Note (C2S).               |
| `/users/{username}/followers`                   | GET    | Followers collection.            |
| `/users/{username}/following`                   | GET    | Following collection.            |
| `/users/{username}/following`                   | POST   | Initiate outbound follow.        |
| `/users/{username}/pending_follows/{id}/accept` | POST   | Accept pending follow.           |
| `/users/{username}/pending_follows/{id}/reject` | POST   | Reject pending follow.           |
| `/users/{username}/aliases`                     | POST   | Add account alias (migration).   |
| `/users/{username}/aliases/{id}`                | DELETE | Remove account alias.            |
| `/users/{username}/move`                        | POST   | Initiate account Move.           |
| `/users/{username}/links`                       | POST   | Add verified link.               |
| `/users/{username}/experiences`                 | POST   | Add work experience.             |
| `/users/{username}/educations`                  | POST   | Add education.                   |
| `/users/{username}/publications`                | POST   | Add publication by DOI.          |
| `/users/{username}/jobs`                        | POST   | Create job listing.              |
| `/users/{username}/posts/{id}`                  | GET    | Single post (AP JSON or HTML).   |
| `/.well-known/webfinger`                        | GET    | Actor discovery (RFC 7033).      |
| `/.well-known/nodeinfo`                         | GET    | NodeInfo discovery.              |
| `/nodeinfo/2.1`                                 | GET    | NodeInfo 2.1 document.           |
| `/healthz`                                      | GET    | Health check.                    |

## Development

### Running tests

```sh
# Unit and integration tests across the workspace.
cargo test --workspace

# Formatting and lints.
cargo fmt --all -- --check
cargo clippy --workspace -- -D warnings

# REUSE licensing compliance (requires: pipx install reuse).
reuse lint

# Prepare sqlx offline query data (requires a running database).
cargo sqlx prepare --workspace
```

### Frontend development

```sh
cd frontend

# Install dependencies.
pnpm install

# Start the Vite dev server (hot-reload for SolidJS islands).
pnpm dev

# Production build (outputs to frontend/dist/).
pnpm build
```

### Chat interoperability tests

```sh
# Start the test environment.
docker compose -f tests/chat-interop/compose.yml up -d --build

# Run the tests.
tests/chat-interop/run.sh http://localhost:8443

# Tear down.
docker compose -f tests/chat-interop/compose.yml down -v

# With Delta Chat interop (requires deltachat-rpc-server):
DELTACHAT_RPC=http://localhost:20808 tests/chat-interop/run.sh
```

### Federation interoperability tests

```sh
# Start the federation test environment (Noombat + GotoSocial + Caddy).
docker compose -f tests/interop/compose.yml up -d --build

# Run the tests.
tests/interop/run.sh

# Tear down.
docker compose -f tests/interop/compose.yml down -v
```

### End-to-end browser tests

```sh
cd tests/e2e
pnpm install
pnpm exec playwright install --with-deps

# Run against a running Noombat instance.
NOOMBAT_URL=http://localhost:8443 pnpm exec playwright test
```

## Deployment

### Container (recommended)

```sh
# Build the container images.
docker build -t noombat .

# Or with podman:
podman build -t noombat .
```

Use `compose.yml` for production deployment with PostgreSQL, Redis, Meilisearch, and the Chatmail relay.
Set `NOOMBAT_JWT_SECRET` to a random string of at least 32 bytes.
Remove `admin_token` from the configuration.

### Chatmail (encrypted messaging)

Every Noombat instance co-deploys its own Chatmail relay (`noombat-chatmail`) with a `noombat-chatmail-admin` sidecar daemon.
The Chatmail relay is a standard upstream Chatmail deployment (Postfix + Dovecot + `doveauth` + `filtermail` + OpenDKIM) packaged with the admin sidecar in a single container.
A closed federation policy restricts message exchange to registered Noombat Chatmail domains via Postfix `transport_maps` allowlist.
The admin sidecar exposes a private REST API for account lifecycle operations (password rotation, session termination, maildir deletion, access map management) required by the moderation layer.

**Requirements:**

- A hosting provider that permits outbound port 25 (e.g. Hetzner).
- DNS records: A/AAAA for `chat.{DOMAIN}`; MX for `chat.{DOMAIN}` pointing to itself; DKIM TXT record under the `chat.{DOMAIN}` zone.
- Registration of the Chatmail domain in the project-maintained allowlist at `https://noombat.org/chatmail-allowlist.json` before inter-instance messaging is functional.

**Setup:**

1. Configure the `chatmail` service in `compose.yml`. Set `MAIL_DOMAIN` to `chat.{DOMAIN}` and `CHATMAIL_ADMIN_SECRET` to a random secret shared with the Noombat application server.
2. Provision DNS records: A/AAAA for `chat.{DOMAIN}`, MX for `chat.{DOMAIN}` pointing to itself, and a DKIM TXT record under the `chat.{DOMAIN}` zone.
3. Verify that the hosting provider permits outbound connections on port 25 and that the DNS records resolve correctly.
4. Register the Chatmail domain in the project allowlist for inter-instance messaging.
5. Set the following environment variables on the Noombat application server: `NOOMBAT_CHATMAIL_DOMAIN=chat.{DOMAIN}`, `NOOMBAT_CHATMAIL_AVAILABLE=true`, `NOOMBAT_CHATMAIL_ADMIN_URL=http://chatmail:9100`, and `NOOMBAT_CHATMAIL_ADMIN_SECRET` (matching the value from step 1).
6. Mount a valid TLS certificate and key at `/etc/ssl/certs/chatmail.pem` and `/etc/ssl/private/chatmail.key` in the chatmail container. If no certificate is mounted, the entrypoint generates a self-signed certificate suitable only for development.

## Licence

AGPL-3.0-or-later.
This project is [REUSE-compliant](https://reuse.software/).
See `LICENSES/AGPL-3.0-or-later.txt` for the full text.
