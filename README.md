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

## Project Structure

```
noombat/
├── Cargo.toml                    # Workspace root.
├── crates/
│   ├── noombat-core/             # Core domain types, error types, and extension-point traits for Noombat.
│   ├── noombat-ap/               # ActivityPub serialisation, vocabulary extensions, and JSON-LD error bodies.
│   ├── noombat-markup/           # (Markdown and KaTeX) to HTML pipeline.
│   ├── noombat-federation/       # ActivityPub S2S federation: inbox, outbox, delivery, WebFinger, NodeInfo, and HTTP Signature verification.
│   ├── noombat-identity/         # Actor repository, key generation, and post persistence.
│   ├── noombat-jobs/             # Job CRUD, search, matching.
│   ├── noombat-groups/           # Group actor logic.
│   ├── noombat-events/           # Event CRUD, RSVP, calendar.
│   ├── noombat-chat/             # Chatmail bridge.
│   ├── noombat-api/              # Axum routes, server-side HTML Askama templates, and internationalisation.
│   └── noombat-server/           # Binary entry point, configuration, and migration runner.
├── frontend/                     # SolidJS islands and HTMX assets (pnpm).
├── migrations/                   # SQL migrations (sqlx).
├── templates/                    # Typst CV templates.
├── docker-compose.yml
├── noombat.toml                  # Default configuration.
└── Dockerfile
```

## Licence

AGPL-3.0-or-later. This project is [REUSE-compliant](https://reuse.software/).
See `LICENSES/AGPL-3.0-or-later.txt` for the full text.
