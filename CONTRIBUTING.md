# Contributing to Noombat

Thank you for considering a contribution to Noombat.
This document describes the development environment, conventions, and workflows.

## Development Environment

### Prerequisites

Install the tools listed in the [README](README.md#prerequisites).

### First-time setup

```sh
git clone https://github.com/noombat/noombat.git
cd noombat
cp .env.example .env          # adjust values as needed

# Start infrastructure services (dev override exposes host ports
# for psql/redis-cli and sets Meilisearch to development mode).
docker compose -f compose.yml -f compose.dev.yml up -d db redis meilisearch chatmail

# Install sqlx-cli and run migrations.
cargo install sqlx-cli --no-default-features --features rustls,postgres
sqlx database create --database-url postgres://noombat:noombat@localhost/noombat
sqlx migrate run --source migrations/

# Build frontend assets.
cd frontend && pnpm install && pnpm build && cd ..

# Run the server.
cargo run --bin noombat
```

## Crate Architecture

The workspace comprises twelve crates.
The dependency graph flows downward; no upward or circular dependencies exist.

```
noombat-server                 (binary entry point)
  └── noombat-api              (Axum routes, templates, middleware)
        ├── noombat-identity   (auth, profiles, CV, DOI)
        ├── noombat-jobs       (job listings)
        ├── noombat-groups     (group actors)
        ├── noombat-events     (events, RSVP)
        ├── noombat-chat       (IMAP/SMTP ciphertext relay, admin client, closed federation allowlist)
        ├── noombat-federation (AP inbox/outbox, delivery, WebFinger)
        ├── noombat-markup     (Markdown + LaTeX pipeline)
        └── noombat-ap         (AP serialisation)
              └── noombat-core (domain types, error types, traits)

noombat-chatmail-admin         (Chatmail relay admin sidecar daemon, independent binary)
```

## Code Conventions

### Safe Rust only

Every first-party crate carries `#![forbid(unsafe_code)]`.
The build fails if `unsafe` is introduced.
Third-party crates that use `unsafe` internally are acceptable when well-audited (e.g. `tokio`, `serde`, `ring`, `sqlx`).

### Workspace dependency hygiene

Each crate should declare only the workspace dependencies it actually uses.
The `subtle` crate (constant-time comparison) is consumed only by `noombat-api` (admin token verification in `auth.rs` and `middleware.rs`); it must not be added to other crates without a concrete use site.

### Authorisation

Write handlers in `routes/actors.rs` must call `require_owner(&principal, &username)?` as the first line after extracting the path parameters.
This verifies that the authenticated principal owns the actor identified by the URL.
Handlers that serve content to any viewer (read-only) use the `visible_to` methods on domain types instead.

### HTMX fragment convention

Handlers invoked by HTMX forms (e.g. skill add, link add, alias add) return an HTML fragment as the response body.
The fragment is a single element (typically a `<li>` or `<span>`) that HTMX swaps into the page via `hx-swap="beforeend"` or `hx-swap="outerHTML"`.
Dynamic content in fragments is escaped via the `html_escape` helper in `actors.rs`.
Do not use `askama::filters::escape` directly; it is not part of the public Askama API in the version used by this project.

### Adding a new route

1. Define the handler function in the appropriate `routes/*.rs` module.
2. Register the route in the module's `router()` function.
3. If the route serves an HTML page, create an Askama template in `templates/` and a template struct in `routes/pages.rs`.
4. Add i18n keys to all locale files (`en-US.yml`, `en-AU.yml`, `pt-BR.yml`) in the same commit. Use the existing naming convention (e.g. `edit_experience_title`, `exp_company`).
5. If the route is an authenticated page, extend `base_auth.html` (not `base.html`) and include a `nav_username: String` field in the template struct.

### Adding a new i18n key

All user-facing strings are extracted into YAML locale files under `crates/noombat-api/locales/`.
When adding a key:

1. Add the key and English value to `en-US.yml`.
2. Add the same key and English value to `en-AU.yml` (identical unless Australian English differs).
3. Add the key with a Portuguese (Brazilian) translation to `pt-BR.yml`.

All files must contain the same set of keys.
Missing keys in any locale will produce a runtime panic on the first request that references them.

### Markdown content pipeline

All user-authored rich text is authored in CommonMark Markdown with LaTeX math delimiters, rendered to MathML server-side.
The `noombat-markup` crate processes the input and produces sanitised HTML.
Both the Markdown source (`*_md` columns) and the pre-rendered HTML (`*_html` columns) are stored.
Write handlers that accept Markdown must render it via `noombat_markup::render(&md).html` before storing the HTML column.
Do not store raw Markdown in the `*_html` column.

### Database conventions

- All tables use `UUID` primary keys generated by `gen_random_uuid()`.
- Timestamps use `TIMESTAMPTZ` (with time zone), defaulting to `now()`.
- Optional date fields from HTML form inputs may arrive as empty strings; normalise them to `None` via `.as_deref().filter(|s| !s.is_empty())` before binding.
- Enum-like columns use `TEXT` with a `CHECK` constraint.
- The `actors` table enforces a unique local username per domain via a partial unique index.

### Commit messages

Follow the [Conventional Commits](https://www.conventionalcommits.org/) specification.
Common scopes: `identity`, `chat`, `autocrypt`, `api`, `frontend`, `federation`.

## Frontend

### Architecture

The application uses a server-rendered architecture with targeted JavaScript enhancements.
Navigation between pages is standard HTTP.
Partial updates use HTMX.
Discrete interactive components (the Markdown editor, the chat interface) are compiled as independent SolidJS entry points ("islands") loaded only on the pages that require them.

### Entry points

| Entry    | File                   | Output             | Purpose                                                 |
|----------|------------------------|--------------------|---------------------------------------------------------|
| `htmx`   | `src/htmx.ts`          | `assets/htmx.js`   | HTMX library (loaded on every page).                    |
| `auth`   | `src/auth.ts`          | `assets/auth.js`   | Split key derivation, form interception, token refresh. |
| `editor` | `src/editor/index.tsx` | `assets/editor.js` | Markdown + LaTeX live-preview editor.                   |
| `chat`   | `src/chat/index.tsx`   | `assets/chat.js`   | Real-time encrypted chat island.                        |

### Encryption and Autocrypt

The chat island uses [OpenPGP.js](https://openpgpjs.org/) (v6) for all cryptographic operations (key generation, encryption, decryption, signature verification) and a purpose-built TypeScript Autocrypt Level 1 state machine (`autocrypt.ts`) for peer key management.
The `openpgp` npm package is a standard `pnpm install` dependency.

## Testing

### Unit and integration tests

```sh
cargo test --workspace
```

### Lints

```sh
cargo fmt --all -- --check
cargo clippy --workspace -- -D warnings
```

### Federation interoperability

```sh
docker compose -f tests/interop/compose.yml up -d --build
tests/interop/run.sh
docker compose -f tests/interop/compose.yml down -v
```

### Chat interoperability

```sh
docker compose -f tests/chat-interop/compose.yml up -d --build
tests/chat-interop/run.sh http://localhost:8443
docker compose -f tests/chat-interop/compose.yml down -v
```

### End-to-end browser tests

```sh
cd tests/e2e
pnpm install
pnpm exec playwright install --with-deps
NOOMBAT_URL=http://localhost:8443 pnpm exec playwright test
```

### sqlx offline query data

The project uses sqlx compile-time checked queries.
After modifying any SQL query in the source, regenerate the offline data:

```sh
cargo sqlx prepare --workspace
```

This requires a running PostgreSQL instance with the current schema.

## Licence

All contributions must be made under the AGPL-3.0-or-later licence.
The project is [REUSE-compliant](https://reuse.software/); every file must carry an SPDX header.
