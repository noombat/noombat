# Scripts

Development and maintenance scripts for the Noombat workspace.

## Quick Reference

| Script              | Purpose                     | When to use                                                |
|---------------------|-----------------------------|------------------------------------------------------------|
| `dev-setup.sh`      | First-time onboarding       | Once, after cloning the repository                         |
| `build.sh`          | Full build pipeline         | After modifying Rust or frontend source                    |
| `clean.sh`          | Remove all build artifacts  | Before a clean rebuild or to reclaim disk space            |
| `test.sh`           | Run all verification checks | Before committing or pushing                               |
| `smoke-test.sh`     | Black-box HTTP tests        | After starting the server, to verify it responds correctly |
| `chatmail-setup.sh` | Chatmail DNS verification   | Before deploying a Chatmail relay on a new domain          |

## `dev-setup.sh`

One-command developer onboarding.
Checks prerequisites, starts infrastructure services (PostgreSQL, Redis, Meilisearch) via Compose, creates the database, runs migrations, installs frontend dependencies, builds frontend assets, compiles the Rust workspace, and runs the test suite.

```sh
./scripts/dev-setup.sh
```

Run once after cloning.
Subsequent builds use `build.sh` instead.

## `build.sh`

Compiles the entire workspace: frontend dependencies, frontend assets (Vite), and the Rust server binary.

```sh
./scripts/build.sh            # debug build
./scripts/build.sh --release  # release build
```

Does not start infrastructure or run migrations.
Assumes `dev-setup.sh` has been run at least once (or the equivalent manual steps).

## `clean.sh`

Removes all build artifacts: `target/` (Cargo), `frontend/node_modules/`, `frontend/dist/` (Vite), and `.sqlx/` (offline query cache).

```sh
./scripts/clean.sh
```

After cleaning, run `build.sh` to rebuild from scratch.

## `test.sh`

Runs all white-box verification steps without requiring a running server: `cargo fmt --check`, `cargo clippy`, `cargo test`, `tsc --noEmit` (frontend type-checking), and `reuse lint` (licensing compliance).

```sh
./scripts/test.sh          # all checks
./scripts/test.sh --quick  # Rust checks only (skip frontend)
```

The exit code equals the number of failed checks (0 = all passed).

Integration-level test suites (chat-interop, federation interop, Playwright e2e) are not included here because they require a running infrastructure stack.
Run them separately:

```sh
# Chat interoperability tests.
docker compose -f tests/chat-interop/compose.yml up -d --build
tests/chat-interop/run.sh http://localhost:8443
docker compose -f tests/chat-interop/compose.yml down -v

# Federation interoperability tests.
docker compose -f tests/interop/compose.yml up -d --build
tests/interop/run.sh
docker compose -f tests/interop/compose.yml down -v

# End-to-end browser tests.
cd tests/e2e && pnpm install && pnpm exec playwright install --with-deps
NOOMBAT_URL=http://localhost:8443 pnpm exec playwright test
```

## `smoke-test.sh`

Black-box HTTP test suite that verifies a running Noombat server responds correctly.
Tests health, WebFinger, NodeInfo, and outbox endpoints via `curl`.

```sh
cargo run --bin noombat &
sleep 2
./scripts/smoke-test.sh
kill %1
```

## `chatmail-setup.sh`

Pre-deployment DNS and network verification for the Chatmail relay.
Checks A/AAAA records, MX record (self-referential), DKIM TXT record, outbound port 25 (tested against multiple well-known MX hosts), and inbound ports 25/993/465.

```sh
./scripts/chatmail-setup.sh chat.noombat.social
```

Run before deploying the `noombat-chatmail` container on a new domain.
Requires `dig` (mandatory) and `nc` or `ncat` (optional, for port checks).
Exits with a non-zero status if any mandatory check fails.

## Typical Workflows

**First-time setup:**

```sh
./scripts/dev-setup.sh
```

**Daily development cycle:**

```sh
./scripts/test.sh --quick     # check before committing
./scripts/build.sh            # rebuild after changes
```

**Pre-push verification:**

```sh
./scripts/test.sh             # full checks including frontend
```

**Clean rebuild:**

```sh
./scripts/clean.sh
./scripts/build.sh
```
