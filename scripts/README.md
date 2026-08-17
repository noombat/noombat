# Scripts

Development and maintenance scripts for the Noombat workspace.

## Quick Reference

| Script                 | Purpose                             | When to use                                                |
|------------------------|-------------------------------------|------------------------------------------------------------|
| `dev-setup.sh`         | First-time onboarding               | Once, after cloning the repository                         |
| `build.sh`             | Full build pipeline                 | After modifying Rust or frontend source                    |
| `clean.sh`             | Remove all build artifacts          | Before a clean rebuild or to reclaim disk space            |
| `test.sh`              | Run all verification checks         | Before committing or pushing                               |
| `smoke-test.sh`        | Black-box HTTP tests                | After starting the server, to verify it responds correctly |
| `e2e-stack.sh`         | Raise/tear down the e2e stack       | Before and after a Playwright run (`up`, `down`, `status`) |
| `check-unused-deps.sh` | Find unused dependency declarations | After removing code, or when a Dependabot bump looks odd   |
| `check-image-pins.sh`  | Compare workflow images to compose  | After touching a workflow service or a compose image       |
| `chatmail-setup.sh`    | Chatmail DNS verification           | Before deploying a Chatmail relay on a new domain          |

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

## `check-unused-deps.sh`

Reports dependencies that a manifest declares and the code never names, across all twelve crate manifests, `[workspace.dependencies]`, and both `package.json` files.

```sh
./scripts/check-unused-deps.sh              # Cargo and npm
./scripts/check-unused-deps.sh --rust-only  # skip the npm half
```

Exit `0` means nothing unused, `1` means candidates were found, and `2` means the scan could not be trusted and reported nothing meaningful.

Output is a list of **candidates, not conclusions**.
A dependency can be load-bearing without ever being named: by enabling a feature on a crate something else uses, by linking a C library, or by registering a runtime provider.
This workspace has already hit the first of those, when `meilisearch-sdk`'s default features turned on a second `jsonwebtoken` crypto backend and every login panicked, with nothing in the source naming it.
Confirm each candidate by deleting the line and running `cargo check --workspace --all-targets`, then comparing `cargo tree --workspace -f '{p} {f}'` before and after.
The check has to be at workspace scope, because Cargo unifies features across the whole workspace and a package-scoped run is a different build rather than a smaller one.

Two declarations are allowlisted in the script, both `noombat-core` in the `noombat-events` and `noombat-groups` placeholder crates.
Those crates are a licence header and one doc line each, so they declare what they will need and use nothing.
Delete the allowlist entry when either grows an implementation.

The scan injects a canary dependency name into every manifest it reads and requires all of them back in the output.
A canary that goes missing means the search matched something it should not have, so a clean result would prove nothing, and the script exits `2` rather than reporting success.
That is not hypothetical: an early version read clean because its file list included `package.json`, so every dependency matched its own declaration.

## `check-image-pins.sh`

Asserts that container images named in workflows are pinned by digest, and that they agree with the compose file naming the same image.

```sh
./scripts/check-image-pins.sh
```

Exit `0` means pinned and in agreement, `1` means a disagreement or an unpinned image, and `2` means the parser matched nothing and the run proves nothing.

This exists because a workflow `services:` or `container:` image is the one image reference no updater reaches.
Dependabot's docker ecosystem reads Dockerfiles, docker-compose reads compose files, and github-actions reads `uses:`.
On 2026-08-17 PR #48 raised Meilisearch in `compose.yml` and could not touch the copy in `ci.yml`; merging it as proposed would have left CI asserting against one Meilisearch while deployments ran another, and both would have started and passed.

The durable half of the fix was to stop naming those images twice: `ci.yml`'s integration job now starts `db`, `redis` and `meilisearch` from `compose.yml` plus `compose.dev.yml` rather than repeating them in a `services:` block.
This check covers what could not move, and pins what stayed.

Two images are allowlisted, each with its reason printed on every run.
The Playwright job container cannot come from compose and must equal the `@playwright/test` version in `tests/e2e`.
GoToSocial tracks `latest` in both the workflow and `tests/interop/compose.yml`, and the reason is unrecorded, so that one is a decision waiting to be made rather than a settled exemption.

It compares what the files say, not what a registry resolves them to; a digest that has been withdrawn upstream passes here and fails at `docker pull`.

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
