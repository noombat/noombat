# Scripts

Development and maintenance scripts for the Noombat workspace.

## Quick Reference

| Script                        | Purpose                                | When to use                                                |
|-------------------------------|----------------------------------------|------------------------------------------------------------|
| `dev-setup.sh`                | First-time onboarding                  | Once, after cloning the repository                         |
| `build.sh`                    | Full build pipeline                    | After modifying Rust or frontend source                    |
| `build-image.sh`              | Build an image with the standard args  | When building a release image by hand                      |
| `asset-manifest.sh`           | Hash every built frontend asset        | To inspect what a build produced                           |
| `image-manifest.sh`           | Hash an image's files and packages     | When comparing two builds of one image                     |
| `clean.sh`                    | Remove all build artifacts             | Before a clean rebuild or to reclaim disk space            |
| `test.sh`                     | Run all verification checks            | Before committing or pushing                               |
| `smoke-test.sh`               | Black-box HTTP tests                   | After starting the server, to verify it responds correctly |
| `e2e-stack.sh`                | Raise/tear down the e2e stack          | Before and after a Playwright run (`up`, `down`, `status`) |
| `check-unused-deps.sh`        | Find unused dependency declarations    | After removing code, or when a Dependabot bump looks odd   |
| `check-image-pins.sh`         | Compare workflow images to compose     | After touching a workflow service or a compose image       |
| `check-compose-config.sh`     | Load every compose combination         | After editing any compose file                             |
| `check-template-comments.sh`  | Find unbalanced HTML comments          | After editing an Askama template                           |
| `check-logical-properties.sh` | Reject physical-direction utilities    | After writing markup that positions anything               |
| `check-contrast.py`           | Measure every semantic colour pair     | After changing any colour token                            |
| `check-action-allowlist.sh`   | Reject actions the policy refuses      | After adding or repinning any `uses:` in a workflow        |
| `check-action-tags.sh`        | Check each pin is the release it names | After repinning any `uses:` by hand                        |
| `check-workflow-startup.sh`   | Find workflows rejected before running | After a push, when a workflow seems not to have run        |
| `check-release-tested.sh`     | Refuse a release main did not test     | Run by `release.yml`; by hand before tagging               |
| `chatmail-setup.sh`           | Chatmail DNS verification              | Before deploying a Chatmail relay on a new domain          |
| `backup.sh`                   | Back up a Compose deployment           | On a schedule, on a deployed instance                      |

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

Runs the checks CI runs that can run without a server: formatting, lints and unit tests for the Rust workspace, the repository's own gates (image pins, compose, locales, templates, contrast, migrations, workflows, CodeQL configuration), the frontend's type-checking, linting, formatting and unit tests, and the end-to-end project's type-checking and linting.
Gates that need docker, a built image, cargo-deny 0.20.2, shellcheck, a signed-in `gh` or `reuse` run only when those are present, and say so when skipped.
CI also runs the browser and interop suites, the image builds, the Typst CV tests that need its binary, the safe-Rust check, the MSRV and reproducible builds, CodeQL and the database-backed tests, which this does not.

```sh
./scripts/test.sh          # all checks
./scripts/test.sh --quick  # skip the frontend, the end-to-end project and the slow docker checks
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
pnpm exec playwright test  # against scripts/e2e-stack.sh up, at https://localhost:8443
```

## `smoke-test.sh`

Black-box HTTP test suite that verifies a running Noombat server responds correctly.
Tests health, WebFinger, NodeInfo, and outbox endpoints via `curl`.

```sh
(cd frontend && pnpm install && pnpm build)  # The server refuses to start without it.
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

Nothing is allowlisted in the script today.
The placeholder crates, `noombat-events` and `noombat-groups`, declare no dependency until they use one, which Cargo itself would warn about from 1.100 on.

The scan injects a canary dependency name into every manifest it reads and requires all of them back in the output.
A canary that goes missing means the search matched something it should not have, so a clean result would prove nothing, and the script exits `2` rather than reporting success.
That is not hypothetical: an early version read clean because its file list included `package.json`, so every dependency matched its own declaration.

## `check-image-pins.sh`

Asserts that container images named in workflows are pinned by digest, that they agree with the compose file naming the same image, that the Playwright job container's tag names the exact `@playwright/test` version in `tests/e2e`, that the Caddy release the e2e job downloads is the one every compose file's Caddy tag names, and that the Dockerfile's Node major is the one `.nvmrc` and the lower bound of `frontend/package.json`'s `engines` name.

```sh
./scripts/check-image-pins.sh
```

Exit `0` means pinned and in agreement, `1` means a disagreement, an unpinned image, or a Playwright, Caddy or Node mismatch, and `2` means a parser matched nothing and the run proves nothing.

This exists because a workflow `services:` or `container:` image is the one image reference no updater reaches.
Dependabot's docker ecosystem reads Dockerfiles, docker-compose reads compose files, and github-actions reads `uses:`.
On 2026-08-17 PR #48 raised Meilisearch in `compose.yml` and could not touch the copy in `ci.yml`; merging it as proposed would have left CI asserting against one Meilisearch while deployments ran another, and both would have started and passed.

The durable half of the fix was to stop naming those images twice: `ci.yml`'s integration job now starts `db`, `redis` and `meilisearch` from `compose.yml` plus `compose.dev.yml` rather than repeating them in a `services:` block.
This check covers what could not move, and pins what stayed.

One image may be unpinned, with its reason printed on every run: GoToSocial floats in `tests/interop/compose.latest.yml`, which `ci-interop-latest.yml` runs on a schedule, and is pinned by digest in `tests/interop/compose.yml`.
The Playwright job container cannot come from compose and must equal the `@playwright/test` version in `tests/e2e`, which the check enforces.
The e2e job has no Docker either, so it downloads Caddy as a release binary, and the check holds that download to the compose files' Caddy tag; a Dependabot bump of the image fails it until the URL and hash in `ci-e2e.yml` move too.

It compares what the files say, not what a registry resolves them to; a digest that has been withdrawn upstream passes here and fails at `docker pull`.

**This runs in CI, in the `dependency-hygiene` job of `ci.yml` and as the first step of the e2e job in `ci-e2e.yml`, and from `test.sh`.**

No workflow runs `test.sh`, so being listed there gates nothing on its own; a check needs a step in a workflow to fail a pull request.
Every check now has one: `check-inline-scripts.sh` and `check-template-comments.sh` in `markup-conventions`, `check-logical-properties.sh` and `check-contrast.py` in `ci-accessibility.yml`, `check-migrations.sh` in `migration-shape`, `check-typst-injection.sh` in `typst.yml`, `check-reproducible.sh` in `ci-frontend.yml` and `release.yml`, and this one with `check-unused-deps.sh` in `dependency-hygiene`.
`check-unused-deps.sh` is the one that does not block: it carries `continue-on-error: true`, because it reports candidates rather than conclusions.

When pinning a digest by hand, take the **manifest list** digest and not a platform one.
`docker manifest inspect --verbose` returns the per-platform descriptor, and pinning that ties the image to a single architecture; `docker buildx imagetools inspect <ref> --format '{{println .Manifest.Digest}}'` returns the list digest, which is also what Dependabot writes.

## `check-compose-config.sh`

Loads every compose combination the repository runs (`docker compose config`), with a placeholder for each required variable, and fails on any that cannot start, such as a dependency cycle between overlays.
A compose file that appears in no combination fails too, so a new overlay must be added to the list.

```sh
./scripts/check-compose-config.sh
```

## `check-action-allowlist.sh`

Asserts that every `uses:` in `.github/workflows/` is one the repository's Actions policy will run, and that each is pinned to a full-length 40-character commit SHA.

```sh
./scripts/check-action-allowlist.sh
```

Exit `0` means every reference is permitted, `1` means at least one will be refused, and `2` means it found no `uses:` at all and so proves nothing.

The policy permits actions owned by `noombat` plus a short list of patterns.
**That list is a GitHub repository setting and is not in this tree**, so the copy in this script is kept in step by hand: adding an entry here is a request to the maintainer to add the same pattern there, and the workflow stays dead until they do.

This exists because the failure is invisible. A refused `uses:` does not fail a job, it makes the whole workflow report `startup_failure`, which creates no jobs and therefore no check runs, so the commit shows every other check green while nothing ran. On 2026-08-17 `ci-e2e.yml` was in that state and all three of its jobs silently did not execute, alongside 35 green checks on the same commit.

`actionlint` does not cover this. It validates the workflow schema and knows nothing about the policy.

## `check-action-tags.sh`

Asserts that every pinned action's SHA is the release its trailing comment names (`@<sha> # v7.0.1`), resolving each tag through the API.

```sh
./scripts/check-action-tags.sh   # every workflow; needs gh with a token
```

Exit `0` means every pin matches, `1` means a SHA is not the release named or a comment names no exact release (such as a moving `v4`), and `2` means a setup or API error.

A reader trusts the comment, and Dependabot moves the SHA and the comment together, but a hand edit can leave them apart.
It runs in the `actions-policy` job of `ci.yml`, and from `test.sh` when `gh` is signed in.

## `check-workflow-startup.sh`

Reports a workflow GitHub rejected before it ran, for one commit or for every run since a time.

```sh
./scripts/check-workflow-startup.sh          # HEAD
./scripts/check-workflow-startup.sh <sha>
./scripts/check-workflow-startup.sh --since 2026-11-22T06:00:00Z   # every branch, runs created since then
```

Exit `0` means nothing was rejected, `1` means at least one was, and `2` means the API gave no usable answer, which must not read as a clean result, or the arguments were malformed.

A rejected workflow concludes `startup_failure`: no jobs, so no check runs, so nothing on the commit page distinguishes it from a workflow that was never triggered.
`check-action-allowlist.sh` catches the usual cause before a push; this catches the symptom afterwards whatever the cause.
`.github/workflows/startup-watch.yml` runs it daily with `--since` two days back, across every branch: a path-filtered workflow creates no run on a commit outside its paths, so main's head alone can miss a rejection.
It is scheduled rather than run on push because one workflow cannot see whether another has concluded yet.

It reads the public API, so no token is needed, though one raises the rate limit. A token that is present but rejected is ignored rather than treated as a failure.

## `check-release-tested.sh`

Refuses to release a commit that is not on main, or that main's workflows did not pass. The `gate` job in `release.yml` runs it on the tagged commit before anything is built.

```sh
./scripts/check-release-tested.sh <sha> [timeout-seconds]   # needs gh with a token
```

Exit `0` means the commit is on main and every listed workflow has a successful push or manual run on it, `1` means the release is refused, and `2` means a usage or API error.

A tag can name any commit, and a push runs a path-filtered workflow once, on its last commit, and only when its paths changed, so a workflow can have no run on the commit being released.
The script then names the command that starts one (`gh workflow run <file> --ref <tag>`), and waits for runs still going, up to the timeout.
The workflows it requires are listed in the script: a new workflow that tests each commit belongs there.

## `check-template-comments.sh`

Asserts that every `<!--` in the Askama templates has its own `-->` in every page the templates can render.

```sh
./scripts/check-template-comments.sh                        # crates/noombat-api/templates
./scripts/check-template-comments.sh path/to/other/templates
```

Exit `0` means balanced, `1` means a violation, and `2` means the directory was missing or held no `.html` file, so the run proves nothing.

Askama compiles templates and validates only its own `{% %}` and `{# #}` syntax; HTML is passed through untouched.
A comment left open therefore builds green, renders without a warning, and is visible only in a browser.
Its blast radius is not the file it is in: the comment runs to the next `-->` in the *rendered* page, which is normally in the layout the template extends.
Commit `01a4e5b` deleted a stylesheet `<link>` from `article.html` and left the opening `<!--` of its comment behind, which swallowed some 1200 characters of `base.html`, i.e. the `main.css` link, the htmx script, `</head>`, the `<body>` tag and the accessibility skip link.
Every article page rendered unstyled and without htmx, and nothing in the build, the test suite or `check-inline-scripts.sh` failed.

What counts as a delimiter is what a browser would count, not what the source looks like.
`{# ... #}` is removed before the scan, because Askama removes it before any HTML exists, so a `-->` written inside one closes nothing; those nest, so the removal counts depth rather than stopping at the first `#}`.
The abrupt forms the HTML tokeniser accepts are read the way it reads them: `--!>` ends a comment, and `<!-->` and `<!--->` are whole empty comments rather than an opening delimiter.

Four faults are reported, the first two at the line where the comment at fault was *opened*.
Delimiters are matched as occurrences rather than per line, so a line holding several and a comment spanning many are both handled.

1. A `<!--` that reaches end of file with no `-->`.
2. A `<!--` inside an open comment. HTML has no nested comments, so this is the fault above, and the reason an end-of-file check is not enough on its own: in `article.html` the runaway comment was terminated by the `-->` of the *next* comment down the file, so the file ended outside a comment and read as balanced. What gave it away was the second `<!--` being swallowed as comment text.
3. A `-->` that closes nothing, reported where it appears.
4. An `{% if %}` branch that opens or closes a comment its sibling branches do not, reported at the line the branch opened. `{% if x %}<!-- note{% else %}-->{% endif %}` holds one of each delimiter and balances in the source, but only one branch is ever emitted, so one rendered page in two carries a runaway comment. Commenting a block out under a condition is written this way too and is reported the same, since nothing in the text says that two conditions always agree.

Blind spot worth knowing before trusting a green run: the check counts delimiters in the source and never renders.
A comment left open and a later stray `-->` cancel out and read as one long deliberate comment, which is the shape of the `article.html` defect minus the second `<!--` that gave it away.
Branches are checked for `{% if %}` only, not `{% for %}` bodies or `{% match %}` arms.

Unlike `check-image-pins.sh`, this one is not a local-only gate: it runs from `test.sh` and as a step of the `Markup conventions` job in `ci.yml`, over the same directory as `check-inline-scripts.sh`.

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
