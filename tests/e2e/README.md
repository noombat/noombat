# End-to-End Tests

Playwright suite driving real browsers against a running Noombat stack. It covers the three things the Rust and unit suites cannot reach: what a browser actually renders, what headers the server actually sends, and whether the pages are accessible.

## Components

| File                       | Purpose                                              |
|----------------------------|------------------------------------------------------|
| `smoke.spec.ts`            | Pages render and permalinks resolve                  |
| `accessibility.spec.ts`    | WCAG 2.2 AA, asserted with axe-core                  |
| `security-headers.spec.ts` | Response headers and the CSP                         |
| `session.ts`               | Registers and signs in the accounts the specs use    |
| `axe-fixture.ts`           | Wires axe-core into the Playwright fixture           |
| `playwright.config.ts`     | Six browser projects, three desktop and three mobile |

This directory is its own pnpm project, `noombat-e2e`, separate from `frontend/` and with its own lockfile, `tsconfig.json` and ESLint config. Run `pnpm lint` and `pnpm typecheck` here; the frontend's do not cover it.

## Running

```sh
# Raise PostgreSQL, Redis, Meilisearch and Noombat, and seed the fixtures.
scripts/e2e-stack.sh up

# Once, to install the suite's own dependencies.
pnpm --dir tests/e2e install --frozen-lockfile

# Everything, one browser, or one spec.
pnpm --dir tests/e2e test
pnpm --dir tests/e2e test:firefox
pnpm --dir tests/e2e exec playwright test security-headers.spec.ts --project=firefox

scripts/e2e-stack.sh down
```

`scripts/e2e-stack.sh` also takes `status`.

## Fixtures three files have to agree on

The suite does not create its own data. `scripts/e2e-stack.sh` seeds it and the specs address it by hard-coded value, so changing one place and not the others breaks the run as a timeout or a missing element rather than as a visible mismatch.

| Fixture                      | Also hard-coded in                                                    |
|------------------------------|-----------------------------------------------------------------------|
| `e2e_admin` and its auth key | `session.ts`, `scripts/e2e-stack.sh`, and the workflow's seeding step |
| The article permalink id     | `smoke.spec.ts`, `scripts/e2e-stack.sh`                               |
| The note permalink id        | `smoke.spec.ts`, `scripts/e2e-stack.sh`                               |

The ids are fixed so that a spec can address a permalink without discovering it first. Article and note are separate fixtures because a note permalink takes a different template branch, and exercising only one of them leaves the other template rendered by nothing.

The administrator exists because `require_admin` redirects every admin page to `/`, so without it the admin accessibility group would measure the feed under other pages' names and still pass.

## CI

The `e2e` job in `.github/workflows/ci-e2e.yml` runs `security-headers.spec.ts` on Firefox first and on its own, then the full cross-browser matrix, which includes that spec again. Reporting it separately keeps a header or CSP regression from being buried in the matrix.

## Coverage

Accessibility is asserted against WCAG 2.2 AA and fails on any violation axe-core returns. Anything axe cannot decide is not asserted, so a passing run means nothing automatically detectable is wrong, not that a page is accessible.
