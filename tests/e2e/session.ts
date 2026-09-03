// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

// A real session for the pages behind `require_auth`.
//
// The development bearer token is not one, and that is why this file
// exists. When the server falls back to that token it derives the
// username from the request path, `/users/{name}` or `/@{name}`, and
// never sets an actor id at all. /chat, /settings/chat, /compose and
// /auth/upgrade carry neither prefix, so the principal ends up with
// both fields empty, `require_auth` answers 307 to /auth/login, and
// every assertion made under that credential is measuring the login
// page rather than the page it names.
//
// A session token carries both fields, because the server mints it from
// the account it has just authenticated. It is presented as a Bearer
// header to a request context and as the `noombat_session` cookie to a
// browser. The server reads the header first and the cookie second, so
// a group that authenticates the browser must not also set a header.
//
// The instance has to be running with NOOMBAT_JWT_SECRET set: without
// it the server disables session authentication entirely and both
// routes below answer 503.

import type { APIRequestContext, BrowserContext } from "@playwright/test";
import { test } from "@playwright/test";

const BASE_URL = process.env.BASE_URL ?? "http://localhost:8443";

/** The cookie the server reads; see crates/noombat-api/src/cookie.rs. */
const COOKIE_NAME = "noombat_session";

/**
 * The authentication key the fixture account is registered with.
 *
 * Neither a password nor a secret. The register route takes the key a
 * client derives from a password, validates it as 64 hex characters and
 * hashes it; these tests need an account to exist, not a password flow.
 */
const AUTH_KEY = "e2e5e551043a4d7b8c6f1e2d3c4b5a69788796a5b4c3d2e1f00112233445566f";

/**
 * How many session accounts the stack seeds.
 *
 * The suite no longer creates accounts, so this is a fixed pool rather
 * than one per worker: the seed has to know every name in advance, and a
 * worker index is not bounded by the worker count. A retried test runs in
 * a fresh worker with the next index, so one run of a single-worker job
 * reached `w17`, and any fixed list of per-index names would have run out.
 */
export const SESSION_ACCOUNTS = 4;

/**
 * The fixture account a Playwright worker signs in as.
 *
 * Indices wrap around the seeded pool. Two workers sharing an account is
 * harmless where it can happen at all: the pool is as large as the worker
 * count this suite is configured for, and the accounts are only ever read
 * from. The per-worker split existed to keep parallel workers from racing
 * to create the same row, which seeding removes.
 */
export function sessionUsername(workerIndex: number): string {
  return `e2e_session_w${workerIndex % SESSION_ACCOUNTS}`;
}

/**
 * The seeded administrator, shared by every worker.
 *
 * `instance_role` is settable through no API a test can reach, so the
 * stack seed registers this account and promotes it. Signed in to here
 * rather than registered, deliberately: an account this file created
 * would carry the default role, `require_admin` would redirect every
 * admin page to `/`, and the scans would pass having measured the feed.
 */
export const ADMIN_USERNAME = "e2e_admin";

/**
 * Sign the seeded administrator in.
 *
 * Returns null when there is no such account, which off CI usually means
 * the stack was started without `seed_admin`. Under CI it throws, for the
 * same reason `sessionToken` does: a skipped group and a passing one look
 * identical in the summary.
 */
export async function adminSessionToken(request: APIRequestContext): Promise<string | null> {
  const signedIn = await request.post("/api/v1/auth/login", {
    data: { username: ADMIN_USERNAME, auth_key: AUTH_KEY },
  });
  if (signedIn.status() === 200) {
    return accessToken(await signedIn.text());
  }

  if (process.env.CI) {
    throw new Error(
      `no session could be obtained for ${ADMIN_USERNAME} (login returned ` +
        `${signedIn.status()}). scripts/e2e-stack.sh and ci-e2e.yml register it and ` +
        "promote it to admin; without that the admin group scans the feed instead.",
    );
  }
  return null;
}

/** The administrator's token, or a skip when the account is absent. */
export async function requireAdminSession(request: APIRequestContext): Promise<string> {
  const token = await adminSessionToken(request);
  // eslint-disable-next-line playwright/no-skipped-test -- conditional, and CI cannot reach it
  test.skip(token === null, `no seeded administrator (${ADMIN_USERNAME}) on this instance`);
  return token ?? "";
}

/**
 * Sign a seeded fixture account in.
 *
 * It only signs in. The account is seeded in SQL by the stack, because
 * `POST /api/v1/auth/register` refuses with 503 unless the instance has an
 * SMTP relay, and this stack configures none.
 *
 * Returns null when the instance issues no sessions, which is a
 * convenience for a local run against a server started without a JWT
 * secret. Under CI it throws instead: the groups that need this would
 * otherwise skip, and a skipped group and a passing one are the same
 * output.
 */
export async function sessionToken(
  request: APIRequestContext,
  workerIndex: number,
): Promise<string | null> {
  const credentials = { username: sessionUsername(workerIndex), auth_key: AUTH_KEY };

  const signedIn = await request.post("/api/v1/auth/login", { data: credentials });
  if (signedIn.status() === 200) {
    return accessToken(await signedIn.text());
  }

  if (process.env.CI) {
    throw new Error(
      `no session could be obtained for ${credentials.username} (login returned ` +
        `${signedIn.status()}). The authenticated groups would skip silently. The ` +
        "instance needs NOOMBAT_JWT_SECRET set, which is what enables session " +
        `authentication, and the stack has to have seeded ${SESSION_ACCOUNTS} ` +
        "session accounts.",
    );
  }
  return null;
}

/**
 * The token, or a skip when this instance issues none.
 *
 * The skip is reachable only off CI, because `sessionToken` throws
 * there rather than returning null.
 */
export async function requireSession(
  request: APIRequestContext,
  workerIndex: number,
): Promise<string> {
  const token = await sessionToken(request, workerIndex);
  // eslint-disable-next-line playwright/no-skipped-test -- conditional, and CI cannot reach it
  test.skip(token === null, "this instance issues no sessions; NOOMBAT_JWT_SECRET is unset");
  // The line above throws when it fires, so the token is present here.
  return token ?? "";
}

/** Put the session on the browser, so that page navigations carry it. */
export async function authenticateBrowser(context: BrowserContext, token: string): Promise<void> {
  await context.addCookies([{ name: COOKIE_NAME, value: token, url: BASE_URL }]);
}

function accessToken(body: string): string {
  const token = (JSON.parse(body) as { access_token?: string }).access_token;
  if (!token) {
    throw new Error(`the session response carried no access_token: ${body.slice(0, 200)}`);
  }
  return token;
}
