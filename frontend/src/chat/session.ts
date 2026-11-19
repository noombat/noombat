// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

/**
 * Session header construction for authenticated API requests.
 *
 * Noombat accepts two session carriers: an `Authorization: Bearer`
 * header and the `__Host-noombat_session` cookie. The server reads the
 * header first and falls back to the cookie when it names no token, as an
 * empty `Bearer ` does once `fetch` trims it, and a write the cookie
 * authenticates must also carry the page's CSRF token.
 *
 * Password-derived flows (registration) hold a bearer token in
 * `sessionStorage`; cookie-only flows (OAuth account upgrade) do
 * not. This helper therefore sends the bearer token when one is stored,
 * and otherwise the CSRF token, leaving the cookie to authenticate.
 * Cookies are attached automatically because `fetch` defaults to
 * `credentials: "same-origin"`.
 */

import { withCsrf } from "../csrf";

/** Session-storage key holding the JWT access token. */
export const ACCESS_TOKEN_KEY = "noombat_access_token";

/** Retrieve the bearer token, or `null` when none is stored. */
export function accessToken(): string | null {
  const token = sessionStorage.getItem(ACCESS_TOKEN_KEY);
  return token && token.length > 0 ? token : null;
}

/**
 * Build request headers for an authenticated API call, merging `extra`:
 * the bearer token when one is stored, and otherwise, the session cookie
 * authenticating the call, the page's CSRF token.
 */
export function authHeaders(extra: Record<string, string> = {}): Record<string, string> {
  const token = accessToken();
  return token ? { ...extra, Authorization: `Bearer ${token}` } : withCsrf(extra);
}
