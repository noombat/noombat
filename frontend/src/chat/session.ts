// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

/**
 * Session header construction for authenticated API requests.
 *
 * Noombat accepts two session carriers: an `Authorization: Bearer`
 * header and the `noombat_session` cookie. The server resolves the
 * header first and only falls back to the cookie when no header is
 * present, so an `Authorization: Bearer ` header with an empty
 * token *shadows* an otherwise valid cookie and produces an
 * unauthenticated request.
 *
 * Password-derived flows (registration) hold a bearer token in
 * `sessionStorage`; cookie-only flows (OAuth account upgrade) do
 * not. This helper therefore emits the header only when a non-empty
 * token exists, leaving the cookie to authenticate otherwise.
 * Cookies are attached automatically because `fetch` defaults to
 * `credentials: "same-origin"`.
 */

/** Session-storage key holding the JWT access token. */
export const ACCESS_TOKEN_KEY = "noombat_access_token";

/** Retrieve the bearer token, or `null` when none is stored. */
export function accessToken(): string | null {
  const token = sessionStorage.getItem(ACCESS_TOKEN_KEY);
  return token && token.length > 0 ? token : null;
}

/** Build request headers for an authenticated API call, merging `extra`. */
export function authHeaders(extra: Record<string, string> = {}): Record<string, string> {
  const token = accessToken();
  return token ? { ...extra, Authorization: `Bearer ${token}` } : { ...extra };
}
