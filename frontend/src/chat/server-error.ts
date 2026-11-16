// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

/** The chat page's words for the errors its server reports. */
export interface ServerErrorStrings {
  loginFailed: string;
  connectFailed: string;
  idleTimeout: string;
  blocked: string;
  sendFailed: string;
  fetchFailed: string;
  serverFault: (detail: string) => string;
}

/** A chat server error in the member's language, chosen by its `code`,
 *  which the server spells in snake case. The server's own `message` is
 *  English and technical, so it is shown only for errors a member is not
 *  expected to meet. */
export function describeServerError(
  strings: ServerErrorStrings,
  code: string | undefined,
  message: string | undefined,
): string {
  switch (code) {
    case "login_failed":
      return strings.loginFailed;
    case "connect_failed":
      return strings.connectFailed;
    case "idle_timeout":
      return strings.idleTimeout;
    case "blocked":
      return strings.blocked;
    case "send_failed":
      return strings.sendFailed;
    case "fetch_failed":
      return strings.fetchFailed;
    default:
      return strings.serverFault(message ?? "");
  }
}
