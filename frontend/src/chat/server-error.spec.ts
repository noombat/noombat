// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

import { describe, expect, it } from "vitest";

import { describeServerError, type ServerErrorStrings } from "./server-error";

const strings: ServerErrorStrings = {
  loginFailed: "login failed",
  connectFailed: "unreachable",
  idleTimeout: "idle",
  blocked: "blocked",
  sendFailed: "not sent",
  fetchFailed: "not fetched",
  serverFault: (detail) => `fault: ${detail}`,
};

describe("describeServerError", () => {
  // The codes as the server spells them (`noombat_chat::relay::ErrorCode`).
  it("puts each error a member can meet in their own words", () => {
    expect(describeServerError(strings, "login_failed", "IMAP authentication failed")).toBe(
      "login failed",
    );
    expect(describeServerError(strings, "connect_failed", "relay down")).toBe("unreachable");
    expect(describeServerError(strings, "idle_timeout", "session timed out")).toBe("idle");
    expect(describeServerError(strings, "blocked", "recipient has blocked")).toBe("blocked");
    expect(describeServerError(strings, "send_failed", "send failed: 451")).toBe("not sent");
    expect(describeServerError(strings, "fetch_failed", "fetch failed: EOF")).toBe("not fetched");
  });

  it("shows the server's own text for any other error", () => {
    expect(describeServerError(strings, "auth_timeout", "auth timeout")).toBe(
      "fault: auth timeout",
    );
    expect(describeServerError(strings, undefined, "from an older server")).toBe(
      "fault: from an older server",
    );
  });
});
