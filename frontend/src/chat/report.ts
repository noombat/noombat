// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

/**
 * Reporting a chat message to the instance's moderators.
 */

import { authHeaders } from "./session";

/** What a report names: the sender, the text, and when it was sent. */
export interface ReportedMessage {
  from: string;
  body: string;
  /** Seconds since the epoch, as the message carries it. */
  timestamp: number;
}

/** Report `message`, best-effort: a failure is not shown. */
export async function reportMessage(message: ReportedMessage): Promise<void> {
  await fetch("/api/v1/chat/reports", {
    method: "POST",
    headers: authHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify({
      target_addr: message.from,
      message_content: message.body,
      message_date: new Date(message.timestamp * 1000).toISOString(),
      reason: "other",
    }),
  }).catch(() => {
    /* best-effort */
  });
}
