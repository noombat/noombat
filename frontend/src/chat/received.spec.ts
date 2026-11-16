// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

/**
 * Tests for the messages a page holds: each shown once, and the UID to
 * ask after when connecting again.
 */

import { describe, expect, it } from "vitest";
import { Received } from "./received";

describe("Received", () => {
  it("takes a message once", () => {
    const received = new Received();
    expect(received.take(5)).toBe(true);
    expect(received.take(5)).toBe(false);
  });

  it("asks after the newest held, whatever order they came in", () => {
    const received = new Received();
    expect(received.newest).toBe(0);
    received.take(7);
    expect(received.take(5)).toBe(true);
    expect(received.newest).toBe(7);
  });

  it("keeps its UIDs while the mailbox is the same one", () => {
    const received = new Received();
    expect(received.inMailbox(41)).toBe(false);
    received.take(5);
    expect(received.inMailbox(41)).toBe(false);
    expect(received.take(5)).toBe(false);
    expect(received.newest).toBe(5);
  });

  it("forgets its UIDs when the mailbox's UIDVALIDITY changes", () => {
    const received = new Received();
    received.inMailbox(41);
    received.take(5);
    expect(received.inMailbox(42)).toBe(true);
    expect(received.newest).toBe(0);
    expect(received.take(5)).toBe(true);
  });

  it("changes nothing for an unknown UIDVALIDITY", () => {
    const received = new Received();
    received.inMailbox(41);
    received.take(5);
    expect(received.inMailbox(null)).toBe(false);
    expect(received.inMailbox(undefined)).toBe(false);
    expect(received.newest).toBe(5);
  });

  it("takes a message without a UID every time, and asks after none for it", () => {
    const received = new Received();
    expect(received.take(0)).toBe(true);
    expect(received.take(0)).toBe(true);
    expect(received.newest).toBe(0);
  });
});
