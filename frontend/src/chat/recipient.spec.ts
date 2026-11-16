// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

/**
 * Tests for choosing the key a message goes to and the key the panel
 * shows, with the instance's answers scripted.
 */

import { describe, expect, it } from "vitest";
import { PeerStateTable } from "./autocrypt";
import type { PublishedKeyResult } from "./directory";
import { KeyLookups, keyShown, resolveRecipient } from "./recipient";

const BOB = "bob@chat.example";
const HANDLE = "@bob@other.example";
const HELD = new Uint8Array([1, 1, 1]);
const FIRST = new Uint8Array([2, 2, 2]);
const SECOND = new Uint8Array([3, 3, 3]);

const found = (key: Uint8Array): PublishedKeyResult => ({
  status: "found",
  address: BOB,
  key,
  fingerprint: `fingerprint of ${key[0]}`,
});

/** An instance answering each request with the next of `answers`, and the requests it saw. */
function instance(...answers: PublishedKeyResult[]): {
  lookups: KeyLookups;
  asked: string[];
} {
  const asked: string[] = [];
  const answer = (who: string): Promise<PublishedKeyResult> => {
    asked.push(who);
    return Promise.resolve(answers.shift() ?? { status: "error" });
  };
  return { lookups: new KeyLookups(answer, answer), asked };
}

describe("resolveRecipient", () => {
  it("uses the key held, asking the instance nothing", async () => {
    const held = new PeerStateTable();
    held.adoptPublishedKey(BOB, HELD);
    const { lookups, asked } = instance(found(FIRST));
    const resolved = await resolveRecipient(BOB, held, lookups);
    expect(resolved).toEqual({ status: "ready", address: BOB, key: HELD, adopted: null });
    expect(asked).toEqual([]);
  });

  it("holds the key the instance publishes when none is held, and says it took it", async () => {
    const held = new PeerStateTable();
    const { lookups } = instance(found(FIRST));
    const resolved = await resolveRecipient(BOB, held, lookups);
    expect(resolved).toEqual({ status: "ready", address: BOB, key: FIRST, adopted: found(FIRST) });
    expect(held.getPublicKey(BOB)).toEqual(FIRST);
  });

  it("prefers a key held meanwhile, from a message, to the instance's", async () => {
    const held = new PeerStateTable();
    const answer = (): Promise<PublishedKeyResult> => {
      held.adoptPublishedKey(BOB, HELD);
      return Promise.resolve(found(FIRST));
    };
    const resolved = await resolveRecipient(BOB, held, new KeyLookups(answer, answer));
    expect(resolved).toEqual({ status: "ready", address: BOB, key: HELD, adopted: null });
  });

  it("sends to the address a handle names, with the key held for it", async () => {
    const held = new PeerStateTable();
    held.adoptPublishedKey(BOB, HELD);
    const { lookups } = instance(found(FIRST));
    const resolved = await resolveRecipient(HANDLE, held, lookups);
    expect(resolved).toEqual({ status: "ready", address: BOB, key: HELD, adopted: null });
  });

  it("names whom a failed lookup was for", async () => {
    const { lookups } = instance({ status: "absent" });
    const resolved = await resolveRecipient(HANDLE, new PeerStateTable(), lookups);
    expect(resolved).toEqual({ status: "failed", who: HANDLE, result: { status: "absent" } });
  });
});

describe("the panel and a send", () => {
  it("encrypt to the key the panel showed, though the instance would now answer another", async () => {
    const held = new PeerStateTable();
    const { lookups, asked } = instance(found(FIRST), found(SECOND));
    expect(await keyShown(BOB, held, lookups, true)).toEqual({ key: FIRST, fromInstance: true });
    const resolved = await resolveRecipient(BOB, held, lookups);
    expect(resolved.status === "ready" && resolved.key).toEqual(FIRST);
    expect(asked).toEqual([BOB]);
  });

  it("share a handle's answer with its address", async () => {
    const held = new PeerStateTable();
    const { lookups, asked } = instance(found(FIRST), found(SECOND));
    await keyShown(HANDLE, held, lookups, true);
    const resolved = await resolveRecipient(BOB, held, lookups);
    expect(resolved.status === "ready" && resolved.key).toEqual(FIRST);
    expect(asked).toEqual([HANDLE]);
  });

  it("ask again after an answer that found nothing", async () => {
    const { lookups, asked } = instance({ status: "error" }, found(FIRST));
    expect(await keyShown(BOB, new PeerStateTable(), lookups, true)).toBeNull();
    expect(await keyShown(BOB, new PeerStateTable(), lookups, true)).toEqual({
      key: FIRST,
      fromInstance: true,
    });
    expect(asked).toEqual([BOB, BOB]);
  });
});

describe("keyShown", () => {
  it("asks nothing unless asked to, but uses an answer already asked for", async () => {
    const held = new PeerStateTable();
    const { lookups, asked } = instance(found(FIRST));
    expect(await keyShown(HANDLE, held, lookups, false)).toBeNull();
    expect(asked).toEqual([]);
    const pending = lookups.lookUp(HANDLE);
    expect(await keyShown(HANDLE, held, lookups, false)).toEqual({
      key: FIRST,
      fromInstance: true,
    });
    await pending;
    expect(asked).toEqual([HANDLE]);
  });

  it("shows the key held for the address a handle names, and where it came from", async () => {
    const held = new PeerStateTable();
    held.adoptPublishedKey(BOB, HELD);
    held.update({
      from: BOB,
      effectiveDate: 1000,
      autocryptHeader: { addr: BOB, preferEncrypt: "mutual", publicKey: HELD },
    });
    const { lookups } = instance(found(FIRST));
    expect(await keyShown(HANDLE, held, lookups, true)).toEqual({ key: HELD, fromInstance: false });
  });
});
