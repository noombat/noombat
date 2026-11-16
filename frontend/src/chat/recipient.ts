// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

/**
 * Which key a message goes to, and which key the verification panel
 * shows, from the keys held and the instance's answers. Kept apart from
 * the page, so it is tested without one.
 */

import type { PeerState } from "./autocrypt";
import { fetchPublishedKey, fetchPublishedKeyByHandle, type PublishedKeyResult } from "./directory";

/** An answer that found a key. */
export type FoundKey = Extract<PublishedKeyResult, { status: "found" }>;

/** The keys held, as `PeerStateTable` holds them. */
export interface HeldKeys {
  get(address: string): PeerState | undefined;
  getPublicKey(address: string): Uint8Array | null;
  adoptPublishedKey(address: string, key: Uint8Array): boolean;
}

type Lookup = (who: string) => Promise<PublishedKeyResult>;

/**
 * The instance's answers for as long as the page is open, by the address
 * or handle asked, so the panel and a send use the same one: the
 * fingerprint a member compared is that of the key their first message
 * goes to. An answer that found no key is asked again the next time.
 */
export class KeyLookups {
  private readonly answers = new Map<string, Promise<PublishedKeyResult>>();
  private readonly byAddress: Lookup;
  private readonly byHandle: Lookup;

  constructor(byAddress: Lookup = fetchPublishedKey, byHandle: Lookup = fetchPublishedKeyByHandle) {
    this.byAddress = byAddress;
    this.byHandle = byHandle;
  }

  /** The answer for `who`, asking the instance only the first time. */
  lookUp(who: string): Promise<PublishedKeyResult> {
    const asked = this.answers.get(who);
    if (asked) return asked;
    const answer = (who.startsWith("@") ? this.byHandle(who) : this.byAddress(who)).then(
      (result) => {
        if (result.status !== "found") {
          this.answers.delete(who);
        } else if (!this.answers.has(result.address)) {
          // A handle's answer is its address's too.
          this.answers.set(result.address, Promise.resolve(result));
        }
        return result;
      },
    );
    this.answers.set(who, answer);
    return answer;
  }

  /** The answer for `who` if it was asked for, arrived or not, without asking. */
  asked(who: string): Promise<PublishedKeyResult> | undefined {
    return this.answers.get(who);
  }
}

/** Where a message to someone goes, or why it cannot. */
export type Recipient =
  | { status: "ready"; address: string; key: Uint8Array; adopted: FoundKey | null }
  | { status: "failed"; who: string; result: PublishedKeyResult };

/**
 * The address a message to `who`, an address or a handle, goes to, and
 * the key: the one held for the address, else the one the instance
 * publishes, held from then on. `adopted` is that published key when this
 * call took it, for the notice that says so.
 */
export async function resolveRecipient(
  who: string,
  held: HeldKeys,
  lookups: KeyLookups,
): Promise<Recipient> {
  let address = who;
  let adopted: FoundKey | null = null;
  if (who.startsWith("@")) {
    const found = await lookups.lookUp(who);
    if (found.status !== "found") return { status: "failed", who, result: found };
    address = found.address;
    if (held.adoptPublishedKey(found.address, found.key)) adopted = found;
  }
  let key = held.getPublicKey(address);
  if (!key) {
    const found = await lookups.lookUp(address);
    if (found.status !== "found") return { status: "failed", who: address, result: found };
    if (held.adoptPublishedKey(found.address, found.key)) adopted = found;
    // A key held meanwhile, from a message's header, wins.
    key = held.getPublicKey(address) ?? found.key;
  }
  return { status: "ready", address, key, adopted };
}

/** A key the panel shows, and whether it is the instance's. */
export interface ShownKey {
  key: Uint8Array;
  fromInstance: boolean;
}

/**
 * The key the panel shows for `who`: the one a message to them would go
 * to. The instance is asked only when `ask`; otherwise an answer already
 * asked for is used, arrived or not, and none is `null`.
 */
export async function keyShown(
  who: string,
  held: HeldKeys,
  lookups: KeyLookups,
  ask: boolean,
): Promise<ShownKey | null> {
  const direct = heldKey(held, who);
  if (direct) return direct;
  const answer = ask ? lookups.lookUp(who) : lookups.asked(who);
  if (!answer) return null;
  const found = await answer;
  if (found.status !== "found") return null;
  // A key held for the address a handle names is the one messages go to.
  return heldKey(held, found.address) ?? { key: found.key, fromInstance: true };
}

function heldKey(held: HeldKeys, address: string): ShownKey | null {
  const entry = held.get(address);
  if (!entry || entry.publicKey.length === 0) return null;
  return { key: new Uint8Array(entry.publicKey), fromInstance: entry.keyOrigin === "instance" };
}
