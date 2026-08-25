// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

/**
 * Tests for the Autocrypt Level 1 peer state machine.
 *
 * The cases that matter most are the key-replacement ones. An
 * operator able to rewrite Autocrypt headers substitutes its own key
 * for a peer's; the client cannot distinguish that from a legitimate
 * key rotation, but it can and must report that a replacement
 * happened. These tests pin the distinction between first
 * acquisition, which is not reportable, and replacement, which is.
 */

import { describe, it, expect } from "vitest";
import { PeerStateTable, parseAutocryptHeader, type AutocryptHeader } from "./autocrypt";

// ..... Fixtures .....

const ALICE = "alice@chat.example.com";

const KEY_A = new Uint8Array([0x01, 0x02, 0x03, 0x04]);
const KEY_B = new Uint8Array([0x05, 0x06, 0x07, 0x08]);
/** Same bytes as KEY_A in a distinct array, to prove the comparison
 *  is by value rather than by reference. */
const KEY_A_COPY = new Uint8Array([0x01, 0x02, 0x03, 0x04]);

function header(publicKey: Uint8Array, addr = ALICE): AutocryptHeader {
  return { addr, publicKey, preferEncrypt: "mutual" };
}

function message(publicKey: Uint8Array, effectiveDate: number, from = ALICE) {
  return { from, effectiveDate, autocryptHeader: header(publicKey, from) };
}

// ..... Header parsing .....

describe("parseAutocryptHeader", () => {
  it("parses addr, prefer-encrypt, and keydata", () => {
    const parsed = parseAutocryptHeader(`addr=${ALICE}; prefer-encrypt=mutual; keydata=AQIDBA==`);
    expect(parsed).not.toBeNull();
    expect(parsed!.addr).toBe(ALICE);
    expect(parsed!.preferEncrypt).toBe("mutual");
    expect(Array.from(parsed!.publicKey)).toEqual([1, 2, 3, 4]);
  });

  it("rejects a header carrying an unknown critical attribute", () => {
    // Autocrypt Level 1 §2.1: an attribute whose name does not begin
    // with an underscore is critical, and an unrecognised critical
    // attribute invalidates the entire header.
    expect(parseAutocryptHeader(`addr=${ALICE}; unknown=x; keydata=AQIDBA==`)).toBeNull();
  });

  it("ignores an unknown non-critical attribute", () => {
    expect(parseAutocryptHeader(`addr=${ALICE}; _draft=x; keydata=AQIDBA==`)).not.toBeNull();
  });

  it("rejects a header with no keydata", () => {
    expect(parseAutocryptHeader(`addr=${ALICE}; prefer-encrypt=mutual`)).toBeNull();
  });
});

// ..... Direct key updates .....

describe("PeerStateTable.update", () => {
  it("reports first acquisition as a mutation but not a key change", () => {
    const table = new PeerStateTable();
    const result = table.update(message(KEY_A, 1000));

    expect(result.mutated).toBe(true);
    // There is no prior value to contradict, so nothing is reportable.
    expect(result.keyChanged).toBe(false);
    expect(table.get(ALICE)!.lastKeyChangeAt).toBeNull();
  });

  it("reports replacement of a known key by different key material", () => {
    const table = new PeerStateTable();
    table.update(message(KEY_A, 1000));

    const result = table.update(message(KEY_B, 2000));

    expect(result.mutated).toBe(true);
    expect(result.keyChanged).toBe(true);
    expect(table.get(ALICE)!.lastKeyChangeAt).toBe(2000);
    expect(Array.from(table.getPublicKey(ALICE)!)).toEqual(Array.from(KEY_B));
  });

  it("does not report a repeated key as a change", () => {
    const table = new PeerStateTable();
    table.update(message(KEY_A, 1000));

    // Distinct array, identical bytes: comparison must be by value.
    const result = table.update(message(KEY_A_COPY, 2000));

    // The timestamp advanced, so the state is still dirty.
    expect(result.mutated).toBe(true);
    expect(result.keyChanged).toBe(false);
    expect(table.get(ALICE)!.lastKeyChangeAt).toBeNull();
  });

  it("ignores an older message and leaves the key intact", () => {
    const table = new PeerStateTable();
    table.update(message(KEY_A, 2000));

    const result = table.update(message(KEY_B, 1000));

    expect(result.keyChanged).toBe(false);
    expect(Array.from(table.getPublicKey(ALICE)!)).toEqual(Array.from(KEY_A));
  });

  it("ignores a header whose addr does not match the sender", () => {
    const table = new PeerStateTable();
    table.update(message(KEY_A, 1000));

    const result = table.update({
      from: ALICE,
      effectiveDate: 2000,
      autocryptHeader: header(KEY_B, "mallory@chat.example.com"),
    });

    expect(result.keyChanged).toBe(false);
    expect(Array.from(table.getPublicKey(ALICE)!)).toEqual(Array.from(KEY_A));
  });

  it("advances lastSeen for a message with no header, marking state dirty", () => {
    const table = new PeerStateTable();
    table.update(message(KEY_A, 1000));

    const result = table.update({ from: ALICE, effectiveDate: 2000, autocryptHeader: null });

    // lastSeen overtaking lastSeenAutocrypt downgrades the
    // recommendation to "discourage", so it must be persisted.
    expect(result.mutated).toBe(true);
    expect(result.keyChanged).toBe(false);
    expect(table.get(ALICE)!.lastSeen).toBe(2000);
  });

  it("canonicalises the address before matching", () => {
    const table = new PeerStateTable();
    table.update(message(KEY_A, 1000, ALICE));

    const result = table.update(message(KEY_B, 2000, `  ${ALICE.toUpperCase()}  `));

    expect(result.keyChanged).toBe(true);
    expect(table.get(ALICE)!.lastKeyChangeAt).toBe(2000);
  });
});

// ..... Gossip key updates .....

// These are specification tests, not regression tests: `updateGossip`
// has no caller. It pins the Autocrypt Level 1 semantics for whenever
// group messaging lands, and the method's own documentation lists the
// six preconditions that must hold before anything may call it.
describe("PeerStateTable.updateGossip", () => {
  it("reports first gossip acquisition as a mutation but not a change", () => {
    const table = new PeerStateTable();
    const result = table.updateGossip(ALICE, KEY_A, 1000);

    expect(result.mutated).toBe(true);
    expect(result.keyChanged).toBe(false);
  });

  it("reports replacement of a gossiped key", () => {
    const table = new PeerStateTable();
    table.updateGossip(ALICE, KEY_A, 1000);

    const result = table.updateGossip(ALICE, KEY_B, 2000);

    expect(result.mutated).toBe(true);
    expect(result.keyChanged).toBe(true);
    expect(table.get(ALICE)!.lastKeyChangeAt).toBe(2000);
  });

  it("respects gossip timestamp precedence", () => {
    const table = new PeerStateTable();
    table.updateGossip(ALICE, KEY_A, 2000);

    const result = table.updateGossip(ALICE, KEY_B, 1000);

    expect(result.mutated).toBe(false);
    expect(result.keyChanged).toBe(false);
    expect(table.get(ALICE)!.gossipKey).toEqual(Array.from(KEY_A));
  });

  it("keeps gossip key material separate from the direct key", () => {
    const table = new PeerStateTable();
    table.update(message(KEY_A, 1000));
    table.updateGossip(ALICE, KEY_B, 1000);

    // getPublicKey returns the directly advertised key; a gossiped
    // key is weaker evidence and must not displace it.
    expect(Array.from(table.getPublicKey(ALICE)!)).toEqual(Array.from(KEY_A));
    expect(table.get(ALICE)!.gossipKey).toEqual(Array.from(KEY_B));
  });
});

// ..... Serialisation .....

describe("PeerStateTable serialisation", () => {
  it("round-trips lastKeyChangeAt through the credential blob", () => {
    const table = new PeerStateTable();
    table.update(message(KEY_A, 1000));
    table.update(message(KEY_B, 2000));

    const restored = PeerStateTable.fromJson(table.toJson());

    expect(restored.get(ALICE)!.lastKeyChangeAt).toBe(2000);
    expect(Array.from(restored.getPublicKey(ALICE)!)).toEqual(Array.from(KEY_B));
  });

  it("normalises state written before lastKeyChangeAt existed", () => {
    // A blob stored by an earlier release lacks the field entirely.
    const legacy = JSON.stringify({
      [ALICE]: {
        lastSeen: 1000,
        lastSeenAutocrypt: 1000,
        publicKey: Array.from(KEY_A),
        preferEncrypt: "mutual",
        gossipKey: null,
        gossipTimestamp: null,
      },
    });

    const restored = PeerStateTable.fromJson(legacy);

    expect(restored.get(ALICE)!.lastKeyChangeAt).toBeNull();
    // A subsequent replacement is still detected against the
    // restored key.
    expect(restored.update(message(KEY_B, 2000)).keyChanged).toBe(true);
  });
});
