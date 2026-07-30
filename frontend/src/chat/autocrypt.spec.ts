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
    // Level 1 §2.1: an attribute whose name does not begin with an
    // underscore is critical, and an unrecognised critical attribute
    // invalidates the entire header.
    expect(parseAutocryptHeader(`addr=${ALICE}; unknown=x; keydata=AQIDBA==`)).toBeNull();
  });

  it("ignores an unknown non-critical attribute", () => {
    expect(parseAutocryptHeader(`addr=${ALICE}; _draft=x; keydata=AQIDBA==`)).not.toBeNull();
  });

  it("rejects a header with no keydata", () => {
    expect(parseAutocryptHeader(`addr=${ALICE}; prefer-encrypt=mutual`)).toBeNull();
  });
});

