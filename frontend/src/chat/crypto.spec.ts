// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

/**
 * Tests for the OpenPGP wrapper.
 *
 * Two properties are load-bearing for the trust indicator shown
 * beside each message:
 *
 *   1. A message carrying several signatures verifies when *any* of
 *      them checks out against the sender's key.
 *   2. The three-state outcome distinguishes "no signature" from
 *      "signature that failed". Collapsing the two would let an
 *      unsigned message display the same indicator as a verified one.
 */

import { describe, it, expect, beforeAll } from "vitest";
import * as openpgp from "openpgp";
import {
  generateKeyPair,
  encryptMessage,
  decryptAndVerify,
  keyFingerprint,
  formatFingerprint,
  type KeyPair,
} from "./crypto";

// ..... Fixtures .....

let alice: KeyPair;
let bob: KeyPair;
let mallory: KeyPair;

beforeAll(async () => {
  [alice, bob, mallory] = await Promise.all([
    generateKeyPair("alice@chat.example.com"),
    generateKeyPair("bob@chat.example.com"),
    generateKeyPair("mallory@chat.example.com"),
  ]);
});

/**
 * Encrypt to `recipientPublic`, signed by each key in `signers`.
 *
 * `encryptMessage` signs with exactly one key, so multi-signature
 * messages are constructed here directly.
 */
async function encryptSignedBy(
  recipientPublic: Uint8Array,
  signers: Uint8Array[],
  plaintext: string,
): Promise<Uint8Array> {
  const encryptionKeys = await openpgp.readKey({ binaryKey: recipientPublic });
  const signingKeys = await Promise.all(
    signers.map((bytes) => openpgp.readPrivateKey({ binaryKey: bytes })),
  );
  const message = await openpgp.createMessage({
    binary: new TextEncoder().encode(plaintext),
  });
  return (await openpgp.encrypt({
    message,
    encryptionKeys,
    signingKeys,
    format: "binary",
  })) as Uint8Array;
}

// ..... Fingerprints .....

describe("keyFingerprint", () => {
  it("returns the key's fingerprint in upper case", async () => {
    const fingerprint = await keyFingerprint(alice.publicKey);
    const key = await openpgp.readKey({ binaryKey: alice.publicKey });

    expect(fingerprint).toBe(key.getFingerprint().toUpperCase());
    expect(fingerprint).toMatch(/^[0-9A-F]+$/);
  });

  it("distinguishes different keys", async () => {
    const a = await keyFingerprint(alice.publicKey);
    const b = await keyFingerprint(bob.publicKey);

    expect(a).not.toBe(b);
  });

  it("agrees between a secret key and its public half", async () => {
    // A user compares the fingerprint shown for their own key
    // against what a peer sees; the two must coincide.
    expect(await keyFingerprint(alice.privateKey)).toBe(await keyFingerprint(alice.publicKey));
  });
});

describe("formatFingerprint", () => {
  it("groups characters in fours", () => {
    expect(formatFingerprint("0123456789ABCDEF")).toBe("0123 4567 89AB CDEF");
  });

  it("leaves a short trailing group intact", () => {
    expect(formatFingerprint("0123456789")).toBe("0123 4567 89");
  });

  it("returns an empty string unchanged", () => {
    expect(formatFingerprint("")).toBe("");
  });

  it("preserves every character of a real fingerprint", async () => {
    const fingerprint = await keyFingerprint(alice.publicKey);
    const formatted = formatFingerprint(fingerprint);

    expect(formatted.replace(/ /g, "")).toBe(fingerprint);
  });
});

// ..... Signature verification .....

describe("decryptAndVerify", () => {
  it("verifies a message signed by the sender", async () => {
    const ciphertext = await encryptMessage(
      bob.publicKey,
      alice.privateKey,
      new TextEncoder().encode("hello"),
    );

    const result = await decryptAndVerify(bob.privateKey, alice.publicKey, ciphertext);

    expect(result.plaintext).toBe("hello");
    expect(result.signatureVerified).toBe(true);
  });

  it("reports failure when the only signature is from another key", async () => {
    const ciphertext = await encryptSignedBy(bob.publicKey, [mallory.privateKey], "hello");

    const result = await decryptAndVerify(bob.privateKey, alice.publicKey, ciphertext);

    expect(result.plaintext).toBe("hello");
    expect(result.signatureVerified).toBe(false);
  });

  it("reports null for an unsigned message", async () => {
    const encryptionKeys = await openpgp.readKey({ binaryKey: bob.publicKey });
    const message = await openpgp.createMessage({
      binary: new TextEncoder().encode("hello"),
    });
    const ciphertext = (await openpgp.encrypt({
      message,
      encryptionKeys,
      format: "binary",
    })) as Uint8Array;

    const result = await decryptAndVerify(bob.privateKey, alice.publicKey, ciphertext);

    // Distinguishable from a failed signature, so the interface can
    // show "encrypted, unverified" rather than a warning.
    expect(result.signatureVerified).toBeNull();
  });

  it("verifies when the sender's signature is not the first", async () => {
    const ciphertext = await encryptSignedBy(
      bob.publicKey,
      [mallory.privateKey, alice.privateKey],
      "hello",
    );

    const result = await decryptAndVerify(bob.privateKey, alice.publicKey, ciphertext);

    expect(result.signatureVerified).toBe(true);
  });

  it("verifies when the sender's signature is first", async () => {
    const ciphertext = await encryptSignedBy(
      bob.publicKey,
      [alice.privateKey, mallory.privateKey],
      "hello",
    );

    const result = await decryptAndVerify(bob.privateKey, alice.publicKey, ciphertext);

    expect(result.signatureVerified).toBe(true);
  });

  it("reports failure when several signatures are present and none matches", async () => {
    const ciphertext = await encryptSignedBy(
      bob.publicKey,
      [mallory.privateKey, bob.privateKey],
      "hello",
    );

    const result = await decryptAndVerify(bob.privateKey, alice.publicKey, ciphertext);

    expect(result.signatureVerified).toBe(false);
  });

  it("carries two signatures in the fixtures it claims to", async () => {
    // Guards the tests above: were multi-signature construction to
    // silently produce one signature, they would pass vacuously.
    const ciphertext = await encryptSignedBy(
      bob.publicKey,
      [mallory.privateKey, alice.privateKey],
      "hello",
    );
    const decryptionKeys = await openpgp.readPrivateKey({ binaryKey: bob.privateKey });
    const message = await openpgp.readMessage({ binaryMessage: ciphertext });
    const { signatures } = await openpgp.decrypt({ message, decryptionKeys, format: "binary" });

    expect(signatures).toHaveLength(2);
  });
});
