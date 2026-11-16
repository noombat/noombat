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
  decryptMessage,
  decryptAndVerify,
  keyFingerprint,
  formatFingerprint,
  checkPublishedKey,
  MAX_DECOMPRESSED_BYTES,
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

// ..... Compression .....

describe("encryptMessage compression", () => {
  /** A message with the redundancy ordinary prose has. */
  const repetitive = "Thanks for the update on the role. ".repeat(40);

  it("produces a fraction of what the same message costs uncompressed", async () => {
    const plainBytes = new TextEncoder().encode(repetitive);

    const compressed = await encryptMessage(bob.publicKey, alice.privateKey, plainBytes);
    // `encryptSignedBy` passes no `config`, so this measures our
    // setting rather than a property of the library.
    const uncompressed = await encryptSignedBy(bob.publicKey, [alice.privateKey], repetitive);

    expect(compressed.length).toBeLessThan(uncompressed.length / 3);
  });

  it("leaves the uncompressed comparison larger than the plaintext", async () => {
    // Guards the test above: a compressing fixture would narrow the
    // comparison silently.
    const uncompressed = await encryptSignedBy(bob.publicKey, [alice.privateKey], repetitive);

    expect(uncompressed.length).toBeGreaterThan(repetitive.length);
  });

  it("round-trips, with the signature still verifying", async () => {
    const plainBytes = new TextEncoder().encode(repetitive);
    const ciphertext = await encryptMessage(bob.publicKey, alice.privateKey, plainBytes);

    const result = await decryptAndVerify(bob.privateKey, alice.publicKey, ciphertext);

    expect(result.plaintext).toBe(repetitive);
    expect(result.signatureVerified).toBe(true);
  });

  it("still reads a message a peer sent uncompressed", async () => {
    // A peer that compresses nothing must keep working.
    const ciphertext = await encryptSignedBy(bob.publicKey, [alice.privateKey], "plain and small");

    const result = await decryptAndVerify(bob.privateKey, alice.publicKey, ciphertext);

    expect(result.plaintext).toBe("plain and small");
    expect(result.signatureVerified).toBe(true);
  });

  it("costs almost nothing on incompressible input", async () => {
    // Measured against the uncompressed equivalent, not the plaintext:
    // OpenPGP's own packets are a few hundred bytes either way.
    const random = new Uint8Array(4096);
    crypto.getRandomValues(random);

    const compressed = await encryptMessage(bob.publicKey, alice.privateKey, random);

    const encryptionKeys = await openpgp.readKey({ binaryKey: bob.publicKey });
    const signingKeys = await openpgp.readPrivateKey({ binaryKey: alice.privateKey });
    const uncompressed = (await openpgp.encrypt({
      message: await openpgp.createMessage({ binary: random }),
      encryptionKeys,
      signingKeys,
      format: "binary",
    })) as Uint8Array;

    expect(compressed.length).toBeLessThan(uncompressed.length * 1.01);
  });
});

// ..... Decompression bound .....

describe("inbound decompression is bounded", () => {
  it("declares a finite ceiling", async () => {
    // The regression this guards is the ceiling quietly going away,
    // which no round-trip test notices.
    expect(Number.isFinite(MAX_DECOMPRESSED_BYTES)).toBe(true);
    expect(MAX_DECOMPRESSED_BYTES).toBe(30 * 1024 * 1024);
  });

  it("refuses a message that expands past the ceiling", async () => {
    // The shape of the attack, at a size a test can afford.
    const bomb = new TextEncoder().encode("A".repeat(512 * 1024));
    const ciphertext = await encryptMessage(bob.publicKey, alice.privateKey, bomb);
    expect(ciphertext.length).toBeLessThan(4096);

    await expect(decryptMessage(bob.privateKey, ciphertext, 64 * 1024)).rejects.toThrow();
  });

  it("accepts the same message when the ceiling allows it", async () => {
    // Guards the test above: a refusal from any other cause would
    // fail here too.
    const bomb = new TextEncoder().encode("A".repeat(512 * 1024));
    const ciphertext = await encryptMessage(bob.publicKey, alice.privateKey, bomb);

    const plain = await decryptMessage(bob.privateKey, ciphertext, 2 * 1024 * 1024);

    expect(plain.length).toBe(512 * 1024);
  });

  it("bounds the verifying path too", async () => {
    // The path the chat UI actually calls. Compressed deliberately:
    // the ceiling governs decompression, so an uncompressed fixture
    // would prove nothing.
    const bomb = new TextEncoder().encode("A".repeat(512 * 1024));
    const ciphertext = await encryptMessage(bob.publicKey, alice.privateKey, bomb);

    await expect(
      decryptAndVerify(bob.privateKey, alice.publicKey, ciphertext, 64 * 1024),
    ).rejects.toThrow();
  });
});

// ..... Keys an instance published .....

describe("checkPublishedKey", () => {
  it("accepts a key made as the client makes it, for its address in any case", async () => {
    const fingerprint = await checkPublishedKey(alice.publicKey, "Alice@Chat.Example.com");
    expect(fingerprint).toBe(await keyFingerprint(alice.publicKey));
  });

  it("refuses a key for another address, a private key and garbage", async () => {
    expect(await checkPublishedKey(alice.publicKey, "bob@chat.example.com")).toBeNull();
    expect(await checkPublishedKey(alice.privateKey, "alice@chat.example.com")).toBeNull();
    expect(await checkPublishedKey(new Uint8Array([1, 2, 3]), "alice@chat.example.com")).toBeNull();
  });

  it("refuses a key with no encryption subkey", async () => {
    const { publicKey } = await openpgp.generateKey({
      type: "ecc",
      curve: "curve25519Legacy",
      userIDs: [{ email: "carol@chat.example.com" }],
      subkeys: [],
      format: "binary",
    });
    expect(await checkPublishedKey(publicKey, "carol@chat.example.com")).toBeNull();
  });

  it("refuses a version 6 key", async () => {
    const { publicKey } = await openpgp.generateKey({
      type: "curve25519",
      userIDs: [{ email: "carol@chat.example.com" }],
      format: "binary",
      config: { v6Keys: true },
    });
    expect(await checkPublishedKey(publicKey, "carol@chat.example.com")).toBeNull();
  });

  it("refuses a valid key larger than the server would store", async () => {
    const email = "carol@chat.example.com";
    const { publicKey } = await openpgp.generateKey({
      type: "ecc",
      curve: "curve25519Legacy",
      userIDs: Array.from({ length: 40 }, (_, i) => ({ name: `Carol ${i}`, email })),
      format: "binary",
    });
    expect(publicKey.length).toBeGreaterThan(8192);
    expect(await checkPublishedKey(publicKey, email)).toBeNull();
  });

  it("reads only a User ID that verifies, not an unsigned one naming the address", async () => {
    const { publicKey } = await openpgp.generateKey({
      type: "ecc",
      curve: "curve25519Legacy",
      userIDs: [{ email: "target@chat.example.com" }, { email: "other@chat.example.com" }],
      format: "binary",
    });
    const key = await openpgp.readKey({ binaryKey: publicKey });
    key.users[0].selfCertifications = [];
    const unsigned = key.write() as Uint8Array;
    expect(await checkPublishedKey(unsigned, "target@chat.example.com")).toBeNull();
  });

  it("refuses a User ID whose self-certification is gone, so it does not verify", async () => {
    const key = await openpgp.readKey({ binaryKey: alice.publicKey });
    key.users[0].selfCertifications = [];
    const unsigned = key.write() as Uint8Array;
    expect(await checkPublishedKey(unsigned, "alice@chat.example.com")).toBeNull();
  });

  it("refuses a second key after the first", async () => {
    const two = new Uint8Array([...alice.publicKey, ...bob.publicKey]);
    expect(await checkPublishedKey(two, "alice@chat.example.com")).toBeNull();
  });

  it("refuses a key that could encrypt only with its primary", async () => {
    // Made by GnuPG with an RSA primary marked to sign and encrypt, and no
    // subkey: OpenPGP.js would encrypt to the primary.
    const primaryOnly = Uint8Array.from(
      atob(
        [
          "mQENBGr5FAUBCADSl/Rl8T24kjG0usDlgpDw3IuEKVQjI9ENt0T1oIs+BVDhBotUkx0xXCALI0nM",
          "EuqH2Db/gzTYkAg3Xiq45/l1+pGjEnzlEKqntiJ4PI82y+bDdlp56ZaSM68GFEIaJsbsHL4LTGRV",
          "ZxHL5T5HkVDl1uTXF4aOs4CEoxPlNdtTJakjCuIqQRbA1TBfY1D7MoRhcZMNRd9/UDNe00p5t8Fn",
          "KlNEe14Vyt+4nHzpUs5tDiBKfftt4WJkIzrZYEKoSn1wfb73xXqK6Ro0VCSc9N61o1H0qW6Brxbf",
          "0rBE6dAiknIAUOuVbNT9NZoxqqVQYzvXQn1VRtMQGBqHJ+4A9G61ABEBAAG0FmNhcm9sQGNoYXQu",
          "ZXhhbXBsZS5jb22JAU4EEwEKADgWIQQqDDrg5k1agWfJcw22MSTsB53J1QUCavkUBQIbDwULCQgH",
          "AgYVCgkICwIEFgIDAQIeAQIXgAAKCRC2MSTsB53J1Q5sB/9ZDV654/HSlv3ngjZGqbN90B4eN9x1",
          "C5s8KFpGIj55tPaxfF1vkk/SVzHK9oUeXTMZrbzXFpY849AUFTh5TpEaOrtpBJy+lojgbWlwJ/26",
          "ZlY89s8YrwXtHO/1wkzpD6IMHUqKWPfqLMZ3+tvCqx0WEKoSPU3manv8wz+5T09j7tTcrIVDQ3W3",
          "w50cT4Cn74TOdlToH1M43oQDoPjlVpuJbnTtp83Jbg+1oHbOY61pDGCbKYNDGYh+grJhDRgQKenE",
          "xQ7VQqB58kWo/ZENZffLdwmIFsEx9fvyoThl/K4T/H5o5HrzEA3BlHsXh+3pXxlaH74zDnYB+T0K",
          "hs97MiQ4",
        ].join(""),
      ),
      (c) => c.charCodeAt(0),
    );
    const key = await openpgp.readKey({ binaryKey: primaryOnly });
    expect((await key.getEncryptionKey()).getKeyID().equals(key.getKeyID())).toBe(true);
    expect(await checkPublishedKey(primaryOnly, "carol@chat.example.com")).toBeNull();
  });

  it("refuses an empty address, which a User ID without one would match", async () => {
    const { publicKey } = await openpgp.generateKey({
      type: "ecc",
      curve: "curve25519Legacy",
      userIDs: [{ name: "Carol" }],
      format: "binary",
    });
    expect(await checkPublishedKey(publicKey, "")).toBeNull();
  });
});
