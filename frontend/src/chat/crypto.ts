// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

/**
 * OpenPGP crypto module.
 *
 * Wraps OpenPGP.js v6 to expose typed, async functions for key
 * generation, message encryption, decryption, and signature
 * verification.
 *
 * All functions accept and return binary key/message representations
 * (Uint8Array) to preserve blob-format compatibility with the
 * existing credential storage layer.
 */

import * as openpgp from "openpgp";

// ..... Key generation .....

export interface KeyPair {
  /** Binary OpenPGP Transferable Public Key. */
  publicKey: Uint8Array;
  /** Binary OpenPGP Transferable Secret Key. */
  privateKey: Uint8Array;
}

/**
 * Generate a new OpenPGP key pair for the given email address.
 *
 * Produces an Ed25519 primary key (signing) with a Curve25519
 * subkey (encryption), matching the Autocrypt Level 1 key profile.
 */
export async function generateKeyPair(email: string): Promise<KeyPair> {
  const { privateKey, publicKey } = await openpgp.generateKey({
    type: "ecc",
    curve: "curve25519Legacy",
    userIDs: [{ email }],
    format: "binary",
  });
  return {
    publicKey: publicKey as Uint8Array,
    privateKey: privateKey as Uint8Array,
  };
}

// ..... Key fingerprints .....

/**
 * Compute the fingerprint of a binary Transferable Public Key.
 *
 * The fingerprint is the only value a user can compare out of band
 * to establish that the key held for a peer is the key that peer
 * actually holds. Until SecureJoin is implemented, this comparison
 * is the sole defence against an operator substituting its own key
 * during Autocrypt header exchange.
 *
 * Returned in upper case; see {@link formatFingerprint} for display.
 */
export async function keyFingerprint(keyBytes: Uint8Array): Promise<string> {
  const key = await openpgp.readKey({ binaryKey: keyBytes });
  return key.getFingerprint().toUpperCase();
}

/**
 * Group a fingerprint into blocks of four characters.
 *
 * Reading a 40-character hexadecimal string aloud, or comparing two
 * of them by eye, is error-prone; grouping is the conventional
 * mitigation and is what other OpenPGP interfaces present.
 */
export function formatFingerprint(fingerprint: string): string {
  return (fingerprint.match(/.{1,4}/g) ?? []).join(" ");
}

// ..... Message encryption .....

/**
 * Sign and encrypt a plaintext message for the given recipient
 * (sign-then-encrypt per the Autocrypt Level 1 specification).
 */
export async function encryptMessage(
  recipientKeyBytes: Uint8Array,
  senderKeyBytes: Uint8Array,
  plaintext: Uint8Array,
): Promise<Uint8Array> {
  const recipientKey = await openpgp.readKey({ binaryKey: recipientKeyBytes });
  const senderKey = await openpgp.readPrivateKey({ binaryKey: senderKeyBytes });
  const message = await openpgp.createMessage({ binary: plaintext });

  const encrypted = await openpgp.encrypt({
    message,
    encryptionKeys: recipientKey,
    signingKeys: senderKey,
    format: "binary",
  });

  return encrypted as Uint8Array;
}

// ..... Message decryption .....

/**
 * Decrypt an OpenPGP-encrypted message without signature verification.
 *
 * Use `decryptAndVerify` when the sender's public key is available.
 */
export async function decryptMessage(
  privateKeyBytes: Uint8Array,
  ciphertext: Uint8Array,
): Promise<Uint8Array> {
  const privateKey = await openpgp.readPrivateKey({
    binaryKey: privateKeyBytes,
  });
  const message = await openpgp.readMessage({ binaryMessage: ciphertext });

  const { data } = await openpgp.decrypt({
    message,
    decryptionKeys: privateKey,
    format: "binary",
  });

  return data as Uint8Array;
}

// ..... Message decryption with signature verification .....

export interface DecryptAndVerifyResult {
  /** The decrypted plaintext string. */
  plaintext: string;
  /**
   * Three-state signature verification outcome:
   *
   * - `true`: at least one signature verified successfully against
   *   the sender's public key.
   * - `false`: one or more signatures were present and none of them
   *   verified (key mismatch, corrupted signature, or algorithm error).
   * - `null`: the message carried no signature at all.
   */
  signatureVerified: boolean | null;
}

/**
 * Decrypt an OpenPGP-encrypted message and verify the embedded
 * signature against the sender's public key.
 *
 * Decryption failure throws. Signature verification failure is
 * **not** an error, i.e. the plaintext is still returned, with
 * `signatureVerified` set to `false`, so the caller can display a
 * warning in the UI. An unsigned message returns `null`.
 */
export async function decryptAndVerify(
  privateKeyBytes: Uint8Array,
  senderKeyBytes: Uint8Array,
  ciphertext: Uint8Array,
): Promise<DecryptAndVerifyResult> {
  const privateKey = await openpgp.readPrivateKey({
    binaryKey: privateKeyBytes,
  });
  const senderKey = await openpgp.readKey({ binaryKey: senderKeyBytes });
  const message = await openpgp.readMessage({ binaryMessage: ciphertext });

  const { data, signatures } = await openpgp.decrypt({
    message,
    decryptionKeys: privateKey,
    verificationKeys: senderKey,
    format: "utf8",
  });

  // Iterate over every signature rather than inspecting only the
  // first. A message may carry several, and OpenPGP.js returns them
  // in packet order, not in order of relevance.
  let signatureVerified: boolean | null = null;
  if (signatures.length > 0) {
    // Every signature is settled, rather than stopping at the first
    // success. OpenPGP.js creates each `verified` promise eagerly
    // during decryption, so a promise left unawaited after an early
    // exit rejects with no handler attached, which surfaces as an
    // unhandled rejection. Mapping each outcome to a boolean attaches
    // a handler to all of them.
    const outcomes = await Promise.all(
      signatures.map((signature) =>
        // `verified` resolves to `true` or rejects; see the
        // OpenPGP.js VerificationResult contract.
        signature.verified.then(
          () => true,
          () => false,
        ),
      ),
    );
    signatureVerified = outcomes.some((verified) => verified);
  }
  // When signatures.length === 0, signatureVerified remains null
  // (the message was unsigned).

  return {
    plaintext: data as string,
    signatureVerified,
  };
}
