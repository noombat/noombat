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

// ..... Message encryption .....

/**
 * Sign and encrypt a plaintext message for the given recipient
 * (sign-then-encrypt per the Autocrypt Level 1 specification).
 *
 * @param recipientKeyBytes: The recipient's binary Transferable
 *   Public Key.
 * @param senderKeyBytes: The sender's binary Transferable Secret
 *   Key (used to sign the message).
 * @param plaintext: The raw message body (UTF-8 bytes).
 * @returns The signed-and-encrypted OpenPGP message (binary).
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
 *
 * @param privateKeyBytes: The recipient's binary Transferable Secret Key.
 * @param ciphertext: The encrypted OpenPGP message (binary).
 * @returns The decrypted plaintext as bytes.
 */
export async function decryptMessage(
  privateKeyBytes: Uint8Array,
  ciphertext: Uint8Array,
): Promise<Uint8Array> {
  const privateKey = await openpgp.readPrivateKey({ binaryKey: privateKeyBytes });
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
  /** Whether the embedded signature was verified against the
   *  sender's public key. */
  signatureVerified: boolean;
}

/**
 * Decrypt an OpenPGP-encrypted message and verify the embedded
 * signature against the sender's public key.
 *
 * Decryption failure throws. Signature verification failure is
 * **not** an error, i.e. the plaintext is still returned, with
 * `signatureVerified` set to `false`, so the caller can display a
 * warning in the UI.
 *
 * @param privateKeyBytes: The recipient's binary Transferable Secret Key.
 * @param senderKeyBytes: The sender's binary Transferable Public Key.
 * @param ciphertext: The encrypted OpenPGP message (binary).
 */
export async function decryptAndVerify(
  privateKeyBytes: Uint8Array,
  senderKeyBytes: Uint8Array,
  ciphertext: Uint8Array,
): Promise<DecryptAndVerifyResult> {
  const privateKey = await openpgp.readPrivateKey({ binaryKey: privateKeyBytes });
  const senderKey = await openpgp.readKey({ binaryKey: senderKeyBytes });
  const message = await openpgp.readMessage({ binaryMessage: ciphertext });

  const { data, signatures } = await openpgp.decrypt({
    message,
    decryptionKeys: privateKey,
    verificationKeys: senderKey,
    format: "utf8",
  });

  let signatureVerified = false;
  if (signatures.length > 0) {
    try {
      await signatures[0].verified;
      signatureVerified = true;
    } catch {
      // Signature verification failed; signatureVerified remains false.
    }
  }

  return {
    plaintext: data as string,
    signatureVerified,
  };
}
